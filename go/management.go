// Management API 是 codex-turn-state 的前台，不是人人发一把管理钥匙的锁匠铺。
// 按操作者明确选择，本部署采用 keyless：CPA 绑定 127.0.0.1，经 SSH 隧道访问；能到隧道的人就能操作面板。这是部署边界，不是插件自带身份认证。
// 面板 HTML、status 及 dry_run、role、clear、selftest、scope save、probe start/cancel 都登记为 ResourceRoute。
// 宿主在 /v0/resource/plugins/<id>/ 下不鉴权，只收 GET，传 query 不传 body；动作凭 confirm=1 防误触，不能把这枚确认章当门锁。
// clear/selftest 另有 /v0/management/ 下带管理密钥的 POST ManagementRoutes，读取 JSON，供脚本使用，并非面板调用的路径。
// 这些路由不填 Menu：宿主会把声明 Menu 的 GET 移挂资源前缀（routeDeclaresLegacyMenuResource），别给带锁柜台偷偷开个无锁后门。
// 所有响应都不返回 Cookie 值，只给池的就绪度和到期信息；auth_id 是含客户邮箱的凭据文件名，匿名状态接口仍暴露它，这是已接受的隐私代价。
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

//go:embed cloud_mint_ui.html
var dashboardHTML []byte

// 路由后缀是认人的暗号：宿主可能给绝对路径，也可能给相对路径。
// 按 suffix 分发，不要求整条门牌长得一模一样。
const (
	routeStatus       = "/codex-turn-state/status"
	routeBucketsClear = "/codex-turn-state/buckets/clear"
	// 叫 selftest，不叫 probe：它不能采集，绿灯只能说明路通。
	// 别把门铃响了当成仓库满了，说明见 selftestNote。
	routeSelftest = "/codex-turn-state/selftest"
	// routeModeltrace 主动 WS 探针：对灌池源连打 N 轮，报告每轮 served 模型及探测判定。
	// 这是带 key 的 POST，像 selftest 一样真花额度，不是舞台纸钞。
	routeModeltrace = "/codex-turn-state/modeltrace"
	// routeGatewaySweep 多轮调用 FC modeltrace，按网关汇总探测所称的满血率；找落点，不给武功颁终身证书。
	routeGatewaySweep = "/codex-turn-state/gateway-sweep"
	// routeDashboard 相对插件资源前缀挂门牌，浏览器地址是
	// /v0/resource/plugins/codex-turn-state/dashboard，别敲隔壁管理柜台。
	routeDashboard = "/dashboard"
	// routeStatusResource 是免管理钥匙的状态别名：/v0/resource/plugins/codex-turn-state/status。
	// 它与 routeStatus 同以 /codex-turn-state/status 收尾，都去 handleStatus；面板一开门就能取数，不必先找钥匙。
	routeStatusResource = "/status"
	// routeConfig 原样返回配置，所以仍锁在管理密钥之后，不设资源别名。
	// 面板已改从 status 取明文代理列表，不靠它开饭；但未来配置里的秘密可能顺势出现在这里。
	// probe_management_key 已是秘密，故不放进 configResponse；别等无声无息公开了才发现柜门没锁。
	routeConfig = "/codex-turn-state/config"

	// 这些 keyless 动作明确登记为 ResourceRoutes：宿主不查管理密钥，只准 GET。
	// 按操作者选择，dry_run、role、clear、selftest 不多带秘密；代理编辑不在这一组，它涉及 userinfo，仍由 routeConfig 与 CPA 鉴权 PATCH 把关。
	// GET 会改状态，故必须 confirm=1 防止裸导航、预取或爬虫误触；这不是身份验证，举手不等于出示身份证。
	// 后缀加 /ops/，免得与管理侧 /buckets/clear、/selftest 撞名，两个柜台抢一张叫号票。
	routeOpsDryRun   = "/ops/dry-run"
	routeOpsRole     = "/ops/role"
	routeOpsClear    = "/ops/clear"
	routeOpsSelftest = "/ops/selftest"
	// routeOpsScope 跟其他 /ops 一样免管理钥匙，保存到插件自己的 scope 文件。
	// 宿主没给插件持久化配置的回调；PATCH /v0/management/plugins/<id>/config 又要鉴权，不能把免钥匙页面最后一步锁进柜子。
	routeOpsScope = "/ops/scope"
	// 探测启停也走 keyless /ops，省掉面板输入管理钥匙这道手续。
	// 执行所需 bearer 来自配置 probe_management_key，两个接口既不接收也不回显它，钥匙只在后台转手。
	// 资源路由是主动选择；别靠带 Menu 的 GET 被宿主悄悄移挂到免鉴权前缀来“碰巧免锁”。
	// start 真花额度，cancel 真停任务，因此都经 handleOpsResource 检查 confirm=1。
	routeOpsProbeStart  = "/ops/probe/start"
	routeOpsProbeCancel = "/ops/probe/cancel"

	// routeOpsProxyCheck 挨个测试已配置出口并逐行回报，实现在 proxy_check.go。
	// 请求不带账号凭据，不花账号额度，但会实际拨号，所以同样走 handleOpsResource，不能把探路当看地图。
	// 只读插件现有池，不从免钥匙 GET 的 query 接收代理 URL；userinfo 可能含密码，不能请它在访问日志和浏览器历史里巡演。
	routeOpsProxyCheck = "/ops/proxy-check"

	// routeOpsChoices 给范围编辑器提供真实 Codex 凭据与模型选项，把手抄点名册换成勾选。
	// normaliseProbeScope 只验形状不验存在性，错拼账号可能悄悄探了个寂寞。
	// 它只读不花额度，故不进要求 confirm=1 的 handleOpsResource；页面加载就能取表。
	// 免钥匙响应视同公开：label 经 maskAuthLabel 去掉邮箱，回传选中值所需 name 仍是完整文件名，暴露范围与 status.auth_id 相同。
	routeOpsChoices = "/ops/choices"
)

// managementRegister 把路由花名册交给 management.register，柜台各归各位。
func managementRegister(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRegistrationRequest
	if len(raw) > 0 {
		// 注册请求格式坏了也不必掀桌：以下路径固定，相对地址由宿主解析。
		_ = json.Unmarshal(raw, &req)
	}

	setCloudPluginID(req.ResourceBasePath)
	response := pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: routeStatus},
			{Method: http.MethodGet, Path: routeCloudDashboardStatus},
			{Method: http.MethodPost, Path: routeBucketsClear},
			{Method: http.MethodPost, Path: routeSelftest},
			{Method: http.MethodPost, Path: routeModeltrace},
			{Method: http.MethodPost, Path: routeGatewaySweep},
			// 数据路由不填 Menu；GET 一填就会被宿主移挂免鉴权资源前缀。
			// 这条若搬错柜台，代理密码就成了门口海报。
			{Method: http.MethodGet, Path: routeConfig},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				// 门牌不能写 "/"：normalizeResourceRoute 去掉尾斜杠后会拒绝空串。
				// 根路由会被无日志丢掉，只留下日后请求的 404，像开店忘挂地址。
				Path:        routeDashboard,
				Menu:        "云端打票",
				Description: "云端打票：真实任务、脱敏流水与打票设置",
			},
			{
				// 只读 status 走免鉴权资源前缀，不填 Menu，给面板取数据，不冒充 dashboard 页面。
				// 暴露 8317 前要看清：任何可达者都能读 auth_id（文件名内含客户邮箱）。
				// 操作者已选择免登录；这个选择不是把邮箱变成了非敏感的魔术。
				Path:        routeStatusResource,
				Description: "只读状态（无需鉴权），供看板拉取",
			},
			// 这些动作明确走免鉴权资源前缀，宿主只收 GET，再靠 confirm=1 防误点。
			// 绝不回显 probe_management_key；不填 Menu，因为面板用 fetch 办事，不是跳去看戏。
			{Path: routeOpsDryRun, Description: "翻转 dry_run（无需鉴权，需 confirm=1）"},
			{Path: routeOpsRole, Description: "切换 role（无需鉴权，需 confirm=1）"},
			{Path: routeOpsClear, Description: "清空桶（无需鉴权，需 confirm=1）"},
			{Path: routeOpsSelftest, Description: "连通性自检（无需鉴权，需 confirm=1，烧额度）"},
			// 保存 scope 免钥匙；按操作者明确要求，status 也回传明文代理列表。
			// 否则每改一次范围就得重输所有密码，编辑器会变成默写考试；routeConfig 仍保留管理密钥。
			{Path: routeOpsScope, Description: "保存探测范围（无需鉴权，需 confirm=1）"},
			// 探测启停与其他 /ops 一样免钥匙但需 confirm=1；运行从配置取探测密钥，不让用户现场翻口袋。
			{Path: routeOpsProbeStart, Description: "启动探测运行（无需鉴权，需 confirm=1，烧额度）"},
			{Path: routeOpsProbeCancel, Description: "取消探测运行（无需鉴权，需 confirm=1）"},
			// 没带凭据所以不花账号额度，但确实逐个拨出口；也得盖 confirm=1 的开工章。
			{Path: routeOpsProxyCheck, Description: "批量测代理到 OpenAI 的连通性（无需鉴权，需 confirm=1，不烧额度）"},
			// 范围选项只读，页面加载即取，不要求 confirm=1，不然复选框还没登台就被拦下。
			// 这里也不填 Menu：页面取的数据不是另一个可导航页面。
			{Path: routeOpsChoices, Description: "可选账号/模型清单（无需鉴权，只读）"},
		},
	}
	for i := range response.Routes {
		response.Routes[i].Path = cloudRegisteredPath(response.Routes[i].Path)
	}
	return okEnvelope(response)
}

// managementHandle 给 management/resource 请求分柜台，别让状态查询走进清仓通道。
func managementHandle(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return okEnvelope(managementError(http.StatusBadRequest, "could not decode the management request"))
	}

	path := cloudCanonicalPath(strings.TrimRight(strings.TrimSpace(req.Path), "/"))
	method := strings.ToUpper(strings.TrimSpace(req.Method))

	switch {
	case hasRouteSuffix(path, routeCloudDashboardStatus):
		if isResourcePath(path) {
			return okEnvelope(managementError(http.StatusForbidden, "cloud status requires management authentication"))
		}
		if method != http.MethodGet {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "cloud status is GET only"))
		}
		return okEnvelope(handleCloudDashboardStatus())
	case hasRouteSuffix(path, routeStatus):
		if method != http.MethodGet && method != "" {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "status is a GET route"))
		}
		return okEnvelope(handleStatus())
	case hasRouteSuffix(path, routeConfig):
		if method != http.MethodGet && method != "" {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "config is a GET route"))
		}
		// routeConfig 仍要钥匙：页面不再调用它，免钥匙体验不受影响；原样配置却不能随便公开。
		// 若日后 configResponse 加入探测 bearer，这层锁尤其不能丢。
		// resource 前缀表示误挂了免鉴权别名，密码在这里止步，不能因门牌挂错就照常迎客。
		if isResourcePath(path) {
			return okEnvelope(managementError(http.StatusNotFound, "no such codex-turn-state route: "+req.Path))
		}
		return okEnvelope(handleConfig())
	case hasRouteSuffix(path, routeBucketsClear):
		if method != http.MethodPost {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "buckets/clear is a POST route"))
		}
		return okEnvelope(handleBucketsClear(req.Body))
	case hasRouteSuffix(path, routeSelftest):
		if method != http.MethodPost {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "selftest is a POST route"))
		}
		return okEnvelope(handleSelftest(req.Body))
	case hasRouteSuffix(path, routeModeltrace):
		if method != http.MethodPost {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "modeltrace is a POST route"))
		}
		return okEnvelope(handleModeltrace(req.Body))
	case hasRouteSuffix(path, routeGatewaySweep):
		if method != http.MethodPost {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "gateway-sweep is a POST route"))
		}
		return okEnvelope(handleGatewaySweep(req.Body))
	case hasRouteSuffix(path, routeOpsChoices):
		// choices 不并入 handleOpsResource：那里的契约是改状态或花额度，才需 confirm=1。
		// 这边只读，加载时裸 GET 就该拿到复选框，不能在点菜前要求确认已经吃饱。
		// 仍自行检查 GET，虽宿主也限制，但宿主改主意时这道门槛还在。
		if method != http.MethodGet && method != "" {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "choices is a GET route"))
		}
		return okEnvelope(handleChoicesResource())
	case hasRouteSuffix(path, routeOpsDryRun),
		hasRouteSuffix(path, routeOpsRole),
		hasRouteSuffix(path, routeOpsClear),
		hasRouteSuffix(path, routeOpsSelftest),
		hasRouteSuffix(path, routeOpsScope),
		hasRouteSuffix(path, routeOpsProbeStart),
		hasRouteSuffix(path, routeOpsProbeCancel),
		hasRouteSuffix(path, routeOpsProxyCheck):
		// 免钥匙动作只从 resource 前缀进来，有 query、没 body、没管理 key。
		// handleOpsResource 先查 GET 与 confirm=1，票据没盖章就不开工。
		return okEnvelope(handleOpsResource(path, method, req.Query))
	case isDashboardPath(path):
		return okEnvelope(handleDashboard())
	default:
		return okEnvelope(managementError(http.StatusNotFound, "no such codex-turn-state route: "+req.Path))
	}
}

// hasRouteSuffix 按后缀认门：/codex-turn-state/status 和
// /v0/management/codex-turn-state/status 都得进同一个柜台，不能因街名长就换业务。
func hasRouteSuffix(path, suffix string) bool {
	return strings.EqualFold(path, suffix) || strings.HasSuffix(strings.ToLower(path), strings.ToLower(suffix))
}

// isDashboardPath 只认资源页面入口，不只看插件 id。
// 否则 /v0/management/codex-turn-state 这种拼错的管理路径也会喜提 HTML 200，把错门牌装成迎宾毯。
func isDashboardPath(path string) bool {
	return isResourcePath(path)
}

// isResourcePath 识别宿主免鉴权 resource 前缀，这是处理器判断是否查过管理钥匙的唯一线索。
// 绝不能匿名回答的路由必须问它，不能靠来客气势判断身份。
func isResourcePath(path string) bool {
	return strings.Contains(strings.ToLower(path), "/resource/plugins/")
}

// handleDashboard 只上页面空壳，不夹数据；这是按边界摆盘，不是厨师忘放菜。
func handleDashboard() pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
			// 页面内嵌了构建版本；升级后不留旧缓存，别让旧菜单指挥新厨房。
			"Cache-Control": []string{"no-store"},
			// 不让页面被套框，也不让浏览器猜 MIME；别给外人临时搭戏台。
			"X-Content-Type-Options": []string{"nosniff"},
		},
		Body: []byte(strings.Replace(string(dashboardHTML), `name="cpa-plugin-id" content="codex-turn-state"`, `name="cpa-plugin-id" content="`+currentCloudPluginID()+`"`, 1)),
	}
}

// handleOpsResource 处理免钥匙动作，只从资源前缀到达，没有管理 key 可验。
// 在仅本机可达的部署边界内，强制 GET + confirm=1，防裸导航、预取和爬虫误触。
// 越过这里就会改状态或花额度；确认章只是防手滑，不是防盗门。
func handleOpsResource(path, method string, q url.Values) pluginapi.ManagementResponse {
	if method != http.MethodGet && method != "" {
		return managementError(http.StatusMethodNotAllowed, "keyless action routes are GET-only")
	}
	if strings.TrimSpace(q.Get("confirm")) != "1" {
		return managementError(http.StatusBadRequest,
			"this action changes state or spends quota; it requires confirm=1 so it cannot fire from a bare navigation or a prefetch")
	}
	switch {
	case hasRouteSuffix(path, routeOpsDryRun):
		return handleDryRunResource(q)
	case hasRouteSuffix(path, routeOpsRole):
		return handleRoleResource(q)
	case hasRouteSuffix(path, routeOpsClear):
		return clearBuckets(clearRequestFromQuery(q))
	case hasRouteSuffix(path, routeOpsSelftest):
		return runSelftest(selftestRequestFromQuery(q))
	case hasRouteSuffix(path, routeOpsScope):
		return handleScopeSave(q)
	case hasRouteSuffix(path, routeOpsProbeStart):
		return handleProbeStartResource()
	case hasRouteSuffix(path, routeOpsProbeCancel):
		return handleProbeCancelResource()
	case hasRouteSuffix(path, routeOpsProxyCheck):
		return runProxyCheck()
	default:
		return managementError(http.StatusNotFound, "no such keyless action route")
	}
}

// handleProbeStartResource 开启探测并返回运行状态。已有任务则给 409，不甩锅成 400 请求错误。
// 依据 runner 自身状态判断，不匹配错误文案；文案换台词不该改变 HTTP 契约。
// 若失败后取快照前任务刚好结束，会回 400；两种情形都保留 runner 原错误，实话实说不补拍。
func handleProbeStartResource() pluginapi.ManagementResponse {
	if errStart := probeRunStart(); errStart != nil {
		status := http.StatusBadRequest
		if probeRunSnapshot().Running {
			status = http.StatusConflict
		}
		return managementError(status, errStart.Error())
	}
	// 现场取新快照：既然任务已在跑，就展示真进度，不虚构“即将开始”的零分成绩单。
	return jsonResponse(http.StatusOK, probeRunSnapshot())
}

// probeCancelResponse 同时报是否真的取消及最终 probe_run 状态。
// 本来没跑与刚被取消都会停着，不能只看空椅子就猜刚才谁坐过；字段与 status 共用解码。
type probeCancelResponse struct {
	Cancelled bool          `json:"cancelled"`
	ProbeRun  probeRunState `json:"probe_run"`
}

// handleProbeCancelResource 请求停工；本来没任务也算达到目标。
// 回 200、cancelled=false，不让页面为“没有人上班”特判一个 404。
func handleProbeCancelResource() pluginapi.ManagementResponse {
	cancelled := probeRunCancel()
	return jsonResponse(http.StatusOK, probeCancelResponse{
		Cancelled: cancelled,
		ProbeRun:  probeRunSnapshot(),
	})
}

// --- /ops/choices：先给菜单，别让用户凭空点菜 -------------------------------

// knownCodexModels 是范围编辑器的模型菜单，不是模型白名单。
// /ops/scope 接收自定义值，normaliseProbeScope 只拒空白，modelChoices 再并入 cfg.Models，手填模型仍能选中。
// 名单来自实测流量（FINDINGS.md），CPA 没有模型列表路由，过时只该少个复选框，不该封了点菜权。
// Go 没有常量切片所以用 var，生产中没人改这本菜单。
var knownCodexModels = []string{"gpt-5.5", "gpt-5.6-sol", "gpt-6-astra"}

// choicesFetchTimeout 限制本路由唯一一次 CPA 调用；页面有人等，不能套探测用的 30 秒 probeMgmtTimeout。
// 五秒足够等回环列表，又不至于等到茶凉；用 var 让测试缩时，生产不修改。
var choicesFetchTimeout = 5 * time.Second

// choiceAccount 是账号复选框：Name 保留 /ops/scope 回传所需完整文件名，Label 给人看。
// 文件名带邮箱，接口又免钥匙，展示名得先过 maskAuthLabel，不能把身份证贴点名册。
type choiceAccount struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	// Disabled 原样传 CPA 开关，让页面灰显而不是把行藏起来。
	// 禁用只影响 CPA 业务路由；离线探测取该凭据 token 直连上游，不看此开关，所以仍可选。
	// 旧式轮流启用账号的解释已过时：离线探测不碰账号状态，别让退役剧本继续指挥演员。
	Disabled bool `json:"disabled"`
	// Selected 按当前 cfg.ProbeAccounts 还原勾选，不让用户每次开门都重背点名册。
	Selected bool `json:"selected"`
}

// choiceModel 是模型的一格复选框，点菜用，不是能力鉴定章。
type choiceModel struct {
	Name     string `json:"name"`
	Selected bool   `json:"selected"`
}

// choicesResponse 是范围编辑器的菜单；Error 故意不用 omitempty。
// 页面无条件读它，空就给空，别玩“字段不见了”的猜谜游戏。
type choicesResponse struct {
	Accounts []choiceAccount `json:"accounts"`
	Models   []choiceModel   `json:"models"`
	Error    string          `json:"error"`
}

// handleChoicesResource 先备模型菜单，再取账号；取不到账号也回 200、accounts:[] 和 error。
// 模型不依赖 CPA 仍可用，明确错误比一张 500 闭店告示更有用；一道菜缺货不必关整间店。
func handleChoicesResource() pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	out := choicesResponse{
		// 两份列表都给 [] 不给 null；页面直接遍历，空盘能端，空气盘会摔。
		Accounts: []choiceAccount{},
		Models:   modelChoices(cfg.Models),
	}

	accounts, errAccounts := choiceAccounts(cfg)
	if errAccounts != nil {
		out.Error = errAccounts.Error()
		// choiceAccounts 已脱敏，日志与响应共用同一条净消息；钥匙不用分两路上镜。
		log.Printf(logPrefix+"choices: credential list unavailable: %s", out.Error)
		return jsonResponse(http.StatusOK, out)
	}
	out.Accounts = accounts
	return jsonResponse(http.StatusOK, out)
}

// choiceAccounts 用 probe runner 客户端取 CPA Codex 凭据，再标出已选项。
// 它读 GET /v0/management/auth-files，与实际 sweep 同视图、同过滤、同 .bak 排除，不混用 statusAccounts 的 host.auth.list。
// 复选框要能真的探到；过滤只复用 listCodexAuths，别另抄一份规则把备份账号也请上场。
func choiceAccounts(cfg pluginConfig) ([]choiceAccount, error) {
	// 没 key 就本地说明缺配置，不发匿名 GET 再怪 CPA 的 401；没带钥匙和钥匙不对不是一回事。
	if strings.TrimSpace(cfg.ProbeManagementKey) == "" {
		return nil, fmt.Errorf("probe_management_key is not set, so CPA's credential list cannot be read; " +
			"set it in config.yaml and reload, or keep listing probe_accounts by hand")
	}

	// 页面单独限时，不借 sweep 的慢钟；每条返回路径都取消，别让人走了电话还占线。
	ctx, cancel := context.WithTimeout(context.Background(), choicesFetchTimeout)
	defer cancel()

	files, errList := newProbeClient(cfg).listCodexAuths(ctx)
	if errList != nil {
		// 错误即便看似不含秘密也先脱敏，因它可能引述响应体，要去匿名字段和日志。
		// probeExplainStatus 只报 probe_management_key 字段名，不把钥匙本尊请出来作证。
		return nil, fmt.Errorf("could not read CPA's credential list: %s", probeRedact(errList.Error()))
	}

	selected := make(map[string]bool, len(cfg.ProbeAccounts))
	for _, name := range cfg.ProbeAccounts {
		selected[strings.TrimSpace(name)] = true
	}

	// listCodexAuths 已按名字排队，这里不再重排，刷新别变成抢座游戏。
	out := make([]choiceAccount, 0, len(files))
	for _, file := range files {
		out = append(out, choiceAccount{
			Name:     file.Name,
			Label:    maskAuthLabel(file.Name),
			Disabled: file.Disabled,
			Selected: selected[file.Name],
		})
	}
	return out, nil
}

// modelChoices 合并配置模型与已知菜单：只留菜单会丢手填模型，只留配置会让新部署无菜可点。
// 按精确字符串去重，不能忽略大小写；GPT-5.5 与 gpt-5.5 在 CPA/store/bucketKey 里是两张桌，别擅自拼桌。
func modelChoices(configured []string) []choiceModel {
	selected := make(map[string]bool, len(configured))
	union := make(map[string]bool, len(configured)+len(knownCodexModels))
	for _, raw := range configured {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		selected[name] = true
		union[name] = true
	}
	for _, name := range knownCodexModels {
		union[name] = true
	}

	// map 遍历会洗牌，排好序再端上页面，别让复选框每轮刷新都换座。
	names := make([]string, 0, len(union))
	for name := range union {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]choiceModel, 0, len(names))
	for _, name := range names {
		out = append(out, choiceModel{Name: name, Selected: selected[name]})
	}
	return out
}

// maskAuthLabel 先按连字符分段，删掉所有含 @ 的部分，再取幸存段的首尾。
// 凭据文件名含 id、邮箱、tier；例如 codex-620f5a42-luo.swmu@example.com-pro.json 应显示成 620f5a42…pro，而不是晒客户邮箱。
// 顺序不能倒：codex-620f5a42-luo@example.com.json 的末段就是邮箱，先取首尾会把秘密端上桌。
// 异常形状宁可短些怪些，也只输出过了 @ 过滤的片段；别拿普通缩写助手冒充隐私保镖，这里是免钥匙响应的最后一道挡板。
func maskAuthLabel(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		// 空名字就给空标签，别凭空捏造身份或 panic；路由虽已滤空，助手还得会接空盘。
		return ""
	}

	// 这两个固定前后缀人人都有，摘掉制服再认人，不损失区分信息。
	body := trimmed
	if lower := strings.ToLower(body); strings.HasSuffix(lower, ".json") {
		body = body[:len(body)-len(".json")]
	}
	if lower := strings.ToLower(body); strings.HasPrefix(lower, "codex-") {
		body = body[len("codex-"):]
	}

	kept := make([]string, 0, 4)
	for _, part := range strings.Split(body, "-") {
		part = strings.TrimSpace(part)
		// 认 @ 不认域名花名册；域名会翻新，漏一个就给邮箱开了后门。
		if part == "" || strings.Contains(part, "@") {
			continue
		}
		kept = append(kept, part)
	}

	switch len(kept) {
	case 0:
		// 全是邮箱形状就只显示省略号，丑一点也不拿隐私凑字数。
		// name 仍能回传选值，复选框能工作，牺牲的是特殊名字的辨识度，不是功能。
		return "…"
	case 1:
		// 只剩一段就直接显示，别把一个人复制两遍冒充双人组。
		return kept[0]
	default:
		// 取首尾保留 id 与 tier，中间连字符再多也别把标签拉成长面条。
		return kept[0] + "…" + kept[len(kept)-1]
	}
}

// clearRequestFromQuery 把 ?all=1 或 ?auth_id=..&model=.. 装成 clearRequest。
// 后续 clearBuckets 与 POST 共用验证和路径净化；query 不是能带 auth_id 翻仓库围墙的贵宾通道。
func clearRequestFromQuery(q url.Values) clearRequest {
	return clearRequest{
		AuthID: strings.TrimSpace(q.Get("auth_id")),
		Model:  strings.TrimSpace(q.Get("model")),
		All:    queryTrue(q.Get("all")),
	}
}

// selftestRequestFromQuery 从 ?model=..&auth_id=.. 取自检单；auth_id 可不填，留给调度器点名。
func selftestRequestFromQuery(q url.Values) selftestRequest {
	return selftestRequest{
		Model:  strings.TrimSpace(q.Get("model")),
		AuthID: strings.TrimSpace(q.Get("auth_id")),
	}
}

// handleDryRunResource 从免钥匙路由切 dry_run，并借 main.go 的 runtimeOverride 持久化，让重启别失忆。
// 改 dry_run 不作废池或计数，仍统一经 swapConfigLocked 换运行配置；只换排练牌，不清厨房。
func handleDryRunResource(q url.Values) pluginapi.ManagementResponse {
	value, ok := parseBoolParam(q.Get("value"))
	if !ok {
		return managementError(http.StatusBadRequest, `"value" must be one of on/off/true/false/1/0`)
	}
	state.mu.Lock()
	cfg := state.config
	cfg.DryRun = value
	swapConfigLocked(cfg)
	dir := cfg.StoreDir
	role := cfg.Role
	state.mu.Unlock()

	persisted := true
	warning := ""
	if err := writeRuntimeOverride(dir, role, value); err != nil {
		// 内存里已经改好，只是落盘失败；重启会回原样，不能拿半张收据冒充办妥。
		persisted = false
		warning = "restart will revert: " + err.Error()
		log.Printf(logPrefix+"dry_run set to %t but persisting the override failed: %v", value, err)
	} else {
		log.Printf(logPrefix+"dry_run set to %t via dashboard (keyless)", value)
	}
	return jsonResponse(http.StatusOK, map[string]any{"dry_run": value, "persisted": persisted, "warning": warning})
}

// handleRoleResource 切角色并持久化；swapConfigLocked 会像配置文件改角色那样重置计数。
// 角色切换可能要重启重谈 hooks，所以选择得留得住，别换完工牌重启又穿回旧制服。
func handleRoleResource(q url.Values) pluginapi.ManagementResponse {
	role := strings.ToLower(strings.TrimSpace(q.Get("value")))
	if role != roleProbe && role != roleBusiness {
		return managementError(http.StatusBadRequest,
			fmt.Sprintf(`"value" must be %q or %q`, roleProbe, roleBusiness))
	}
	state.mu.Lock()
	cfg := state.config
	if role == roleProbe && strings.TrimSpace(cfg.StoreDir) == "" {
		state.mu.Unlock()
		return managementError(http.StatusConflict, "role probe requires store_dir, which is not configured")
	}
	cfg.Role = role
	swapConfigLocked(cfg)
	dir := cfg.StoreDir
	dryRun := cfg.DryRun
	state.mu.Unlock()

	persisted := true
	warning := ""
	if err := writeRuntimeOverride(dir, role, dryRun); err != nil {
		persisted = false
		warning = "restart will revert: " + err.Error()
		log.Printf(logPrefix+"role set to %s but persisting the override failed: %v", role, err)
	} else {
		log.Printf(logPrefix+"role set to %s via dashboard (keyless)", role)
	}
	return jsonResponse(http.StatusOK, map[string]any{
		"role":      role,
		"persisted": persisted,
		"warning":   warning,
		"note":      "若切换后发现钩子没被重新协商（probe 采不到 / business 不替换），重启一次 CPA。",
	})
}

// queryTrue 给 ?all= 认常见真值拼法；缺失或其余内容都算 false，不靠语气猜真假。
func queryTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// parseBoolParam 同时报布尔值与是否认得；拼错返回 ok=false，不能把错字悄悄当关灯口令。
func parseBoolParam(v string) (value bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true, true
	case "0", "false", "off", "no":
		return false, true
	}
	return false, false
}

// statusBucket 是就绪矩阵的一格 (account, model)，别把一张桌的账记到全店。
type statusBucket struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	Ready  bool   `json:"ready"`
	// Len 如实记最后签发的 turn-state 长度；FINDINGS.md 的长度档位是套餐实测，不是协议铁律。
	// 超出配置两档也先当观测数据，别看身高超表就说客人不存在。
	Len int `json:"len"`
	// Enabled 把凭据状态带到每个格子，页面可直接灰显整行；禁用也保留，免得“没采到”与“账号关了”混成失踪案。
	// accounts_source=store 时没有权威账号列表，暂报 true，不编造禁用状态；来源标签已说明这是借旧账本认人。
	Enabled bool `json:"enabled"`
	// RouteCookiesSecondsLeft 是全局池最好 __cflb/__oailb 的剩余寿命，各格同一口钟，不绑账号或票。
	// ready=true 仍可能为零：上游曾签正常状态，却没活 pair 可引路；0/省略都指池里没活 pair，绿招牌不等于有房卡。
	RouteCookiesSecondsLeft int64 `json:"route_cookies_seconds_left,omitempty"`
	// Observed 按是否携带引导 pair 拆开真实上游观测；没见过就不填。
	// 没有客流不等于客人满意，页面不能把“没数据”画成“正常”。
	Observed *observationSummary `json:"observed,omitempty"`
}

type statusResponse struct {
	Role           string         `json:"role"`
	DryRun         bool           `json:"dry_run"`
	TTLSeconds     int            `json:"ttl_seconds"`
	TemplateLength int            `json:"template_length"`
	ReplaceLength  int            `json:"replace_length"`
	StoreDir       string         `json:"store_dir"`
	Models         []string       `json:"models"`
	Buckets        []statusBucket `json:"buckets"`
	TargetsTotal   int            `json:"targets_total"`
	TargetsReady   int            `json:"targets_ready"`
	// AccountsSource=host 表示来自 host.auth.list，store 表示问不到宿主，只能从已有存储推账号。
	// 后者看不见从未探测的账号；空矩阵可能是没问成，不是全店没人，别把账本空白当人口普查。
	AccountsSource string           `json:"accounts_source"`
	AccountsError  string           `json:"accounts_error,omitempty"`
	Counters       decisionCounters `json:"counters"`
	CountersSince  string           `json:"counters_since"`
	GeneratedAt    string           `json:"generated_at"`
	StoreError     string           `json:"store_error,omitempty"`

	// ---- 探测范围：这一柜全部可匿名读取，不是上了锁的保险箱 ----
	// handleStatus 同时服务 /v0/management/codex-turn-state/status 与免鉴权 /v0/resource/plugins/codex-turn-state/status，没有按路由过滤字段。
	// probe_proxies 曾只有计数和脱敏列表；按操作者明确要求改为明文，避免编辑器用 socks5h://***@exit:1080 回填后，每次保存都得重输所有密码。
	// 这是既有部署选择：CPA 绑定 127.0.0.1、经 SSH 隧道访问；不等于本机其他进程或任何可达者读不到。
	// 日志与 configErrors 仍必须走 maskProxyURL，日志会被贴到工单和聊天，钥匙不能随账单外卖。
	// 以后新增字段同样视为公开；probe_management_key 绝不放进来，连脱敏版本也不摆。
	ProbeAccounts   []string `json:"probe_accounts"`
	ProbeProxyCount int      `json:"probe_proxy_count"`
	// ProbeProxies 按操作者明确选择回明文；上面的风险说明不是装饰招牌。
	ProbeProxies []string `json:"probe_proxies"`
	// 这里同 ProbeProxies 回明文，理由相同；换个池名不会自动变出门锁。
	ProbeProxyRotatingCount int      `json:"probe_proxy_rotating_count"`
	ProbeProxiesRotating    []string `json:"probe_proxies_rotating"`
	// ConfigErrors 展示 configure 拒掉的范围项；不致命不等于没影响，别悄悄少做半桌菜。
	ConfigErrors []string `json:"config_errors,omitempty"`
	// ProbeRun 合并 runner 进度，面板轮询一份文档即可；同样匿名可读。
	// Lines 只写进度结果，不写 key 或 Cookie 值，现场播报不是晒钥匙大会。
	ProbeRun probeRunState `json:"probe_run"`

	// ObservationsSince 交代统计从何时起算；3 次与 4237 次不是同一分量，别只报胜率不报场次。
	ObservationsSince string `json:"observations_since,omitempty"`
	// ObservationFeed 新记录在前，全部结构化字段，不给自由文本留泄密话筒。
	// 它会公开逐账号请求时间与活动模式；本机回环加 SSH 隧道的边界可接受，放到公开可达网络就不能照搬。
	ObservationFeed []observationEvent `json:"observation_feed"`
}

// handleStatus 只读配置、矩阵就绪度和决策计数，可经鉴权管理路由或免鉴权资源 status 访问。
// 暴露范围见 managementRegister；不回 Cookie 值，只报长度、就绪度、时间等观测，明文代理等配置另按字段注释的既定边界处理，别把“无 Cookie”误读成“无秘密”。
func handleStatus() pluginapi.ManagementResponse {
	now := time.Now()

	state.mu.Lock()
	cfg := state.config
	counts := state.counts
	countsAt := state.countsAt
	configErrors := append([]string(nil), state.configErrors...)
	state.mu.Unlock()

	out := statusResponse{
		Role:           cfg.Role,
		DryRun:         cfg.DryRun,
		TTLSeconds:     cfg.TTLSeconds,
		TemplateLength: cfg.TemplateLength,
		ReplaceLength:  cfg.ReplaceLength,
		StoreDir:       cfg.StoreDir,
		Models:         append([]string(nil), cfg.Models...),
		Counters:       counts,
		CountersSince:  countsAt.UTC().Format(time.RFC3339),
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		Buckets:        []statusBucket{},
		ProbeAccounts:  append([]string(nil), cfg.ProbeAccounts...),
		// 明文代理依操作者选择返回；计数也保留，页面懒加载列表时不必先把每个客人叫起来数一遍。
		ProbeProxyCount: len(cfg.ProbeProxies),
		ProbeProxies:    append([]string(nil), cfg.ProbeProxies...),

		ProbeProxyRotatingCount: len(cfg.ProbeProxiesRotating),
		ProbeProxiesRotating:    append([]string(nil), cfg.ProbeProxiesRotating...),
		ConfigErrors:            configErrors,
		// 在 state.mu 外取 runner 快照，它有自己的锁；两把锁别互相等着请客。
		// 这里不要求两个视图严格同一时刻，没必要为了合影制造死锁。
		ProbeRun: probeRunSnapshot(),
	}
	if out.Models == nil {
		out.Models = []string{}
	}
	if out.ProbeAccounts == nil {
		out.ProbeAccounts = []string{}
	}
	// 空列表给 []，不给 null；编辑器不该凭空长出一行叫 null 的代理。
	if out.ProbeProxies == nil {
		out.ProbeProxies = []string{}
	}
	if out.ProbeProxiesRotating == nil {
		out.ProbeProxiesRotating = []string{}
	}

	ttl := cfg.ttl()

	// 池寿命只剩一个全局数值：pair 不认账号，各格共用一口钟，不各自报时。
	state.mu.Lock()
	poolLeft := state.poolSecondsLeftLocked(now, ttl)
	state.mu.Unlock()

	// 每桶只读观测快照；模板仓已退场，就绪看上游最后签了什么，不看不存在的库存。
	observed, feed, since := observationsSnapshot()
	out.ObservationsSince = since
	out.ObservationFeed = feed
	if out.ObservationFeed == nil {
		out.ObservationFeed = []observationEvent{}
	}
	byKey := make(map[string]observationSummary, len(observed))
	for _, cell := range observed {
		byKey[bucketKey(cell.AuthID, cell.Model)] = cell.summary(now)
	}

	// 矩阵列出应关注的目标，而非只列已经看见的流量。
	// 部署刚开张最需要看覆盖范围，不能因为还没来客就把桌椅从菜单上抹掉。
	accounts, accountsSource, errAccounts := statusAccounts(observed)
	out.AccountsSource = accountsSource
	if errAccounts != nil {
		// 问宿主失败只降级，不把页面掀掉；仍展示观测推导的矩阵，并明说是旧账本认人。
		out.AccountsError = errAccounts.Error()
	}
	// 配置的探测范围替换矩阵行集合，而非只过滤宿主列表；否则范围内但宿主没报的账号会无声失踪。
	// 已知账号仍用宿主 enabled，未知账号保留行并标禁用，让少了谁有个说法。
	if len(cfg.ProbeAccounts) > 0 {
		known := make(map[string]bool, len(accounts))
		for _, account := range accounts {
			known[account.AuthID] = account.Enabled
		}
		scoped := make([]codexAuth, 0, len(cfg.ProbeAccounts))
		for _, name := range cfg.ProbeAccounts {
			enabled, seen := known[name]
			// 宿主不认识就暂按 enabled=false 表示当前不可达，别替陌生人办通行证。
			scoped = append(scoped, codexAuth{AuthID: name, Enabled: seen && enabled})
		}
		accounts = scoped
	}

	models := out.Models
	if len(models) == 0 {
		// 没配模型列表就借已有观测的名单，让页面在菜单填好前也不至于只端空盘。
		modelSeen := make(map[string]bool)
		for _, cell := range observed {
			modelSeen[cell.Model] = true
		}
		for model := range modelSeen {
			models = append(models, model)
		}
		sort.Strings(models)
	}

	enabledByAuth := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		enabledByAuth[account.AuthID] = account.Enabled
	}

	// cellFor 按观测画格子；Ready 指上游最后在此签过正常状态，不是仓库里还藏着一张模板票。
	cellFor := func(auth, model string) statusBucket {
		cell := statusBucket{AuthID: auth, Model: model}
		if summary, ok := byKey[bucketKey(auth, model)]; ok {
			copied := summary
			cell.Observed = &copied
			// Ready 接受非已知降级长度，含 other；档位是套餐实测，不能把未知签名长度一律当失败。
			// 已见健康 332/780，但新降级长度也可能落入 other，这是不硬编码上游尺寸的取舍，量衣尺不是验功仪。
			cell.Ready = summary.LastSignedKind != "" && summary.LastSignedKind != observationLimited
			cell.Len = summary.LastLen
		}
		cell.RouteCookiesSecondsLeft = poolLeft
		return cell
	}

	// targetsReady 只数本轮目标矩阵，不把下方追加的历史漂移行也算进成绩单。
	targetsTotal := 0
	targetsReady := 0
	seen := make(map[string]bool, len(accounts)*len(models))
	for _, account := range accounts {
		for _, model := range models {
			cell := cellFor(account.AuthID, model)
			cell.Enabled = account.Enabled
			out.Buckets = append(out.Buckets, cell)
			seen[bucketKey(account.AuthID, model)] = true
			targetsTotal++
			if cell.Ready {
				targetsReady++
			}
		}
	}
	// 已观测但不在当前矩阵的账号/模型仍显示；名单变了不等于历史客人凭空蒸发。
	for _, cell := range observed {
		key := bucketKey(cell.AuthID, cell.Model)
		if seen[key] {
			continue
		}
		seen[key] = true
		row := cellFor(cell.AuthID, cell.Model)
		enabled, known := enabledByAuth[cell.AuthID]
		row.Enabled = !known || enabled
		out.Buckets = append(out.Buckets, row)
	}

	// 固定行列顺序，刷新只更新账目，不让整间店的座位重新抽签。
	sort.Slice(out.Buckets, func(i, j int) bool {
		if out.Buckets[i].AuthID != out.Buckets[j].AuthID {
			return out.Buckets[i].AuthID < out.Buckets[j].AuthID
		}
		return out.Buckets[i].Model < out.Buckets[j].Model
	})

	// 进度分母只算目标矩阵，不用 len(out.Buckets)；2 账号 × 2 模型不能报成“8/25”。
	// 漂移行仍展示，但不混进用户没点过的套餐。
	out.TargetsTotal = targetsTotal
	out.TargetsReady = targetsReady

	return jsonResponse(http.StatusOK, out)
}

// configResponse 是可编辑配置的带钥匙视图，代理原样回传；旧编辑器不能把 *** 当密码写回去。
// 现在面板从 status 取代理，这条路保留而不再被页面调用。
// probe_management_key 绝不能新增到这里：它不供编辑或展示，别等一个误挂资源别名就把钥匙送到街上。
type configResponse struct {
	Role           string   `json:"role"`
	StoreDir       string   `json:"store_dir"`
	Models         []string `json:"models"`
	ProbeAccounts  []string `json:"probe_accounts"`
	ProbeProxies   []string `json:"probe_proxies"`
	DryRun         bool     `json:"dry_run"`
	TTLSeconds     int      `json:"ttl_seconds"`
	TemplateLength int      `json:"template_length"`
	ReplaceLength  int      `json:"replace_length"`
	ConfigErrors   []string `json:"config_errors,omitempty"`
}

// handleConfig 只读，且在管理密钥之后；写入交给 CPA 的 PATCH /v0/management/plugins/codex-turn-state/config。
// 宿主管持久化，没提供 host.config.save；自建写路由只改内存，下次 reconfigure 又会打回原形，不能卖会消失的收据。
func handleConfig() pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	configErrors := append([]string(nil), state.configErrors...)
	state.mu.Unlock()

	out := configResponse{
		Role:           cfg.Role,
		StoreDir:       cfg.StoreDir,
		Models:         append([]string(nil), cfg.Models...),
		ProbeAccounts:  append([]string(nil), cfg.ProbeAccounts...),
		ProbeProxies:   append([]string(nil), cfg.ProbeProxies...),
		DryRun:         cfg.DryRun,
		TTLSeconds:     cfg.TTLSeconds,
		TemplateLength: cfg.TemplateLength,
		ReplaceLength:  cfg.ReplaceLength,
		ConfigErrors:   configErrors,
	}
	if out.Models == nil {
		out.Models = []string{}
	}
	if out.ProbeAccounts == nil {
		out.ProbeAccounts = []string{}
	}
	if out.ProbeProxies == nil {
		out.ProbeProxies = []string{}
	}
	return jsonResponse(http.StatusOK, out)
}

type scopeSaveResponse struct {
	Saved              bool     `json:"saved"`
	Fields             []string `json:"fields"`
	ProbeAccounts      []string `json:"probe_accounts"`
	Models             []string `json:"models"`
	ProbeProxyCount    int      `json:"probe_proxy_count"`
	ProbeProxiesMasked []string `json:"probe_proxies_masked"`
	RotatingCount      int      `json:"probe_proxy_rotating_count"`
	RotatingMasked     []string `json:"probe_proxies_rotating_masked"`
	TargetsTotal       int      `json:"targets_total"`
	ConfigErrors       []string `json:"config_errors,omitempty"`
	Note               string   `json:"note"`
}

// handleScopeSave 从 keyless query 持久化探测范围；用 fields 明说替换哪份列表，不凭参数有没有出现来猜。
// “清空代理”和“这次没传代理”可能长得一样，猜错会把整本凭据账撕掉。
// 值用重复参数 account=a&account=b&model=x&proxy=…；资源 GET 无 body，只能走 query，代理 userinfo 因而会进入 URL。
// 既有 CPA 日志记录上游 /v1/* 而非管理请求行，插件也只记脱敏代理；这不是保证浏览器或其他中间层永不留 URL 的隐身术。
func handleScopeSave(q url.Values) pluginapi.ManagementResponse {
	requested := map[string]bool{}
	for _, field := range strings.Split(q.Get("fields"), ",") {
		if name := strings.ToLower(strings.TrimSpace(field)); name != "" {
			requested[name] = true
		}
	}
	if len(requested) == 0 {
		return managementError(http.StatusBadRequest,
			`"fields" is required: name which lists to replace, e.g. fields=accounts,models,proxies,rotating. `+
				`Without it an empty query would be indistinguishable from "clear everything".`)
	}
	for name := range requested {
		switch name {
		case "accounts", "models", "proxies", "rotating", "mint_accounts":
		default:
			return managementError(http.StatusBadRequest,
				"unknown field "+name+"; expected accounts, models, proxies, rotating or mint_accounts")
		}
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if strings.TrimSpace(cfg.StoreDir) == "" {
		return managementError(http.StatusConflict,
			"store_dir is not configured, so there is nowhere to save the probe scope")
	}

	accounts, models, proxies := cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies
	rotating := cfg.ProbeProxiesRotating
	mintAccounts := cfg.MintAccounts
	if requested["accounts"] {
		accounts = q["account"]
	}
	if requested["models"] {
		models = q["model"]
	}
	if requested["proxies"] {
		proxies = q["proxy"]
	}
	if requested["rotating"] {
		rotating = q["rotating_proxy"]
	}
	if requested["mint_accounts"] {
		mintAccounts = q["mint_account"]
	}

	accounts, models, proxies, rotating, problems := normaliseProbeScope(accounts, models, proxies, rotating)
	// 打票账号先滤空白；是否属于 probe_accounts 交给 fillAccounts 查名册，不能只看衣服像不像。
	{
		cleaned := mintAccounts[:0:0]
		for _, a := range mintAccounts {
			if s := strings.TrimSpace(a); s != "" {
				cleaned = append(cleaned, s)
			}
		}
		mintAccounts = cleaned
	}

	scope := probeScope{
		Accounts:     accounts,
		Models:       models,
		Proxies:      proxies,
		Rotating:     rotating,
		MintAccounts: mintAccounts,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if errWrite := writeProbeScope(cfg.StoreDir, scope); errWrite != nil {
		return managementError(http.StatusInternalServerError,
			"could not save the probe scope: "+errWrite.Error())
	}

	// 内存与磁盘一起更新，不等宿主下次 reconfigure 才开工。
	// 范围只管下一轮探谁，不抹掉已发生的观测；换菜单不等于撕掉旧账单。
	state.mu.Lock()
	state.config.ProbeAccounts = accounts
	state.config.Models = models
	state.config.ProbeProxies = proxies
	state.config.ProbeProxiesRotating = rotating
	state.config.MintAccounts = mintAccounts
	state.configErrors = problems
	liveCfg := state.config
	state.mu.Unlock()
	// 灌池子集或探针账号一变，后台立即按新名单开工，不等宿主 reconfigure 再发开饭通知。
	cloudPoolFillerReconfigure(liveCfg)

	log.Printf(logPrefix+"probe scope saved: accounts=%d models=%d proxies=%d rotating=%d (fields=%s)",
		len(accounts), len(models), len(proxies), len(rotating), q.Get("fields"))
	for _, problem := range problems {
		log.Printf(logPrefix+"config error (probe scope, not fatal): %s", problem)
	}

	out := scopeSaveResponse{
		Saved:              true,
		Fields:             sortedKeys(requested),
		ProbeAccounts:      accounts,
		Models:             models,
		ProbeProxyCount:    len(proxies),
		ProbeProxiesMasked: maskProxyURLs(proxies),
		RotatingCount:      len(rotating),
		RotatingMasked:     maskProxyURLs(rotating),
		TargetsTotal:       len(accounts) * len(models),
		ConfigErrors:       problems,
		Note: "已保存到插件自己的 scope 文件，立即生效，覆盖 config.yaml 里的同名项。" +
			"采集由看板上的「探测」启动，续期循环每 20 秒重读一次范围。",
	}
	if out.ProbeAccounts == nil {
		out.ProbeAccounts = []string{}
	}
	if out.Models == nil {
		out.Models = []string{}
	}
	return jsonResponse(http.StatusOK, out)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// statusAccounts 先问宿主要所有 Codex 凭据，禁用也带状态保留；只有宿主认识从未采集过的账号。
// 问不到才从已有存储推名单并注明来源，区分“真没人”与“电话没打通”，别靠空账本宣布闭店。
func statusAccounts(observed []bucketObservation) ([]codexAuth, string, error) {
	accounts, errList := listCodexAuths()
	if errList == nil {
		return accounts, "host", nil
	}

	seen := make(map[string]bool)
	var fallback []codexAuth
	for _, cell := range observed {
		if seen[cell.AuthID] {
			continue
		}
		seen[cell.AuthID] = true
		// 这条回退路径不知道 Enabled，暂报 true，因为旧观测只证明当时能工作。
		// accounts_source 已提醒不权威，不能凭没问到就给账号贴停业封条。
		fallback = append(fallback, codexAuth{AuthID: cell.AuthID, Enabled: true})
	}
	sort.Slice(fallback, func(i, j int) bool { return fallback[i].AuthID < fallback[j].AuthID })
	return fallback, "store", errList
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

type clearRequest struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	All    bool   `json:"all"`
}

type clearedBucket struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
}

type clearResponse struct {
	Cleared int             `json:"cleared"`
	Buckets []clearedBucket `json:"buckets"`
}

// handleBucketsClear 接清理单再交共享清理核心；实际清哪份账由 clearBuckets 的池模型规则决定，不按旧模板文件账猜。
func handleBucketsClear(body []byte) pluginapi.ManagementResponse {
	var req clearRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if errUnmarshal := json.Unmarshal(body, &req); errUnmarshal != nil {
			return managementError(http.StatusBadRequest, "could not decode the request body as JSON")
		}
	}
	return clearBuckets(req)
}

// clearBuckets 是鉴权 POST（JSON）和免钥匙 GET（query）的同一个清理后厨，区别只在单子从哪来。
// 池模型已无每桶模板文件：auth+model 只清该桶 OBSERVATION 行，all 才清路由 Cookie 池及全部观测。
// 别把擦一张桌子的单子理解成拆整间店。
func clearBuckets(req clearRequest) pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	namesBucket := strings.TrimSpace(req.AuthID) != "" || strings.TrimSpace(req.Model) != ""

	var targets []clearedBucket
	switch {
	case req.All && namesBucket:
		// all 与单桶同时来是矛盾指令；不能在“擦桌子”和“拆饭馆”之间替用户猜大的。
		return managementError(http.StatusBadRequest,
			`"all" cannot be combined with "auth_id" or "model" -- send one or the other`)
	case req.All:
	case strings.TrimSpace(req.AuthID) != "" && strings.TrimSpace(req.Model) != "":
		// auth_id/model 来自用户，用 selftest 同一套净化规则；清仓通道也不能夹带越界门牌。
		if _, errPath := bucketRelPath(req.AuthID, req.Model); errPath != nil {
			return managementError(http.StatusBadRequest, errPath.Error())
		}
		targets = append(targets, clearedBucket{AuthID: req.AuthID, Model: req.Model})
	default:
		return managementError(http.StatusBadRequest, `give either {"all":true} or both "auth_id" and "model"`)
	}

	if req.All {
		// 池是仅剩的可复用凭据仓；清空后立刻重写文件，免得重启把已撤的旧票又摆回柜台。
		now := time.Now()
		state.mu.Lock()
		state.cookies = make(map[string]*routeCookieEntry)
		state.cookiesDirty = true
		state.mu.Unlock()
		if strings.TrimSpace(cfg.StoreDir) != "" {
			if err := writeRouteCookiePool(cfg.StoreDir, state.cookies, now, cfg.ttl()); err != nil {
				log.Printf(logPrefix+"pool rewrite after clear failed: %v", err)
			}
		}
		clearAllObservations()
		log.Printf(logPrefix + "cleared route-cookie pool and all observations")
		return jsonResponse(http.StatusOK, clearResponse{Cleared: 1, Buckets: []clearedBucket{}})
	}

	cleared := 0
	var done []clearedBucket
	for _, target := range targets {
		if deleteObservation(target.AuthID, target.Model) {
			cleared++
			done = append(done, target)
		}
	}
	if cleared > 0 {
		log.Printf(logPrefix+"cleared %d bucket observation(s)", cleared)
	}
	if done == nil {
		done = []clearedBucket{}
	}
	return jsonResponse(http.StatusOK, clearResponse{Cleared: cleared, Buckets: done})
}

type selftestRequest struct {
	Model  string `json:"model"`
	AuthID string `json:"auth_id"`
}

type selftestResponse struct {
	// Reached 只问上游有没有回答，429、401 或 JSON 错误体都算到达。
	// 路通但被拒该等/重试，压根没到才查网络；别把服务员说没菜听成饭馆不存在。
	Reached    bool   `json:"reached"`
	StatusCode int    `json:"status_code"`
	Model      string `json:"model"`
	AuthID     string `json:"auth_id"`
	// Targeted 说明是否主动点了 auth_id；空串代表没指定且无从得知，不是调度器选了个隐形账号。
	Targeted  bool `json:"targeted"`
	Harvested bool `json:"harvested"`
	// UpstreamErrorCode 取上游错误体 code，供失败自检判断；历史记录中 server_is_overloaded 与降级 312 同信号（FINDINGS.md）。
	// 当时意味着无 292 可采，应等待而非排查断网；别把厨房忙当成马路塌。
	UpstreamErrorCode string `json:"upstream_error_code"`
	UpstreamErrorType string `json:"upstream_error_type"`
	Note              string `json:"note"`
	Error             string `json:"error,omitempty"`
}

// upstreamErrorBody 对应 OpenAI 风格错误信封；收到上游自己的错误结构也是到达证据，网络断线不会替厨房写缺菜条。
type upstreamErrorBody struct {
	Error struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// selftest 的 harvested 两处都固定 false，指定 AuthID 也不能把它变成采集器。
// 宿主回调为防插件递归跳过调用方：host_callbacks_unix.go:43 标插件 id，host_callbacks.go:304 读 skipPluginID，:306 填 SkipInterceptorPluginID。
// 因此这里的请求不会经过本插件 response interceptor；能证明路通，不能往桶里加货，别把门铃当进货铃。
const (
	selftestNote = "连通性自检不会落盘：host.model.execute 会跳过本插件的响应拦截器。采集请用看板上的「探测」。"
	// HostModelExecutionResponse 只有 StatusCode、Headers、Body；不指定凭据就不知道谁回答。
	// 不报比乱报强，不能听声音就替调度器点名。
	selftestNoteUntargeted = selftestNote +
		" 本次未指定 auth_id，由调度器选号；上游响应不含账号标识，因此无法得知实际使用的是哪个号。要定点检查请传 auth_id。"
	// 上游已回错但宿主没传 HTTP 状态时附加说明，status_code 保持 0 不瞎编。
	// 零是没拿到状态码，不是没收到回答，别把空账格当店员失踪。
	selftestNoteNoStatus = " 上游返回了错误但宿主未透传 HTTP 状态码，故 status_code 为 0；请看 upstream_error_code 和 error 原文。"
)

// handleSelftest 发最小请求，只问通不通；不按 role 或启用账号数拦截，排障时不能因为店里乱就拒绝开灯。
// 可选 auth_id 定点检查 (account, model)，不传就由调度器选，并明说不知道归属。
// 它绝不启停账号：半途切换可能无法恢复，离线 harvester 直接持账号 token，早已不用靠“只留一人上班”认人。
func handleSelftest(body []byte) pluginapi.ManagementResponse {
	var req selftestRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if errUnmarshal := json.Unmarshal(body, &req); errUnmarshal != nil {
			return managementError(http.StatusBadRequest, "could not decode the request body as JSON")
		}
	}
	return runSelftest(req)
}

// runSelftest 共用鉴权 POST/JSON 与免钥匙 GET/query 的执行核心。
// 一发真实请求就花额度，所以 GET 早由 handleOpsResource 检查 confirm=1；彩排也是真买菜。
func runSelftest(req selftestRequest) pluginapi.ManagementResponse {
	model := strings.TrimSpace(req.Model)
	if model == "" {
		return managementError(http.StatusBadRequest, `"model" is required`)
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// 先查模型 id，别拿打错的菜名花额度请上游猜谜。
	if len(cfg.Models) > 0 && !containsFold(cfg.Models, model) {
		return managementError(http.StatusBadRequest,
			fmt.Sprintf("model %q is not in the configured models list", model))
	}

	// auth_id 可选；有值时会进入出站请求，沿用存储路径同一套净化规则，别另立一套会走样的门规。
	// 存在性由调度器判断，未知 id 的上游错误原样报告，不在这里养第二本可能过期的户口簿。
	authID := strings.TrimSpace(req.AuthID)
	if authID != "" {
		if _, errAuth := bucketRelPath(authID, model); errAuth != nil {
			return managementError(http.StatusBadRequest, "unsafe auth_id or model: "+errAuth.Error())
		}
	}

	// 先验输入再查 callback，错参数仍拿具体 4xx；没有回调表就明确失败。
	// 自检根本没跑不能回 200/reached=false，没出门和出门没找到人不是同一出戏。
	if !hostAPIAvailable() {
		log.Printf(logPrefix + "selftest could not run: no host callback table")
		return managementError(http.StatusServiceUnavailable,
			"this plugin holds no host callback table, so it could not issue any request. "+
				"The self-test did not run; this says nothing about the upstream. "+
				"The plugin was loaded without a host API, which is a loader problem.")
	}

	out := selftestResponse{
		Model:     model,
		AuthID:    authID,
		Targeted:  authID != "",
		Harvested: false,
		Note:      selftestNote,
	}
	if !out.Targeted {
		out.Note = selftestNoteUntargeted
	}

	// 只发最小回合，不带 X-Codex-Turn-State；旧状态会妨碍上游铸新票，自检也别教厨房回锅旧菜。
	payload := map[string]any{
		"model": model,
		"input": []map[string]any{{
			"role":    "user",
			"content": []map[string]any{{"type": "input_text", "text": "ping"}},
		}},
		"store": false,
	}
	rawBody, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return managementError(http.StatusInternalServerError, errMarshal.Error())
	}

	exec := pluginapi.HostModelExecutionRequest{
		EntryProtocol: "openai-responses",
		ExitProtocol:  "openai-responses",
		Model:         model,
		Stream:        false,
		Body:          rawBody,
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
		// 空值让调度器点名，宿主会省略字段；不是请一位名叫空串的演员。
		AuthID: authID,
	}

	var execResp pluginapi.HostModelExecutionResponse
	errCall := hostCallJSON("host.model.execute", exec, &execResp)
	if errCall == nil {
		out.Reached = true
		out.StatusCode = execResp.StatusCode
		log.Printf(logPrefix+"selftest reached upstream model=%s auth=%s targeted=%t status=%d",
			orDash(model), orDash(authID), out.Targeted, out.StatusCode)
		return jsonResponse(http.StatusOK, out)
	}

	// 宿主可能把上游拒绝压进错误信封而不保留 HTTP 状态，要从文字捞回“已到达但被拒”。
	// 先认上游错误结构，例如 host_call_failed: {"error":{"type":"service_unavailable_error","code":"server_is_overloaded",...}}；再认宿主的 failed with status N。
	// 两者都没有才按传输失败 reached=false；每支保留原消息，不只甩一个分类，让排障别被带去修一条没坏的路。
	out.Error = errCall.Error()
	upstream, okUpstream := upstreamErrorFrom(out.Error)
	status, okStatus := statusFromExecutionError(out.Error)
	switch {
	case okUpstream:
		out.Reached = true
		out.UpstreamErrorCode = strings.TrimSpace(upstream.Error.Code)
		out.UpstreamErrorType = strings.TrimSpace(upstream.Error.Type)
		if okStatus {
			out.StatusCode = status
		} else {
			out.Note += selftestNoteNoStatus
		}
	case okStatus:
		out.Reached = true
		out.StatusCode = status
	}
	log.Printf(logPrefix+"selftest model=%s auth=%s targeted=%t reached=%t status=%d upstream_code=%s",
		orDash(model), orDash(authID), out.Targeted, out.Reached, out.StatusCode, orDash(out.UpstreamErrorCode))
	return jsonResponse(http.StatusOK, out)
}

// upstreamErrorFrom 从 host_call_failed: {...} 包装中捞上游 JSON；用 Decoder 容忍尾随文字。
// 至少一个有效非空字段才认账，不能见到任意花括号就说厨房回话了。
func upstreamErrorFrom(message string) (upstreamErrorBody, bool) {
	idx := strings.Index(message, "{")
	if idx < 0 {
		return upstreamErrorBody{}, false
	}
	var body upstreamErrorBody
	if errDecode := json.NewDecoder(strings.NewReader(message[idx:])).Decode(&body); errDecode != nil {
		return upstreamErrorBody{}, false
	}
	if body.Error.Type == "" && body.Error.Code == "" && body.Error.Message == "" {
		return upstreamErrorBody{}, false
	}
	return body, true
}

// statusFromExecutionError 只认宿主完整的 failed with status <code> 口令。
// 单搜 status 会误抓上游 JSON 字符串，别把菜名里的“三号”当桌号。
func statusFromExecutionError(message string) (int, bool) {
	const marker = "failed with status "
	idx := strings.LastIndex(message, marker)
	if idx < 0 {
		return 0, false
	}
	digits := strings.TrimSpace(message[idx+len(marker):])
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	status := 0
	for _, char := range digits[:end] {
		status = status*10 + int(char-'0')
	}
	if status < 100 || status > 599 {
		return 0, false
	}
	return status, true
}

// hostCallJSON 编码回调、拆 RPC 信封再解结果；返回码和信封内错误都要查，封面漂亮不等于里面没退单。
func hostCallJSON(method string, payload any, out any) error {
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return errMarshal
	}
	response, errCall := hostCall(method, raw)
	if errCall != nil {
		return errCall
	}
	if len(response) == 0 {
		return fmt.Errorf("host call %s returned nothing", method)
	}
	var env envelope
	if errUnmarshal := json.Unmarshal(response, &env); errUnmarshal != nil {
		return fmt.Errorf("decode %s response: %w", method, errUnmarshal)
	}
	if !env.OK {
		if env.Error != nil {
			return fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return fmt.Errorf("host call %s failed", method)
	}
	if out == nil || len(env.Result) == 0 {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// jsonResponse 输出管理载荷；Schema 6 宿主不做 HTML 实体转义，正文按原样到浏览器，不额外给文字裹糖衣。
func jsonResponse(status int, payload any) pluginapi.ManagementResponse {
	body, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return managementError(http.StatusInternalServerError, "could not encode the response")
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}
}

// managementError 回结构化错误，不 panic；原生插件一掀桌，整个 CPA 进程都可能跟着翻锅。
func managementError(status int, message string) pluginapi.ManagementResponse {
	body, errMarshal := json.Marshal(map[string]string{"error": message})
	if errMarshal != nil {
		body = []byte(`{"error":"internal error"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}
}
