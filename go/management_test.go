package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

// 路由路径手写，不借实现常量；这是管理接口合同，生产改名就该当场响铃，不能跟着一起换招牌。
const (
	mgmtStatusPath   = "/v0/management/codex-turn-state/status"
	mgmtClearPath    = "/v0/management/codex-turn-state/buckets/clear"
	mgmtSelftestPath = "/v0/management/codex-turn-state/selftest"
	mgmtConfigPath   = "/v0/management/codex-turn-state/config"
	mgmtResourcePath = "/v0/resource/plugins/codex-turn-state/"

	// 探测运行控制与其他免密动作同住未鉴权资源前缀，不另起收费柜台。
	opsProbeStartPath  = mgmtResourcePath + "ops/probe/start"
	opsProbeCancelPath = mgmtResourcePath + "ops/probe/cancel"

	// 范围编辑菜单也在同一免密前缀，但它只读，不要 confirm=1；只看菜单不必先签点菜确认书。
	opsChoicesPath = mgmtResourcePath + "ops/choices"
)

// --- 线上形状：信封也有规矩 ---
// 解到本地结构，不绑内部类型名。pluginapi 管理类型没 JSON tag，线上用 Go 字段名
// StatusCode、Headers、Body，这里照样摆座位。

type mgmtResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

type mgmtRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type mgmtRegistration struct {
	Routes    []mgmtRoute `json:"routes"`
	Resources []mgmtRoute `json:"resources"`
}

type mgmtBucket struct {
	AuthID      string `json:"auth_id"`
	Model       string `json:"model"`
	Ready       bool   `json:"ready"`
	Len         int    `json:"len"`
	Enabled     bool   `json:"enabled"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	SecondsLeft int64  `json:"seconds_left"`
	// 未见流量 bucket 不带 Observed，用指针分清“没人来”与“正常”，空椅子不能冒充好评。
	Observed *mgmtObserved `json:"observed"`
}

type mgmtObserved struct {
	NaturalNormal   int64  `json:"natural_normal"`
	NaturalLimited  int64  `json:"natural_limited"`
	InjectedSilent  int64  `json:"injected_silent"`
	InjectedLimited int64  `json:"injected_limited"`
	LastKind        string `json:"last_kind"`
	LastWrote       bool   `json:"last_wrote"`
	LastNaturalKind string `json:"last_natural_kind"`
	LastNaturalAt   string `json:"last_natural_at"`
}

type mgmtObservationEvent struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	Len    int    `json:"len"`
	Wrote  bool   `json:"wrote"`
	Kind   string `json:"kind"`
}

type mgmtCounters struct {
	Harvest int64 `json:"harvest"`
	Steer   int64 `json:"steer"`
	Pass    int64 `json:"pass"`
	Skip    int64 `json:"skip"`
}

type mgmtStatus struct {
	Role           string       `json:"role"`
	DryRun         bool         `json:"dry_run"`
	TTLSeconds     int          `json:"ttl_seconds"`
	TemplateLength int          `json:"template_length"`
	ReplaceLength  int          `json:"replace_length"`
	StoreDir       string       `json:"store_dir"`
	Models         []string     `json:"models"`
	Buckets        []mgmtBucket `json:"buckets"`
	TargetsTotal   int          `json:"targets_total"`
	TargetsReady   int          `json:"targets_ready"`
	// AccountsSource 为 host 表示 host.auth.list 名单，store 表示从库存推断。
	// store 看不到从未探测账号，必须说明来源，别把短名单说成客人都到齐。
	AccountsSource    string                 `json:"accounts_source"`
	AccountsError     string                 `json:"accounts_error"`
	StoreError        string                 `json:"store_error"`
	Counters          mgmtCounters           `json:"counters"`
	ObservationsSince string                 `json:"observations_since"`
	ObservationFeed   []mgmtObservationEvent `json:"observation_feed"`
	ProbeAccounts     []string               `json:"probe_accounts"`
	// ProbeProxies 明文是现在的刻意合同，不是手滑；理由见 TestStatusShowsProbeProxiesInTheClear。
	// 其他遮罩边界仍在，ProbeProxyCount 也留着，换招牌不拆计数器。
	ProbeProxyCount int      `json:"probe_proxy_count"`
	ProbeProxies    []string `json:"probe_proxies"`
}

type mgmtClearResult struct {
	Cleared int `json:"cleared"`
}

// mgmtSelftestResult 镜像自检响应，Harvested 虽恒 false 也要解码断言，字段存在和否定都算合同。
// AuthID 只能回显请求，不能冒充发现：CPA 的 HostModelExecutionResponse 只有 StatusCode、Headers、Body，
// 无账号身份也无 auth-id 响应头。旧版猜头名已撤掉，猜对口音不算查过身份证。
// 可行方向是请求：HostModelExecutionRequest.AuthID 可锁精确凭据，宿主原样转发
// （internal/pluginhost/host_callbacks.go:330）。插件决定用谁，再回显自己点的名，不是事后侦察。
// Targeted 消除空 auth_id 歧义：空值并非调度器没选，而是未指定且无法知道选了谁。
// targeted:false 直说未点名，见 TestSelftestEchoesTargetingHonestly 与 TestSelftestAuthIDIsNeverFabricated。
type mgmtSelftestResult struct {
	Reached    bool   `json:"reached"`
	StatusCode int    `json:"status_code"`
	Model      string `json:"model"`
	AuthID     string `json:"auth_id"`
	Targeted   bool   `json:"targeted"`
	Harvested  bool   `json:"harvested"`
	Note       string `json:"note"`
	Error      string `json:"error"`
}

// --- 驱动：真流程上台，道具来配合 ---

// decodeMgmtEnvelope 拆插件 ok/error 信封，与 main_test.go 的 interceptAfter 分开；
// 管理调用失败要报插件原话，不让通用解码失败抢了真凶台词。
func decodeMgmtEnvelope(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v (raw: %s)", err, truncateMgmtLog(raw))
	}
	if !env.OK {
		t.Fatalf("plugin returned an error envelope: %+v", env.Error)
	}
	return env.Result
}

// truncateMgmtLog 把大响应失败信息截短，既便于读，也不让意外漏 token 满屏巡演。
func truncateMgmtLog(raw []byte) string {
	const limit = 200
	if len(raw) <= limit {
		return string(raw)
	}
	return string(raw[:limit]) + "..."
}

// driveManagement 端到端走一次 management.handle，整段戏不跳场。
func driveManagement(t *testing.T, method, path string, body []byte) mgmtResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Method":  method,
		"Path":    path,
		"Headers": http.Header{},
		"Query":   url.Values{},
		"Body":    body,
	})
	if err != nil {
		t.Fatalf("marshal management request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementHandle, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.handle) %s %s: %v", method, path, errHandle)
	}
	var resp mgmtResponse
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
			t.Fatalf("decode management response: %v", errUnmarshal)
		}
	}
	// SDK 规定零即 200，先归一，调用者别对一张票验两种字号。
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return resp
}

// driveManagementJSON 带 JSON 对象正文发一次调用，参数装正经信封。
func driveManagementJSON(t *testing.T, method, path string, payload any) mgmtResponse {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return driveManagement(t, method, path, body)
}

// driveManagementRegister 跑 management.register，取回声明路由花名册。
func driveManagementRegister(t *testing.T) mgmtRegistration {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Plugin":           map[string]any{"Name": "codex-turn-state"},
		"BasePath":         "/v0/management",
		"ResourceBasePath": "/v0/resource/plugins/codex-turn-state",
	})
	if err != nil {
		t.Fatalf("marshal management registration request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementRegister, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.register): %v", errHandle)
	}
	var reg mgmtRegistration
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &reg); errUnmarshal != nil {
			t.Fatalf("decode management registration: %v", errUnmarshal)
		}
	}
	return reg
}

// mustManagementStatus 获取并解码状态文档，坏信封当场报错。
func mustManagementStatus(t *testing.T) mgmtStatus {
	t.Helper()
	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("decode status: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	return status
}

// probeRoleConfig 给 probe 指 dir 地址，与 main_test.go 的 businessConfig 结对，不串角色。
func probeRoleConfig(dir string) string {
	return fmt.Sprintf(`role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: true
log_decisions: false
models:
  - gpt-5.5
  - gpt-5.6-sol
`, dir)
}

// businessConfigWithModels 给 businessConfig 加模型表；两角色自检都照表验模型。
// 没表只会 400，永远到不了要考的戏，入场券先备齐。
func businessConfigWithModels(dir string) string {
	return fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: true
log_decisions: false
models:
  - gpt-5.5
  - gpt-5.6-sol
`, dir)
}

// probeRoleConfigModels 接自选模型表，让测试能拉宽就绪矩阵这张桌。
func probeRoleConfigModels(dir string, models ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: true
log_decisions: false
models:
`, dir)
	for _, model := range models {
		fmt.Fprintf(&b, "  - %s\n", model)
	}
	return b.String()
}

// seedMgmtBucket 记一次观测，回假 token 供搜响应抓泄漏；道具票也不准走上公开台面。
func seedMgmtBucket(t *testing.T, dir, authID, model string, issued time.Time) string {
	t.Helper()
	recordObservation(defaultConfig(), authID, model, 292, false)
	return fakeToken(292, issued)
}

// observedCellCount 像给观测行拍库存照；拒绝调用后账本必须原封不动，门没开就不该少东西。
func observedCellCount() int {
	cells, _, _ := observationsSnapshot()
	return len(cells)
}

// mgmtBucketByKey 在状态文档按键找 bucket，按门牌不按脸熟。
func mgmtBucketByKey(status mgmtStatus, authID, model string) (mgmtBucket, bool) {
	for _, bucket := range status.Buckets {
		if bucket.AuthID == authID && bucket.Model == model {
			return bucket, true
		}
	}
	return mgmtBucket{}, false
}

// --- 1. 保密：库房物件不出橱窗 ---

// 设计立在值不离开存储这条底线上；状态文档从含值记录组装，最易顺手漏货，柜台尤其要查。
func TestManagementStatusNeverLeaksTokenValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-5 * time.Minute)
	secrets := []string{
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued),
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued),
		seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued),
	}

	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200", resp.StatusCode)
	}
	body := string(resp.Body)
	for i, secret := range secrets {
		// 取 40 字符前缀足够排除偶然撞脸，又能抓截短泄漏，不能只认全身照。
		needle := secret[:40]
		if strings.Contains(body, needle) {
			t.Errorf("status body leaked token %d", i)
		}
	}
	// 先证响应非空且真有 bucket，别让泄漏断言对一张白纸夸“保密不错”。
	if len(resp.Body) == 0 {
		t.Fatal("status body is empty; the leak assertions above proved nothing")
	}
	// 状态列的是目标桶：配置模型 × 已见账号，缺桶显示未就绪而非失踪。
	// 因此不拿总数替代泄漏检查，只确认种下的桶存在且 ready，验货不考乘法口诀。
	status := mustManagementStatus(t)
	for _, want := range [][2]string{
		{"codex-alpha.json", "gpt-5.5"},
		{"codex-alpha.json", "gpt-5.6-sol"},
		{"codex-beta.json", "gpt-5.5"},
	} {
		bucket, ok := mgmtBucketByKey(status, want[0], want[1])
		if !ok || !bucket.Ready {
			t.Fatalf("seeded bucket %s/%s is not reported ready; the leak assertions above were not exercised against real records", want[0], want[1])
		}
	}
}

// 资源壳走免密前缀，必须是固定资产；一旦渲染运行时状态就把它公开。
// 改存储前后字节相等才算守约，壳别偷偷长出库存窗口。
func TestResourceShellIsStaticAndDataFree(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	before := driveManagement(t, http.MethodGet, mgmtResourcePath, nil)
	if before.StatusCode != http.StatusOK {
		t.Fatalf("resource shell returned %d, want 200", before.StatusCode)
	}
	if len(before.Body) == 0 {
		t.Fatal("resource shell body is empty; nothing was actually served")
	}

	issued := wallClock().Add(-time.Minute)
	secret := seedMgmtBucket(t, dir, "codex-secret-account.json", "gpt-5.6-sol", issued)

	after := driveManagement(t, http.MethodGet, mgmtResourcePath, nil)
	if string(before.Body) != string(after.Body) {
		t.Error("resource shell changed after the store changed; it is rendering runtime state on an unauthenticated route")
	}

	shell := string(after.Body)
	for _, forbidden := range []string{
		secret[:40],
		"codex-secret-account.json",
		dir,
	} {
		if strings.Contains(shell, forbidden) {
			t.Errorf("resource shell embedded runtime data: %q", truncateMgmtLog([]byte(forbidden)))
		}
	}
}

// --- 2. 能力与路由声明：门牌挂哪，权限就在哪 ---

func TestRegistrationAdvertisesManagementAPI(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	raw, err := json.Marshal(map[string]any{
		"config_yaml":    []byte(probeRoleConfig(dir)),
		"schema_version": 6,
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodPluginRegister, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(plugin.register): %v", errHandle)
	}
	var reg struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &reg); errUnmarshal != nil {
			t.Fatalf("decode registration: %v", errUnmarshal)
		}
	}
	enabled, ok := reg.Capabilities["management_api"].(bool)
	if !ok {
		t.Fatalf("registration does not declare management_api at all; capabilities: %v", reg.Capabilities)
	}
	if !enabled {
		t.Error("management_api is false; the management routes will never be mounted")
	}
}

// 管理接口最尖的坑：CPA 的 routeDeclaresLegacyMenuResource
// （internal/pluginhost/management.go:156）把带 Menu 的 GET 当旧资源，
// 再挂 /v0/resource/plugins/<id>/，不经管理鉴权。status 一挂 Menu 就悄悄公开整份文档，招牌变了万能钥匙。
func TestManagementDataRoutesCarryNoMenu(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	if len(reg.Routes) == 0 {
		t.Fatal("no management routes declared; this test would pass vacuously")
	}
	for _, route := range reg.Routes {
		if strings.TrimSpace(route.Menu) != "" {
			t.Errorf("management route %s %s carries Menu=%q, which demotes it to the unauthenticated resource prefix",
				route.Method, route.Path, route.Menu)
		}
	}
}

// 只准 dashboard 壳一个资源带 Menu；限制的是 Menu，不是资源总数。
// 壳与匿名 /status 已是两项，以后还可增；Menu 会把资源挂进管理中心，而每个入口都走免密前缀。
// 用户只要求免登录看板，其他项不能不声不响蹭招牌开门。
func TestManagementRegisterExposesExactlyOneMenuResource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	if len(reg.Resources) == 0 {
		t.Fatal("no resources declared; this test would pass vacuously")
	}

	var withMenu []mgmtRoute
	for _, res := range reg.Resources {
		if strings.TrimSpace(res.Menu) != "" {
			withMenu = append(withMenu, res)
		}
	}
	if len(withMenu) != 1 {
		t.Fatalf("declared %d resources with a Menu, want exactly 1 (the shell); the rest must stay off the menu", len(withMenu))
	}
	if withMenu[0].Path != "/dashboard" {
		t.Errorf("the menu-bearing resource is %q, want /dashboard", withMenu[0].Path)
	}
}

// 匿名 /status 是看板数据源，与鉴权状态同处理器同 JSON，资源前缀使其免密。
// 它是 fetch 目标不是导航页面，不挂 Menu；菜单名额只给 dashboard，送菜单的别抢餐桌。
func TestManagementRegisterExposesAnonymousStatusResource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	var status *mgmtRoute
	for i := range reg.Resources {
		if reg.Resources[i].Path == "/status" {
			status = &reg.Resources[i]
			break
		}
	}
	if status == nil {
		t.Fatal("no /status resource declared; the dashboard has nothing to fetch from")
	}
	if strings.TrimSpace(status.Menu) != "" {
		t.Errorf("the /status resource carries Menu=%q; it is a fetch target, not a page", status.Menu)
	}
}

// 匿名状态与鉴权路由同文档，同守保密线；账号文件名公开是用户知情选择，token 值绝不在选择题里。
// 专在资源路径重跑防泄漏，免密来客走的正是这扇门。
func TestAnonymousStatusResourceNeverLeaksTokenValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	secrets := []string{
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued),
		seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.6-sol", issued),
	}

	resp := driveManagement(t, http.MethodGet, "/v0/resource/plugins/codex-turn-state/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous status returned %d, want 200: %s", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if len(resp.Body) == 0 {
		t.Fatal("anonymous status body is empty; the leak check below would prove nothing")
	}
	for i, secret := range secrets {
		if strings.Contains(string(resp.Body), secret[:40]) {
			t.Errorf("anonymous status leaked token %d", i)
		}
	}
	// 证明正文是真状态文档，不是错误或空替身；泄漏检查得真对 bucket 数据照灯。
	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("anonymous status body is not a status document: %v", err)
	}
	if b, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5"); !ok || !b.Ready {
		t.Error("seeded bucket missing from anonymous status; leak check saw no real data")
	}
}

// clear 把请求账号、模型拼成文件路径，必须先净化；auth_id 为 ".." 可走出 store 删隔壁，清洁工不能兼职拆迁。
func TestClearBucketRejectsPathTraversal(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	// 哨兵放 store 上一层，正是 ../<model> 落点，名字也像 <model>.json；真穿越就真会删它，道具摆在刀口上。
	sentinel := filepath.Join(base, "sentinel.json")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	cases := []struct {
		name   string
		authID string
		model  string
	}{
		{"parent via auth", "..", "sentinel"},
		{"parent via model", "codex-alpha.json", "../sentinel"},
		{"nested parent", "../..", "sentinel"},
		{"slash in auth", "codex/../..", "sentinel"},
		{"backslash in auth", `..\..`, "sentinel"},
		{"absolute model", "codex-alpha.json", filepath.ToSlash(sentinel)},
		{"empty auth", "", "gpt-5.5"},
		{"empty model", "codex-alpha.json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagementJSON(t, http.MethodPost, mgmtClearPath, map[string]any{
				"auth_id": tc.authID,
				"model":   tc.model,
			})
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("traversal accepted: status %d, want 4xx", resp.StatusCode)
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatalf("sentinel outside the store was removed: %v", err)
			}
		})
	}

	// 合法 bucket 仍须在；全拒绝也会过前面题，但会误伤正常清理。
	// 如今“在”指观测行，逐桶文件存储已撤，别去旧地址查房。
	if _, ok := mgmtBucketByKey(mustManagementStatus(t), "codex-alpha.json", "gpt-5.5"); !ok {
		t.Fatal("the ordinary bucket was collateral damage")
	}
}

func TestClearBucketRejectsMalformedBody(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))
	before := observedCellCount()

	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("this is not json")},
		{"empty body", nil},
		{"empty object", []byte(`{}`)},
		{"model without auth", []byte(`{"model":"gpt-5.5"}`)},
		{"auth without model", []byte(`{"auth_id":"codex-alpha.json"}`)},
		{"all and auth together", []byte(`{"all":true,"auth_id":"codex-alpha.json","model":"gpt-5.5"}`)},
		{"json array", []byte(`["codex-alpha.json"]`)},
		{"wrong types", []byte(`{"auth_id":42,"model":true}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagement(t, http.MethodPost, mgmtClearPath, tc.body)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("malformed body accepted: status %d, want 4xx", resp.StatusCode)
			}
		})
	}
	if observedCellCount() != before {
		t.Error("a rejected clear still modified the tally")
	}
}

// --- 4. 自检：通路检查不是采集丰收 ---
// 旧 /probe 曾声称采集，但 host.model.execute 标记跳过调用插件自有拦截器
// （host_callbacks_unix.go:43 → host_callbacks.go:304 → :306），响应不到 interceptResponse，根本不会存。
// 现在只做连通性自检，测试不让它再报虚假产量。

// 自检不谈 bucket，不限 probe；business 也要查能否回源，越忙越不能把检查员赶出去。
func TestSelftestWorksRegardlessOfRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(dir string) string
	}{
		{"probe", probeRoleConfig},
		{"business", func(dir string) string { return businessConfigWithModels(dir) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mustConfigure(t, tc.cfg(dir))

			resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})
			// 没有宿主 API 注定不成功，查的是为什么失败；不能赖角色穿错衣服。
			if resp.StatusCode == http.StatusConflict {
				t.Errorf("selftest refused with 409 under role %s: %s", tc.name, truncateMgmtLog(resp.Body))
			}
			if strings.Contains(strings.ToLower(string(resp.Body)), "role") {
				t.Errorf("selftest under role %s blamed the role: %s", tc.name, truncateMgmtLog(resp.Body))
			}
		})
	}
}

// 只准已配置模型，自检不能向任意字符串开火，配额不替陌生菜单买单。
func TestSelftestRejectsUnconfiguredModel(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-4-turbo"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("selftest with an unconfigured model returned %d, want 400", resp.StatusCode)
	}
	// 已配置模型要能过门；否则全拒绝也能糊弄前题，门卫不是木板。
	next := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})
	if next.StatusCode == http.StatusBadRequest {
		t.Error("a configured model was also rejected as unconfigured")
	}
}

// 无宿主 API 就无执行对象；正常已运行的自检以 200 表示检查完成，reached 承载通路结果。
// 这里须诚实区分根本没出进程：未到达、未采集、未碰存储，不能足不出户就报旅行成功；无宿主的 HTTP 状态以下方 503 专项为准。
func TestSelftestFailsClosedWithoutHostAPI(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})

	// 严格断言 503，不是 200，也不是随便 >=400；建接口时这题从 >=400 改 200+reached:false 又回 503，定案不再放宽。
	// 两种失败不能混：无 host 回调表是自检根本没运行，插件没拿接口，不能说明上游；
	// host 在但没答复则检查已运行、通路坏，才用 200+reached:false 表示查到了故障。
	// 把第一种报 200 会让凌晨值班者去查网络、凭据、上游，实际只是插件没装对，别拿内部断电指挥人修隔壁路灯。
	// 503 来自 managementError，只带 error，故意无 note；note 解释运行过却没存，这里压根没运行。
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("selftest with no host API returned %d, want 503: %s", resp.StatusCode, truncateMgmtLog(resp.Body))
	}

	var result mgmtSelftestResult
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		t.Fatalf("decode selftest result: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	if result.Reached {
		t.Error("selftest claimed it reached upstream with no host API available")
	}
	if result.Harvested {
		t.Error("selftest claimed a harvest; it structurally cannot harvest")
	}
	if strings.TrimSpace(result.Error) == "" {
		t.Error("the 503 carries no explanation, leaving the operator with no reason")
	}
	if n := poolEntryCount(); n != 0 {
		t.Errorf("a failed selftest still pooled %d entries", n)
	}
}

func TestSelftestRejectsMalformedBody(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("nope")},
		{"empty body", nil},
		{"no model", []byte(`{}`)},
		{"empty model", []byte(`{"model":""}`)},
		{"wrong type", []byte(`{"model":42}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagement(t, http.MethodPost, mgmtSelftestPath, tc.body)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("malformed selftest body accepted: status %d, want 4xx", resp.StatusCode)
			}
		})
	}
}

// auth_id 来自请求且进入出站请求，按存储路径同一净化规矩，案例照 TestClearBucketRejectsPathTraversal，
// 不另养一套会走样的门卫。还须先净化再查 host：坏 ID 得具体 400，不能被缺 host 的 503 盖住，写错名字别报剧院倒闭。
func TestSelftestRejectsUnsafeAuthID(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	cases := []struct {
		name   string
		authID string
	}{
		{"parent", ".."},
		{"nested parent", "../.."},
		{"slash", "codex/../.."},
		{"backslash", `..\..`},
		{"leading slash", "/etc/passwd"},
		{"embedded null", "codex\x00.json"},
	}
	// 全空白 auth_id 刻意不在坏值表；先 Trim，再判空，"   " 等于没指定账号，
	// 空表单是默认行为，不是来客伪造身份证。
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{
				"model":   "gpt-5.5",
				"auth_id": tc.authID,
			})
			// 必须 400；503 只说明坏值混过净化，被缺 host 临时拦下，生产可没这位替补门卫。
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("unsafe auth_id %q returned %d, want 400: %s",
					tc.authID, resp.StatusCode, truncateMgmtLog(resp.Body))
			}
		})
	}

	// 合法账号要过净化而停在缺 host 的 503，这才证明不是门卫把所有人都拦了。
	ok := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{
		"model":   "gpt-5.5",
		"auth_id": "codex-alpha.json",
	})
	if ok.StatusCode == http.StatusBadRequest {
		t.Errorf("a well-formed auth_id was rejected as unsafe: %s", truncateMgmtLog(ok.Body))
	}

	// 故意不考不存在账号的拒绝：未知 ID 交真实调度器答，不养第二份可能分歧的名单。
	// 硬断言 4xx 是给不存在的合同盖章。
}

// managementFuncBody 取 management.go 顶层函数源码；自检无 host 提前返回，下游响应逻辑单测走不到，
// 只能在源码上验规矩，不假装已经看过真人演出。
func managementFuncBody(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "func "+name+"(")
	if start < 0 {
		t.Fatalf("management.go has no func %s; the selftest contract requires it", name)
	}
	// 顶层函数由第零列右花括号谢幕，按它认场界。
	end := strings.Index(text[start:], "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of func %s", name)
	}
	return text[start : start+end]
}

// auth_id 只能回显调用者要求。CPA 响应只有 StatusCode、Headers、Body，源码查过无任何 auth-id 响应头，
// 不是尚未找到，而是根本不存在。非输入得来的账号名就是编造，会误导人查额度、禁账号、转交同事。
// 空串更诚实，targeted 解释其为空；单测过不了 host 检查，因此从源码堵住“看相认账号”。
func TestSelftestAuthIDIsNeverFabricated(t *testing.T) {
	body := managementFuncBody(t, "runSelftest")

	assignments := 0
	for idx := 0; ; {
		at := strings.Index(body[idx:], "AuthID")
		if at < 0 {
			break
		}
		at += idx
		idx = at + len("AuthID")

		rest := strings.TrimLeft(body[idx:], " \t")
		var value string
		switch {
		case strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, ":="):
			value = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "="):
			value = strings.TrimLeft(rest[1:], " \t")
		default:
			continue
		}
		assignments++
		// authID 是请求净化后的值；头查找或读响应助手都只是把猜测穿上答案戏服。
		if !strings.HasPrefix(value, "authID") {
			line := strings.Count(body[:at], "\n")
			t.Errorf("runSelftest assigns AuthID from %q (about %d lines into the function); "+
				"it must come from the caller-supplied authID, because CPA reports no credential on the response",
				truncateMgmtLog([]byte(value[:min(50, len(value))])), line)
		}
	}
	if assignments == 0 {
		t.Error("no assignment to AuthID found in runSelftest; this test would pass vacuously")
	}
}

// 回显必须原样，targeted 必须从是否提供 auth_id 得来。串线会让查疑似坏账号却报告另一好账号，运营者就清错凭据。
// 硬编码 targeted 或从别处猜，会让 auth_id:"" 不再可读；配 targeted:false 才表示从未指定，不描述调度器选择。
// 同样因无 host 过不了响应构造前门，按源码验，不能凭空宣称现场验证。
func TestSelftestEchoesTargetingHonestly(t *testing.T) {
	body := managementFuncBody(t, "runSelftest")

	at := strings.Index(body, "selftestResponse{")
	if at < 0 {
		t.Fatal("runSelftest builds no selftestResponse; this test would pass vacuously")
	}
	end := strings.Index(body[at:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the selftestResponse literal")
	}
	literal := body[at : at+end]

	// 回显净化后的请求值，不加工成另一个人名。
	if !strings.Contains(literal, "AuthID:") {
		t.Error("the selftestResponse does not set AuthID, so the caller is never told which account was targeted")
	} else if !strings.Contains(literal, "AuthID:    authID") && !strings.Contains(literal, "AuthID: authID") {
		t.Errorf("AuthID is not echoed verbatim from the request; literal was:\n%s", literal)
	}

	// targeted 只问调用者是否提供，别夹带调度器小道消息。
	if !strings.Contains(literal, `Targeted:  authID != ""`) && !strings.Contains(literal, `Targeted: authID != ""`) {
		t.Errorf(`Targeted is not derived from 'authID != ""'; it must say whether the caller asked, not anything about the outcome. Literal was:`+"\n%s", literal)
	}
}

// 定向必须真应用，不只是回报。targeted:true 表示这次真用了指定凭据；
// 若只验证回显却不放进 HostModelExecutionRequest，调度器随便选人，干净结果就替错人洗白。
// AuthID 文档承诺锁精确凭据，宿主原样转发（internal/pluginhost/host_callbacks.go:330），设上即可，别只给准考证拍照不带进考场。
func TestSelftestTargetingIsActuallyApplied(t *testing.T) {
	body := managementFuncBody(t, "runSelftest")

	at := strings.Index(body, "HostModelExecutionRequest{")
	if at < 0 {
		t.Fatal("runSelftest builds no HostModelExecutionRequest; this test would pass vacuously")
	}
	end := strings.Index(body[at:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the HostModelExecutionRequest literal")
	}
	literal := body[at : at+end]

	if !strings.Contains(literal, "AuthID:") {
		t.Error("the outbound HostModelExecutionRequest does not set AuthID, " +
			"so auth_id is validated and echoed but never applied: targeted:true would describe a request that was never targeted")
	}
}

// harvested 必须字面量 false，不能运行时猜。宿主跳过本插件拦截器，自检真采不到；
// 动态计算迟早会报虚假采集，让人停探测。单测无 host 无法成功运行，从源码查每次赋值都是 false，假收成别进账。
func TestSelftestNeverClaimsHarvest(t *testing.T) {
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	text := string(src)

	const field = "Harvested"
	if !strings.Contains(text, field) {
		t.Fatalf("management.go has no %s field; the selftest contract requires one reported as false", field)
	}

	assignments := 0
	for idx := 0; ; {
		at := strings.Index(text[idx:], field)
		if at < 0 {
			break
		}
		at += idx
		idx = at + len(field)

		rest := strings.TrimLeft(text[idx:], " \t")
		// 只看结构字面量 Harvested:<value> 与赋值 Harvested=<value>；
		// 字段声明 Harvested bool `json:...` 和注释台词不算出手，别误抓背景板。
		var value string
		switch {
		case strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, ":="):
			value = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "="):
			value = strings.TrimLeft(rest[1:], " \t")
		default:
			continue
		}
		assignments++
		if !strings.HasPrefix(value, "false") {
			line := 1 + strings.Count(text[:at], "\n")
			t.Errorf("management.go:%d assigns %s a computed value (%q); it must be the literal false, because the selftest structurally cannot harvest",
				line, field, truncateMgmtLog([]byte(value[:min(40, len(value))])))
		}
	}
	if assignments == 0 {
		t.Error("no assignment to Harvested found; this test would pass vacuously")
	}
}

// --- 5. 未知路径与坏输入：乱投简历也别炸前台 ---

func TestManagementUnknownPathReturns404(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	// 故意不列 /v0/management/codex-turn-state 与空路径：实现把插件 ID 结尾路径及空值映射到无数据 dashboard 壳
	// （management.go 的 isDashboardPath），资源请求本就到插件根。这是选择不是 bug；这里列的才真该 404。
	for _, path := range []string{
		"/v0/management/codex-turn-state/nope",
		"/v0/management/other-plugin/status",
		"/v0/management/codex-turn-state/status/extra",
		"/v0/management/codex-turn-state/buckets",
	} {
		t.Run(path, func(t *testing.T) {
			resp := driveManagement(t, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("unknown path %q returned %d, want 404", path, resp.StatusCode)
			}
		})
	}
}

// 已知路径用错方法必须拦住，不能换个嗓音就混进处理器。
func TestManagementRejectsWrongMethod(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))
	before := observedCellCount()

	cases := []struct{ method, path string }{
		{http.MethodPost, mgmtStatusPath},
		{http.MethodDelete, mgmtStatusPath},
		{http.MethodGet, mgmtClearPath},
		{http.MethodGet, mgmtSelftestPath},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := driveManagement(t, tc.method, tc.path, nil)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("%s %s returned %d, want 4xx", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
	if observedCellCount() != before {
		t.Error("a wrong-method call still modified the tally")
	}
}

// host 不会发但管理端口来客可构造的输入，也不能让 handleMethod panic，门口吵架别把楼震塌。
func TestManagementHandleSurvivesMalformedInput(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	for _, raw := range [][]byte{
		nil,
		[]byte(""),
		[]byte("{"),
		[]byte("[]"),
		[]byte(`{"Method":42}`),
		[]byte(`{"Path":null,"Method":null}`),
	} {
		// panic 自会展开失败；返回错误完全可接受，唯一不准的是崩掉整个 CPA 进程，一人闹事不能全店停业。
		if _, err := handleMethod(pluginabi.MethodManagementHandle, raw); err != nil {
			t.Logf("management.handle rejected %q: %v", truncateMgmtLog(raw), err)
		}
	}
}

// --- 6. 计数：只算本场账 ---

// 计数全进程共用，其他用例也会驱动决定；只比增量，不比总量，别把前桌饭钱记到本桌。
func TestManagementCountersTrackDecisions(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	resetHarvestState(t)

	issued := wallClock().Add(-time.Minute)
	seedPoolEntry(t, map[string]string{"__cflb": "cf", "__oailb": "lb"}, time.Now(), "")

	base := mustManagementStatus(t).Counters

	// 两个可归属 Codex 请求都引导；池是全局的，第二账号也拿同 pair，不是空手放行。
	interceptAfter(t, request("codex-alpha.json", "gpt-5.5", fakeToken(312, issued)))
	interceptAfter(t, request("codex-beta.json", "gpt-5.6-sol", fakeToken(312, issued)))
	// 没 auth id，记一次 skip，查不到人就别硬分座位。
	noAuth := request("", "gpt-5.5", fakeToken(312, issued))
	interceptAfter(t, noAuth)

	after := mustManagementStatus(t).Counters
	if got := after.Steer - base.Steer; got != 2 {
		t.Errorf("steer delta = %d, want 2", got)
	}
	if got := after.Skip - base.Skip; got != 1 {
		t.Errorf("skip delta = %d, want 1", got)
	}
}

// --- 状态内容：能报尺寸，不能晒真票 ---

func TestStatusReflectsConfiguredValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	status := mustManagementStatus(t)
	if status.Role != roleProbe {
		t.Errorf("role = %q, want %q", status.Role, roleProbe)
	}
	if !status.DryRun {
		t.Error("dry_run = false, want true")
	}
	if status.TTLSeconds != 3600 {
		t.Errorf("ttl_seconds = %d, want 3600", status.TTLSeconds)
	}
	if status.TemplateLength != 292 || status.ReplaceLength != 312 {
		t.Errorf("lengths = %d/%d, want 292/312", status.TemplateLength, status.ReplaceLength)
	}
	if len(status.Models) != 2 {
		t.Errorf("models = %v, want the 2 configured", status.Models)
	}
}

// 每桶 len 只报长度，不报值；292 对 312 是插件辨别线索，可公开。
// 但字段挨着 token 最容易复制手滑，所以既查数字像长度，也查文档不带真票，量身高别顺手交身份证。
func TestStatusBucketLenIsALengthNotAValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	secret := seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)

	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), secret[:40]) {
		t.Fatal("status leaked the token value alongside its length")
	}

	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	stored, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5")
	if !ok {
		t.Fatal("the seeded bucket is missing from status")
	}
	if stored.Len != 292 {
		t.Errorf("len = %d for a stored 292-character template, want 292", stored.Len)
	}
	// 从未采集 bucket 无值也无长度，空仓库别报货物尺寸。
	missing, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.6-sol")
	if !ok {
		t.Fatal("the unharvested target bucket is missing from status")
	}
	if missing.Len != 0 {
		t.Errorf("len = %d for a bucket that was never harvested, want 0", missing.Len)
	}
}

// --- 6b. 上游错误分类：到门口被拒不等于没路 ---
// reached 分三级：上游错误体可解析则已到（该 schema 来自上游）；
// 找到完整 failed with status N 则已到且有码；两者都无才是真传输失败。
// handleSelftest 无 host 早退到不了这儿，直接测同包两分类器，不另挖接缝。

// 以下消息来自真实部署，原文必须留；分类器读别人的输出，改成“差不多”台词只会考不存在的协议。
const (
	// OVH 原样观测到的台词，别替上游润色。
	msgOverloaded = `host_call_failed: {"error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later.","param":null},"sequence_number":2}`
	// OVH 观测消息正文截断过，这里补全；分类器所读 error 字段仍照实记录，不把台词补写冒充证据。
	msgServerError = `host_call_failed: {"error":{"type":"server_error","code":"server_error","message":"An error occurred while processing your request.","param":null},"sequence_number":1}`
)

func TestUpstreamErrorClassification(t *testing.T) {
	cases := []struct {
		name       string
		message    string
		wantBody   bool
		wantCode   string
		wantType   string
		wantStatus int  // 找不到状态码就记 0，不凭空补票
		wantOKStat bool //nolint:revive // 照分类器第二返回值报到，不另演一套
	}{
		{
			// 这级专治 server_is_overloaded：同 312 降级信号（FINDINGS.md），取回 code 才知该等而非查断网。
			// 误报 reached=false 曾把人指去修网络，其实厨房只是忙不过来。
			name:     "overloaded, no status",
			message:  msgOverloaded,
			wantBody: true,
			wantCode: "server_is_overloaded",
			wantType: "service_unavailable_error",
		},
		{
			name:     "server_error, no status",
			message:  msgServerError,
			wantBody: true,
			wantCode: "server_error",
			wantType: "server_error",
		},
		{
			name:       "body and status together",
			message:    `host_call_failed: {"error":{"type":"rate_limit_error","code":"rate_limit_exceeded","message":"slow down"}} failed with status 429`,
			wantBody:   true,
			wantCode:   "rate_limit_exceeded",
			wantType:   "rate_limit_error",
			wantStatus: 429,
			wantOKStat: true,
		},
		{
			name:       "status only, no body",
			message:    "host_call_failed: request failed with status 502",
			wantBody:   false,
			wantStatus: 502,
			wantOKStat: true,
		},
		{
			// 第三级无可恢复线索，诚实报 reached=false，不编到店打卡。
			name:    "transport failure",
			message: "host_call_failed: dial tcp 127.0.0.1:8317: connect: connection refused",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, okBody := upstreamErrorFrom(tc.message)
			if okBody != tc.wantBody {
				t.Fatalf("upstreamErrorFrom ok = %t, want %t", okBody, tc.wantBody)
			}
			if okBody {
				if got := strings.TrimSpace(body.Error.Code); got != tc.wantCode {
					t.Errorf("upstream_error_code = %q, want %q", got, tc.wantCode)
				}
				if got := strings.TrimSpace(body.Error.Type); got != tc.wantType {
					t.Errorf("upstream_error_type = %q, want %q", got, tc.wantType)
				}
			}

			status, okStatus := statusFromExecutionError(tc.message)
			if okStatus != tc.wantOKStat {
				t.Fatalf("statusFromExecutionError ok = %t, want %t", okStatus, tc.wantOKStat)
			}
			if okStatus && status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}

			// 任一层到达信号成立，就说明请求到了，不能还说路断了。
			if reached := okBody || okStatus; reached != (tc.wantBody || tc.wantOKStat) {
				t.Errorf("reached would be %t, want %t", reached, tc.wantBody || tc.wantOKStat)
			}
		})
	}
}

// 消息夹无关 JSON 不算上游回答；否则纯传输失败也变 reached=true，假成功比真报错更会藏猫猫。
func TestUpstreamErrorFromRejectsUnrelatedJSON(t *testing.T) {
	for _, message := range []string{
		`host_call_failed: {"foo":"bar"}`,
		`host_call_failed: {}`,
		`host_call_failed: {"error":{}}`,
		`host_call_failed: {"error":{"type":"","code":"","message":""}}`,
		`host_call_failed: not json at all`,
		`host_call_failed: {"sequence_number":2}`,
	} {
		t.Run(message, func(t *testing.T) {
			if _, ok := upstreamErrorFrom(message); ok {
				t.Error("an unrelated JSON object was accepted as an upstream error body")
			}
		})
	}
}

// 状态标记必须完整 failed with status ，不能只找 status 。上游正文同在消息里，
// check status page 等人话不该被挖成 HTTP 码；放宽就会让路边数字冒充收据。
func TestStatusFromExecutionErrorRequiresTheFullPhrase(t *testing.T) {
	rejected := []string{
		// 区分题：上游人话 status 后跟数字，宽松匹配会挖出 503 当 HTTP 结果。
		// 只有完整短语才拒收；软化此题，老误读又会穿新衣回来。
		`host_call_failed: {"error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Overloaded -- check status 503 page for updates."}}`,
		"host_call_failed: status 429",
		"host_call_failed: http status 500",
		"host_call_failed: failed with status",
		"host_call_failed: failed with status abc",
		// 超合理 HTTP 范围的数字不是状态码，门牌再长也不是票价。
		"host_call_failed: failed with status 42",
		"host_call_failed: failed with status 900",
	}
	for _, message := range rejected {
		t.Run(message, func(t *testing.T) {
			if status, ok := statusFromExecutionError(message); ok {
				t.Errorf("recovered status %d from a message that carries none", status)
			}
		})
	}

	// 反向对照仍须认真实短语；否则聋门卫什么都拒，也能过上面题。
	accepted := map[string]int{
		"host_call_failed: request failed with status 429": 429,
		"host_call_failed: request failed with status 500": 500,
		"host_call_failed: request failed with status 100": 100,
		"host_call_failed: request failed with status 599": 599,
	}
	for message, want := range accepted {
		t.Run(message, func(t *testing.T) {
			status, ok := statusFromExecutionError(message)
			if !ok {
				t.Fatalf("the documented phrasing was not recognised")
			}
			if status != want {
				t.Errorf("status = %d, want %d", status, want)
			}
		})
	}
}

// 两上游字段不带 omitempty，有无码形状都恒定；空就消失会让页面读 undefined，
// 分不清“无代码”和“没实现字段”，空盘也得留桌上。
func TestSelftestUpstreamFieldsHaveNoOmitempty(t *testing.T) {
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	for _, field := range []string{"upstream_error_code", "upstream_error_type"} {
		tag := `json:"` + field + `"`
		if !strings.Contains(string(src), tag) {
			t.Errorf("%s is not declared with a bare %s tag; an omitempty here would make the response shape vary", field, tag)
		}
	}
}

// --- 6c. 312 归属可查，仓库不收 ---
// 312 是上游负载下的降级/限流 state，与 server_is_overloaded 同信号（FINDINGS.md）。
// 采集仍归属只是为日志指出哪个账号降级，不再 auth=-；不能入库。
// 存后重放降级票会被拒 could not be decrypted。这里守存储半边，上方分类器守诊断半边，坏票可登记不可转卖。

// harvestResponseHeaders 按探针所见造响应头，装入调用者要归属的 state 道具。
func harvestResponseHeaders(value string) http.Header {
	h := http.Header{}
	h.Set(testHeader, value)
	return h
}

// resetHarvestState 清内存 bucket 缓存与路由 Cookie 池；harvestFromResponse 遇同键同值会跳过重复写。
// Codex 每轮铸新票，相同说明重放；两缓存进程全局不随测试自动清。
// 开始先清场，免得旧记录压掉待测写入，或旧 Cookie 混到别的账号手里。
func resetHarvestState(t *testing.T) {
	t.Helper()
	state.mu.Lock()
	state.cookies = make(map[string]*routeCookieEntry)
	state.cookiesDirty = false
	state.mu.Unlock()
	t.Cleanup(func() {
		state.mu.Lock()
		state.cookies = make(map[string]*routeCookieEntry)
		state.cookiesDirty = false
		state.mu.Unlock()
	})
}

// --- 6d. 单账号归属：最危险的猜人环节 ---
// 无 selected_auth_id 时可依规范 §7 “probe 一次只启一个 Codex 账号”推断。猜错会把 A 模板写到或注入 B，
// 直接违 §0 规则 1 不跨账号共享 state。soleEnabledCodexAuth 的 count!=1 就是门禁，尤其 2+ 情形绝不能悄悄退化。
// codexAuthLister 是 management.go 包级接缝；每次替换须还原并 resetAuthCache()，
// 查找有 2 秒缓存，假名单不能串到下场，门卫的记忆也要清。

// withAuthList 给单用例装假名单并保证恢复；集中换还流程，别让某用例忘 defer 留下假演员占岗。
func withAuthList(t *testing.T, accounts []codexAuth, err error) {
	t.Helper()
	codexAuthLister = func() ([]codexAuth, error) {
		return accounts, err
	}
	resetAuthCache()
	t.Cleanup(func() {
		codexAuthLister = listCodexAuths
		resetAuthCache()
	})
}

func enabledAccounts(names ...string) []codexAuth {
	out := make([]codexAuth, len(names))
	for i, name := range names {
		out[i] = codexAuth{AuthID: name, Enabled: true}
	}
	return out
}

// harvestNoAuthMeta 就是最简探针的空元数据；故意没账号，才逼归属推断真正上台。
var harvestNoAuthMeta = map[string]any{}

// --- 7. 就绪矩阵：空座位也得画出来 ---

// 降级必须看得见。单测无 host API，host.auth.list 总失败，只能从存储推账号；
// 从未探测的账号隐身，若不说明，短或空矩阵会被看成没目标，而不是问不到名单。
// 静默降级反复出事，所以来源与理由都得写，别把门卫失联讲成宾客绝迹。
func TestStatusReportsDegradedAccountSource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	status := mustManagementStatus(t)
	if status.AccountsSource != "store" {
		t.Errorf("accounts_source = %q with no host API, want %q", status.AccountsSource, "store")
	}
	if strings.TrimSpace(status.AccountsError) == "" {
		t.Error("accounts_error is empty on the degraded path, so the fallback is silent")
	}
}

// 矩阵是打算填的桶，不只已填桶；刚部署一无所获时最需要看 0/N 才知道该干啥，空仓库也要挂货架图。
func TestStatusMatrixCoversEveryTarget(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol"))

	issued := wallClock().Add(-time.Minute)
	// 存储推断出两账号，配两模型得 2×2 矩阵，只填三格；第四把空椅子不能藏起来。
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued)

	status := mustManagementStatus(t)
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
	if status.TargetsTotal != 4 {
		t.Errorf("targets_total = %d for 2 accounts x 2 models, want 4", status.TargetsTotal)
	}

	// 没采集那格必须在并诚实报空，别把欠账划掉当结清。
	gap, ok := mgmtBucketByKey(status, "codex-beta.json", "gpt-5.6-sol")
	if !ok {
		t.Fatal("the never-harvested combination is missing from the matrix; the page would not show it as a gap")
	}
	if gap.Ready {
		t.Error("a never-harvested cell reports ready")
	}
	if gap.Len != 0 {
		t.Errorf("a never-harvested cell reports len = %d, want 0", gap.Len)
	}
	if gap.IssuedAt != "" || gap.ExpiresAt != "" {
		t.Errorf("a never-harvested cell carries timestamps: issued=%q expires=%q", gap.IssuedAt, gap.ExpiresAt)
	}
	if gap.SecondsLeft != 0 {
		t.Errorf("a never-harvested cell reports seconds_left = %d, want 0", gap.SecondsLeft)
	}

	// 反向加宽模型表，矩阵也要加宽；否则只列磁盘记录的懒掌柜也能过前题。
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol", "gpt-6-astra"))
	wider := mustManagementStatus(t)
	if wider.TargetsTotal != 6 {
		t.Errorf("targets_total = %d after adding a third model to 2 accounts, want 6", wider.TargetsTotal)
	}
}

// 页面定时重取，顺序不稳会让行列在鼠标下跳舞，看板不是打地鼠。
func TestStatusBucketOrderIsStable(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.6-sol", "gpt-5.5"))

	issued := wallClock().Add(-time.Minute)
	// 故意乱序种数据，别让 map/磁盘原序恰好排对，靠运气过考不算。
	seedMgmtBucket(t, dir, "codex-zulu.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-mike.json", "gpt-5.6-sol", issued)

	first := mustManagementStatus(t)
	second := mustManagementStatus(t)

	if len(first.Buckets) != len(second.Buckets) {
		t.Fatalf("two consecutive calls returned %d and %d buckets", len(first.Buckets), len(second.Buckets))
	}
	for i := range first.Buckets {
		if first.Buckets[i].AuthID != second.Buckets[i].AuthID || first.Buckets[i].Model != second.Buckets[i].Model {
			t.Fatalf("order changed between calls at index %d: %s/%s then %s/%s",
				i, first.Buckets[i].AuthID, first.Buckets[i].Model,
				second.Buckets[i].AuthID, second.Buckets[i].Model)
		}
	}
	// 稳定还不够，稳定排错也是错；合同按（auth_id, model）字典序，座次写清。
	for i := 1; i < len(first.Buckets); i++ {
		prev, cur := first.Buckets[i-1], first.Buckets[i]
		if prev.AuthID > cur.AuthID || (prev.AuthID == cur.AuthID && prev.Model > cur.Model) {
			t.Errorf("buckets are not sorted by (auth_id, model): %s/%s precedes %s/%s",
				prev.AuthID, prev.Model, cur.AuthID, cur.Model)
		}
	}
}

// 空存储在降级路径确实没账号可列，空矩阵可以，但不能只甩空数组。
// 须标明来源，否则“问不到”与“没人可探”长一样；accounts_source 就是给这张白纸写清来历。
func TestStatusEmptyStoreStillNamesItsSource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	status := mustManagementStatus(t)
	if status.AccountsSource != "store" {
		t.Errorf("accounts_source = %q, want %q", status.AccountsSource, "store")
	}
	if strings.TrimSpace(status.AccountsError) == "" {
		t.Error("an empty matrix arrived with no accounts_error, so it reads as 'nothing to probe'")
	}
	if status.TargetsReady != 0 {
		t.Errorf("targets_ready = %d on an empty store, want 0", status.TargetsReady)
	}
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
}

// --- 9. 探测秘密：一项刻意公开，两把钥匙仍不露脸 ---
// 范围里代理列表如今按要求明文公开；runner 两个 bearer 则哪里都不公布。
// 两边都钉牢，别看隔壁开窗就把保险柜也拆了。

const (
	// 密钥起独特道具名，断言到处搜它，不能撞上合法格式化文字造成冤案。
	testProbeManagementKey = "mk-probe-management-never-show-me"
)

// probeConfigWithSecrets 在 probeRoleConfig 上加带密码代理（probe_scope_test.go 的 testProxyWithPW）与 bearer。
// 同一份道具考两条线：代理列表原样展示，key 哪里都不露。
func probeConfigWithSecrets(dir string) string {
	return probeRoleConfig(dir) + fmt.Sprintf(`probe_accounts:
  - codex-a.json
probe_proxies:
  - %s
probe_management_key: %s
`, testProxyWithPW, testProbeManagementKey)
}

// 代理列表明文是刻意反转旧遮罩：textarea 塞 socks5h://***@exit:1080 就变只能写不能读，
// 每次存范围都得重输整表，运营者明确要求真实值。测试钉住这个决定，
// 后人别以“这该遮罩吧”又修回不可用编辑器。其他位置遮罩见 probe_scope_test.go 与 TestProbeKeysAreNeverDisplayedOrLogged。
func TestStatusShowsProbeProxiesInTheClear(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeConfigWithSecrets(dir))

	status := mustManagementStatus(t)
	if status.ProbeProxyCount != 1 {
		t.Fatalf("probe_proxy_count = %d, want 1; the count stays alongside the list", status.ProbeProxyCount)
	}
	if len(status.ProbeProxies) != 1 || status.ProbeProxies[0] != testProxyWithPW {
		t.Fatalf("probe_proxies = %v, want the configured entry verbatim", status.ProbeProxies)
	}

	// 匿名资源真公开的也是这份文档；只考带 key 路由等于只检查锁着的窗，不看大门。
	resp := driveManagement(t, http.MethodGet, mgmtResourcePath+"status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous status returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var anonymous mgmtStatus
	if err := json.Unmarshal(resp.Body, &anonymous); err != nil {
		t.Fatalf("decode anonymous status: %v", err)
	}
	if len(anonymous.ProbeProxies) != 1 || anonymous.ProbeProxies[0] != testProxyWithPW {
		t.Fatalf("anonymous probe_proxies = %v, want the same verbatim entry", anonymous.ProbeProxies)
	}

	// 被替换的旧字段要消失，不能并排留；否则页面看遮罩，真值却躺同文档，保密与可用两头都输。
	if strings.Contains(string(resp.Body), "probe_proxies_masked") {
		t.Error("status still carries probe_proxies_masked; the masked field was replaced, not supplemented")
	}
}

// 两个探测 key 让看板不用人输 key 就能开跑，前提是它们绝不回流。
// 状态免密、configure 日志会贴工单，两处任何形式都不能带 key，连遮罩展示都不设，钥匙不参加时装秀。
func TestProbeKeysAreNeverDisplayedOrLogged(t *testing.T) {
	dir := t.TempDir()

	// configure 是读 key 的地方，它那行日志最容易把钥匙带出门。
	logged := captureLog(t, func() { mustConfigure(t, probeConfigWithSecrets(dir)) })
	if strings.TrimSpace(logged) == "" {
		t.Fatal("configure logged nothing; the leak assertions below would prove nothing")
	}
	for _, secret := range []string{testProbeManagementKey} {
		if strings.Contains(logged, secret) {
			t.Error("the configure log line carried a probe key verbatim")
		}
	}
	// 只报存在与否；日志需要回答配没配，不需要任何长相提示。
	for _, want := range []string{"probe_management_key=set"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the configure log line does not report %q, so a missing key would be invisible: %s", want, logged)
		}
	}

	// 所有配置展示位置一起查：两状态路由、原样返配置的鉴权 config 路由；后者最易无意长出新字段。
	for name, path := range map[string]string{
		"management status": mgmtStatusPath,
		"anonymous status":  mgmtResourcePath + "status",
		"config":            mgmtConfigPath,
	} {
		resp := driveManagement(t, http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d, want 200 (body: %s)", name, resp.StatusCode, truncateMgmtLog(resp.Body))
		}
		if len(resp.Body) == 0 {
			t.Fatalf("%s body is empty; the assertions below would prove nothing", name)
		}
		body := string(resp.Body)
		for _, secret := range []string{testProbeManagementKey} {
			if strings.Contains(body, secret) {
				t.Errorf("%s leaked a probe key", name)
			}
		}
		// 字段名同样不能露：把 key 写成 "" 或 "***" 会像未配置，还诱导下一人填真值，
		// 空保险柜招牌也会招来错误装修。
		for _, field := range []string{"probe_management_key"} {
			if strings.Contains(body, field) {
				t.Errorf("%s carries a %q field; these are never displayed, not even empty or masked", name, field)
			}
		}
	}
}

// runner 两控制有意免密，所以必须 Resources；GET 会花配额或停在途运行，
// 缺 confirm=1 必须拒绝，预取路过不能替人喊开机、停机。
func TestProbeRunRoutesAreKeylessResourcesGuardedByConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeConfigWithSecrets(dir))

	reg := driveManagementRegister(t)
	if len(reg.Resources) == 0 {
		t.Fatal("no resources declared; this test would pass vacuously")
	}
	resources := make(map[string]mgmtRoute, len(reg.Resources))
	for _, res := range reg.Resources {
		resources[res.Path] = res
	}
	managementRoutes := make(map[string]bool, len(reg.Routes))
	for _, route := range reg.Routes {
		managementRoutes[route.Path] = true
	}

	for _, path := range []string{"/ops/probe/start", "/ops/probe/cancel"} {
		res, ok := resources[path]
		if !ok {
			t.Errorf("%s is not registered as a resource, so it would demand a management key the dashboard does not have", path)
			continue
		}
		// GET 带 Menu 会意外降到资源前缀；这些本来就该在那里，不带 Menu，也别把动作假扮导航页面。
		if strings.TrimSpace(res.Menu) != "" {
			t.Errorf("%s declares Menu %q; it is fetched by the page, not navigated to", path, res.Menu)
		}
		if managementRoutes[path] {
			t.Errorf("%s is also a management route; a keyless action must live only on the unauthenticated prefix", path)
		}
	}

	// 新增路由时再查 config 不入资源表；复制黏贴最会让原样配置响应跟错队伍。
	for _, res := range reg.Resources {
		if strings.HasSuffix(res.Path, "/config") {
			t.Errorf("config route %q is registered as a resource; it must stay behind the management key", res.Path)
		}
	}

	for _, path := range []string{opsProbeStartPath, opsProbeCancelPath} {
		resp := driveResource(t, path, url.Values{})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s without confirm=1 returned %d, want 400 (body: %s)", path, resp.StatusCode, truncateMgmtLog(resp.Body))
		}
	}
	// 拒绝后还要确认没启动；嘴上拒绝手里开跑，正是 confirm=1 要防的双簧。
	if snapshot := probeRunSnapshot(); snapshot.Running {
		t.Error("a probe run is in flight after two requests that were refused for lack of confirm=1")
	}
}

// --- /ops/choices：勾选菜单别替人忘事 ---
// 三份手输列表改复选框，须免 key、免 confirm，否则空框；selected 忠实映保存范围，否则下一次保存丢未重勾项；
// 展示 label 不带客户邮件；名单取不到也保模型菜单并说明原因，不能柜台断网就把餐厅招牌摘了。

// choicesCPAFile 是假 auth-files 的一条，用 map 不用结构，方便按题故意造坏形状，道具可换脸。
type choicesCPAFile map[string]any

// choicesCPA 只扮 /ops/choices 要用的 GET /v0/management/auth-files。
// 不借 probe_runner_test.go 那个给所有条目标 codex 的 fakeCPA，因为两题要过滤，其中一个正是非 Codex，替身不能先替坏人洗白。
type choicesCPA struct {
	server *httptest.Server

	// 下面状态被服务 goroutine 读、测试 goroutine 写，统一 mutex 守门；不赌请求往返刚好带来的 happens-before。
	mu sync.Mutex
	// status 控制名单回应，401 是考题不是片场故障，生产过期 probe_management_key 就会这样。
	status int
	files  []choicesCPAFile
	// hold 卡处理器直到测试关掉，扮 CPA 收连接后装没听见。
	hold chan struct{}
	// authSeen 收 Authorization 头，实证带了配置 key，不是碰巧摸进未鉴权名单柜。
	authSeen []string
}

func newChoicesCPA(t *testing.T, files ...choicesCPAFile) *choicesCPA {
	t.Helper()
	fake := &choicesCPA{status: http.StatusOK, files: files}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		hold, status, files := fake.hold, fake.status, fake.files
		fake.authSeen = append(fake.authSeen, r.Header.Get("Authorization"))
		fake.mu.Unlock()

		// 阻塞在锁外，别让一个发呆处理器把其他客人全锁在门口。
		if hold != nil {
			<-hold
		}
		if r.URL.Path != probeRouteAuthFiles {
			http.Error(w, `{"error":"no such route"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			// 照 CPA 拒绝格式连 body 一起演；错误体可能被引用进页面报错，别让带秘密台词混过去。
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// refuse 让名单端点按 status 与错误体拒客。
func (f *choicesCPA) refuse(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

// stall 让每请求堵到测试结束，只准插件自己的超时出来喊停，不能靠对手演员提醒散场。
func (f *choicesCPA) stall(t *testing.T) {
	t.Helper()
	gate := make(chan struct{})
	f.mu.Lock()
	f.hold = gate
	f.mu.Unlock()
	t.Cleanup(func() { close(gate) })
}

func (f *choicesCPA) authHeaders() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.authSeen...)
}

// 假凭据按生产 codex-<hex>-<email>-<tier>.json 命名，遮罩就考这种衣服。
// 邮件全用 RFC 2606 保留 example.com，不请真实客户来当泄漏道具。
const (
	choicesAuthPro  = "codex-620f5a42-luo.swmu@example.com-pro.json"
	choicesAuthPlus = "codex-aa11bb22-someone@example.com-plus.json"
	// 备份不能变复选框；一勾就可能被扫进启用凭据的队伍，副本不领主演工牌。
	choicesAuthBak = "codex-620f5a42-luo.swmu@example.com-pro.json.bak"
	// 这不是 Codex 凭据，CPA 同库放着它；若探它就是给插件不懂的提供商白花请求，别乱认同行。
	choicesAuthOther = "gemini-someone@example.com.json"
)

// choicesConfig 独立写指向假 CPA 的 probe 配置，不借 probeTestConfig，runner 道具改装别带这场戏换布景。
func choicesConfig(dir, baseURL, mgmtKey string, accounts, models []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "role: probe\nstore_dir: %q\nlog_decisions: false\ndry_run: true\n", dir)
	fmt.Fprintf(&b, "probe_base_url: %q\n", baseURL)
	fmt.Fprintf(&b, "probe_management_key: %q\n", mgmtKey)
	for _, block := range []struct {
		key    string
		values []string
	}{{"probe_accounts", accounts}, {"models", models}} {
		if len(block.values) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s:\n", block.key)
		for _, value := range block.values {
			fmt.Fprintf(&b, "  - %q\n", value)
		}
	}
	return b.String()
}

type mgmtChoiceAccount struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Disabled bool   `json:"disabled"`
	Selected bool   `json:"selected"`
}

type mgmtChoiceModel struct {
	Name     string `json:"name"`
	Selected bool   `json:"selected"`
}

// mgmtChoices 镜像看板解码形状；生产 Error 不带 omitempty，这里按普通字符串解，
// 防未来改指针或空时消失，空盘也该能认得出来。
type mgmtChoices struct {
	Accounts []mgmtChoiceAccount `json:"accounts"`
	Models   []mgmtChoiceModel   `json:"models"`
	Error    string              `json:"error"`
}

// mustChoices 按看板原样取 /ops/choices：免密前缀裸 GET，无 key、无 confirm、无参数，空手看菜单。
func mustChoices(t *testing.T) (mgmtChoices, mgmtResponse) {
	t.Helper()
	resp := driveResource(t, opsChoicesPath, url.Values{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d, want 200 (body: %s)", opsChoicesPath, resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var out mgmtChoices
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("decode choices: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	return out, resp
}

func choiceAccountByName(choices mgmtChoices, name string) (mgmtChoiceAccount, bool) {
	for _, account := range choices.Accounts {
		if account.Name == name {
			return account, true
		}
	}
	return mgmtChoiceAccount{}, false
}

// 路由与 /ops 其他项同免密，却不同于它们，不需 confirm=1。
// 看板不持 key，又在加载时就取菜单尚无事可确认；任加一门槛都会只剩空框，不能先点菜才准看菜单。
func TestChoicesIsAKeylessResourceNeedingNoConfirm(t *testing.T) {
	dir := t.TempDir()
	fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
	mustConfigure(t, choicesConfig(dir, fake.server.URL, "mk-choices", nil, []string{"gpt-5.5"}))

	reg := driveManagementRegister(t)
	if len(reg.Resources) == 0 {
		t.Fatal("no resources declared; this test would pass vacuously")
	}
	var declared *mgmtRoute
	for index, res := range reg.Resources {
		if res.Path == "/ops/choices" {
			declared = &reg.Resources[index]
		}
	}
	if declared == nil {
		t.Fatal("/ops/choices is not registered as a resource, so it would demand a management key the dashboard does not have")
	}
	// GET 的 Menu 会被宿主重挂资源前缀；这里有意免密但无 Menu，取数文档别伪装成导航页面。
	if strings.TrimSpace(declared.Menu) != "" {
		t.Errorf("/ops/choices declares Menu %q; it is fetched by the page, not navigated to", declared.Menu)
	}
	for _, route := range reg.Routes {
		if route.Path == "/ops/choices" {
			t.Error("/ops/choices is also a management route; a keyless route must live only on the unauthenticated prefix")
		}
	}

	// 真取一次：无 key、无 confirm，还要能解 body，门口牌子别只写得好看。
	choices, _ := mustChoices(t)
	if len(choices.Models) == 0 {
		t.Error("choices returned no models on a keyless fetch; the checkboxes would render empty")
	}
}

// CPA 名单过滤为 Codex，保存范围预先勾好；不滤会出现探不了的选项，
// 丢 selected 会让用户下次保存忘勾从前选择，编辑器不能兼职清场员。
func TestChoicesListsCPACredentialsAndMarksTheScope(t *testing.T) {
	dir := t.TempDir()
	const mgmtKey = "mk-choices-never-show-me"
	fake := newChoicesCPA(t,
		// 故意乱序来，页面刷新不能让菜单换座位。
		choicesCPAFile{"name": choicesAuthPlus, "provider": "codex", "disabled": true},
		choicesCPAFile{"name": choicesAuthPro, "provider": "codex", "disabled": false},
		choicesCPAFile{"name": choicesAuthBak, "provider": "codex"},
		choicesCPAFile{"name": choicesAuthOther, "provider": "gemini"},
	)
	mustConfigure(t, choicesConfig(dir, fake.server.URL, mgmtKey,
		[]string{choicesAuthPro},
		// 一个已知模型加一个 fallback 菜单没听过的，同时考并集两头，别只会招待熟客。
		[]string{"gpt-5.5", "gpt-local-only"}))

	choices, resp := mustChoices(t)
	if choices.Error != "" {
		t.Fatalf("choices reported an error against a healthy CPA: %q", choices.Error)
	}

	// --- 账号：先验工牌再排座 ---
	gotNames := make([]string, 0, len(choices.Accounts))
	for _, account := range choices.Accounts {
		gotNames = append(gotNames, account.Name)
	}
	// 按 name 排，620f... 应到先发布的 aa11... 前；.bak 和非 Codex 不入场，先到不等于合格。
	wantNames := []string{choicesAuthPro, choicesAuthPlus}
	if len(gotNames) != len(wantNames) {
		t.Fatalf("accounts = %v, want exactly %v (a .bak copy or a non-Codex credential leaked into the menu)", gotNames, wantNames)
	}
	for index, want := range wantNames {
		if gotNames[index] != want {
			t.Fatalf("accounts = %v, want %v in that order", gotNames, wantNames)
		}
	}

	selected, _ := choiceAccountByName(choices, choicesAuthPro)
	if !selected.Selected {
		t.Error("the account in probe_accounts came back unselected; the page would render the saved scope as empty")
	}
	if selected.Disabled {
		t.Error("an enabled credential came back disabled")
	}
	unselected, _ := choiceAccountByName(choices, choicesAuthPlus)
	if unselected.Selected {
		t.Error("an account that is not in probe_accounts came back selected; ticking it was nobody's decision")
	}
	// CPA disabled 只透传不拿来过滤；禁用凭据也是合法目标，藏起来会像账号被删，暂停演员仍在名单上。
	if !unselected.Disabled {
		t.Error("a credential CPA reports as disabled came back enabled")
	}

	// --- 模型：菜单合并不漏菜 ---
	wantModels := []struct {
		name     string
		selected bool
	}{
		{"gpt-5.5", true},        // 配置与备用菜单都点了名
		{"gpt-5.6-sol", false},   // 只在菜单候场
		{"gpt-6-astra", false},   // 只在菜单候场
		{"gpt-local-only", true}, // 手动配置点的客人，菜单还不认得
	}
	if len(choices.Models) != len(wantModels) {
		t.Fatalf("models = %+v, want %d entries (the union of the configured list and the fallback menu, de-duplicated)", choices.Models, len(wantModels))
	}
	for index, want := range wantModels {
		got := choices.Models[index]
		if got.Name != want.name {
			t.Fatalf("models[%d] = %q, want %q; the union must be sorted so the checkboxes do not reshuffle", index, got.Name, want.name)
		}
		if got.Selected != want.selected {
			t.Errorf("model %q selected=%v, want %v", got.Name, got.Selected, want.selected)
		}
	}

	// --- 正文禁区：这些秘密不上桌 ---
	body := string(resp.Body)
	if strings.Contains(body, mgmtKey) {
		t.Error("the choices body carries probe_management_key; this route answers without any key at all")
	}
	if strings.Contains(body, "probe_management_key\"") {
		t.Error("the choices body carries a probe_management_key field; these are never displayed, not even empty")
	}
	// 真检查获取名单已鉴权，否则误入免密名单接口也会过题，门卫得真验过票。
	headers := fake.authHeaders()
	if len(headers) == 0 {
		t.Fatal("the fake CPA saw no request; the accounts above came from somewhere else")
	}
	if headers[0] != "Bearer "+mgmtKey {
		t.Errorf("CPA was called with Authorization %q, want the configured probe_management_key as a bearer", headers[0])
	}
}

// label 遮邮件是页面显示边界：文件名含客户邮件，文档任何可达者可读，展示名不能带地址。
// 四类形状包括通常名、无邮件、额外横线、空串；末尾邮件尤其考验先删邮件再取首尾，
// 顺序反了就把地址当艺名挂出来。
func TestMaskAuthLabel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "the normal codex-<hex>-<email>-<tier>.json shape",
			in:   "codex-620f5a42-luo.swmu@example.com-pro.json",
			want: "620f5a42…pro",
		},
		{
			name: "no email in the name at all",
			in:   "codex-620f5a42-pro.json",
			want: "620f5a42…pro",
		},
		{
			// 含横线邮件会拆多段，中间 tag 没必要晒；保留合规首尾，其他请下镜头。
			name: "extra dashes around the email",
			in:   "codex-620f5a42-luo-swmu@example.com-team-pro.json",
			want: "620f5a42…pro",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			// 先删邮件部分再取首尾，反过来就把地址上墙，这道顺序题不能倒着演。
			name: "email in the final position",
			in:   "codex-620f5a42-luo@example.com.json",
			want: "620f5a42",
		},
		{
			name: "nothing but an email",
			in:   "codex-luo@example.com.json",
			want: "…",
		},
	}
	for _, c := range cases {
		got := maskAuthLabel(c.in)
		if got != c.want {
			t.Errorf("%s: maskAuthLabel(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		// 再上一道便宜保险：无论什么形状，label 有 @ 就说明邮件上了免密页面。
		if strings.Contains(got, "@") {
			t.Errorf("%s: maskAuthLabel(%q) = %q, which still carries an email address", c.name, c.in, got)
		}
	}
}

// 名单取不到仍给可用页面：200、空账号、模型完整、解释原因。
// 报 5xx 会因一个十秒可修配置清空整个编辑器，别为找不到一位客人就拉闸餐厅。
func TestChoicesDegradesWhenCredentialListUnavailable(t *testing.T) {
	t.Run("management key unset", func(t *testing.T) {
		dir := t.TempDir()
		fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
		mustConfigure(t, choicesConfig(dir, fake.server.URL, "", nil, []string{"gpt-5.5"}))

		choices, _ := mustChoices(t)
		if len(choices.Accounts) != 0 {
			t.Errorf("accounts = %+v, want [] when the credential list could not be fetched", choices.Accounts)
		}
		if !strings.Contains(choices.Error, "probe_management_key") {
			t.Errorf("error = %q; it must name the setting that is missing, or the operator has nothing to act on", choices.Error)
		}
		// 模型半边不用 CPA，另一半摔倒不能把它也拽下台。
		if len(choices.Models) != len(knownCodexModels) {
			t.Errorf("models = %+v, want the fallback menu; a credential fetch failure must not take the model list with it", choices.Models)
		}
		// 没 key 就根本不该发请求；裸 GET 后拿 CPA 401 告状，是把自己的漏钥匙赖给门锁。
		if headers := fake.authHeaders(); len(headers) != 0 {
			t.Errorf("CPA was called %d time(s) with no key configured; the refusal must be local", len(headers))
		}
	})

	t.Run("cpa rejects the key", func(t *testing.T) {
		dir := t.TempDir()
		const mgmtKey = "mk-choices-stale-never-show-me"
		fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
		fake.refuse(http.StatusUnauthorized)
		mustConfigure(t, choicesConfig(dir, fake.server.URL, mgmtKey, []string{choicesAuthPro}, []string{"gpt-5.5"}))

		choices, resp := mustChoices(t)
		if len(choices.Accounts) != 0 {
			t.Errorf("accounts = %+v, want [] after a 401", choices.Accounts)
		}
		if !strings.Contains(choices.Error, "401") {
			t.Errorf("error = %q; a 401 must be reported as one, because it means a wrong key rather than a wrong path", choices.Error)
		}
		if len(choices.Models) == 0 {
			t.Error("the model list went missing along with the accounts")
		}
		// 失败路径最爱引用原文，key 绝不能被引进台词里。
		if strings.Contains(string(resp.Body), mgmtKey) {
			t.Error("the error body carries probe_management_key verbatim")
		}
	})
}

// CPA 装死不能挂住看板；页面等它才渲染，所以得有限超时，返回同样可理解的降级结果，不接受“总有一天回”。
func TestChoicesDoesNotHangOnUnresponsiveCPA(t *testing.T) {
	dir := t.TempDir()
	fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
	fake.stall(t)
	mustConfigure(t, choicesConfig(dir, fake.server.URL, "mk-choices", nil, []string{"gpt-5.5"}))

	previous := choicesFetchTimeout
	choicesFetchTimeout = 100 * time.Millisecond
	t.Cleanup(func() { choicesFetchTimeout = previous })

	// 手驱动不用 mustChoices：调用放另一 goroutine，主测试才能计时；
	// 那里不能 t.Fatal，停错 goroutine 会让测试就卡在自己要报告的死局，报警员不能先把电话砸了。
	request, errMarshal := json.Marshal(map[string]any{
		"Method": http.MethodGet, "Path": opsChoicesPath,
		"Headers": http.Header{}, "Query": url.Values{}, "Body": nil,
	})
	if errMarshal != nil {
		t.Fatalf("marshal resource request: %v", errMarshal)
	}

	type outcome struct {
		raw []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		raw, err := handleMethod(pluginabi.MethodManagementHandle, request)
		done <- outcome{raw: raw, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("handleMethod(management.handle) GET %s: %v", opsChoicesPath, got.err)
		}
		var resp mgmtResponse
		if result := decodeMgmtEnvelope(t, got.raw); len(result) > 0 {
			if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
				t.Fatalf("decode resource response: %v", errUnmarshal)
			}
		}
		if resp.StatusCode != 0 && resp.StatusCode != http.StatusOK {
			t.Fatalf("a timed-out fetch returned %d, want 200 with the reason in the body", resp.StatusCode)
		}
		var choices mgmtChoices
		if err := json.Unmarshal(resp.Body, &choices); err != nil {
			t.Fatalf("decode choices: %v (body: %s)", err, truncateMgmtLog(resp.Body))
		}
		if choices.Error == "" {
			t.Error("a timed-out fetch reported no error; the page would render an empty account list as if CPA held none")
		}
		if len(choices.Models) == 0 {
			t.Error("the model list went missing on a timeout, though it needs no CPA call")
		}
	case <-time.After(10 * time.Second):
		// 期限故意宽松，只验有界，不争谁跑得快，考试不是竞速。
		t.Fatal("/ops/choices did not return against an unresponsive CPA")
	}
}
