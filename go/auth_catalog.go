// 凭据花名册：宿主认识哪些 Codex 账号，采集路径就在这里点名，外加一口短命缓存。
// 原来这套能力挤在 management.go，热路径要找管理台借花名册，像厨师向收银员借锅。
// 现在花名册提供能力，管理台与拦截器各自来读；同属一个 package，搬家不等于编译器设门禁，
// 但至少把边界画给后来人看。edd3de3 从 management.go、main.go 原样迁出，
// b9da52e 将 statusAccount 改名；两次都没改行为。

package main

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// codexAuth 是宿主报来的一位 Codex 伙计：凭据文件名，加上眼下能不能接客。
// 禁用和 unavailable 都算不能上班，区别见 listCodexAuths。没有 JSON 标签，也不序列化。
// 旧名 statusAccount 容易让人以为只给状态页打工；其实 soleEnabledCodexAuth 的请求路径也用它。
type codexAuth struct {
	AuthID  string
	Enabled bool
}

// 花名册只缓存 2 秒，免得每个上游响应都拉宿主出来点名。
// 探测期间账号开关会变，缓存不能把刚下班的伙计硬记成当班，所以窗口宁短勿长。
// handleStatus 不借这本旧账：面板访问少，操作者要的是眼前状态，不是两秒前的合影。
const authListCacheTTL = 2 * time.Second

var (
	authListMu      sync.Mutex
	authListCache   []codexAuth
	authListErr     error
	authListFetched time.Time
)

// codexAuthLister 列出当前 Codex 凭据。留成包变量，是给测试一个换演员的入口。
// 采集与替换路径都要验归属兜底，尤其双账号时宁可不猜，也别把甲的账记到乙头上。
// 生产环境仍用宿主提供的真名单，不请替身。
var codexAuthLister = listCodexAuths

// authCatalogLister 给完整凭据目录留同样的测试入口，非 Codex 也得点名。
// “别家提供商的客人”和“查无此人”不是一回事；前者绝不能被池里的 Cookie 拉错包间。
var authCatalogLister = listAuthCatalog

// cachedCodexAuths 给 codexAuthLister 加短缓存，并把查询放在互斥锁里排队。
// 一群响应同时敲门，只让宿主答一次，不上演百人齐声查户口。
func cachedCodexAuths() ([]codexAuth, error) {
	authListMu.Lock()
	defer authListMu.Unlock()
	if !authListFetched.IsZero() && time.Since(authListFetched) < authListCacheTTL {
		return authListCache, authListErr
	}
	authListCache, authListErr = codexAuthLister()
	authListFetched = time.Now()
	return authListCache, authListErr
}

var (
	authCatalogMu      sync.Mutex
	authCatalogCache   []pluginapi.HostAuthFileEntry
	authCatalogErr     error
	authCatalogFetched time.Time
)

// cachedAuthCatalog 复用 Codex 名单的短缓存窗口，为路由门卫提供高频查询。
// 花名册可以暂存，门卫不能每看一人就重印一本。
func cachedAuthCatalog() ([]pluginapi.HostAuthFileEntry, error) {
	authCatalogMu.Lock()
	defer authCatalogMu.Unlock()
	if !authCatalogFetched.IsZero() && time.Since(authCatalogFetched) < authListCacheTTL {
		return authCatalogCache, authCatalogErr
	}
	authCatalogCache, authCatalogErr = authCatalogLister()
	authCatalogFetched = time.Now()
	return authCatalogCache, authCatalogErr
}

// resetAuthCache 清空两份凭据视图，下次直接找 lister 重新点名。
// 测试换名单后必须赶走那份 2 秒旧账，免得上场演员替本场答题；生产不调用，缓存正常活满窗口。
func resetAuthCache() {
	authListMu.Lock()
	authListCache = nil
	authListErr = nil
	authListFetched = time.Time{}
	authListMu.Unlock()
	authCatalogMu.Lock()
	authCatalogCache = nil
	authCatalogErr = nil
	authCatalogFetched = time.Time{}
	authCatalogMu.Unlock()
}

// listAuthCatalog 取宿主全部凭据，不筛人：Codex 名单和路由门卫都从这锅原料分菜。
func listAuthCatalog() ([]pluginapi.HostAuthFileEntry, error) {
	var listed struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if errCall := hostCallJSON("host.auth.list", map[string]any{}, &listed); errCall != nil {
		return nil, errCall
	}
	return listed.Files, nil
}

// listCodexAuths 把宿主的 Codex 凭据按名字排队，启用状态照实报，不给缺勤者补签到。
func listCodexAuths() ([]codexAuth, error) {
	files, errList := listAuthCatalog()
	if errList != nil {
		return nil, errList
	}
	var out []codexAuth
	for _, file := range files {
		if !isCodexAuth(file) {
			continue
		}
		name := strings.TrimSpace(file.Name)
		if name == "" {
			continue
		}
		// unavailable 和 disabled 都不能接请求，这里统一记为未启用。
		// 操作者问的是“这桶现在能不能装”，不是“究竟哪块告示牌挂歪了”。
		out = append(out, codexAuth{AuthID: name, Enabled: !file.Disabled && !file.Unavailable})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AuthID < out[j].AuthID })
	return out, nil
}

func isCodexAuth(file pluginapi.HostAuthFileEntry) bool {
	if strings.EqualFold(strings.TrimSpace(file.Provider), "codex") ||
		strings.EqualFold(strings.TrimSpace(file.Type), "codex") {
		return true
	}
	// 文件型凭据未必填 Provider，缺这一栏时才看命名惯例，和采集器认人用同一把尺。
	name := strings.ToLower(strings.TrimSpace(file.Name))
	return strings.HasPrefix(name, "codex-") && strings.HasSuffix(name, ".json")
}

// soleEnabledCodexAuth 只在恰有一个启用的 Codex 凭据时报名字，同时报人数方便解释拒绝。
// 零人或多人都回空名：独苗才可点名，挤满一屋不能靠闭眼抓阄。
func soleEnabledCodexAuth() (string, int, error) {
	accounts, errList := cachedCodexAuths()
	if errList != nil {
		return "", 0, errList
	}
	name := ""
	count := 0
	for _, account := range accounts {
		if !account.Enabled {
			continue
		}
		count++
		name = account.AuthID
	}
	if count != 1 {
		return "", count, nil
	}
	return name, 1, nil
}

// selectedAuthIsCodex 按宿主档案判断调度器选中的账号是不是 Codex，不凭文件名看面相。
// 先匹配稳定 auth index，再匹配 id/name，对应 selected_auth_index、selected_auth_id。
// resolved=false 表示目录读不到，才退回仅存的文件名线索。
// resolved=true 且 codex=false 包括别家提供商和目录中不存在两种情况；
// 调度器只能选已登记账号，失踪说明竞争或不一致，不是给猜谜发许可证。
func selectedAuthIsCodex(authID, authIndex string) (codex, resolved bool) {
	files, errList := cachedAuthCatalog()
	if errList != nil {
		return false, false
	}
	for i := range files {
		if authIndex != "" && files[i].AuthIndex == authIndex {
			return entryIsCodex(files[i]), true
		}
	}
	for i := range files {
		if authID != "" && (files[i].ID == authID || files[i].Name == authID) {
			return entryIsCodex(files[i]), true
		}
	}
	return false, true
}

// entryIsCodex 查单条档案：Provider 有值就一锤定音；文件名像 Codex 也不能冒充。
// 否则 OpenAI 路由 Cookie 会被送进别家厨房。Provider 空才看 Type，两者都空才看文件名。
// 它比 isCodexAuth 的“任一线索命中”更严：那位负责面板点名，这位负责凭据守门。
func entryIsCodex(file pluginapi.HostAuthFileEntry) bool {
	if provider := strings.ToLower(strings.TrimSpace(file.Provider)); provider != "" {
		return provider == "codex"
	}
	if kind := strings.ToLower(strings.TrimSpace(file.Type)); kind != "" {
		return kind == "codex"
	}
	return looksCodexAuthID(file.Name) || looksCodexAuthID(file.ID)
}
