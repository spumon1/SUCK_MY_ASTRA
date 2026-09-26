// Package main 是 CLIProxyAPI 原生插件：在池模式回放上游发的 __cflb/__oailb，给官方 Codex 流量带位。
// 2026-09-22 实测见 FINDINGS.md：上游有 chat.gateway.unified-N.api.openai.com 等节点，
// 路由 pair 与账号无关，带着健康节点的活 pair 可正常服务；这条池路径单靠 Cookie，不用旧 turn-state 替换。
// 池模式做三件事：收 Set-Cookie pair 进全局池；给可归属请求合并最佳活 pair；
// 按账号模型观察上游正常、降级及桶学习的签名，给反复降级的 pair 降低座次。
// 离线探测用可用凭据访问配置出口，收更多节点的 pair；默认关闭，手动 /ops/probe/start 才开工。
// 额外流量有账号风险，所以先捡已有响应，不擅自替客人点菜。
// 引导只对可确认的 Codex 账号：selected_auth_id 或唯一启用凭据；认不清就不动，免得 OpenAI Cookie 串桌到别家。
// 只回放 __cflb/__oailb，设备与会话 Cookie 在采集时过滤。pair 自最近见到起受 ttl_seconds（默认 3900）约束，
// 有 __oailb JWT exp 取它，否则用 Max-Age/Expires 再限期；Cookie 值是凭据，绝不写日志。
// business 负责附 Cookie，probe 请求原样，两角色都采集观察。云端票注入是独立分支，详见 cloud_mint_service.go。
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

// cliproxy_invoke_host calls back into the host. The host owns the response
// buffer, so every non-NULL ptr it hands back must go to cliproxy_release_host.
static int cliproxy_invoke_host(const cliproxy_host_api* host, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (host == NULL || host->call == NULL) {
		return 1;
	}
	return host->call(host->host_ctx, method, request, request_len, response);
}

static void cliproxy_release_host(const cliproxy_host_api* host, void* ptr, size_t len) {
	if (host == NULL || host->free_buffer == NULL || ptr == NULL) {
		return;
	}
	host->free_buffer(ptr, len);
}

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// turnStateHeader 给观察器读取响应签名长度；池路径不改它。
// 云端模式另有注入分支，不能把观察员“不写字”误当整个插件永不动笔。
const turnStateHeader = "X-Codex-Turn-State"

// selectedAuthMetadataKey 内联 cliproxyexecutor.SelectedAuthMetadataKey，免得为借一个门牌把 executor 整栋楼搬来。
const selectedAuthMetadataKey = "selected_auth_id"

// selectedAuthIndexMetadataKey 对齐 cliproxyexecutor.SelectedAuthIndexMetadataKey，与 id 一起发布。
// index 能跨凭据改名保持稳定，演员改艺名也别认丢身份证。
const selectedAuthIndexMetadataKey = "selected_auth_index"

const logPrefix = "[codex-turn-state] "

// 两种角色每个配置代次选其一；改 config.yaml 后由宿主 reconfigure 换班，不在半场随手换帽子。
const (
	roleProbe    = "probe"
	roleBusiness = "business"
)

// runtimeOverrideFileName 在 store 目录保存面板无 key 可改的 role、dry_run，每次 configure 叠到配置之上。
// 角色切换需重启协商能力，没有这本便条，CPA 一重启就把操作者刚选的角色和 dry_run 当没听见。
// 只有角色字符串和布尔值，不放秘密，公开便条也不等于公开钥匙。
const runtimeOverrideFileName = "runtime.json"

var state = pluginState{
	config:  defaultConfig(),
	cookies: make(map[string]*routeCookieEntry),
}

// hostAPI 保存 init 收到的 *C.cliproxy_host_api，供管理处理器回调宿主。
// 只在初始化写一次，goroutine 会读，用 atomic 传递这张总机号码。
var hostAPI unsafe.Pointer

// hostAPIAvailable 单独查宿主有无回调表，不能只等 hostCall 失败。
// “根本没电话”和“对方没接”不同，别让装载问题把操作者赶去修网线。
func hostAPIAvailable() bool {
	return atomic.LoadPointer(&hostAPI) != nil
}

// hostCall 调宿主回调并回原始 RPC 信封。API 为 nil 是装载方没交回调表的配置问题，
// 不是上游请求空手而归；需要它的管理路由会明说，不装作电话已拨通。
func hostCall(method string, request []byte) ([]byte, error) {
	raw := atomic.LoadPointer(&hostAPI)
	if raw == nil {
		return nil, fmt.Errorf("host API unavailable: this plugin was initialised without one")
	}
	host := (*C.cliproxy_host_api)(raw)

	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var requestPtr *C.uint8_t
	if len(request) > 0 {
		requestPtr = (*C.uint8_t)(unsafe.Pointer(&request[0]))
	}

	var response C.cliproxy_buffer
	rc := C.cliproxy_invoke_host(host, cMethod, requestPtr, C.size_t(len(request)), &response)
	// 把 Go request 内存借给 C 到调用结束，宿主返回前会复制；中途不能让 GC 把椅子抽走。
	runtime.KeepAlive(request)

	if response.ptr != nil {
		defer C.cliproxy_release_host(host, response.ptr, response.len)
	}
	if rc != 0 {
		return nil, fmt.Errorf("host call %s failed with code %d", method, int(rc))
	}
	if response.ptr == nil || response.len == 0 {
		return nil, nil
	}
	return C.GoBytes(response.ptr, C.int(response.len)), nil
}

// decisionCounters 给管理状态页记操作次数，只记结果，不把 Cookie 值写成菜单。
type decisionCounters struct {
	// Harvest 数真正给池添了 pair 的响应，空手路过不记进货。
	Harvest int64 `json:"harvest"`
	// Steer 数确实带着池 pair 出门的请求，心里想带不算带。
	Steer int64 `json:"steer"`
	Pass  int64 `json:"pass"`
	Skip  int64 `json:"skip"`
}

type pluginState struct {
	mu     sync.Mutex
	config pluginConfig
	// cookies 是以 cookieEntryKey 为键的全局活 pair 池，不按账号分包间。
	// 响应钩子和探测写入，请求钩子挑最佳可用项；pair 与账号无关，一池共用。
	cookies map[string]*routeCookieEntry
	// cookiesDirty 记未落盘修改，最多每 routeCookieFlushInterval 写一次，关闭再补一笔，别每夹一筷就报账。
	cookiesDirty   bool
	cookiesFlushed time.Time
	// counts 与 countsAt 给状态页供数；角色换了导致口径失效就清零，不把前班业绩塞后班口袋。
	counts   decisionCounters
	countsAt time.Time
	// configErrors 收探测范围的账号名、模型 ID、代理 URL 错误，不让 configure 因此拒绝注册。
	// 这些字段不是业务引导的承重柱，探测菜单写错不能逼营业厅停业；错误交状态页给操作者看。
	configErrors []string
}

type pluginConfig struct {
	CloudMint cloudMintConfig `yaml:"cloud_mint"`
	// Role 只取 probe 或 business，空值按 business，也就是正常引导请求的角色。
	// probe 留给只采集不动请求的进程，坐观众席就别抢导演喇叭。
	Role string `yaml:"role"`
	// StoreDir 收池文件及 runtime.json、probe-scope.json、observations.json，插件自己的账本归自己柜子。
	StoreDir string `yaml:"store_dir"`
	// TemplateLength、ReplaceLength 是观察分类锚点：统一格式前 292 正常、312 降级。
	// 现在不据此存或替换票，也不当死白名单；noteSignedLen 学重复未知长度为本桶正常，
	// 避免 292 -> 780 换制服后健康流量一直被当生面孔。
	TemplateLength int `yaml:"template_length"`
	ReplaceLength  int `yaml:"replace_length"`
	// TTLSeconds 从 pair 最近见到时刻限寿，再受 JWT exp 或无 claim 时的 Max-Age/Expires 约束，不给旧票续神仙命。
	TTLSeconds int `yaml:"ttl_seconds"`
	// DryRun 只记决策，不改出站 Cookie 头，排练不真搬客人的椅子。
	DryRun bool `yaml:"dry_run"`
	// LogDecisions 给每次引导或采集决策记一行，账本可以热闹，凭据不能露面。
	LogDecisions bool `yaml:"log_decisions"`
	// Models 是面板可选模型和探测铸票载荷所用列表，不再是 pair 采集维度。
	// pair 与账号无关，按模型重复采同类路由凭据，就像给同一把椅子发几张合影。
	Models []string `yaml:"models"`
	// ProbeAccounts 限定探测可借的凭据及顺序，一个能用的足够全轮。
	// pair 不绑铸它的账号，这是借钥匙顺序，不是挨家挨户盖章清单。
	ProbeAccounts []string `yaml:"probe_accounts"`
	// MintAccounts 缩小后台灌池借用账号范围，非空仅取也在 ProbeAccounts 里的名字。
	// 空则兼容回退全 ProbeAccounts；铸出的 __cflb/__oailb 仍全账号共享，
	// 谁负责打水和谁可以喝水是两回事，不给桶贴私人姓氏。
	MintAccounts []string `yaml:"mint_accounts"`
	// ProbeProxies 按序列出探测出口，多出口用于覆盖更多网关 pair。
	// URL 可能有 userinfo，日志和错误一律经 maskProxyURL；状态文档按操作者明确要求明文展示，
	// 详见 statusResponse，但面板开了灯不代表日志能把钥匙挂街上。
	ProbeProxies []string `yaml:"probe_proxies"`
	// ProbeProxiesRotating 装每次连接换地址的住宅网关，与静态出口分两份账。
	// 静态项代表一个 IP，一次访问收一个节点；轮换项每次尝试可能换节点，所以每次访问用完整尝试预算，
	// 不是只打一枪。日志同样脱敏，状态文档按操作者要求明文展示；两种车不能按同一油耗算路。
	ProbeProxiesRotating []string `yaml:"probe_proxies_rotating"`
	// 下面两字段让面板无需每次输入 key 就能跑探测。探测管理调用需要 bearer，
	// 把它放配置并只给 runner 读取，比让用户在匿名可读页面敲秘密更合适。
	// ProbeManagementKey 用于 /v0/management/* 的列账号、下载 token 两个只读调用。
	// 它比代理列表更严格：日志只说 set/unset，不进 statusResponse 或 configResponse，
	// 连掩码展示都不提供，因为无人需要看钥匙长什么样。
	ProbeManagementKey string `yaml:"probe_management_key"`
	// ProbeBaseURL 是这两个管理调用的目的地，默认 CPA 自身回环监听；插件问宿主家事，不绕城找邻居。
	ProbeBaseURL string `yaml:"probe_base_url"`
}

// fillAccounts 有 MintAccounts 就取经 ProbeAccounts 验证的子集，否则全选 ProbeAccounts。
// 限定谁铸票不限定谁复用 Cookie，一人打水仍可全桌喝茶。
func (c pluginConfig) fillAccounts() []string {
	if len(c.MintAccounts) == 0 {
		return c.ProbeAccounts
	}
	allowed := make(map[string]bool, len(c.ProbeAccounts))
	for _, a := range c.ProbeAccounts {
		allowed[a] = true
	}
	out := make([]string, 0, len(c.MintAccounts))
	seen := map[string]bool{}
	for _, a := range c.MintAccounts {
		if allowed[a] && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	// 全部指定项无效则回退全量，避免误配把灌池水泵整个拔电。
	if len(out) == 0 {
		return c.ProbeAccounts
	}
	return out
}

// defaultProbeBaseURL 默认 CPA 自身回环监听，常见部署就是插件问承载自己的进程，不必每次填写自家门牌。
const defaultProbeBaseURL = "http://127.0.0.1:8317"

func defaultConfig() pluginConfig {
	return pluginConfig{
		CloudMint:      defaultCloudMintConfig(),
		Role:           "",
		StoreDir:       "",
		TemplateLength: 292,
		ReplaceLength:  312,
		// 2026-09-22 实测 __oailb 的 exp-iat=3900，这是网关执行的期限。
		// Max-Age/Expires 只写 3600，观察过越过属性期限仍服务；默认跟凭据 exp，不让包装纸抢证件的话筒。
		TTLSeconds:   3900,
		DryRun:       false,
		LogDecisions: true,
		ProbeBaseURL: defaultProbeBaseURL,
	}
}

// isProbe 判断当前是不是只采集不改请求的角色，先认工牌再拿工具。
func (c pluginConfig) isProbe() bool {
	return strings.EqualFold(strings.TrimSpace(c.Role), roleProbe)
}

// ttl 把配置池寿命换成 duration，日历换钟表，不替凭据加寿。
func (c pluginConfig) ttl() time.Duration {
	return time.Duration(c.TTLSeconds) * time.Second
}

// maskProxyURL 让代理 URL 能安全进日志或匿名视图，userinfo 整段替换。
// 不露密码长度、不留头两字，那些都可能是线索，蒙面就别只遮一只眼。
// 解析不了回固定占位符，绝不回显原输入；坏 URL 很可能恰是密码打错字符，不能越坏越裸奔。
func maskProxyURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse != nil || parsed.Host == "" {
		return "<unparsable proxy url>"
	}
	if parsed.User == nil {
		return parsed.String()
	}
	// 手动拼掩码，不用 url.User("***")，因为 URL.String 会编码成 %2A%2A%2A。
	// 安全仍要可读，操作者在辨出口，别给他发乱码字谜。
	stripped := *parsed
	stripped.User = nil
	out := stripped.String()
	marker := parsed.Scheme + "://"
	if !strings.HasPrefix(out, marker) {
		// opaque 或陌生形状直接拒绝，乱拼可能留下原凭据残片；看不懂的锁不拿锤子假装修好。
		return "<unparsable proxy url>"
	}
	return marker + "***@" + out[len(marker):]
}

// secretPresence 只准说 set 或 unset，供 probe_management_key 日志使用。
// 不报长度、不露前缀，操作者只需知道配没配钥匙，不需要鉴赏钥匙齿。
func secretPresence(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unset"
	}
	return "set"
}

// maskProxyURLs 整列脱敏但不换顺序，让遮脸的出口还能按座号认出。
func maskProxyURLs(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		out = append(out, maskProxyURL(value))
	}
	return out
}

// proxySchemes 只列 CPA 真能拨的协议；别让协议拼错拖到探测深处才扮成上游拒客。
var proxySchemes = map[string]bool{"http": true, "https": true, "socks5": true, "socks5h": true}

// normaliseProbeScope 裁空白、验范围列表，返回干净条目和每个拒收项的可读原因。
// 坏项确实剔除，但必须解释，不能让探测“跑完”却偷偷少了操作者以为会覆盖的半张菜单。
func normaliseProbeScope(accounts, models, proxies, rotating []string) ([]string, []string, []string, []string, []string) {
	var problems []string

	cleanAccounts := make([]string, 0, len(accounts))
	for _, raw := range accounts {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		// 这里只验名字形状，不查文件存在；configure 时宿主凭据未必加载齐，别在演员还化妆时宣布缺席。
		if !strings.HasPrefix(strings.ToLower(name), "codex-") || !strings.HasSuffix(strings.ToLower(name), ".json") {
			problems = append(problems, fmt.Sprintf("probe_accounts: %q is not a Codex credential filename (expected codex-*.json)", name))
			continue
		}
		if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			problems = append(problems, fmt.Sprintf("probe_accounts: %q contains a path component", name))
			continue
		}
		cleanAccounts = append(cleanAccounts, name)
	}

	cleanModels := make([]string, 0, len(models))
	for _, raw := range models {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, " \t\r\n") {
			problems = append(problems, fmt.Sprintf("models: %q contains whitespace", name))
			continue
		}
		cleanModels = append(cleanModels, name)
	}

	cleanProxies, proxyProblems := normaliseProxyList(proxies, "probe_proxies")
	problems = append(problems, proxyProblems...)
	cleanRotating, rotatingProblems := normaliseProxyList(rotating, "probe_proxies_rotating")
	problems = append(problems, rotatingProblems...)

	return cleanAccounts, cleanModels, cleanProxies, cleanRotating, problems
}

// normaliseProxyList 让静态、轮换两池共用有效性规则，差别只在探测如何花尝试预算。
// field 写进每条错误，面前有两个输入框时，只喊“协议错了”像对整条街喊“你鞋带松了”。
func normaliseProxyList(proxies []string, field string) ([]string, []string) {
	var problems []string
	clean := make([]string, 0, len(proxies))
	for index, raw := range proxies {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		parsed, errParse := url.Parse(candidate)
		switch {
		case errParse != nil || parsed.Host == "":
			// 错误只报列表序号不报值；越解析不了越可能带错写密码，报座号足够找人，不用当街脱面罩。
			problems = append(problems, fmt.Sprintf("%s[%d]: not a valid URL", field, index))
			continue
		case !proxySchemes[strings.ToLower(parsed.Scheme)]:
			problems = append(problems, fmt.Sprintf("%s: unsupported scheme %q in %s (want http, https, socks5 or socks5h)", field, parsed.Scheme, maskProxyURL(candidate)))
			continue
		}
		clean = append(clean, candidate)
	}
	return clean, problems
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registerRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

// registrationCapability 对齐宿主 rpcCapabilities JSON。
// 流式钩子必须叫 response_stream_interceptor，不是 Go 接口名；门铃按错，宿主会安静得像没住人。
type registrationCapability struct {
	RequestInterceptor        bool `json:"request_interceptor"`
	ResponseInterceptor       bool `json:"response_interceptor"`
	StreamChunkInterceptor    bool `json:"response_stream_interceptor"`
	WebSocketResponseObserver bool `json:"websocket_response_observer"`
	ManagementAPI             bool `json:"management_api"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	// hostAPI 供管理侧调用 host.auth.list、host.model.execute，初始化最先交一次，插件存活期间内存由宿主持有。
	if host != nil {
		atomic.StorePointer(&hostAPI, unsafe.Pointer(host))
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	cloudPoolFillerStop()
	currentCloudMintService().close()
	// 关闭落盘只是尽力，docker kill 不会调用这里，实际丢账窗口仍是 observationsFlushInterval 和 routeCookieFlushInterval。
	// flushObservationsNow 取另一把锁，必须在 state.mu 前调用，别让两把门锁互相等钥匙。
	flushObservationsNow()

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.cookiesDirty && state.config.StoreDir != "" {
		if err := writeRouteCookiePool(state.config.StoreDir, state.cookies, time.Now(), state.config.ttl()); err != nil {
			log.Printf(logPrefix+"pool flush on shutdown failed: %v", err)
		}
	}
	state.cookies = make(map[string]*routeCookieEntry)
	state.cookiesDirty = false
	state.cookiesFlushed = time.Time{}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodRequestInterceptBefore:
		// 宿主还没选认证，桶名无从得知；此处绝不碰头，客人没到不能先给他换座位牌。
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	case pluginabi.MethodRequestInterceptAfter:
		return interceptAfterAuth(request)
	case pluginabi.MethodResponseInterceptAfter:
		return interceptResponse(request)
	case pluginabi.MethodResponseInterceptStreamChunk:
		return interceptStreamChunk(request)
	case pluginabi.MethodWebSocketResponseEvent:
		return observeWebSocketEvent(request)
	case pluginabi.MethodManagementRegister:
		return managementRegister(request)
	case pluginabi.MethodManagementHandle:
		return managementHandle(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req registerRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	if req.SchemaVersion < 2 {
		return fmt.Errorf("codex-turn-state requires host schema version 2 or newer")
	}
	cfg := defaultConfig()
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return errUnmarshal
		}
	}

	if err := cfg.CloudMint.validate(); err != nil {
		return err
	}

	// 把面板持久化的 role、dry_run 叠在配置值上，角色切换所需 CPA 重启也不会丢选择。
	// 只覆盖操作者真写过的字段，其余保留 config.yaml；后续角色与 store_dir 校验检查合并结果，
	// 便条能改菜单，不能绕过厨房验收。
	if ov, okOverride := readRuntimeOverride(strings.TrimSpace(cfg.StoreDir)); okOverride {
		if ov.Role != nil {
			cfg.Role = *ov.Role
		}
		if ov.DryRun != nil {
			cfg.DryRun = *ov.DryRun
		}
	}

	// 角色为空先按 business，兼容先装 .so 后补 config.yaml 的部署窗口，不把装修未完误报成房子塌了。
	role := strings.ToLower(strings.TrimSpace(cfg.Role))
	switch role {
	case "":
		role = roleBusiness
	case roleProbe, roleBusiness:
	default:
		return fmt.Errorf("role must be %q or %q, got %q", roleProbe, roleBusiness, cfg.Role)
	}
	cfg.Role = role
	cfg.StoreDir = strings.TrimSpace(cfg.StoreDir)
	// 去掉意外空白和尾换行，免得它们混入 bearer 造成 401；钥匙上粘纸屑不是锁坏了。
	cfg.ProbeManagementKey = strings.TrimSpace(cfg.ProbeManagementKey)
	// probe_base_url 显式空串也回默认，与缺省保持一致。
	// 别让“没写门牌”和“写了空门牌”走两条路，最后才在探测里报运输错误。
	if cfg.ProbeBaseURL = strings.TrimSpace(cfg.ProbeBaseURL); cfg.ProbeBaseURL == "" {
		cfg.ProbeBaseURL = defaultProbeBaseURL
	}

	if cfg.TemplateLength < 1 {
		return fmt.Errorf("template_length must be greater than zero")
	}
	if cfg.ReplaceLength < 1 {
		return fmt.Errorf("replace_length must be greater than zero")
	}
	if cfg.TemplateLength == cfg.ReplaceLength {
		return fmt.Errorf("template_length and replace_length must differ, both are %d", cfg.TemplateLength)
	}
	if cfg.TTLSeconds < 1 {
		return fmt.Errorf("ttl_seconds must be greater than zero")
	}
	// 探测没地方落盘就直说配置错；默默收一堆又丢光，比开门前说明没仓库更糟。
	if cfg.isProbe() && cfg.StoreDir == "" {
		return fmt.Errorf("role %q requires store_dir", roleProbe)
	}

	// 探测范围照验但不致命，笔误上状态页；业务替换不靠这些列表，不能让隔壁菜单写错就封全店。
	var scopeProblems []string
	cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies, cfg.ProbeProxiesRotating, scopeProblems =
		normaliseProbeScope(cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies, cfg.ProbeProxiesRotating)

	// 已保存 scope 直接覆盖 config.yaml，面板现在是编辑入口；否则保存后又因宿主重写配置而悄悄反悔。
	// 尚未保存时仍用 config.yaml 起始值，第一次开张用旧菜单，之后尊重掌柜的新批示。
	scopeSource := "config.yaml"
	if saved, errScope := loadProbeScope(cfg.StoreDir); errScope != nil {
		scopeProblems = append(scopeProblems,
			"probe scope file unreadable, falling back to config.yaml: "+errScope.Error())
	} else if saved != nil {
		var savedProblems []string
		cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies, cfg.ProbeProxiesRotating, savedProblems =
			normaliseProbeScope(saved.Accounts, saved.Models, saved.Proxies, saved.Rotating)
		cfg.MintAccounts = saved.MintAccounts
		scopeProblems = append(scopeProblems, savedProblems...)
		scopeSource = scopeFileName + " (saved " + saved.UpdatedAt + ")"
	}

	state.mu.Lock()
	// 宿主 reconfigure 很频繁，启动就可调用五次，自己重写 config.yaml 又会触发。
	// swapConfigLocked 只在真失效时清池，空操作不拆家具；再读持久池并幂等并入旧桶 Cookie，廉价扫描保暖场。
	cloudChanged := state.config.CloudMint != cfg.CloudMint || state.config.DryRun != cfg.DryRun || state.config.Role != cfg.Role
	cleared, _ := swapConfigLocked(cfg)
	state.cookies = loadRouteCookiePool(cfg.StoreDir)
	state.cookiesDirty = false
	state.cookiesFlushed = time.Time{}
	state.configErrors = scopeProblems
	state.mu.Unlock()
	if cloudChanged {
		resetCloudMintService()
		cloudPoolFillerReconfigure(cfg)
	}

	// loadObservations 必须在 state.mu 外，因为它取自己的锁；store_dir 没变就不动计数，不因频繁重配反复擦账。
	loadObservations(cfg.StoreDir)

	pool := "pool kept"
	if cleared {
		pool = "pool cleared"
	}
	// 日志只报代理数量不报内容，userinfo 不能随着工单或聊天扩散，即便状态文档按要求展示也一样。
	// 探测 key 更只报 set/unset；probe_base_url 非秘密可打印，定位“到不了 CPA”还得看门牌。
	log.Printf(logPrefix+"configured role=%s store_dir=%q template_length=%d replace_length=%d ttl_seconds=%d dry_run=%t models=%d probe_accounts=%d probe_proxies=%d probe_proxies_rotating=%d probe_base_url=%q probe_management_key=%s scope_from=%s (%s)",
		cfg.Role, cfg.StoreDir, cfg.TemplateLength, cfg.ReplaceLength, cfg.TTLSeconds, cfg.DryRun,
		len(cfg.Models), len(cfg.ProbeAccounts), len(cfg.ProbeProxies), len(cfg.ProbeProxiesRotating), cfg.ProbeBaseURL,
		secretPresence(cfg.ProbeManagementKey), scopeSource, pool)
	for _, problem := range scopeProblems {
		// 拒收范围项逐条醒目报告，否则下一轮少跑了半条街，操作者还以为全城走完。
		log.Printf(logPrefix+"config error (probe scope, not fatal): %s", problem)
	}
	return nil
}

// poolInvalidatedBy 判断配置切换是否需换池。pair 自身为键，主要是 store_dir 换了才代表另一家仓库。
// ttl_seconds 不触发清池，每次读都按当前 TTL 重算；seenAt 不改，不拿配置调整伪造新出厂日期。
func poolInvalidatedBy(oldCfg, newCfg pluginConfig) bool {
	return oldCfg.StoreDir != newCfg.StoreDir
}

// swapConfigLocked 安装运行配置并更新派生状态，调用方持 state.mu。
// 回报是否清池、是否换角色，方便记日志，交班不能只换帽子不签账。
func swapConfigLocked(cfg pluginConfig) (cleared, roleChanged bool) {
	cleared = poolInvalidatedBy(state.config, cfg)
	roleChanged = !strings.EqualFold(state.config.Role, cfg.Role)
	state.config = cfg
	if cleared {
		state.cookies = make(map[string]*routeCookieEntry)
		state.cookiesDirty = false
		state.cookiesFlushed = time.Time{}
	}
	// probe 不引导，两角色决策构成不同；换角色清计数，别把上一班的炒菜量算成这一班洗碗量。
	if roleChanged {
		state.counts = decisionCounters{}
		state.countsAt = time.Now()
	}
	return cleared, roleChanged
}

func pluginRegistration() registration {
	// 两角色都声明所有钩子和管理路由。早先只有 probe 采集响应，是怕替换污染采集；
	// 如今离线探测直连上游，不走这些钩子，再禁业务采集只会白丢空桶请求自然带回的状态和 Cookie。
	// 读现有响应不额外花额度；有活 pair 后引导让边缘不再发新 pair，自然安静到过期，见 harvestFromResponse。
	// probe 的请求钩子仍声明但不动作，让日志可证明没改请求；管理页两边都有，换班后才有地方核对工牌。
	capabilities := registrationCapability{
		RequestInterceptor:        true,
		ManagementAPI:             true,
		ResponseInterceptor:       true,
		StreamChunkInterceptor:    true,
		WebSocketResponseObserver: true,
	}

	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "Codex Cloud Mint",
			Version:          "0.3.3-ws-chain",
			Author:           "arden-aaai",
			GitHubRepository: "https://github.com/arden-aaai/cpa-plugin-codex-turn-state",
			ConfigFields: []pluginapi.ConfigField{

				{
					Name:        "role",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{roleProbe, roleBusiness},
					Description: "Whether this process rewrites requests. \"business\" merges the pool's best live __cflb/__oailb pair into attributable Codex requests; \"probe\" leaves every request exactly as it found it. Empty means business. Both roles collect pairs and observe serving states off upstream responses -- role does not switch that off.",
				},
				{
					Name:        "store_dir",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Directory holding the route-cookie pool file (route-cookies.json) and the other plugin-owned documents (runtime.json, probe-scope.json, observations.json). Required for role=probe.",
				},
				{
					Name:        "template_length",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Turn-state length classifying a NORMAL serving state (default 292). An anchor, not a whitelist: each bucket learns its own recurring signature. Observation only -- nothing is stored or substituted off it.",
				},
				{
					Name:        "replace_length",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Turn-state length classifying a DEGRADED serving state (default 312). Observation only -- nothing is stored or substituted off it.",
				},
				{
					Name:        "ttl_seconds",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "How long a pooled __cflb/__oailb pair stays usable, measured from when it was last seen and shortened by the pair's own declared deadline (default 3600, matching the upstream's declared one-hour Max-Age/Expires).",
				},
				{
					Name:        "dry_run",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Log decisions without rewriting the outgoing Cookie header.",
				},
				{
					Name:        "log_decisions",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Emit one log line per harvest or steer decision.",
				},
				{
					Name:        "models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Official model ids the probe uses for its minting payload. Recorded so the running config and the probe script cannot drift apart; the pair itself is model-agnostic.",
				},
				{
					Name:        "probe_accounts",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Credential filenames the probe run may borrow. PROBE SCOPE ONLY: the business path never reads this, and one usable credential is enough -- a minted pair is not bound to the account that minted it.",
				},
				{
					Name:        "probe_proxies",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Ordered exits the probe tries per bucket, applied to the probed account's own proxy_url. PROBE SCOPE ONLY; never read by the business path. May contain credentials, so it is masked in every log line; the status document shows it in the clear at the operator's explicit request.",
				},
				{
					Name:        "probe_proxies_rotating",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Exits whose address changes on every connection (a residential gateway). PROBE SCOPE ONLY; never read by the business path. Separate from probe_proxies because a rotating entry is re-dialed on a 312 -- the next request is a different address -- while a static one is not. Masked in every log line.",
				},
				{
					Name:        "probe_management_key",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Bearer the probe runner sends to /v0/management/*, for the two read-only calls that list the accounts and download one token. PROBE SCOPE ONLY; never read by the business path. It exists so the dashboard needs no key from the operator, and it is NEVER displayed anywhere, masked or otherwise -- not on the status page, not in the config response, not in a log line (which reports only set/unset).",
				},
				{
					Name:        "probe_base_url",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Where the probe runner sends the above (default http://127.0.0.1:8317, CPA's own loopback listener). PROBE SCOPE ONLY; never read by the business path. Not a secret.",
				},
				{
					Name:        "cloud_mint",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "云端打票（默认关闭）：enabled/url/proxy_url/proxy_env/key_env/transport/gateway/ticket_length/ttl_seconds/wait_ms/timeout_ms。密钥只从环境变量读取；冷启动短等待，未就绪返回 503。",
				},
			},
		},
		Capabilities: capabilities,
	}
}

// interceptAfterAuth 在调度器选好凭据后执行，此时桶键两半都有了，演员到齐再排座。
func interceptAfterAuth(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// probe 必须让请求原样走；提前附池 pair 会钉住已知节点，反而收不到它来探的新 pair，钓鱼别先把池盖上。
	if cfg.isProbe() {
		return noop()
	}

	authID := metadataString(req.Metadata, selectedAuthMetadataKey)
	authIndex := metadataString(req.Metadata, selectedAuthIndexMetadataKey)
	model := pickModel(req.Model, req.RequestedModel)
	value := headerValue(req.Headers, turnStateHeader)

	// 请求与响应钩子收到不同 metadata map，只能在此把实际选中账号传给响应侧。
	// 在所有决策之前记录，哪怕请求最终原样放行，因为这类响应最可能带值得收的新状态与 pair。
	// 只转交观察到的名字，不转交推断，猜到的亲戚不能给另一位记账员盖成亲属证明。
	rememberRequestAuth(req.RequestID, authID)
	if cfg.CloudMint.Enabled {
		return okEnvelope(interceptCloudMint(req, cfg))
	}

	// 空 metadata 请求缺 selected_auth_id：publishSelectedAuthMetadata 遇空 map 早返，见 conductor_execution.go:1726。
	// 真实 Codex 常带会话元数据，但单账号的无元数据请求也不能永远不引导。
	// 仅恰有一个启用 Codex 才推断；离线探测不再切账号开关，唯一性是部署现状，必须每次重查。
	// 零个或多个都留空并原样放行，别闭眼把 OpenAI Cookie 塞进别家提供商口袋。
	if authID == "" && model != "" {
		if sole, _, errSole := soleEnabledCodexAuth(); errSole == nil && sole != "" {
			authID = sole
		}
	}

	// 第一道门：仅引导可归属 Codex 流量，OpenAI 路由凭据不能泄到别家上游。
	// 宿主目录必须验证选中账号，唯一账号推断也要同验，不是独苗就免试。
	// 只有目录整体不可读才用 looksCodexAuthID 命名兜底；目录有答复就以 Provider 为准，外号不能冒充身份证。
	codex := false
	if authID != "" || authIndex != "" {
		if verified, resolved := selectedAuthIsCodex(authID, authIndex); resolved {
			codex = verified
		} else {
			codex = looksCodexAuthID(authID)
		}
	}
	if !codex {
		if value != "" || authID != "" {
			logDecision("skip", authID, model, len(value), "request not attributable to a Codex account")
		}
		return noop()
	}
	cloudRememberRequest(req, pluginapi.RequestInterceptResponse{})

	now := time.Now()
	state.mu.Lock()
	set, pairKey, haveCookies := state.bestRouteCookieLocked(now, cfg.ttl())
	state.mu.Unlock()
	if !haveCookies {
		logDecision("pass", authID, model, len(value), "no live route-cookie pair in the pool")
		return noop()
	}

	current := headerValue(req.Headers, "Cookie")
	merged := mergeRouteCookies(current, set.pairs)
	if merged == current {
		logDecision("pass", authID, model, len(value), "route cookies already current")
		return noop()
	}

	if cfg.DryRun {
		logDecision("steer", authID, model, len(value), "route cookies ready but withheld (dry_run)")
		return noop()
	}
	// 传实际使用的池键给响应侧，别到那时重新挑“最佳”；成绩变化后可能换了人，奖罚必须认原座号。
	markRequestSteered(req.RequestID, pairKey)
	logDecision("steer", authID, model, len(value), "route cookies merged")

	out := pluginapi.RequestInterceptResponse{}
	out.ClearHeaders = append(out.ClearHeaders, "Cookie")
	out.Headers = http.Header{}
	out.Headers.Set("Cookie", merged)
	cloudRememberRequest(req, out)
	return okEnvelope(out)
}

// interceptResponse 是非流式就地采集点，两角色都运行，返回空 ResponseInterceptResponse 使头和 body 原样。
// CPA 先给原始上游头，之后 downstreamHeadersAfterInterceptors 才剥给客户端的头；
// 因此这里能看 turn-state，即便客户端看不到，后台验票员和观众看的是不同票面。
func interceptResponse(raw []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if cloudHasRequestLog(req.RequestID) || headerValue(req.ResponseHeaders, turnStateHeader) != "" {
		cloudLogResponse(req.RequestID, req.ResponseHeaders, "")
		cloudLogResponseBody(req.RequestID, req.Body)
	}
	harvestFromResponse(cfg, req.ResponseHeaders, req.Metadata, pickModel(req.Model, req.RequestedModel), req.RequestID)
	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

// interceptStreamChunk 负责真实 Codex 常走的 SSE 采集；响应头只在 header-init 有。
// 随后仅廉价查流中第一个 model，统一格式下与请求模型不符是降级信号；其余片段原样不多看。
// 每请求在 header-init 设一次观察，得结论就结束，平时每片只查 map。
// 两角色都运行，初始化时 CPA 带原始头与请求元数据，优先认实际选中账号，不靠看面相猜。
func interceptStreamChunk(raw []byte) ([]byte, error) {
	var req pluginapi.StreamChunkInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	if req.ChunkIndex != pluginapi.StreamChunkHeaderInitIndex {
		cloudLogStreamChunk(req.RequestID, req.Body)
		noteServedModelChunk(req)
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if cloudHasRequestLog(req.RequestID) || headerValue(req.ResponseHeaders, turnStateHeader) != "" {
		cloudLogResponse(req.RequestID, req.ResponseHeaders, "")
	}
	harvestFromResponse(cfg, req.ResponseHeaders, req.Metadata, pickModel(req.Model, req.RequestedModel), req.RequestID)
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

// WS 只记严格解析的 created 声明和终止事件，不逐片刷屏，也不把账号文件名挂字幕上。
func observeWebSocketEvent(raw []byte) ([]byte, error) {
	var event pluginapi.WebSocketResponseEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}
	if cloudObserveWSChain(event) {
		return okEnvelope(struct{}{})
	}
	if event.EventType == "error" || event.EventType == "response.failed" {
		cloudRecordLog("WS 异常", "账号 #%s · %s · 请求模型 %s", cloudFingerprint(event.AuthID), event.EventType, cloudSafeLabel(pickModel(event.Model, event.RequestedModel)))
	}
	return okEnvelope(struct{}{})
}

// pendingAuth 跨请求、响应钩子接账号线索：两边名叫 Metadata，却不是同一个 map。
// handlers_interceptors.go:565 传 executor req.Metadata，:595 传 handler opts.Metadata，后者没被写入选中账号。
// 2026-09-18 实测响应侧 auth=-；两钩子却共用 RequestID（:556、:584），据此关联。
// 转交的是 CPA 真选的账号，不是推断；同名信封不代表里面装同一封信。
type pendingAuthEntry struct {
	authID string
	// steered 只在真的把池 pair 写出后置位，不随决策意图抢先置位。
	// dry_run 只排练，算成真动作会把 natural/steered 分账彻底演乱。
	steered bool
	// pairKey 是附加 pair 的 cookieEntryKey，让响应给同一条目写 good_at/bad_at，别把黄牌递隔壁。
	pairKey string
	seenAt  time.Time
}

var pendingAuth = struct {
	mu   sync.Mutex
	byID map[string]pendingAuthEntry
}{byID: make(map[string]pendingAuthEntry)}

const (
	// pendingAuthTTL 给两钩子间留足数分钟流式时间，也回收永无响应的悬账，客人不来不能永远占座。
	pendingAuthTTL = 15 * time.Minute
	// pendingAuthMax 触发扫除，条目短小短命，主要防响应全断后候客厅越挤越满。
	pendingAuthMax = 4096
)

// rememberRequestAuth 每个请求都记录观察到的账号；没观察到也要清同 ID 旧条目，不可直接返回。
// CPA 可能用同 RequestID 重试，第二遍缺 selected_auth_id 时留旧值会把新响应算到第一位账号。
// 宁可缺一次观察，别把甲的限流账单递给乙。
func rememberRequestAuth(requestID, authID string) {
	if requestID == "" {
		return
	}
	now := time.Now()
	pendingAuth.mu.Lock()
	defer pendingAuth.mu.Unlock()
	if authID == "" {
		delete(pendingAuth.byID, requestID)
		return
	}
	if len(pendingAuth.byID) >= pendingAuthMax {
		for key, entry := range pendingAuth.byID {
			if now.Sub(entry.seenAt) > pendingAuthTTL {
				delete(pendingAuth.byID, key)
			}
		}
	}
	// 整项替换并把 steered 归 false；本轮尚未决策，不能拿上轮“真改过”冒充本轮已上菜。
	pendingAuth.byID[requestID] = pendingAuthEntry{authID: authID, seenAt: now}
}

// markRequestSteered 记录真写出的 pair 及池键，和 rememberRequestAuth 分开，因为先知道账号后知道动作。
// 缺条目不算错：推断账号不会被 rememberRequestAuth 当事实登记，因此无项可标。
// 没有可证归属就丢观察，别把猜出的名字写进客户限流账。
func markRequestSteered(requestID, pairKey string) {
	if requestID == "" {
		return
	}
	pendingAuth.mu.Lock()
	defer pendingAuth.mu.Unlock()
	if entry, ok := pendingAuth.byID[requestID]; ok {
		entry.steered = true
		entry.pairKey = pairKey
		pendingAuth.byID[requestID] = entry
	}
}

// recallRequestRecord 取出就忘掉，一请求一响应，不让用过的座号长期占柜。
// 超过 pendingAuthTTL 当不存在，旧戏票不能认作今天入场记录。
func recallRequestRecord(requestID string) (authID string, steered bool, pairKey string) {
	if requestID == "" {
		return "", false, ""
	}
	pendingAuth.mu.Lock()
	defer pendingAuth.mu.Unlock()
	entry, ok := pendingAuth.byID[requestID]
	if !ok {
		return "", false, ""
	}
	delete(pendingAuth.byID, requestID)
	if time.Since(entry.seenAt) > pendingAuthTTL {
		return "", false, ""
	}
	return entry.authID, entry.steered, entry.pairKey
}

// pendingModelScan 把 pendingAuth 的跨钩子关联再延伸到流片段。
// 统一格式各拒绝路径都铸 780，降级改看 SSE 声明模型是否不同，即 x-codex-safety-buffering 回退。
// header-init 时账号、steered、pairKey 齐备就设观察，首个带 model 的片段消费它，不看票长猜演员。
type pendingModelScanEntry struct {
	authID  string
	model   string // 向上游点的模型，点菜单原件
	tsLen   int    // 本响应签的 turn-state 长度，留给播报对账
	steered bool
	pairKey string
	seenAt  time.Time
}

var pendingModelScans = struct {
	mu   sync.Mutex
	byID map[string]pendingModelScanEntry
}{byID: make(map[string]pendingModelScanEntry)}

// pendingModelScanMaxChunk 限扫描深度，response.created 通常首个 SSE 事件。
// 这么多片还没 model 就结束观察，不让报幕员守到散场等一个从未报的名字。
const pendingModelScanMaxChunk = 8

// rememberModelScan 给请求设观察，沿用 pendingAuth 的 TTL 清扫；流没声明就结束的遗留项也有人收桌。
func rememberModelScan(requestID, authID, model string, tsLen int, steered bool, pairKey string) {
	if requestID == "" || authID == "" || model == "" {
		return
	}
	now := time.Now()
	pendingModelScans.mu.Lock()
	defer pendingModelScans.mu.Unlock()
	if len(pendingModelScans.byID) >= pendingAuthMax {
		for key, entry := range pendingModelScans.byID {
			if now.Sub(entry.seenAt) > pendingAuthTTL {
				delete(pendingModelScans.byID, key)
			}
		}
	}
	pendingModelScans.byID[requestID] = pendingModelScanEntry{
		authID: authID, model: model, tsLen: tsLen, steered: steered, pairKey: pairKey, seenAt: now,
	}
}

// recallModelScan 消费观察，一请求只判一次；首个声明模型就是当前答案，不无限复读点名。
func recallModelScan(requestID string) (pendingModelScanEntry, bool) {
	pendingModelScans.mu.Lock()
	defer pendingModelScans.mu.Unlock()
	entry, ok := pendingModelScans.byID[requestID]
	if ok {
		delete(pendingModelScans.byID, requestID)
		if time.Since(entry.seenAt) > pendingAuthTTL {
			return pendingModelScanEntry{}, false
		}
	}
	return entry, ok
}

// dropModelScan 在越过扫描窗口仍无声明时撤哨，不伪造结论，收凳子也不算验票成功。
func dropModelScan(requestID string) {
	pendingModelScans.mu.Lock()
	delete(pendingModelScans.byID, requestID)
	pendingModelScans.mu.Unlock()
}

// noteServedModelChunk 每片只做轻量 map 查询，首个模型提取后结束观察。
// 常规不取 state.mu，免得每条流每片都排引导锁；仅少见不匹配时取一次，黄牌要登记才去柜台。
func noteServedModelChunk(req pluginapi.StreamChunkInterceptRequest) {
	if req.RequestID == "" {
		return
	}
	if req.ChunkIndex > pendingModelScanMaxChunk {
		dropModelScan(req.RequestID)
		return
	}
	served, ok := servedModelFromChunk(req.Body)
	if !ok {
		return
	}
	entry, found := recallModelScan(req.RequestID)
	if !found {
		return
	}
	if served == entry.model {
		// 上游给的正是请求模型，观察使命结束；报对名字就收话筒。
		return
	}
	recordDowngrade(entry.authID, entry.model, served, entry.tsLen, entry.steered)
	logDecision("downgrade", entry.authID, entry.model, entry.tsLen, "served="+served)
	if entry.steered && entry.pairKey != "" {
		// 已引导请求仍降级，说明节点没交所求模型，权重等同旧格式降级签名，座位牌没保住节目。
		state.mu.Lock()
		state.markRouteCookieOutcomeLocked(entry.pairKey, observationLimited, time.Now())
		state.mu.Unlock()
	}
}

// servedModelFromChunk 提取片段首个 model；Codex SSE 的 response.created 首先报模型，所以不用另解析事件名。
// 字段若跨片，两边都会漏；开场约 1 KB 事件里这种情况少，这里不加尾缓冲，别把轻哨兵改成仓管。
func servedModelFromChunk(body []byte) (string, bool) {
	const needle = `"model":"`
	i := bytes.Index(body, []byte(needle))
	if i < 0 {
		return "", false
	}
	rest := body[i+len(needle):]
	j := bytes.IndexByte(rest, '"')
	if j <= 0 {
		return "", false
	}
	return string(rest[:j]), true
}

// harvestFromResponse 喂全局池与观察账，绝不改响应；降级响应也可能带 pair，路过顺手收而不额外发请求。
func harvestFromResponse(cfg pluginConfig, headers http.Header, metadata map[string]any, model, requestID string) {
	value := headerValue(headers, turnStateHeader)
	now := time.Now()
	cookies := routeCookiesFromResponseHeaders(headers, now)

	// 请求侧记录先无条件取一次，读完即消费；后面观察和结果标记共享它，别第二次开空信封。
	relayedAuth, steered, pairKey := recallRequestRecord(requestID)

	authID := metadataString(metadata, selectedAuthMetadataKey)
	if authID == "" {
		// 响应 metadata 不同导致缺账号是常态，用 RequestID 找请求侧实录；仍是 CPA 选中的人，不是现场认亲。
		authID = relayedAuth
	}

	// 账号最后兜底推断只在 probe 角色开放，business 路径不会进这里。
	// 通常 metadata 或 pendingAuth 已交接；只有完全不带元数据、宿主没发布 selected_auth_id 才会到此，
	// 见 conductor_execution.go:1726。当前部署常驻 business，由 /ops/probe/start 开探测，不切角色。
	// 2026-09-20 的 3.3 小时实测 15 桶全为 observed，没有 inferred；别把主要精力押在这条备用小巷。
	// 响应侧推断更弱：cachedCodexAuths 的 2 秒缓存可能仍把刚冷却账号看作启用。
	// 任意已签状态都可用于该兜底，不只配置两长度；套餐变尺寸不能让认人规则突然失明。
	if authID == "" && model != "" && len(value) > 0 && cfg.isProbe() {
		if sole, _, errSole := soleEnabledCodexAuth(); errSole == nil && sole != "" {
			authID = sole
		}
	}

	// 故意在空状态检查前记录：引导后的静默也值得观察，不能把没新签状态的健康桶全写成无人来过。
	recordObservation(cfg, authID, model, len(value), steered)

	// 新见 __cflb/__oailb 直接入全局池，无需桶键；pair 不绑账号，一桌打来的水可供下一桌喝。
	if len(cookies.pairs) > 0 {
		state.mu.Lock()
		state.noteRouteCookiesLocked(cookies, "")
		state.mu.Unlock()
		logDecision("harvest", authID, model, len(value), "route-cookie pair pooled")
	}

	// 把结果记回本请求实际携带的 pair：正常加好评，降级降低下次优先级；也可能是账号问题，所以只黄牌不拆椅子。
	if steered && pairKey != "" {
		kind := classifyObservation(cfg, len(value))
		state.mu.Lock()
		state.markRouteCookieOutcomeLocked(pairKey, kind, now)
		state.mu.Unlock()
	}

	// 给后续片段设 served-model 观察：长度已在 header-init 看过，统一格式降级却在 body；此时账号和引导上下文还齐全。
	rememberModelScan(requestID, authID, model, len(value), steered, pairKey)
}

// runtimeOverride 持久化面板两字段，都用指针区别未写与零值。
// 只写 dry_run 的文件不能顺带主张 role="" 把角色切成 business，没点的菜别替客人下单。
type runtimeOverride struct {
	Role   *string `json:"role,omitempty"`
	DryRun *bool   `json:"dry_run,omitempty"`
}

// readRuntimeOverride 从 dir 读覆盖文件，缺失是新部署常态，ok=false 不吵日志。
// 文件坏了同样退回 config.yaml，不因一张便条破了就拒绝插件注册、整店停业。
func readRuntimeOverride(dir string) (runtimeOverride, bool) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return runtimeOverride{}, false
	}
	data, errRead := os.ReadFile(filepath.Join(dir, runtimeOverrideFileName))
	if errRead != nil {
		return runtimeOverride{}, false
	}
	var ov runtimeOverride
	if errUnmarshal := json.Unmarshal(data, &ov); errUnmarshal != nil {
		log.Printf(logPrefix+"ignoring malformed %s: %v", runtimeOverrideFileName, errUnmarshal)
		return runtimeOverride{}, false
	}
	if ov.Role == nil && ov.DryRun == nil {
		return runtimeOverride{}, false
	}
	return ov, true
}

// writeRuntimeOverride 总把当前 role 与 dry_run 一起快照保存，重启保留；后改角色不能冲掉早先的 dry_run 便条。
func writeRuntimeOverride(dir string, role string, dryRun bool) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty, cannot persist the dashboard override")
	}
	ov := runtimeOverride{Role: &role, DryRun: &dryRun}
	data, errMarshal := json.MarshalIndent(ov, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	return atomicWrite(filepath.Join(dir, runtimeOverrideFileName), append(data, '\n'))
}

// scopeFileName 存面板编辑的探测范围，放插件拥有可写的 store 目录。
// 宿主有 host.auth.save 却没插件配置持久化回调；改用 PATCH /v0/management/plugins/<id>/config 又需要 key。
// 操作者要无 key 面板，所以自管文件，把钥匙需求留在后台，不让柜台每次问客人开锁。
const scopeFileName = "probe-scope.json"

// probeScope 是可编辑的下轮桶范围和出口列表，业务路径不读这份探测行程单。
type probeScope struct {
	Accounts []string `json:"probe_accounts"`
	Models   []string `json:"models"`
	Proxies  []string `json:"probe_proxies"`
	// 分池前的旧文件没有此项，解成 nil 正合适：当时保存的全是静态出口，别替旧账生出新亲戚。
	Rotating []string `json:"probe_proxies_rotating,omitempty"`
	// MintAccounts 限后台灌池借用账号；空或缺失即全部 Accounts，旧文件 nil 也照此，不让老菜单缺栏就断炊。
	MintAccounts []string `json:"mint_accounts,omitempty"`
	UpdatedAt    string   `json:"updated_at"`
}

// loadProbeScope 读已存范围，没有就回 nil；操作者还未保存是正常白纸，不算账本失踪。
func loadProbeScope(dir string) (*probeScope, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	data, errRead := os.ReadFile(filepath.Join(dir, scopeFileName))
	if errRead != nil {
		if os.IsNotExist(errRead) {
			return nil, nil
		}
		return nil, errRead
	}
	var scope probeScope
	if errUnmarshal := json.Unmarshal(data, &scope); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &scope, nil
}

// writeProbeScope 原子持久化范围，文件带代理 userinfo，权限与桶文件同为 0600。
// atomicWrite 经 os.CreateTemp 再 rename，装钥匙的抽屉不能随手敞开。
func writeProbeScope(dir string, scope probeScope) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty, so there is nowhere to save the probe scope")
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	data, errMarshal := json.MarshalIndent(scope, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	return atomicWrite(filepath.Join(dir, scopeFileName), append(data, '\n'))
}

// pickModel 让探测和业务两边认同一个模型名；同一演员两套艺名，观察账就找不到本人。
func pickModel(model, requestedModel string) string {
	if resolved := strings.TrimSpace(model); resolved != "" {
		return resolved
	}
	return strings.TrimSpace(requestedModel)
}

// headerValue 不分大小写找头。经 JSON 往返的键保留宿主拼法，
// http.Header.Get 只会按规范键取，不能要求来客都戴同款帽子才认人。
func headerValue(headers http.Header, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

// looksCodexAuthID 按凭据文件命名看是否像 Codex，是 isCodexAuth 的兜底线索。
// 引导路径只在目录完全不可读时才用；目录能答就听 selectedAuthIsCodex 的 Provider 判断，外号不压过档案。
func looksCodexAuthID(authID string) bool {
	name := strings.ToLower(strings.TrimSpace(authID))
	return strings.HasPrefix(name, "codex-") && strings.HasSuffix(name, ".json")
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// logDecision 只记长度与桶身份，状态值接近凭据秘密，不能给日志当台词素材。
func logDecision(decision, authID, model string, valueLen int, reason string) {
	if decision == "" {
		return
	}
	state.mu.Lock()
	enabled := state.config.LogDecisions
	// log_decisions 关了照样计数；操作者只是让喇叭安静，不是让账房罢工。
	switch decision {
	case "harvest":
		state.counts.Harvest++
	case "steer":
		state.counts.Steer++
	case "pass":
		state.counts.Pass++
	case "skip":
		state.counts.Skip++
	}
	state.mu.Unlock()
	if !enabled {
		return
	}
	log.Printf(logPrefix+"%s auth=%s model=%s len=%d (%s)", decision, orDash(authID), orDash(model), valueLen, reason)
}

func noop() ([]byte, error) {
	return okEnvelope(pluginapi.RequestInterceptResponse{})
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, errMarshal := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	if errMarshal != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"encode error"}}`)
	}
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
