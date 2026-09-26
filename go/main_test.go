package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// 头名与元数据键在这里手写，不向 main.go 借答案；测试守合同，生产改名就该响警铃，不能跟着一起改口。
const (
	testHeader  = "X-Codex-Turn-State"
	testAuthKey = "selected_auth_id"
)

// 纯函数显式收 now，用固定参考时刻当摄影棚的钟；可复现，也不在整点边缘摔跤。
var testNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

const testTTL = time.Hour

// wallClock 用插件真正会看到的时刻；请求路径内部读 time.Now()，给 handleMethod
// 的样本必须跟真实钟走。冻结在未来的时间会被当新鲜票，过期测试就演反了。
// issued_at 经 RFC3339 往返不带亚秒，因此截到秒，别给时钟贴假睫毛。
func wallClock() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// storeDirLine 给临时目录开 store_dir 地址条；probe 没地方落脚就拒绝开工。
func storeDirLine(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("store_dir: %q\n", t.TempDir())
}

// tokenByteLen 按 FINDINGS.md 实测把 X-Codex-Turn-State 的 base64 身高换成字节体重：
// 292→217，312→233，正差一个 16 字节 AES-CBC 块。780→585（33 块），
// 这是 2026-09-22 上游统一格式，七个模型量过尺，不凭目测裁戏服。
var tokenByteLen = map[int]int{292: 217, 312: 233, 780: 585}

// fakeToken 造恰好 n 个 base64 字符的 Fernet 道具票，内嵌 issued 时刻。
// 全是虚构道具，不读取、不提交、不记录生产 X-Codex-Turn-State，真票不进片场。
func fakeToken(n int, issued time.Time) string {
	return fakeTokenSeed(n, issued, 0x5a)
}

// fakeTokenSeed 让调用者挑填充字节，同一时刻铸票也各有面孔。
// 跨账号、跨模型测试靠这点认人，两张不同票不能靠撞脸互换。
func fakeTokenSeed(n int, issued time.Time, seed byte) string {
	size, ok := tokenByteLen[n]
	if !ok {
		panic(fmt.Sprintf("fakeTokenSeed: no decoded byte length known for %d base64 chars", n))
	}
	raw := make([]byte, size)
	raw[0] = 0x80
	binary.BigEndian.PutUint64(raw[1:9], uint64(issued.Unix()))
	for i := 9; i < size; i++ {
		raw[i] = seed + byte(i)
	}
	// 用带填充 URLEncoding，不用 RawURLEncoding；真头部带 "="，fernetIssuedAt 解码前再摘帽。
	out := base64.URLEncoding.EncodeToString(raw)
	if len(out) != n {
		panic(fmt.Sprintf("fakeTokenSeed: encoded to %d chars, want %d", len(out), n))
	}
	return out
}

// configureYAML 走真实 plugin.register，角色归一化、别名和校验按宿主原班人马演。
// 信封用 map 构造，不依赖内部 request 类型名，合同测试不认演员艺名。
func configureYAML(t *testing.T, cfgYAML string) error {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"config_yaml":    []byte(cfgYAML),
		"schema_version": 6,
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	t.Cleanup(resetPluginConfig)
	return configure(raw)
}

// mustConfigure 一见配置被拒就让测试亮红灯，不让坏菜单混进厨房。
func mustConfigure(t *testing.T, cfgYAML string) {
	t.Helper()
	if err := configureYAML(t, cfgYAML); err != nil {
		t.Fatalf("configure rejected a valid config: %v", err)
	}
}

// captureLog 在 fn 期间接管标准日志，收全输出；探针密钥绝不能上日志。
// 事后才查 stderr 太晚，收集器早把秘密端走了。flags 清零只比消息，不让时间戳抢戏。
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buffer bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	fn()
	return buffer.String()
}

// resetPluginConfig 在用例间还原包级配置，同时清 configErrors；configure 本来一起写它们，
// 不能让上个用例的抱怨跑到下个状态页。存储缓存按目录隔离，各用 t.TempDir()，不必掀它的桌。
func resetPluginConfig() {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.config = defaultConfig()
	state.configErrors = nil
}

// businessConfig 给 business 角色安排 dir 住址。
func businessConfig(dir string, dryRun bool) string {
	return fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: %t
log_decisions: false
`, dir, dryRun)
}

// interceptAfter 真走 request.intercept_after 分发，再拆开插件响应信封。
func interceptAfter(t *testing.T, req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal intercept request: %v", err)
	}
	out, err := handleMethod(pluginabi.MethodRequestInterceptAfter, raw)
	if err != nil {
		t.Fatalf("handleMethod(request.intercept_after): %v", err)
	}
	// 解码到本地形状，不向内部信封类型名攀亲戚。
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if errUnmarshal := json.Unmarshal(out, &env); errUnmarshal != nil {
		t.Fatalf("decode envelope: %v", errUnmarshal)
	}
	if !env.OK {
		t.Fatalf("plugin returned an error envelope: %+v", env.Error)
	}
	var resp pluginapi.RequestInterceptResponse
	if len(env.Result) > 0 {
		if errUnmarshal := json.Unmarshal(env.Result, &resp); errUnmarshal != nil {
			t.Fatalf("decode intercept response: %v", errUnmarshal)
		}
	}
	return resp
}

// request 给一个 bucket 配最简拦截请求，够上台就不多带行李。
func request(authID, model, headerValue string) pluginapi.RequestInterceptRequest {
	req := pluginapi.RequestInterceptRequest{
		Model:    model,
		Metadata: map[string]any{testAuthKey: authID},
		Headers:  http.Header{},
	}
	if headerValue != "" {
		req.Headers.Set(testHeader, headerValue)
	}
	return req
}

// outgoingHeader 报插件想发到线上去的值；没动请求就回 ""，沉默也算答卷。
func outgoingHeader(resp pluginapi.RequestInterceptResponse) string {
	if resp.Headers == nil {
		return ""
	}
	for key, values := range resp.Headers {
		if !equalFoldASCII(key, testHeader) {
			continue
		}
		for _, value := range values {
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// --- 票据助手体检：道具尺码先校准 ---

func TestFakeTokenMatchesObservedLengths(t *testing.T) {
	for _, n := range []int{292, 312} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			token := fakeToken(n, testNow)
			if len(token) != n {
				t.Fatalf("fakeToken produced %d chars, want %d", len(token), n)
			}
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
			if err != nil || len(raw) < 9 || raw[0] != 0x80 {
				t.Fatal("synthetic token is not in Fernet shape; the fixture no longer matches the real format")
			}
			issued := time.Unix(int64(binary.BigEndian.Uint64(raw[1:9])), 0)
			if !issued.Equal(testNow) {
				t.Fatalf("embedded timestamp = %s, want %s", issued.UTC(), testNow)
			}
		})
	}
}

func TestFakeTokenSeedProducesDistinctValues(t *testing.T) {
	a := fakeTokenSeed(292, testNow, 0x11)
	b := fakeTokenSeed(292, testNow, 0x22)
	if a == b {
		t.Fatal("two seeds produced the same token; the isolation tests would be vacuous")
	}
	if len(a) != 292 || len(b) != 292 {
		t.Fatalf("lengths = %d/%d, want 292/292", len(a), len(b))
	}
}

// --- §8.11 配置：inband 别名与 business 强制关灯 ---

// businessHarvestConfig 给业务角色安排落盘处；池持久化需要这间仓库，probeRoleConfig 没给。
func businessHarvestConfig(dir string) string {
	return fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: false
log_decisions: false
`, dir)
}

// 能力声明才是真门票：过去只给 probe 宣告响应钩子，business 连回调都收不到，函数内检查白站岗。
// 若退化不会报错，只会悄悄不收响应，probe 填不了的 bucket 永远空着，门卫失业还装忙。
func TestBusinessRoleDeclaresResponseHooks(t *testing.T) {
	mustConfigure(t, businessHarvestConfig(t.TempDir()))

	caps := pluginRegistration().Capabilities
	if !caps.ResponseInterceptor {
		t.Error("business role does not advertise the response interceptor, so it is never handed a response to harvest")
	}
	if !caps.StreamChunkInterceptor {
		t.Error("business role does not advertise the stream-chunk interceptor, which is the path real Codex SSE traffic takes")
	}
	if !caps.RequestInterceptor {
		t.Error("business role stopped advertising the request interceptor, so it cannot substitute at all")
	}
}

// 业务正常流量的 Set-Cookie pair 可顺手免费入池；测试走真实 Codex 的 SSE header-init chunk，
// 元数据照 CPA 给法递上，不能从后门塞答案。
func TestBusinessRoleHarvestsFromLiveResponse(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessHarvestConfig(dir))
	resetHarvestState(t)

	chunk := pluginapi.StreamChunkInterceptRequest{
		Model:      "gpt-5.5",
		ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
		ResponseHeaders: setCookieHeaders(fakeToken(292, wallClock().Add(-time.Minute)),
			"__cflb=cf-live", "__oailb=lb-live"),
		Metadata: map[string]any{testAuthKey: "codex-alpha.json"},
	}
	raw, errMarshal := json.Marshal(chunk)
	if errMarshal != nil {
		t.Fatalf("marshal chunk: %v", errMarshal)
	}
	if _, errHook := interceptStreamChunk(raw); errHook != nil {
		t.Fatalf("interceptStreamChunk: %v", errHook)
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	key := cookieEntryKey(map[string]string{"__cflb": "cf-live", "__oailb": "lb-live"})
	if _, ok := state.cookies[key]; !ok {
		t.Fatalf("the live response's pair was not pooled; pool holds %d entries", len(state.cookies))
	}
}

// 带内采集靠 RequestID 拉线：CPA 请求钩子拿执行器元数据（有选中凭据），
// 响应钩子拿处理器元数据（没有账号），真流量也会到达为 auth=-。两边 RequestID 相同，
// 请求报过账号后，同 ID 的无元数据响应仍须落到该账号 bucket。
// 若失联只会静默报 incomplete bucket key，仓库永远收不到货，线不能断在柜台后面。
func TestInBandHarvestAttributesByRequestID(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessHarvestConfig(dir))
	resetHarvestState(t)

	const (
		requestID = "req-correlate-1"
		auth      = "codex-alpha.json"
		model     = "gpt-5.5"
	)

	// 请求钩子认出账号；手里没模板，所以不注入，别空手表演变票。
	req := request(auth, model, "")
	req.RequestID = requestID
	interceptAfter(t, req)

	// 响应带新鲜 292 到场，却像 CPA 真交付那样不带账号元数据，考验前台记性。
	chunk := pluginapi.StreamChunkInterceptRequest{
		RequestID:       requestID,
		Model:           model,
		ChunkIndex:      pluginapi.StreamChunkHeaderInitIndex,
		ResponseHeaders: harvestResponseHeaders(fakeToken(292, wallClock().Add(-time.Minute))),
		Metadata:        nil,
	}
	raw, errMarshal := json.Marshal(chunk)
	if errMarshal != nil {
		t.Fatalf("marshal chunk: %v", errMarshal)
	}
	if _, errHook := interceptStreamChunk(raw); errHook != nil {
		t.Fatalf("interceptStreamChunk: %v", errHook)
	}

	cells, _, _ := observationsSnapshot()
	found := false
	for _, cell := range cells {
		if cell.AuthID == auth && cell.Model == model {
			found = true
		}
	}
	if !found {
		t.Fatalf("the response was not attributed back to %s; tally holds %d bucket(s)", auth, len(cells))
	}
}

// 关联只能消费一次：一请求配一响应；第二个复用 ID 的响应不能继承前人的账号，
// 否则回收门牌会把别人的 state 塞进本 bucket，房客串门就变偷家。
func TestInBandHarvestForgetsAfterUse(t *testing.T) {
	rememberRequestAuth("req-once", "codex-alpha.json")
	got, steered, _ := recallRequestRecord("req-once")
	if got != "codex-alpha.json" {
		t.Fatalf("first recall = %q, want the recorded account", got)
	}
	if steered {
		t.Error("first recall reports the request was steered; markRequestSteered was never called")
	}
	if got, _, _ = recallRequestRecord("req-once"); got != "" {
		t.Fatalf("second recall = %q, want empty: the entry must be consumed", got)
	}
}

// markRequestSteered 告诉响应侧引导确实发出；它在 dry_run 检查后执行。
// 标记必须往返保住，不然所有 steered 都被当 natural，明明请了向导却记成自由行。
func TestRequestWriteFlagSurvivesRecall(t *testing.T) {
	rememberRequestAuth("req-wrote", "codex-alpha.json")
	markRequestSteered("req-wrote", "pair-key-1")
	got, steered, pairKey := recallRequestRecord("req-wrote")
	if got != "codex-alpha.json" || !steered || pairKey != "pair-key-1" {
		t.Fatalf("recall = (%q, %v, %q), want the account, steered and the pair key", got, steered, pairKey)
	}

	// 未知 ID 不能凭空建记录：rememberRequestAuth 只记见过的账号，
	// 给跳过的请求补标会复活空账号幽灵。
	markRequestSteered("req-never-seen", "pair-key-2")
	if got, _, _ := recallRequestRecord("req-never-seen"); got != "" {
		t.Errorf("marking an unknown request created an entry with account %q", got)
	}
}

func TestConfigureRoleValidation(t *testing.T) {
	t.Run("missing role defaults to business", func(t *testing.T) {
		mustConfigure(t, "template_length: 292\nreplace_length: 312\n")
		state.mu.Lock()
		got := state.config.Role
		state.mu.Unlock()
		if got != roleBusiness {
			t.Fatalf("Role = %q, want %q: an absent role must fail safe to the non-writing side, "+
				"and DEPLOY.md step 6 installs the .so before step 7 sets the role", got, roleBusiness)
		}
	})

	t.Run("invalid role is rejected", func(t *testing.T) {
		if err := configureYAML(t, "role: probesque\n"); err == nil {
			t.Fatal("configure accepted an invalid role")
		}
	})

	t.Run("probe and business are both accepted", func(t *testing.T) {
		for _, role := range []string{roleProbe, roleBusiness} {
			if err := configureYAML(t, "role: "+role+"\n"+storeDirLine(t)); err != nil {
				t.Fatalf("configure rejected role %q: %v", role, err)
			}
		}
	})

	t.Run("probe without a store_dir is rejected", func(t *testing.T) {
		// probe 没写入位置却报成功，就会收获空气，--until-complete 也永远等不到散场。
		if err := configureYAML(t, "role: probe\n"); err == nil {
			t.Fatal("configure accepted a probe with no store_dir")
		}
	})
}

func TestIsProbe(t *testing.T) {
	probe := defaultConfig()
	probe.Role = roleProbe
	if !probe.isProbe() {
		t.Fatal("role probe did not report isProbe")
	}
	business := defaultConfig()
	business.Role = roleBusiness
	if business.isProbe() {
		t.Fatal("role business reported isProbe")
	}
}

// probe_base_url 默认 CPA 自身回环监听，插件就在被探进程里；显式空值也回到该默认值。
// 留空会在探测深处变传输错，看似上游倒闭，实际只是自己没写门牌。
func TestProbeBaseURLDefaultsToLoopback(t *testing.T) {
	if got := defaultConfig().ProbeBaseURL; got != defaultProbeBaseURL {
		t.Fatalf("defaultConfig().ProbeBaseURL = %q, want %q", got, defaultProbeBaseURL)
	}

	for name, cfgYAML := range map[string]string{
		"absent":           "role: business\n",
		"explicitly empty": "role: business\nprobe_base_url: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			mustConfigure(t, cfgYAML)
			state.mu.Lock()
			got := state.config.ProbeBaseURL
			state.mu.Unlock()
			if got != defaultProbeBaseURL {
				t.Fatalf("probe_base_url = %q, want the default %q", got, defaultProbeBaseURL)
			}
		})
	}

	// 对照组保留显式地址；否则一个完全不理配置的函数也能混过前两题。
	t.Run("configured value wins", func(t *testing.T) {
		mustConfigure(t, "role: business\nprobe_base_url: http://127.0.0.1:9317\n")
		state.mu.Lock()
		got := state.config.ProbeBaseURL
		state.mu.Unlock()
		if got != "http://127.0.0.1:9317" {
			t.Fatalf("probe_base_url = %q, want the configured value", got)
		}
	})
}
