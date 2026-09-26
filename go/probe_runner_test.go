package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 离线（不借 CPA 执行模型）采集器考试，不考翻回凭据状态，因为根本不翻。
// 真正烧钱的门禁逐项守：空选择或无管理 key 不启动；292 按业务查找的凭据文件名入库，312 不存；
// 过期 access token 跳过，绝不刷新，免得轮换 CPA refresh token 伤在线流量；
// 代理按序分配，死出口往下走，快过期 bucket 续采；免密流水不准出现代理密码或 token。
// 假 CPA 只演两个只读 GET，另有假上游扮 chatgpt.com。testProxySecret 从
// probe_scope_test.go 借同一枚道具密码，一处起名，到处都能 grep 抓它偷上镜。

// --- 假 CPA：只读柜台，不办改户口 ---

// fakeCredSeed 是假 CPA 发布供下载的一份凭据；exp 是 access token 期限，零表示还有数天，别当天赶客。
type fakeCredSeed struct {
	name      string
	accountID string
	proxyURL  string
	disabled  bool
	exp       time.Time
	// noToken 从下载里抽走 access_token，扮演采集器用不了的空壳凭据。
	noToken bool
}

type fakeCPA struct {
	mu     sync.Mutex
	server *httptest.Server
	seeds  map[string]fakeCredSeed
}

// encodeJWT 只在载荷装采集器要看的非秘密 exp 与 ChatGPT account id；
// 头段 e30 是 base64url("{}")，probeJWTClaims 只解载荷，这身简装够上台。
func encodeJWT(exp time.Time, accountID string) string {
	claims := map[string]any{
		"exp":                         exp.Unix(),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": accountID},
	}
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func newFakeCPA(t *testing.T, seeds ...fakeCredSeed) *fakeCPA {
	t.Helper()
	fake := &fakeCPA{seeds: make(map[string]fakeCredSeed, len(seeds))}
	for _, seed := range seeds {
		if seed.exp.IsZero() {
			seed.exp = time.Now().Add(72 * time.Hour)
		}
		fake.seeds[seed.name] = seed
	}
	fake.server = httptest.NewServer(fake)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeCPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == probeRouteAuthFiles:
		f.writeJSON(w, map[string]any{"files": f.fileList()})
	case r.Method == http.MethodGet && r.URL.Path == probeRouteAuthDownload:
		f.serveDownload(w, r)
	default:
		// 写路由一到假 CPA 就已违规，采集器绝不能调它；回 405 大声喊停，不默默陪演。
		http.Error(w, `{"error":"the offline harvester must not call this route"}`, http.StatusMethodNotAllowed)
	}
}

func (f *fakeCPA) fileList() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, 0, len(f.seeds))
	for _, seed := range f.seeds {
		out = append(out, map[string]any{
			"name":     seed.name,
			"provider": "codex",
			"disabled": seed.disabled,
		})
	}
	return out
}

func (f *fakeCPA) serveDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f.mu.Lock()
	seed, found := f.seeds[name]
	f.mu.Unlock()
	if !found {
		http.Error(w, `{"error":"no such credential"}`, http.StatusNotFound)
		return
	}
	blob := map[string]any{
		"account_id":    seed.accountID,
		"proxy_url":     seed.proxyURL,
		"type":          "codex",
		"disabled":      seed.disabled,
		"email":         "someone@example.com",
		"refresh_token": "refresh-must-never-be-used",
	}
	if !seed.noToken {
		blob["access_token"] = encodeJWT(seed.exp, seed.accountID)
	}
	f.writeJSON(w, blob)
}

func (f *fakeCPA) writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// --- 假上游：chatgpt.com 的本地替身 ---

type upstreamCall struct {
	model         string
	authorization string
	accountID     string
	sessionID     string
	sentTurnState bool
	// cookie 原样记录请求 Cookie 头；这里检查每次上游调用携账号池中 __cflb/__oailb pair 的预期，道具不换名。
	cookie string
}

type fakeUpstream struct {
	mu     sync.Mutex
	server *httptest.Server
	calls  []upstreamCall
	// status 与 tsLen 定剧情：200 加 tsLen 长 state 可作模板，312 是降级，非 200 则拒绝，别凭戏服颜色验票。
	status int
	tsLen  int
	// tsLenSeq 若设置就按调用序号覆盖 tsLen，最后一项循环返场。
	tsLenSeq []int
	// setCookies 非空则每个响应原样发 Set-Cookie，把路由 pair 从假上游递给采集器。
	setCookies []string
	// hold 让请求留台上，才能看见并发重叠；否则前一个抢先结束，真正并发也可能被 peak=1 误拍成独角戏。
	hold     time.Duration
	inFlight int
	peak     int
}

func (u *fakeUpstream) peakInFlight() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peak
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	upstream := &fakeUpstream{status: http.StatusOK, tsLen: 292}
	upstream.server = httptest.NewServer(upstream)
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (u *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Model string `json:"model"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	u.mu.Lock()
	u.inFlight++
	if u.inFlight > u.peak {
		u.peak = u.inFlight
	}
	hold := u.hold
	u.mu.Unlock()
	if hold > 0 {
		time.Sleep(hold)
	}
	defer func() {
		u.mu.Lock()
		u.inFlight--
		u.mu.Unlock()
	}()

	u.mu.Lock()
	index := len(u.calls)
	u.calls = append(u.calls, upstreamCall{
		model:         body.Model,
		authorization: r.Header.Get("Authorization"),
		accountID:     r.Header.Get("Chatgpt-Account-Id"),
		sessionID:     r.Header.Get("Session-Id"),
		sentTurnState: r.Header.Get(turnStateHeader) != "",
		cookie:        r.Header.Get("Cookie"),
	})
	status, tsLen := u.status, u.tsLen
	setCookies := u.setCookies
	// tsLenSeq 按调用次序答复，演“这出口限流、下个没限”；假上游不认出口脸，但认排队号。
	if len(u.tsLenSeq) > 0 {
		if index < len(u.tsLenSeq) {
			tsLen = u.tsLenSeq[index]
		} else {
			tsLen = u.tsLenSeq[len(u.tsLenSeq)-1]
		}
	}
	u.mu.Unlock()

	// state 顶着真实 Fernet 前缀考遮罩，值形态像真货，只断言长度，不看假票花纹。
	if status == http.StatusOK && tsLen >= 6 {
		w.Header().Set(turnStateHeader, "gAAAAA"+strings.Repeat("x", tsLen-6))
	}
	for _, line := range setCookies {
		w.Header().Add("Set-Cookie", line)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
}

func (u *fakeUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *fakeUpstream) snapshot() []upstreamCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamCall(nil), u.calls...)
}

// --- 帮手：后台也排好班 ---

// bucket 键故意别于其他测试：缓存全进程共用，撞名会以为仓库已满，不再补货。
const (
	probeTestAccount = "codex-runnera-a@example.com-pro.json"
	probeTestOther   = "codex-runnerb-b@example.com-pro.json"
	probeTestModel   = "gpt-runner-1"
)

type probeConfigOptions struct {
	dir      string
	baseURL  string
	role     string
	mgmtKey  string
	accounts []string
	models   []string
	proxies  []string

	templateLen int
	replaceLen  int
	ttlSeconds  int
}

func probeTestOptions(dir, baseURL string) probeConfigOptions {
	return probeConfigOptions{
		dir:         dir,
		baseURL:     baseURL,
		role:        roleProbe,
		mgmtKey:     "test-mgmt-key",
		accounts:    []string{probeTestAccount},
		models:      []string{probeTestModel},
		templateLen: 292,
		replaceLen:  312,
		ttlSeconds:  3600,
	}
}

func probeTestConfig(opts probeConfigOptions) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "role: %s\nstore_dir: %q\nlog_decisions: false\n", opts.role, opts.dir)
	fmt.Fprintf(&builder, "template_length: %d\nreplace_length: %d\nttl_seconds: %d\n", opts.templateLen, opts.replaceLen, opts.ttlSeconds)
	fmt.Fprintf(&builder, "probe_base_url: %q\n", opts.baseURL)
	fmt.Fprintf(&builder, "probe_management_key: %q\n", opts.mgmtKey)
	for _, block := range []struct {
		key    string
		values []string
	}{
		{"probe_accounts", opts.accounts},
		{"models", opts.models},
		{"probe_proxies", opts.proxies},
	} {
		if len(block.values) == 0 {
			continue
		}
		fmt.Fprintf(&builder, "%s:\n", block.key)
		for _, value := range block.values {
			fmt.Fprintf(&builder, "  - %q\n", value)
		}
	}
	return builder.String()
}

// resetProbeRunner 清包级 runner、claim guard、存储缓存，还确认旧用例没留演员在台上跑。
func resetProbeRunner(t *testing.T) {
	t.Helper()
	clear := func() {
		probeRunner.mu.Lock()
		probeRunner.run = probeRunState{}
		probeRunner.cancel = nil
		probeRunner.mu.Unlock()
		probeActive.mu.Lock()
		probeActive.set = make(map[string]bool)
		probeActive.mu.Unlock()
		// 冷却表全进程共用，键为（exit, account, model）；不清就让前场开火压住后场，
		// 只表现为流水啥都没发生，串场幽灵最会装安静。
		probeCooldown.mu.Lock()
		probeCooldown.until = make(map[string]time.Time)
		probeCooldown.mu.Unlock()
		// 账号休息表同理要清；上例一个 429 不能让后面所有同账号演员集体请假。
		probeAccountRest.mu.Lock()
		probeAccountRest.until = make(map[string]time.Time)
		probeAccountRest.mu.Unlock()
		state.mu.Lock()
		state.cookies = make(map[string]*routeCookieEntry)
		state.cookiesDirty = false
		state.cookiesFlushed = time.Time{}
		state.mu.Unlock()
	}
	t.Cleanup(func() {
		probeRunCancel()
		waitForProbeRun(t)
		clear()
	})
	clear()
}

// setUpstream 给本用例采集器指向假上游，别走出片场。
func setUpstream(t *testing.T, rawURL string) {
	t.Helper()
	previous := probeUpstreamURL
	probeUpstreamURL = rawURL
	t.Cleanup(func() { probeUpstreamURL = previous })
}

// fastRenew 同时缩短续期节奏与三元组冷却，只给测试快进。生产每分钟检查，每三元组 55 分钟至多一发。
// 只调节奏不动 55 分钟冷却，续期会正确拒绝开火，测试等超时却什么也没考到。
func fastRenew(t *testing.T, interval, threshold, cooldown time.Duration) {
	t.Helper()
	prevInterval, prevThreshold, prevCooldown := probeRenewInterval, probeRenewThreshold, probeExitCooldown
	probeRenewInterval, probeRenewThreshold, probeExitCooldown = interval, threshold, cooldown
	t.Cleanup(func() {
		probeRenewInterval, probeRenewThreshold, probeExitCooldown = prevInterval, prevThreshold, prevCooldown
	})
}

// waitForProbeRun 等 running 清零，只用于会返回的失败路径；健康运行进续期循环直到取消，成功用例要等进度，不等谢幕。
func waitForProbeRun(t *testing.T) probeRunState {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		run := probeRunSnapshot()
		if !run.Running {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe run did not finish; last state %+v", run)
			return run
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitUntil 在期限内轮询条件；采集并发，要等可见效果，不靠固定睡眠做梦猜结局。
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitForInitialFill 等初填达到 Total，每个所选 bucket 都轮过一次，点名不能漏人。
func waitForInitialFill(t *testing.T) {
	t.Helper()
	waitUntil(t, "initial fill to finish", func() bool {
		run := probeRunSnapshot()
		return run.Total > 0 && run.Done >= run.Total
	})
}

func poolEntryCount() int {
	state.mu.Lock()
	defer state.mu.Unlock()
	return len(state.cookies)
}

// startProbeRun 启动并登记停止、等 goroutine 退出的清理；它在 setUpstream/fastRenew 后调用，
// 所以 LIFO 最先清它。先让续期演员下台，再恢复 probeUpstreamURL 和节奏等包变量，免得换布景时撞人竞态。
func startProbeRun(t *testing.T) {
	t.Helper()
	if errStart := probeRunStart(); errStart != nil {
		t.Fatalf("probeRunStart refused a complete config: %v", errStart)
	}
	t.Cleanup(func() {
		probeRunCancel()
		waitForProbeRun(t)
	})
}

// --- 拒绝开工：缺道具就别硬演 ---

func TestProbeRunStartRefusesIncompleteConfig(t *testing.T) {
	// 空选择不能偷解释为全账号，免得花掉没被选中的配额；无 key 读不了名单，无 store_dir 没处落货。
	// 每个检查都是真门槛，不是门口贴张纸。
	tests := []struct {
		name   string
		narrow func(opts *probeConfigOptions)
		want   string
	}{
		{"no accounts", func(o *probeConfigOptions) { o.accounts = nil }, "probe_accounts"},
		{"no models", func(o *probeConfigOptions) { o.models = nil }, "models"},
		{"no management key", func(o *probeConfigOptions) { o.mgmtKey = "" }, "probe_management_key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetProbeRunner(t)
			dir := t.TempDir()
			opts := probeTestOptions(dir, "http://127.0.0.1:1")
			tc.narrow(&opts)
			mustConfigure(t, probeTestConfig(opts))

			errStart := probeRunStart()
			if errStart == nil {
				t.Fatalf("probeRunStart accepted a config with %s missing", tc.want)
			}
			if !strings.Contains(errStart.Error(), tc.want) {
				t.Fatalf("the refusal does not name %s: %v", tc.want, errStart)
			}
			if probeRunSnapshot().Running {
				t.Fatal("a refused start left the runner marked as running")
			}
		})
	}
}

func TestProbeRunStartRefusesEmptyStoreDir(t *testing.T) {
	// probe 的 store_dir 在 configure 就校验；此处直接造无仓库的运行考拒绝，没地方存模板就别向业务报丰收。
	resetProbeRunner(t)
	opts := probeTestOptions("", "http://127.0.0.1:1")
	state.mu.Lock()
	state.config = pluginConfig{
		Role:               roleProbe,
		ProbeManagementKey: opts.mgmtKey,
		ProbeAccounts:      opts.accounts,
		Models:             opts.models,
		TemplateLength:     292,
		ReplaceLength:      312,
	}
	state.mu.Unlock()

	errStart := probeRunStart()
	if errStart == nil || !strings.Contains(errStart.Error(), "store_dir") {
		t.Fatalf("probeRunStart did not refuse an empty store_dir: %v", errStart)
	}
}

func TestProbeRunStartIsSingleFlight(t *testing.T) {
	// 运行自己管续期直到取消，第二次 start 必须拒绝，同一批 bucket 不雇两班人撞着补货。
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))

	startProbeRun(t)
	errSecond := probeRunStart()
	if errSecond == nil {
		t.Fatal("a second start was accepted while a run was already going")
	}
	if !strings.Contains(errSecond.Error(), "already running") {
		t.Fatalf("the second refusal gave an unexpected reason: %v", errSecond)
	}
}

// --- 采集：收对东西才算丰收 ---

func TestProbePoolsTheMintedPair(t *testing.T) {
	// 业务所依赖的是响应 __cflb/__oailb 进全局池，任意账号可用。
	// 还要查请求已鉴权且不带 pair；带旧房卡钉节点，边缘就不造新房卡，空手才领得到。
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	upstream.tsLen = 292
	upstream.setCookies = []string{"__cflb=cf-minted; Path=/", "__oailb=lb-minted; Path=/"}
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	waitForInitialFill(t)

	if poolEntryCount() == 0 {
		t.Fatalf("no pair pooled for the account %q", probeTestAccount)
	}

	calls := upstream.snapshot()
	if len(calls) != 1 {
		t.Fatalf("upstream received %d calls, want exactly 1", len(calls))
	}
	call := calls[0]
	if !strings.HasPrefix(call.authorization, "Bearer ") {
		t.Fatalf("upstream call was not authorised: %q", call.authorization)
	}
	if call.accountID != "acct-a" {
		t.Fatalf("upstream call carried account id %q, want acct-a", call.accountID)
	}
	if call.sessionID == "" {
		t.Fatal("upstream call carried no Session-Id")
	}
	if call.sentTurnState {
		t.Fatal("the probe sent a turn-state upstream, which stops a fresh one being minted")
	}
	if call.cookie != "" {
		t.Fatalf("the probe sent cookies on a mint call -- a carried pair pins the node and the edge mints nothing: %q", call.cookie)
	}
}

func TestProbeSkipsThrottled312(t *testing.T) {
	// 312 是降级/限流，不是模板；存它再交业务，等于专卖本来要避开的坏票。
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	upstream.tsLen = 312
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	waitForInitialFill(t)

	if poolEntryCount() != 0 {
		t.Fatal("a 312 that set no cookies still pooled an entry")
	}
	joined := strings.Join(probeRunSnapshot().Lines, "\n")
	if !strings.Contains(joined, "degraded") {
		t.Fatalf("the transcript does not explain the 312 was skipped: %s", joined)
	}
}

func TestProbeSkipsExpiredTokenWithoutRefreshing(t *testing.T) {
	// 过期 access token 跳过且绝不刷新，免得轮换 CPA refresh token 破坏在线流量。
	// 唯一账号过期就干净失败，上游零调用，不拿死票敲门，也不背后改钥匙。
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{
		name:      probeTestAccount,
		accountID: "acct-a",
		exp:       time.Now().Add(-1 * time.Minute),
	})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	run := waitForProbeRun(t)

	if run.Error == "" {
		t.Fatal("a run with only an expired credential did not fail")
	}
	if upstream.count() != 0 {
		t.Fatalf("upstream was called %d times on an expired token; it must be skipped", upstream.count())
	}
	if !strings.Contains(strings.Join(run.Lines, "\n"), "expired") {
		t.Fatalf("the transcript does not say the token was skipped as expired: %v", run.Lines)
	}
}

func TestProbeUnreadableTokenIsSkipped(t *testing.T) {
	// 凭据缺 access_token 不可用但不该炸进程；记一行丢弃，没人可用就干净失败，不拆舞台。
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a", noToken: true})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	run := waitForProbeRun(t)
	if run.Error == "" {
		t.Fatal("a run whose only credential had no token did not fail")
	}
	if upstream.count() != 0 {
		t.Fatal("the upstream was called for a credential with no token")
	}
}

// --- 代理池：门挨个敲，账挨个记 ---

func TestProbeExitsAssignInOrderWithFallback(t *testing.T) {
	// 账号 i 从出口 i 起按序走一圈，每账号都有完整回退序列；空池只直连一次，没菜单也有默认菜。
	got := probeExits([]string{"p0", "p1", "p2"}, 0)
	if fmt.Sprint(got) != fmt.Sprint([]string{"p0", "p1", "p2"}) {
		t.Fatalf("account 0 order = %v, want p0,p1,p2", got)
	}
	got = probeExits([]string{"p0", "p1", "p2"}, 1)
	if fmt.Sprint(got) != fmt.Sprint([]string{"p1", "p2", "p0"}) {
		t.Fatalf("account 1 order = %v, want p1,p2,p0", got)
	}
	got = probeExits(nil, 0)
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("empty pool order = %v, want a single direct attempt", got)
	}
}

// newFakeProxy 起真实可拨 HTTP 转发代理，造两条真能用的不同出口。
// 否则只有 "" 直连可用，而多个 "" 共用冷却键，根本考不到沿池换门。
func newFakeProxy(t *testing.T, hits *atomic.Int64) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// 代理请求带绝对 URL，原样转交，不给门牌添戏。
		outbound, errNew := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if errNew != nil {
			http.Error(w, errNew.Error(), http.StatusBadGateway)
			return
		}
		outbound.Header = r.Header.Clone()
		response, errDo := http.DefaultTransport.RoundTrip(outbound)
		if errDo != nil {
			http.Error(w, errDo.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// harvestTestConfig 最简配置直接喂 probeHarvestBucket 考池规则；
// 走 probeRunStart 会经 normaliseProbeScope 改形状，题目道具不能先被后台修掉。
func harvestTestConfig(t *testing.T) (pluginConfig, probeCredential, *probeClientPool) {
	t.Helper()
	cfg := pluginConfig{
		StoreDir:       t.TempDir(),
		TemplateLength: 292,
		ReplaceLength:  312,
		TTLSeconds:     3600,
	}
	cred := probeCredential{name: probeTestAccount, accessToken: "token-a", accountID: "acct-a"}
	pool := newProbeClientPool()
	t.Cleanup(pool.closeIdle)
	// 生产出口间隔两秒，整套测试照睡会睡成连续剧；节奏有专门用例，这里快进。
	previous := probeExitPause
	probeExitPause = time.Millisecond
	t.Cleanup(func() { probeExitPause = previous })
	return cfg, cred, pool
}

func TestProbeAdvancesToNextExitOn312(t *testing.T) {
	// 钉住旧缺陷：312 曾让整次停止，第二出口永远不上场，池沦为摆设。
	// 312 限的是此账号当前出口 IP，下一出口必须有出场机会。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLenSeq = []int{312, 292} // 首出口限流，第二扇门正常开
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)

	var hitsA, hitsB atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	exitB := newFakeProxy(t, &hitsB)
	cfg, cred, pool := harvestTestConfig(t)

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{exitA, exitB}, nil, 0) {
		t.Fatal("probeHarvestBucket reported no upstream call at all")
	}

	if poolEntryCount() == 0 {
		t.Fatal("no pair pooled: the 312 on the first exit ended the attempt instead of moving to the second")
	}
	if got := upstream.count(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2 (one per exit)", got)
	}
	if hitsA.Load() != 1 || hitsB.Load() != 1 {
		t.Fatalf("exit hits A=%d B=%d, want 1 each -- the pool was not walked in order", hitsA.Load(), hitsB.Load())
	}
}

func TestProbeStopsAfterWalkingThePoolAndCoolsDown(t *testing.T) {
	// 本窗口所有出口试完就无路可走；冷却内第二次不能再花配额，防止重演每小时 540 次乱敲门。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 312 // 所有出口都挂限流牌
	setUpstream(t, upstream.server.URL)

	var hitsA, hitsB atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	exitB := newFakeProxy(t, &hitsB)
	exits := []string{exitA, exitB}
	cfg, cred, pool := harvestTestConfig(t)

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, exits, nil, 0) {
		t.Fatal("the first pass made no upstream call")
	}
	if got := upstream.count(); got != 2 {
		t.Fatalf("first pass made %d upstream calls, want 2 (one per exit)", got)
	}

	if probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, exits, nil, 0) {
		t.Fatal("a second pass inside the cooldown still fired; this is the runaway-retry defect")
	}
	if got := upstream.count(); got != 2 {
		t.Fatalf("upstream calls grew to %d inside the cooldown, want it pinned at 2", got)
	}
}

func TestProbeNewExitIsEligibleImmediately(t *testing.T) {
	// 池耗尽后新增代理应立刻试，新门没参加旧冷却，不必陪罚站；按出口 URL 记冷却就能区分。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLenSeq = []int{312, 312, 292} // 先两扇旧门，再给新出口试镜
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)

	var hitsA, hitsB, hitsC atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	exitB := newFakeProxy(t, &hitsB)
	cfg, cred, pool := harvestTestConfig(t)

	probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{exitA, exitB}, nil, 0)
	if upstream.count() != 2 {
		t.Fatalf("setup: expected the pool to be walked once, got %d calls", upstream.count())
	}

	exitC := newFakeProxy(t, &hitsC)
	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{exitA, exitB, exitC}, nil, 0) {
		t.Fatal("adding an exit did not make the bucket fireable again")
	}

	if poolEntryCount() == 0 {
		t.Fatal("the new exit did not mint a pair")
	}
	if got := upstream.count(); got != 3 {
		t.Fatalf("upstream calls = %d, want 3: only the new exit should have fired", got)
	}
	if hitsA.Load() != 1 || hitsB.Load() != 1 {
		t.Fatalf("a cooling exit was re-dialed: A=%d B=%d, want 1 each", hitsA.Load(), hitsB.Load())
	}
	if hitsC.Load() != 1 {
		t.Fatalf("the new exit was dialed %d times, want 1", hitsC.Load())
	}
}

// 429 不是换出口能治：2026-09-18 把几次 312 打成 21 次 429，
// 正因剩余出口仍拿同一份被要求慢下来的凭据；人该休息，不是换鞋继续跑。
func TestProbe429StopsTheWalkAndRestsTheAccount(t *testing.T) {
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.status = http.StatusTooManyRequests
	setUpstream(t, upstream.server.URL)

	var hitsA, hitsB, hitsC atomic.Int64
	exits := []string{
		newFakeProxy(t, &hitsA),
		newFakeProxy(t, &hitsB),
		newFakeProxy(t, &hitsC),
	}
	cfg, cred, pool := harvestTestConfig(t)

	probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, exits, nil, 0)

	if got := upstream.count(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1: a 429 must end the walk, not advance to the next exit", got)
	}
	if probeAccountReady(cred.name, time.Now()) {
		t.Fatal("the account was not rested after a 429, so the next bucket will hit it again immediately")
	}

	// 账号休息期内任何桶都不能再开火，同一演员不能换面具加班。
	probeHarvestBucket(context.Background(), cfg, pool, cred, "another-model", exits, nil, 0)
	if got := upstream.count(); got != 1 {
		t.Fatalf("upstream calls grew to %d while the account was resting", got)
	}
}

// 一凭据只由一 goroutine 干活，其两桶不同时在途；按目标散开曾让单账号每秒约 7.5 请求，群演抢同一张工牌。
func TestProbeSerialisesOneAccountsBuckets(t *testing.T) {
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.hold = 40 * time.Millisecond
	setUpstream(t, upstream.server.URL)

	cfg, cred, pool := harvestTestConfig(t)
	creds := map[string]probeCredential{cred.name: cred}
	targets := []probeTarget{
		{account: cred.name, model: "m-1"},
		{account: cred.name, model: "m-2"},
		{account: cred.name, model: "m-3"},
	}

	probeFireBatch(context.Background(), cfg, pool, creds, targets,
		map[string]int{cred.name: 0}, nil, nil, false)

	if got := upstream.count(); got != 3 {
		t.Fatalf("upstream calls = %d, want 3 (one per bucket)", got)
	}
	if peak := upstream.peakInFlight(); peak != 1 {
		t.Fatalf("peak concurrent requests against ONE credential = %d, want 1", peak)
	}
}

func TestProbeFallsThroughToNextExitOnTransportFailure(t *testing.T) {
	// 首出口死了要落到下个出口；直接给 probeHarvestBucket 池，保留直连 ""。
	// normaliseProbeScope 会裁空代理，生产正确（空池已表示直连），但本题必须保住第二扇门。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)

	cfg := pluginConfig{
		StoreDir:       t.TempDir(),
		TemplateLength: 292,
		ReplaceLength:  312,
		TTLSeconds:     3600,
	}
	cred := probeCredential{name: probeTestAccount, accessToken: "token-a", accountID: "acct-a"}
	pool := newProbeClientPool()
	defer pool.closeIdle()

	// 出口 0 关端口即刻拒连，出口 1 直连；一扇假门，一条真路。
	probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{"http://127.0.0.1:1", ""}, nil, 0)

	if poolEntryCount() == 0 {
		t.Fatal("no pair pooled, so the fallback to the second exit did not happen")
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream received %d calls, want 1 (only the working exit)", upstream.count())
	}
	if !strings.Contains(strings.Join(probeRunSnapshot().Lines, "\n"), "trying next") {
		t.Fatal("no transport-failure fallthrough was logged")
	}
}

// --- 续期：票快馊了再开灶 ---

func TestProbeRenewsBucketNearingExpiry(t *testing.T) {
	// 初填后继续守着近过期 bucket；阈值设大，新填马上又到期续补，
	// 第二次上游调用就证明续期循环真在值班。
	resetProbeRunner(t)
	fastRenew(t, 15*time.Millisecond, 2*time.Hour, time.Millisecond)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	waitForInitialFill(t)
	waitUntil(t, "a renewal fire", func() bool { return upstream.count() >= 2 })
}

// --- 秘密：流水不能当密码展览 ---

func TestProbeRunNeverLeaksAProxyPassword(t *testing.T) {
	// Lines、运行错误、Current 都进免密页面；带密码的死代理即便在传输失败行也必须遮罩，失败不许摘口罩。
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	opts := probeTestOptions(t.TempDir(), fake.server.URL)
	// 带密码出口指拒连端口，让它快失败，专考日志是否走遮罩通道。
	opts.proxies = []string{"http://prober:" + testProxySecret + "@127.0.0.1:1"}
	mustConfigure(t, probeTestConfig(opts))
	startProbeRun(t)
	waitForInitialFill(t)

	run := probeRunSnapshot()
	for _, text := range append(append([]string(nil), run.Lines...), run.Error, run.Current) {
		if strings.Contains(text, testProxySecret) {
			t.Fatalf("a proxy password reached the run state: %q", text)
		}
	}
	if !strings.Contains(strings.Join(run.Lines, "\n"), "***@") {
		t.Fatal("no masked proxy appears anywhere, so this test proved nothing")
	}
}

// 旧 probeShortAuth 自抄一份遮罩算法还得手工同步，如今两边统一用 maskAuthLabel。
// TestMaskAuthLabel 覆盖原测试且更多，尤其邮件在末尾、全名就是邮件这两种真漏法；两本假账改成一本真账。

// --- 轮换池：同门口不等于同出口 ---
// 轮换条目是每连接换地址的网关；2026-09-19 实测连续 20 请求得到 20 个不同英国地址。
// 静态规矩禁止的重试恰是这里消除 312 的办法，两池不能共穿一双鞋。

// shrinkRotating 只给本用例缩轮换预算，生产不写这些；真跑十次假往返只会多等，不多长见识。
func shrinkRotating(t *testing.T, attempts int, cooldown time.Duration) {
	t.Helper()
	prevAttempts, prevCooldown := probeRotatingAttempts, probeRotatingCooldown
	probeRotatingAttempts, probeRotatingCooldown = attempts, cooldown
	t.Cleanup(func() {
		probeRotatingAttempts, probeRotatingCooldown = prevAttempts, prevCooldown
	})
}

func TestProbeRotatingRetriesOneEntryForAFreshAddress(t *testing.T) {
	// 拆池治的是单条目被静态规矩锁成 55 分钟一次：一次 312 就空整窗，
	// 可同条目下一连接本会换 IP，不能因为门牌相同就认定来客还是同一人。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLenSeq = []int{312, 312, 292} // 第三个地址没挂限流牌
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)
	cfg, cred, pool := harvestTestConfig(t)
	shrinkRotating(t, 5, time.Minute)

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, []string{""}, 0) {
		t.Fatal("probeHarvestBucket reported no upstream call at all")
	}
	if poolEntryCount() == 0 {
		t.Fatal("no pair pooled: the rotating pool stopped at the first 312 instead of asking for another address")
	}
	if got := upstream.count(); got != 3 {
		t.Fatalf("upstream calls = %d, want 3 (two throttled addresses, then one that was not)", got)
	}
}

func TestProbeRotatingStopsAtItsBudgetAndRestsBriefly(t *testing.T) {
	// 预算必须真封顶，所有地址都 312 不能无休止试；之后休息用短窗口而非静态 55 分钟，
	// 否则运营者的桶一空就是五十分钟，午休比营业还长。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 312 // 每个地址都限流，换鞋也跑不动
	setUpstream(t, upstream.server.URL)
	cfg, cred, pool := harvestTestConfig(t)
	shrinkRotating(t, 4, time.Hour) // 休息安排够长，才能拍到冷板凳场面

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, []string{""}, 0) {
		t.Fatal("the first pass made no upstream call")
	}
	if got := upstream.count(); got != 4 {
		t.Fatalf("first pass made %d calls, want 4 (the whole budget)", got)
	}
	if probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, []string{""}, 0) {
		t.Fatal("a second pass inside the rest window still fired")
	}
	if got := upstream.count(); got != 4 {
		t.Fatalf("upstream calls = %d after the second pass, want 4 -- the rest window is not holding", got)
	}

	// 确实等轮换短窗，不是 probeExitCooldown；短窗一过就准 bucket 回台。
	shrinkRotating(t, 4, time.Nanosecond)
	probeCooldownSet(probeRotatingExit, cred.name, probeTestModel, time.Now().Add(-time.Second))
	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, []string{""}, 0) {
		t.Fatal("the bucket never became eligible again after its rotating rest expired")
	}
}

func TestProbeRotatingStopsOnAccountLimit(t *testing.T) {
	// 429 叫凭据慢下来，网关换任何地址都不改这条命令；剩余预算不花，与静态路径同分 312/429。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.status = http.StatusTooManyRequests
	setUpstream(t, upstream.server.URL)
	cfg, cred, pool := harvestTestConfig(t)
	shrinkRotating(t, 6, time.Minute)

	probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, []string{""}, 0)

	if got := upstream.count(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 -- a 429 must end the rotating attempt, not burn the budget", got)
	}
	if probeAccountReady(cred.name, time.Now()) {
		t.Fatal("the account was not rested after a 429")
	}
}

func TestProbeRotatingPoolSuppressesTheImplicitDirectExit(t *testing.T) {
	// 空 probe_proxies 原来表示本机出网；若代理全搬轮换表，这个默认会偷偷从服务器地址采集。
	// 用户花钱正是为了不走本机出口，所以轮换池要压住这条老近路。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 292
	setUpstream(t, upstream.server.URL)
	cfg, cred, pool := harvestTestConfig(t)
	shrinkRotating(t, 1, time.Minute)

	var hits atomic.Int64
	rotatingExit := newFakeProxy(t, &hits)

	probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, []string{rotatingExit}, 0)

	if got := upstream.count(); got != 1 {
		t.Fatalf("upstream calls = %d, want exactly 1 -- an extra call means the direct exit fired too", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("the rotating exit carried %d request(s), want 1; the harvest went out direct instead", hits.Load())
	}
}

func TestProbeStaticPoolIsTriedBeforeRotating(t *testing.T) {
	// 静态预算每出口每窗一发，没用也过期；轮换条目随时可用，先吃保质期短的那盘。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLenSeq = []int{312, 292} // 静态出口限流，轮换出口照常开窗
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)
	cfg, cred, pool := harvestTestConfig(t)
	shrinkRotating(t, 3, time.Minute)

	var staticHits, rotatingHits atomic.Int64
	staticExit := newFakeProxy(t, &staticHits)
	rotatingExit := newFakeProxy(t, &rotatingHits)

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel,
		[]string{staticExit}, []string{rotatingExit}, 0) {
		t.Fatal("no upstream call was made")
	}
	if poolEntryCount() == 0 {
		t.Fatal("no pair pooled although the rotating pool had a good address")
	}
	if staticHits.Load() != 1 || rotatingHits.Load() != 1 {
		t.Fatalf("static=%d rotating=%d, want 1 each -- the static exit must be spent first",
			staticHits.Load(), rotatingHits.Load())
	}
}

// 64KB 上限早于 v7.3.4 富 auth-files 条目（recent_requests、quota、model_quotas、cooldowns）。
// 不大一队账号就把 JSON 截腰，报 unexpected end of JSON input。如今上限放宽，超了必须明说，不能把剪坏菜单怪成厨师不识字。
func TestProbeClientReadsLargeManagementDocument(t *testing.T) {
	big := strings.Repeat("x", 200<<10) // 200KB，挤破旧 64KB 小信封
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"files":[%q]}`, big)
	}))
	defer server.Close()

	client := &probeClient{baseURL: server.URL, mgmtKey: "k", http: server.Client()}
	res, err := client.call(context.Background(), http.MethodGet, probeRouteAuthFiles, "k", nil, probeMgmtTimeout)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var doc struct {
		Files []string `json:"files"`
	}
	if errUnmarshal := json.Unmarshal(res.body, &doc); errUnmarshal != nil {
		t.Fatalf("the large document was not returned whole: %v", errUnmarshal)
	}
	if len(doc.Files) != 1 || len(doc.Files[0]) != len(big) {
		t.Fatalf("document content was altered: files=%d", len(doc.Files))
	}
}

func TestProbeClientReportsOversizeRatherThanMisParsing(t *testing.T) {
	// 超过宽上限要报可读容量错，不是 JSON 语法错；64KB 那次难查就难在裁纸人装作没来过。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, probeMgmtMaxBodyBytes+2))
	}))
	defer server.Close()

	client := &probeClient{baseURL: server.URL, mgmtKey: "k", http: server.Client()}
	_, err := client.call(context.Background(), http.MethodGet, probeRouteAuthFiles, "k", nil, probeMgmtTimeout)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an oversize response was not reported as such: %v", err)
	}
}
