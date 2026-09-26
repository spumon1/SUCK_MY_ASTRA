package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// 代理检查的合同：告诉运营者哪些出口能到 OpenAI，一分账号配额不花，一字代理密码不晒。
// 两条最怕被“优化”掉：请求绝不带凭据，加 Authorization 装真实就开始烧配额；
// 连不上与连上被拒要分开，前者找代理商，后者看出口信誉，不能让修水管的去给门卫写检讨。

const opsProxyCheckPath = mgmtResourcePath + "ops/proxy-check"

// --- 替身：本地搭台不借真账号 ---

// fakeCheckUpstream 扮 Codex 端点并记每个来客所带物件，零凭据要实查，不靠口头保证。
type fakeCheckUpstream struct {
	mu       sync.Mutex
	status   int
	authSeen []string
	hdrSeen  []http.Header
	server   *httptest.Server
}

func newFakeCheckUpstream(t *testing.T, status int) *fakeCheckUpstream {
	t.Helper()
	up := &fakeCheckUpstream{status: status}
	up.server = httptest.NewServer(up)
	t.Cleanup(up.server.Close)
	return up
}

func (u *fakeCheckUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.authSeen = append(u.authSeen, r.Header.Get("Authorization"))
	u.hdrSeen = append(u.hdrSeen, r.Header.Clone())
	status := u.status
	u.mu.Unlock()
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{}`))
}

func (u *fakeCheckUpstream) auths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.authSeen...)
}

// fakeTrace 扮 Cloudflare /cdn-cgi/trace，假演员也报真格式台词。
type fakeTrace struct {
	mu     sync.Mutex
	ip     string
	loc    string
	colo   string
	status int
	calls  int
	server *httptest.Server
}

func newFakeTrace(t *testing.T) *fakeTrace {
	t.Helper()
	tr := &fakeTrace{ip: "203.0.113.7", loc: "GB", colo: "LHR", status: http.StatusOK}
	tr.server = httptest.NewServer(tr)
	t.Cleanup(tr.server.Close)
	return tr
}

func (f *fakeTrace) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	ip, loc, colo, status := f.ip, f.loc, f.colo, f.status
	f.mu.Unlock()
	w.WriteHeader(status)
	// 真 trace 有十来个键，只读三个；多余键专考解析器不乱认亲。
	_, _ = w.Write([]byte("fl=1a2b3c\nh=chatgpt.com\nip=" + ip +
		"\nts=1750000000\nvisit_scheme=https\ncolo=" + colo +
		"\nloc=" + loc + "\ntls=TLSv1.3\n"))
}

// setTraceURL 给本用例 trace 指向替身，别敲到线上大门。
func setTraceURL(t *testing.T, rawURL string) {
	t.Helper()
	previous := proxyCheckTraceURL
	proxyCheckTraceURL = rawURL
	t.Cleanup(func() { proxyCheckTraceURL = previous })
}

// checkConfig 给指定代理池配最小合格菜单。
func checkConfig(t *testing.T, dir string, proxies ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("role: business\nstore_dir: " + jsonQuote(dir) +
		"\ndry_run: true\nlog_decisions: false\n" +
		"models:\n  - gpt-5.5\n")
	if len(proxies) > 0 {
		b.WriteString("probe_proxies:\n")
		for _, p := range proxies {
			b.WriteString("  - " + jsonQuote(p) + "\n")
		}
	}
	return b.String()
}

func jsonQuote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func decodeProxyCheck(t *testing.T, body []byte) proxyCheckResponse {
	t.Helper()
	var out proxyCheckResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode proxy-check response: %v\nbody: %s", err, body)
	}
	return out
}

// --- 免密门禁：不用钥匙也得确认 ---

func TestProxyCheckRequiresConfirm(t *testing.T) {
	// 检查会拨池里每个出口，裸导航和预取不能路过就开全场灯。
	mustConfigure(t, checkConfig(t, t.TempDir()))

	resp := driveResource(t, opsProxyCheckPath, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the proxy check ran without confirm=1; a prefetch could dial the whole pool")
	}
}

// --- 判决：闭门羹与走错路两码事 ---

func TestProxyCheckVerdictsFollowTheUpstreamStatus(t *testing.T) {
	// 401 在此算通路成功：没带凭据被告知缺凭据，证明到了 OpenAI 而非死在代理。
	// 其他结果各有诊断，不能都拿同一张表情包回人。
	tests := []struct {
		name    string
		status  int
		verdict string
	}{
		{"401 means the exit reached OpenAI", http.StatusUnauthorized, proxyVerdictOK},
		{"403 means the exit is refused", http.StatusForbidden, proxyVerdictBlocked},
		{"429 means the exit is rate limited", http.StatusTooManyRequests, proxyVerdictRateLimited},
		{"anything else is flagged, not assumed fine", http.StatusInternalServerError, proxyVerdictUnexpected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newFakeCheckUpstream(t, tc.status)
			trace := newFakeTrace(t)
			setUpstream(t, upstream.server.URL)
			setTraceURL(t, trace.server.URL)

			pool := newProbeClientPool()
			defer pool.closeIdle()
			got := proxyCheckOne(t.Context(), pool, proxyPoolStatic, 1, "", "gpt-5.5")

			if got.Verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q (status %d, detail %q)",
					got.Verdict, tc.verdict, tc.status, got.Detail)
			}
			if got.StatusCode != tc.status {
				t.Fatalf("status_code = %d, want %d", got.StatusCode, tc.status)
			}
			// trace 无论判决都装饰每行，被拒出口尤其要看地址，挨骂的人也得报座位。
			if got.ExitIP != "203.0.113.7" || got.Country != "GB" || got.Colo != "LHR" {
				t.Fatalf("trace fields not reported: ip=%q loc=%q colo=%q",
					got.ExitIP, got.Country, got.Colo)
			}
		})
	}
}

func TestProxyCheckSendsNoCredential(t *testing.T) {
	// 业务和探针活着也能安全检查，全靠不带 Authorization；一旦带上就烧配额并可能触发账号限流，白票别变收费票。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	trace := newFakeTrace(t)
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, trace.server.URL)

	pool := newProbeClientPool()
	defer pool.closeIdle()
	proxyCheckOne(t.Context(), pool, proxyPoolStatic, 1, "", "gpt-5.5")

	auths := upstream.auths()
	if len(auths) == 0 {
		t.Fatal("the upstream was never called")
	}
	for i, value := range auths {
		if value != "" {
			t.Fatalf("call %d carried an Authorization header (%q); this check must spend no quota", i, value)
		}
	}
}

func TestProxyCheckSeparatesUnreachableFromRefused(t *testing.T) {
	// 拨不通叫 dead，不叫 blocked；两种病找不同大夫，分清就是功能本身。
	trace := newFakeTrace(t)
	setTraceURL(t, trace.server.URL)
	// .invalid 为 RFC 2606 保留且不解析，道具门牌没有真住户。
	setUpstream(t, "http://exit.invalid:9/responses")

	pool := newProbeClientPool()
	defer pool.closeIdle()
	got := proxyCheckOne(t.Context(), pool, proxyPoolStatic, 1, "", "gpt-5.5")

	if got.Verdict != proxyVerdictDead {
		t.Fatalf("verdict = %q, want %q for an exit that cannot be reached", got.Verdict, proxyVerdictDead)
	}
	if got.StatusCode != 0 {
		t.Fatalf("status_code = %d, want 0 when no response was ever received", got.StatusCode)
	}
}

func TestProxyCheckSurvivesATraceOutage(t *testing.T) {
	// 地址只是配菜，trace 失败只能少地址，不能改 API 请求判决，配菜糊了不算主菜没熟。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, "http://trace.invalid:9/cdn-cgi/trace")

	pool := newProbeClientPool()
	defer pool.closeIdle()
	got := proxyCheckOne(t.Context(), pool, proxyPoolStatic, 1, "", "gpt-5.5")

	if got.Verdict != proxyVerdictOK {
		t.Fatalf("verdict = %q, want %q; a trace outage must not change the verdict", got.Verdict, proxyVerdictOK)
	}
	if got.ExitIP != "" {
		t.Fatalf("exit_ip = %q, want empty when the trace failed", got.ExitIP)
	}
}

// --- 批次：一桌一桌验 ---

func TestProxyCheckEmptyPoolChecksTheDirectExit(t *testing.T) {
	// 空池是合法配置，probeExits 会变一次直连；检查该给这条路成绩，不可因菜单空白拒绝开灶。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	trace := newFakeTrace(t)
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, trace.server.URL)
	mustConfigure(t, checkConfig(t, t.TempDir()))

	resp := driveResource(t, opsProxyCheckPath, confirmed(nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := decodeProxyCheck(t, resp.Body)
	if !got.Direct {
		t.Fatal("direct = false; an empty pool means the box's own egress and should say so")
	}
	if got.Checked != 1 || got.OK != 1 {
		t.Fatalf("checked=%d ok=%d, want 1 and 1", got.Checked, got.OK)
	}
	if got.Note == "" {
		t.Fatal("no note explaining that the pool is empty")
	}
}

func TestProxyCheckCountsDistinctExitAddresses(t *testing.T) {
	// 这题要揭穿同一网关多凭据可能全穿同一地址外套；页面别处看不出它们是一个出口。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	trace := newFakeTrace(t)
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, trace.server.URL)

	var hitsA, hitsB atomic.Int64
	proxyA := newFakeProxy(t, &hitsA)
	proxyB := newFakeProxy(t, &hitsB)
	mustConfigure(t, checkConfig(t, t.TempDir(), proxyA, proxyB))

	resp := driveResource(t, opsProxyCheckPath, confirmed(nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := decodeProxyCheck(t, resp.Body)
	if got.Checked != 2 {
		t.Fatalf("checked = %d, want 2", got.Checked)
	}
	// 两出口转发到同一个 trace，报回同一门牌。
	if got.DistinctIPs != 1 {
		t.Fatalf("distinct_ips = %d, want 1 -- two pool entries sharing one address must be visible",
			got.DistinctIPs)
	}
	// 遮罩后长一样的条目，只靠位置认座位，排号别弄丢。
	if len(got.Results) != 2 || got.Results[0].Index != 1 || got.Results[1].Index != 2 {
		t.Fatalf("results are not indexed 1..n: %+v", got.Results)
	}
}

// --- 禁区：失败也不准交出密码 ---

func TestProxyCheckNeverLeaksAProxyPassword(t *testing.T) {
	// 结果在免密页展示，摘要还会被日志贴进工单；死出口最险，传输错常带拨号 URL，
	// 别把失败诊断变成密码报纸。
	trace := newFakeTrace(t)
	setTraceURL(t, trace.server.URL)
	setUpstream(t, "http://exit.invalid:9/responses")
	mustConfigure(t, checkConfig(t, t.TempDir(), testProxyWithPW))

	var resp mgmtResponse
	logged := captureLog(t, func() {
		resp = driveResource(t, opsProxyCheckPath, confirmed(nil))
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), testProxySecret) {
		t.Fatalf("the proxy password reached the keyless response body:\n%s", resp.Body)
	}
	if strings.Contains(logged, testProxySecret) {
		t.Fatalf("the proxy password reached the log:\n%s", logged)
	}

	got := decodeProxyCheck(t, resp.Body)
	if len(got.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(got.Results))
	}
	if got.Results[0].Verdict != proxyVerdictDead {
		t.Fatalf("verdict = %q, want %q for an unresolvable exit", got.Results[0].Verdict, proxyVerdictDead)
	}
	// 要遮罩不是删行；运营者还得知道是哪个出口摔跤。
	if !strings.Contains(got.Results[0].Proxy, "***@exit.invalid:1080") {
		t.Fatalf("proxy = %q, want the userinfo replaced wholesale", got.Results[0].Proxy)
	}
}

// --- 路由注册：免密是选择不是失手 ---

func TestProxyCheckIsRegisteredKeylessWithoutAMenu(t *testing.T) {
	// GET 管理路由带 Menu 会被宿主偷偷注册到未鉴权前缀；本路由有意免密且不带 Menu，
	// 别把明确的安排演成误开后门。
	reg := driveManagementRegister(t)
	var found bool
	for _, route := range reg.Resources {
		if route.Path == routeOpsProxyCheck {
			found = true
			if route.Menu != "" {
				t.Fatalf("the proxy-check route declares Menu %q; it is data the page fetches, not a page to navigate to", route.Menu)
			}
		}
	}
	if !found {
		t.Fatalf("%s is not registered as a resource route", routeOpsProxyCheck)
	}
	for _, route := range reg.Routes {
		if strings.Contains(route.Path, "proxy-check") {
			t.Fatal("the proxy-check route is also declared as a management route; one home only")
		}
	}
}

// --- 两种池：静态与轮换分班 ---

// rotatingTrace 每请求报不同地址，模拟住宅网关每次换一件外套。
type rotatingTrace struct {
	mu     sync.Mutex
	n      int
	server *httptest.Server
}

func newRotatingTrace(t *testing.T) *rotatingTrace {
	t.Helper()
	tr := &rotatingTrace{}
	tr.server = httptest.NewServer(tr)
	t.Cleanup(tr.server.Close)
	return tr
}

func (f *rotatingTrace) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf("ip=203.0.113.%d\nloc=GB\ncolo=LHR\n", n)))
}

func TestProxyCheckFlagsARotatingEntryDeclaredStatic(t *testing.T) {
	// 只标有证据的方向：同条目出现两个地址就不可能固定，设 static 一定错。
	// 错了会从轮换的每十分钟十次变成静态每 55 分钟一次，静默饿桶才最难看见。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, newRotatingTrace(t).server.URL)

	var hits atomic.Int64
	exit := newFakeProxy(t, &hits)
	mustConfigure(t, checkConfig(t, t.TempDir(), exit))

	resp := driveResource(t, opsProxyCheckPath, confirmed(nil))
	got := decodeProxyCheck(t, resp.Body)
	if len(got.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(got.Results))
	}
	row := got.Results[0]
	if !row.Rotated {
		t.Fatal("two samples returned different addresses but rotated is false")
	}
	if row.Mismatch == "" {
		t.Fatal("a rotating entry sitting in the static pool was not flagged")
	}
	if got.Mismatches != 1 {
		t.Fatalf("mismatches = %d, want 1", got.Mismatches)
	}
}

func TestProxyCheckDoesNotFlagASteadyRotatingEntry(t *testing.T) {
	// 反过来不能推：小网关池偶然重复地址很正常；标错会劝用户把正确配置改坏，别靠撞衫认双胞胎。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	trace := newFakeTrace(t) // 每次同一地址，外套不换也照样点名
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, trace.server.URL)

	var hits atomic.Int64
	exit := newFakeProxy(t, &hits)
	mustConfigure(t, checkConfig(t, t.TempDir())+
		"probe_proxies_rotating:\n  - "+jsonQuote(exit)+"\n")

	resp := driveResource(t, opsProxyCheckPath, confirmed(nil))
	got := decodeProxyCheck(t, resp.Body)
	if len(got.Results) != 1 || got.Results[0].Pool != proxyPoolRotating {
		t.Fatalf("the rotating pool was not checked: %+v", got.Results)
	}
	if got.Results[0].Mismatch != "" || got.Mismatches != 0 {
		t.Fatalf("a rotating entry that happened to repeat an address was flagged: %q", got.Results[0].Mismatch)
	}
}

func TestProxyCheckCountsDistinctAddressesForTheStaticPoolOnly(t *testing.T) {
	// distinct_ips 问的是几个静态条目是否暗中共用一出口；轮换本该次次变，
	// 算进去只会把数字变成轮换条目数的复读机。
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	setUpstream(t, upstream.server.URL)
	setTraceURL(t, newRotatingTrace(t).server.URL)

	var hits atomic.Int64
	exit := newFakeProxy(t, &hits)
	mustConfigure(t, checkConfig(t, t.TempDir())+
		"probe_proxies_rotating:\n  - "+jsonQuote(exit)+"\n")

	resp := driveResource(t, opsProxyCheckPath, confirmed(nil))
	got := decodeProxyCheck(t, resp.Body)
	if got.StaticChecked != 0 {
		t.Fatalf("static_checked = %d, want 0 -- only a rotating entry was configured", got.StaticChecked)
	}
	if got.DistinctIPs != 0 {
		t.Fatalf("distinct_ips = %d, want 0: rotating addresses must not be counted", got.DistinctIPs)
	}
}
