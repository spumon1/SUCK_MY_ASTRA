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

// The proxy checker's contract, in one sentence: it must tell an operator which
// exits can reach OpenAI without spending a single unit of account quota and
// without ever printing a proxy password.
//
// Two properties here are load-bearing and easy to break by "improving" the
// code later:
//
//   - The outbound request carries NO credential. The moment someone adds an
//     Authorization header to make the check "more realistic", this stops being
//     free and starts counting against an account -- and it would still pass a
//     naive "did it work" test.
//   - "Could not connect" and "connected and was refused" stay different
//     verdicts. Collapsing them sends the operator to the wrong place: the first
//     is the proxy vendor's problem, the second is the exit's reputation.

const opsProxyCheckPath = mgmtResourcePath + "ops/proxy-check"

// --- fakes ---------------------------------------------------------------

// fakeCheckUpstream stands in for the codex endpoint and records what every
// caller sent, which is how the "no credential" property is asserted rather
// than assumed.
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

// fakeTrace stands in for Cloudflare's /cdn-cgi/trace.
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
	// Real trace documents carry a dozen keys; only three are read, and the extra
	// ones here prove the parser ignores what it does not recognise.
	_, _ = w.Write([]byte("fl=1a2b3c\nh=chatgpt.com\nip=" + ip +
		"\nts=1750000000\nvisit_scheme=https\ncolo=" + colo +
		"\nloc=" + loc + "\ntls=TLSv1.3\n"))
}

// setTraceURL points the trace probe at a fake for one test.
func setTraceURL(t *testing.T, rawURL string) {
	t.Helper()
	previous := proxyCheckTraceURL
	proxyCheckTraceURL = rawURL
	t.Cleanup(func() { proxyCheckTraceURL = previous })
}

// checkConfig is a minimal valid config carrying the given proxy pool.
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

// --- the keyless gate ----------------------------------------------------

func TestProxyCheckRequiresConfirm(t *testing.T) {
	// It dials every exit in the pool, so a bare navigation or a link prefetch
	// must not be able to fire it.
	mustConfigure(t, checkConfig(t, t.TempDir()))

	resp := driveResource(t, opsProxyCheckPath, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the proxy check ran without confirm=1; a prefetch could dial the whole pool")
	}
}

// --- the verdicts --------------------------------------------------------

func TestProxyCheckVerdictsFollowTheUpstreamStatus(t *testing.T) {
	// 401 is the success case: no credential was sent, so being told "no
	// credential" proves the request reached OpenAI rather than dying in the
	// proxy. Everything else is a distinct diagnosis.
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
			// The trace decorates every row regardless of the verdict: an exit
			// that is refused is exactly the one whose address you want to see.
			if got.ExitIP != "203.0.113.7" || got.Country != "GB" || got.Colo != "LHR" {
				t.Fatalf("trace fields not reported: ip=%q loc=%q colo=%q",
					got.ExitIP, got.Country, got.Colo)
			}
		})
	}
}

func TestProxyCheckSendsNoCredential(t *testing.T) {
	// The whole reason this check is safe to run while business traffic and a
	// probe are both live. If an Authorization header ever appears here, the
	// check starts costing quota and can trip an account's rate limit.
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
	// An exit that cannot be dialled is "dead", never "blocked". They send the
	// operator to different places, so the distinction is the feature.
	trace := newFakeTrace(t)
	setTraceURL(t, trace.server.URL)
	// .invalid is reserved by RFC 2606 and can never resolve.
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
	// The address is decoration. A trace that fails must cost the address and
	// nothing else -- the verdict belongs to the API request alone.
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

// --- the batch -----------------------------------------------------------

func TestProxyCheckEmptyPoolChecksTheDirectExit(t *testing.T) {
	// An empty pool is a real configuration -- probeExits turns it into a single
	// direct attempt -- so the check has to report on that, not refuse.
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
	// The insight this exists for: a pool of credentials on one gateway can be
	// many entries wearing one address. Nothing else on the page reveals it.
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
	// Both exits forward to the same trace, which reports one address.
	if got.DistinctIPs != 1 {
		t.Fatalf("distinct_ips = %d, want 1 -- two pool entries sharing one address must be visible",
			got.DistinctIPs)
	}
	// Positions are the only handle the page has on entries that mask alike.
	if len(got.Results) != 2 || got.Results[0].Index != 1 || got.Results[1].Index != 2 {
		t.Fatalf("results are not indexed 1..n: %+v", got.Results)
	}
}

// --- the thing that must never happen ------------------------------------

func TestProxyCheckNeverLeaksAProxyPassword(t *testing.T) {
	// The results render on a page that needs no key, and the summary goes to a
	// log that gets pasted into tickets. A dead exit is the dangerous case: its
	// detail carries a transport error, and a transport error quotes the URL it
	// failed to dial.
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
	// Masked, not omitted: the operator still needs to see which exit it was.
	if !strings.Contains(got.Results[0].Proxy, "***@exit.invalid:1080") {
		t.Fatalf("proxy = %q, want the userinfo replaced wholesale", got.Results[0].Proxy)
	}
}

// --- route registration --------------------------------------------------

func TestProxyCheckIsRegisteredKeylessWithoutAMenu(t *testing.T) {
	// A GET management route that declares a Menu is silently re-registered
	// under the unauthenticated prefix by the host. This one belongs on the
	// keyless prefix by choice, and must carry no Menu -- otherwise it is
	// keyless by accident, which is the failure mode that rule exists for.
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

// --- the two pools --------------------------------------------------------

// rotatingTrace serves a different address on every request, which is what a
// residential gateway actually does.
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
	// Only the provable direction is flagged. Two different addresses from one
	// entry cannot happen on a fixed exit, so declaring it static is definitely
	// wrong -- and the cost of getting it wrong is silent: the probe would give
	// that entry one attempt per 55 minutes instead of ten per ten.
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
	// The other direction is NOT proof: a small gateway pool repeats an address
	// by chance. Flagging it would tell the operator to undo a correct setting.
	upstream := newFakeCheckUpstream(t, http.StatusUnauthorized)
	trace := newFakeTrace(t) // same address every time
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
	// distinct_ips answers "are several static entries secretly one exit". A
	// rotating entry is supposed to differ every time, so counting it here would
	// turn the figure into a restatement of how many rotating entries there are.
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
