package main

// Route-cookie tests. The mechanics being pinned: __cflb/__oailb are a GLOBAL
// routing credential -- a pair minted anywhere serves every Codex account, so
// the pool is keyed by the pair values themselves, never by an account. The
// request side merges the pool's best live entry onto attributable Codex
// traffic; the response side folds every Set-Cookie pair back into the pool.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setCookieHeaders builds a response header carrying the given Set-Cookie lines.
func setCookieHeaders(turnState string, lines ...string) http.Header {
	h := http.Header{}
	if turnState != "" {
		h.Set(testHeader, turnState)
	}
	for _, line := range lines {
		h.Add("Set-Cookie", line)
	}
	return h
}

// --- parsing ---------------------------------------------------------------

func TestRouteCookiesKeepsOnlyTheLoadBalancerPair(t *testing.T) {
	h := setCookieHeaders("",
		"__cflb=cf-pair-1; Path=/; HttpOnly",
		"__oailb=lb-pair-2; Path=/",
		"oai-did=device-identity; Path=/",                   // identity cookie: never replayed
		"__Secure-session-token=session-material; HttpOnly", // session material: never replayed
		"__cf_bm=bot-management; Path=/",                    // not part of the pair
	)
	set := routeCookiesFromResponseHeaders(h, testNow)
	if len(set.pairs) != 2 {
		t.Fatalf("kept %d cookies, want exactly the LB pair: %v", len(set.pairs), set.pairs)
	}
	if set.pairs["__cflb"] != "cf-pair-1" || set.pairs["__oailb"] != "lb-pair-2" {
		t.Fatalf("pairs = %v", set.pairs)
	}
}

func TestRouteCookiesMatchesUnderscoreVariants(t *testing.T) {
	// The upstream spelling has been observed as __cflb/__oailb; the match is on
	// the name with leading underscores stripped so a _cflb variant still lands.
	h := setCookieHeaders("", "_cflb=one-underscore", "___oailb=three-underscores")
	set := routeCookiesFromResponseHeaders(h, testNow)
	if set.pairs["_cflb"] != "one-underscore" || set.pairs["___oailb"] != "three-underscores" {
		t.Fatalf("underscore variants not kept: %v", set.pairs)
	}
}

func TestRouteCookiesHonoursMaxAge(t *testing.T) {
	h := setCookieHeaders("",
		"__cflb=a; Max-Age=120",
		"__oailb=b; Max-Age=300",
	)
	set := routeCookiesFromResponseHeaders(h, testNow)
	if !set.expireAt.Equal(testNow.Add(120 * time.Second)) {
		t.Fatalf("expireAt = %s, want the earlier declared deadline (120s)", set.expireAt)
	}
}

func TestRouteCookiesHonoursExpires(t *testing.T) {
	// __cflb is issued with Expires only -- a Max-Age-only reader would treat
	// its declared lifetime as absent.
	expires := testNow.Add(time.Hour).UTC().Format(http.TimeFormat)
	set := routeCookiesFromResponseHeaders(setCookieHeaders("", "__cflb=a; Expires="+expires), testNow)
	want, err := http.ParseTime(expires)
	if err != nil {
		t.Fatalf("test bug: %v", err)
	}
	if !set.expireAt.Equal(want) {
		t.Fatalf("expireAt = %s, want the declared Expires %s", set.expireAt, want)
	}
}

func TestRouteCookiesPastExpiresIsADeletion(t *testing.T) {
	past := testNow.Add(-time.Minute).UTC().Format(http.TimeFormat)
	set := routeCookiesFromResponseHeaders(setCookieHeaders("",
		"__cflb=retired; Expires="+past, "__oailb=live"), testNow)
	if _, ok := set.pairs["__cflb"]; ok {
		t.Fatal("a cookie whose Expires already passed was stored as a live value")
	}
	if set.pairs["__oailb"] != "live" {
		t.Fatalf("the surviving cookie was dropped with the deletion: %v", set.pairs)
	}
}

func TestRouteCookiesEarlierOfMaxAgeAndExpiresWins(t *testing.T) {
	expires := testNow.Add(time.Hour).UTC().Format(http.TimeFormat)
	set := routeCookiesFromResponseHeaders(setCookieHeaders("",
		"__cflb=a; Expires="+expires+"; Max-Age=120"), testNow)
	if !set.expireAt.Equal(testNow.Add(120 * time.Second)) {
		t.Fatalf("expireAt = %s, want the earlier of the two declarations (Max-Age 120s)", set.expireAt)
	}
}

func TestRouteCookiesUnparseableExpiresIsIgnored(t *testing.T) {
	// A malformed Expires is ignored rather than honoured: it must not become
	// an absent deadline, and must not become a deadline either.
	set := routeCookiesFromResponseHeaders(setCookieHeaders("", "__cflb=a; Expires=not-a-date"), testNow)
	if set.pairs["__cflb"] != "a" {
		t.Fatalf("the cookie itself was dropped over a bad Expires: %v", set.pairs)
	}
	if !set.expireAt.IsZero() {
		t.Fatalf("an unparseable Expires produced a deadline: %s", set.expireAt)
	}
}

func TestRouteCookiesDeletionIsNotAValue(t *testing.T) {
	h := setCookieHeaders("", "__cflb=gone; Max-Age=0", "__oailb=live; Max-Age=200")
	set := routeCookiesFromResponseHeaders(h, testNow)
	if _, ok := set.pairs["__cflb"]; ok {
		t.Fatal("a Max-Age=0 deletion was stored as a live value")
	}
	if set.pairs["__oailb"] != "live" {
		t.Fatalf("the surviving cookie was dropped with the deletion: %v", set.pairs)
	}
}

func TestRouteCookiesRejectsSmuggledShapes(t *testing.T) {
	h := setCookieHeaders("",
		"__cflb=va,lue",       // comma inside the value -- would corrupt the merge
		"__ cflb=spaced-name", // space inside the name
		"__oailb=ok; Path=/",
	)
	set := routeCookiesFromResponseHeaders(h, testNow)
	if len(set.pairs) != 1 || set.pairs["__oailb"] != "ok" {
		t.Fatalf("unsafe shapes were not rejected: %v", set.pairs)
	}
}

// --- usability -------------------------------------------------------------

func TestRouteCookieSetUsable(t *testing.T) {
	ttl := 240 * time.Second
	fresh := routeCookieSet{pairs: map[string]string{"__cflb": "v"}, seenAt: testNow}

	tests := []struct {
		name string
		set  routeCookieSet
		at   time.Time
		want bool
	}{
		{"fresh", fresh, testNow.Add(time.Minute), true},
		{"empty", routeCookieSet{seenAt: testNow}, testNow, false},
		{"expired", fresh, testNow.Add(ttl), false},
		{"future-stamped", routeCookieSet{pairs: map[string]string{"__cflb": "v"}, seenAt: testNow.Add(time.Hour)}, testNow, false},
		{"past declared Max-Age", routeCookieSet{pairs: map[string]string{"__cflb": "v"}, seenAt: testNow, expireAt: testNow.Add(time.Minute)}, testNow.Add(2 * time.Minute), false},
		{"inside declared Max-Age", routeCookieSet{pairs: map[string]string{"__cflb": "v"}, seenAt: testNow, expireAt: testNow.Add(time.Minute)}, testNow.Add(30 * time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.set.usable(tc.at, ttl); got != tc.want {
				t.Errorf("usable() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRouteCookieSecondsLeftUsesTheEarlierDeadline(t *testing.T) {
	e := routeCookieEntry{
		Pairs:    map[string]string{"__cflb": "v"},
		SeenAt:   testNow.UTC().Format(time.RFC3339),
		ExpireAt: testNow.Add(time.Minute).UTC().Format(time.RFC3339), // declared deadline wins over the longer ttl
	}
	if got := entrySecondsLeft(e, testNow, 240*time.Second); got != 60 {
		t.Fatalf("entrySecondsLeft = %d, want 60 (the declared deadline, not the ttl)", got)
	}
}

// --- request-header merge ----------------------------------------------------

func TestMergeRouteCookiesOverlaysOnlyItsOwnNames(t *testing.T) {
	pairs := map[string]string{"__cflb": "fresh-cf", "__oailb": "fresh-lb"}
	merged := mergeRouteCookies("oai-did=device-1; __cflb=stale-cf", pairs)
	want := "oai-did=device-1; __cflb=fresh-cf; __oailb=fresh-lb"
	if merged != want {
		t.Fatalf("merged = %q, want %q", merged, want)
	}
	// The client's own cookies keep their place; the pooled pair replaces the
	// stale same-named entry and appends the missing one.
	if !strings.HasPrefix(merged, "oai-did=device-1") {
		t.Fatalf("client cookies were reordered or dropped: %q", merged)
	}
}

func TestMergeRouteCookiesNoSetIsIdentity(t *testing.T) {
	if got := mergeRouteCookies("a=b", nil); got != "a=b" {
		t.Fatalf("empty set rewrote the header: %q", got)
	}
	if got := mergeRouteCookies("", map[string]string{"__cflb": "v"}); got != "__cflb=v" {
		t.Fatalf("empty request header did not get the set: %q", got)
	}
}

// --- pool round-trip ---------------------------------------------------------

// seedPoolEntry folds a pair into the in-memory pool the same way the harvest
// paths do on a sighting.
func seedPoolEntry(t *testing.T, pairs map[string]string, seenAt time.Time, via string) {
	t.Helper()
	state.mu.Lock()
	state.noteRouteCookiesLocked(routeCookieSet{pairs: pairs, seenAt: seenAt}, via)
	state.mu.Unlock()
}

func TestPoolFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	set := map[string]string{"__cflb": "cf", "__oailb": "lb"}
	key := cookieEntryKey(set)
	pool := map[string]*routeCookieEntry{
		key: {Pairs: set, Gateway: gatewayLabel(set), SeenAt: testNow.UTC().Format(time.RFC3339)},
	}
	if err := writeRouteCookiePool(dir, pool, testNow, testTTL); err != nil {
		t.Fatalf("writeRouteCookiePool: %v", err)
	}
	loaded := loadRouteCookiePool(dir)
	if len(loaded) != 1 || loaded[key].Pairs["__cflb"] != "cf" {
		t.Fatalf("pool round trip lost the entry: %v", loaded)
	}
}

func TestPoolWriteDropsDeadEntries(t *testing.T) {
	dir := t.TempDir()
	dead := map[string]string{"__cflb": "dead"}
	live := map[string]string{"__cflb": "live"}
	pool := map[string]*routeCookieEntry{
		cookieEntryKey(dead): {Pairs: dead, SeenAt: testNow.Add(-2 * time.Hour).UTC().Format(time.RFC3339)},
		cookieEntryKey(live): {Pairs: live, SeenAt: testNow.UTC().Format(time.RFC3339)},
	}
	if err := writeRouteCookiePool(dir, pool, testNow, testTTL); err != nil {
		t.Fatalf("writeRouteCookiePool: %v", err)
	}
	loaded := loadRouteCookiePool(dir)
	if len(loaded) != 1 {
		t.Fatalf("dead entries were persisted: %v", loaded)
	}
	if _, ok := loaded[cookieEntryKey(live)]; !ok {
		t.Fatal("the live entry was pruned with the dead one")
	}
}

func TestPoolEntryKeyDedupesByValueNotOrigin(t *testing.T) {
	// Two mints that produce the same pairs collapse to one entry -- they ARE
	// the same credential. Two exits landing on the same node is exactly that
	// case.
	state.mu.Lock()
	state.cookies = make(map[string]*routeCookieEntry)
	state.mu.Unlock()
	pairs := map[string]string{"__cflb": "same", "__oailb": "same2"}
	seedPoolEntry(t, pairs, testNow, "exit-a")
	seedPoolEntry(t, pairs, testNow.Add(time.Minute), "exit-b")
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.cookies) != 1 {
		t.Fatalf("identical pairs did not dedupe: %d entries", len(state.cookies))
	}
}

// --- request side ------------------------------------------------------------

func TestSteerAttachesThePoolPair(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf", "__oailb": "lb"}, time.Now(), "")

	req := request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77))
	req.Headers.Set("Cookie", "oai-did=device-1")
	resp := interceptAfter(t, req)

	cookie := resp.Headers.Get("Cookie")
	if !strings.Contains(cookie, "__cflb=cf") || !strings.Contains(cookie, "__oailb=lb") {
		t.Fatalf("the pooled pair was not attached: %q", cookie)
	}
	if !strings.Contains(cookie, "oai-did=device-1") {
		t.Fatalf("the client's own cookie was dropped: %q", cookie)
	}
	// The plugin never writes the turn-state header itself.
	if got := outgoingHeader(resp); got != "" {
		t.Fatalf("the plugin wrote a turn-state header: %q", got)
	}
}

func TestSteerAttachesWithoutAClientTicket(t *testing.T) {
	// The pair is the credential under reuse now, not something that keeps a
	// ticket alive -- so an attributable request gets it whether or not the
	// request carries a state of its own.
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")

	resp := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", ""))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("an attributable request without a ticket was not steered: %q", cookie)
	}
}

func TestSteerRefusesNonCodexAccount(t *testing.T) {
	// Rule 1: the pair is OpenAI's credential and must never ride on traffic
	// bound for another provider's upstream. An attributable but non-Codex
	// auth id is refused the same way an unattributable one is.
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")

	resp := interceptAfter(t, request("gemini-someone.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("a non-Codex request carried the pool pair: %q", cookie)
	}
	resp2 := interceptAfter(t, request("", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp2.Headers.Get("Cookie"); cookie != "" {
		t.Fatalf("an unattributable request carried the pool pair: %q", cookie)
	}
}

func TestPoolServesEveryCodexAccount(t *testing.T) {
	// The pool is global: a pair minted anywhere serves every Codex account --
	// that is the whole point of collecting it. "Cross-account" only applies to
	// credentials of a DIFFERENT provider, which the previous test pins.
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf-a"}, time.Now(), "")

	resp := interceptAfter(t, request("codex-b.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "cf-a") {
		t.Fatalf("the global pair was not served to a second Codex account: %q", cookie)
	}
}

func TestDryRunAttachesNothing(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, true))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")

	resp := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if got := outgoingHeader(resp); got != "" {
		t.Fatal("dry_run rewrote the state header")
	}
	if cookie := resp.Headers.Get("Cookie"); cookie != "" {
		t.Fatalf("dry_run attached cookies: %q", cookie)
	}
}

func TestNoLivePairNoWrite(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	state.mu.Lock()
	state.cookies = make(map[string]*routeCookieEntry)
	state.mu.Unlock()

	resp := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); cookie != "" {
		t.Fatalf("an empty pool still attached cookies: %q", cookie)
	}
}

// --- harvest side ------------------------------------------------------------

func TestHarvestPoolsThePair(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	resetHarvestState(t)

	meta := map[string]any{testAuthKey: "codex-alpha.json"}
	headers := setCookieHeaders(fakeToken(292, wallClock().Add(-time.Minute)),
		"__cflb=cf-minted; Max-Age=200", "__oailb=lb-minted", "oai-did=not-stored")

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()
	harvestFromResponse(cfg, headers, meta, "gpt-5.5", "")

	state.mu.Lock()
	defer state.mu.Unlock()
	e, ok := state.cookies[cookieEntryKey(map[string]string{"__cflb": "cf-minted", "__oailb": "lb-minted"})]
	if !ok {
		t.Fatalf("the minted pair was not pooled: %v", state.cookies)
	}
	if _, bad := e.Pairs["oai-did"]; bad {
		t.Fatal("an identity cookie was pooled; only the LB pair may be replayed")
	}
	if e.ExpireAt == "" {
		t.Fatal("the declared Max-Age was not kept on the entry")
	}
}

func TestHarvestPoolsOnSilentAndDegradedResponses(t *testing.T) {
	// The pair is minted at the edge and does not depend on the serving state:
	// a silent response and a 312 both still deliver it, and both belong in the
	// pool.
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	resetHarvestState(t)

	meta := map[string]any{testAuthKey: "codex-alpha.json"}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()
	harvestFromResponse(cfg, setCookieHeaders("", "__cflb=silent", "__oailb=lb1"), meta, "gpt-5.5", "")
	harvestFromResponse(cfg, setCookieHeaders(fakeToken(312, wallClock()), "__cflb=degraded", "__oailb=lb2"), meta, "gpt-5.5", "")

	state.mu.Lock()
	defer state.mu.Unlock()
	if _, ok := state.cookies[cookieEntryKey(map[string]string{"__cflb": "silent", "__oailb": "lb1"})]; !ok {
		t.Fatal("the silent response's pair was not pooled")
	}
	if _, ok := state.cookies[cookieEntryKey(map[string]string{"__cflb": "degraded", "__oailb": "lb2"})]; !ok {
		t.Fatal("the 312 response's pair was not pooled")
	}
}

func TestHarvestPoolsWithoutAttribution(t *testing.T) {
	// The pair is a GLOBAL credential -- it is not filed under an account, so
	// there is nothing to attribute. A response with no account metadata still
	// feeds the pool.
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	resetHarvestState(t)

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()
	harvestFromResponse(cfg, setCookieHeaders("", "__cflb=orphan"), map[string]any{}, "gpt-5.5", "")

	state.mu.Lock()
	defer state.mu.Unlock()
	if _, ok := state.cookies[cookieEntryKey(map[string]string{"__cflb": "orphan"})]; !ok {
		t.Fatal("an unattributed pair was dropped; the pool is global and needs none")
	}
}

func TestSteeredPairGetsOutcomeMarks(t *testing.T) {
	// A request that left carrying a pool entry reports back through the
	// pendingAuth relay: a normal signed state marks the entry good, a degraded
	// one marks it bad and deprioritises it for the next pick.
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	resetHarvestState(t)
	pairs := map[string]string{"__cflb": "cf", "__oailb": "lb"}
	seedPoolEntry(t, pairs, time.Now(), "")
	key := cookieEntryKey(pairs)

	req := request("codex-a.json", "gpt-5.5", fakeTokenSeed(312, wallClock(), 0x77))
	req.RequestID = "req-marked"
	interceptAfter(t, req)

	meta := map[string]any{}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()
	harvestFromResponse(cfg, setCookieHeaders(fakeToken(292, wallClock())), meta, "gpt-5.5", "req-marked")

	state.mu.Lock()
	e := state.cookies[key]
	good := e.GoodAt
	state.mu.Unlock()
	if good == "" {
		t.Fatal("a normal state on a steered request did not mark the pair good")
	}
}

// --- probe side --------------------------------------------------------------

func TestProbeMintsBareAndPools(t *testing.T) {
	// A mint call goes out BARE: carrying a pair pins the node, and the edge
	// sets no new cookies on a steered request -- so collecting means sending
	// nothing. The response's pair lands in the global pool.
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.setCookies = []string{"__cflb=cf-minted; Path=/", "__oailb=lb-minted; Path=/"}
	setUpstream(t, upstream.server.URL)

	cfg, cred, pool := harvestTestConfig(t)
	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, nil, 0) {
		t.Fatal("first harvest fired nothing")
	}
	calls := upstream.snapshot()
	if calls[0].cookie != "" {
		t.Fatalf("the mint call carried cookies -- a carried pair stops the edge minting: %q", calls[0].cookie)
	}

	state.mu.Lock()
	_, pooled := state.cookies[cookieEntryKey(map[string]string{"__cflb": "cf-minted", "__oailb": "lb-minted"})]
	state.mu.Unlock() // explicit, not deferred: the second harvest below takes this lock again
	if !pooled {
		t.Fatalf("the minted pair was not pooled: %v", state.cookies)
	}

	// The next mint goes out bare too -- the pool exists for the business side
	// to steer with, never for the probe to send back.
	if !probeHarvestBucket(context.Background(), cfg, pool, cred, "gpt-runner-2", nil, nil, 0) {
		t.Fatal("second harvest fired nothing")
	}
	calls = upstream.snapshot()
	if len(calls) != 2 {
		t.Fatalf("upstream calls = %d, want 2", len(calls))
	}
	if calls[1].cookie != "" {
		t.Fatalf("the second mint carried the pooled pair: %q", calls[1].cookie)
	}
}

func TestProbeSuccessRestAlignsWithRenewal(t *testing.T) {
	// A spent-or-throttled triple rests probeExitCooldown; a successful one must
	// be back on the table exactly when its template wants renewing
	// (ttl - probeRenewThreshold), or a 240s template would lapse inside a
	// 55-minute rest. The config uses a short ttl so the success window is
	// visibly inside the failure cooldown.
	resetProbeRunner(t)
	upstream := newFakeUpstream(t) // 200 + 292 by default
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)

	var hitsA atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	cfg, cred, pool := harvestTestConfig(t)
	cfg.TTLSeconds = 300 // successRest = 300 - 90 = 210s << probeExitCooldown

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{exitA}, nil, 0) {
		t.Fatal("harvest fired nothing")
	}
	now := time.Now()
	rest := probeSuccessRest(cfg)
	if probeCooldownReady(exitA, cred.name, probeTestModel, now.Add(rest-time.Second)) {
		t.Fatal("the minting exit was free before the renewal window -- the success rest did not apply")
	}
	if !probeCooldownReady(exitA, cred.name, probeTestModel, now.Add(rest+time.Minute)) {
		t.Fatal("the minting exit is still resting past the renewal window -- the template will lapse before it can be redialed")
	}
}

func TestProbeThrottledTripleKeepsTheLongRest(t *testing.T) {
	// Contrast for the test above: a 312 changes nothing about how long the
	// exit sits out -- it is the IP being throttled, and re-dialing it inside
	// the window only earns 429s.
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 312
	setUpstream(t, upstream.server.URL)

	var hitsA atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	cfg, cred, pool := harvestTestConfig(t)
	cfg.TTLSeconds = 300 // same short ttl as the success case -- the difference under test is the outcome, not the clock

	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{exitA}, nil, 0) {
		t.Fatal("harvest fired nothing")
	}
	now := time.Now()
	if probeCooldownReady(exitA, cred.name, probeTestModel, now.Add(probeSuccessRest(cfg))) {
		t.Fatal("a throttled exit was released at the success window -- it must rest the full cooldown")
	}
	if probeCooldownReady(exitA, cred.name, probeTestModel, now.Add(probeExitCooldown-time.Minute)) {
		t.Fatal("a throttled exit was released inside the cooldown window")
	}
}

// A 312 that still sets a pair pools the pair but does NOT count as stored:
// the edge mints the cookie regardless of serving state, while the exit's IP
// is throttled for this bucket -- so the walk must move on to the next exit.
func TestProbeConsumePaired312PoolsButTriesNext(t *testing.T) {
	resetProbeRunner(t)
	cfg := pluginConfig{
		StoreDir:       t.TempDir(),
		TemplateLength: 292,
		ReplaceLength:  312,
		TTLSeconds:     3600,
	}
	res := probeFireResult{
		status:     http.StatusOK,
		stateValue: strings.Repeat("x", 312),
		cookies: routeCookieSet{
			pairs:  map[string]string{"__cflb": "cf", "__oailb": "lb"},
			seenAt: time.Now(),
		},
	}
	if got := probeConsume(cfg, "acct", "acct", "model", res, ""); got != probeOutcomeTryNext {
		t.Fatalf("paired 312 outcome = %v, want TryNext -- the pair is pooled but the exit is degraded", got)
	}
	if poolEntryCount() == 0 {
		t.Fatal("the pair on a 312 was not pooled")
	}
}

// A steered request answered with an unrecognised length still stamps the pair
// good: the length classes are per-plan measurements, and a healthy 332/780 is
// evidence the node accepted the steer, not a reason to withhold the mark.
func TestSteeredPairMarksGoodOnOtherLength(t *testing.T) {
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 780 // signed, but outside the configured classes
	upstream.setCookies = []string{"__cflb=cf-good; Path=/", "__oailb=lb-good; Path=/"}
	setUpstream(t, upstream.server.URL)

	cfg, cred, pool := harvestTestConfig(t)
	if !probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, nil, nil, 0) {
		t.Fatal("harvest fired nothing")
	}
	key := cookieEntryKey(map[string]string{"__cflb": "cf-good", "__oailb": "lb-good"})
	state.mu.Lock()
	state.markRouteCookieOutcomeLocked(key, observationOther, time.Now())
	got := state.cookies[key].GoodAt
	state.mu.Unlock()
	if got == "" {
		t.Fatal("a signed-but-unclassified state did not stamp the pair good")
	}
}

// The credential's own claim wins: __oailb is a JWT whose exp is the deadline
// the gateway actually enforces -- measured exp-iat=3900 while Max-Age/Expires
// declare only 3600 -- so the token's own expiry overrides the transport hint.
func TestRouteCookiesPrefersTheTokensOwnExpiry(t *testing.T) {
	exp := testNow.Add(3900 * time.Second).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iat":%d,"exp":%d}`, testNow.Unix(), exp)))
	jwt := "hdr." + payload + ".sig"
	set := routeCookiesFromResponseHeaders(setCookieHeaders("",
		"__oailb="+jwt+"; Max-Age=60", // transport declares one minute; the token itself signs 3900s
		"__cflb=cf"), testNow)
	if !set.expireAt.Equal(time.Unix(exp, 0).UTC()) {
		t.Fatalf("expireAt = %s, want the JWT's own exp %s, not the conservative Max-Age", set.expireAt, time.Unix(exp, 0).UTC())
	}
}

// A non-JWT value keeps the attribute path working: __cflb is not a token, so
// its Expires declaration remains the deadline source.
func TestRouteCookiesNonJwtFallsBackToAttributes(t *testing.T) {
	set := routeCookiesFromResponseHeaders(setCookieHeaders("",
		"__cflb=cf; Expires="+testNow.Add(time.Hour).UTC().Format(http.TimeFormat)), testNow)
	if !set.expireAt.Equal(testNow.Add(time.Hour).UTC().Truncate(time.Second)) {
		t.Fatalf("expireAt = %s, want the declared Expires for a non-JWT value", set.expireAt)
	}
}
