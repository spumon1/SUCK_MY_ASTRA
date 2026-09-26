package main

// 路由 Cookie 的户口在全局池：__cflb/__oailb 任一处铸出的 pair 都供 Codex 账号用。
// 池按 pair 值记账，不按账号分包厢；请求侧给可归属 Codex 流量合并最佳活条目，
// 响应侧把每组 Set-Cookie pair 收回池中，房卡周转，不给房客改姓。

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

// setCookieHeaders 把给定 Set-Cookie 行装进响应头信封，一张不落。
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

// --- 解析：门牌先认清 ---

func TestRouteCookiesKeepsOnlyTheLoadBalancerPair(t *testing.T) {
	h := setCookieHeaders("",
		"__cflb=cf-pair-1; Path=/; HttpOnly",
		"__oailb=lb-pair-2; Path=/",
		"oai-did=device-identity; Path=/",                   // 身份 Cookie 不回放，私人证件不拿来当房卡
		"__Secure-session-token=session-material; HttpOnly", // 会话材料不回放，钥匙串不借台上演戏
		"__cf_bm=bot-management; Path=/",                    // 不是 pair 的成员，别混进双人组
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
	// 上游常写 __cflb/__oailb；验名时先摘前导下划线帽子，_cflb 换帽也能入场。
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
	// __cflb 只带 Expires；若只认 Max-Age，就会把有期限房卡误当没写退房日。
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
	// Expires 写坏了就拒认这条声明；不能把乱码算成有效期限，也不能借它洗成无期限。
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
		"__cflb=va,lue",       // 值内逗号会搅坏合并，台词分隔符别乱入
		"__ cflb=spaced-name", // 名字夹空格，门牌裂成两半
		"__oailb=ok; Path=/",
	)
	set := routeCookiesFromResponseHeaders(h, testNow)
	if len(set.pairs) != 1 || set.pairs["__oailb"] != "ok" {
		t.Fatalf("unsafe shapes were not rejected: %v", set.pairs)
	}
}

// --- 可用性：房卡有样子还得开得了门 ---

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
		ExpireAt: testNow.Add(time.Minute).UTC().Format(time.RFC3339), // 声明期限压过较长 ttl，租约先到就退房
	}
	if got := entrySecondsLeft(e, testNow, 240*time.Second); got != 60 {
		t.Fatalf("entrySecondsLeft = %d, want 60 (the declared deadline, not the ttl)", got)
	}
}

// --- 请求头合并：换房卡，不掀行李箱 ---

func TestMergeRouteCookiesOverlaysOnlyItsOwnNames(t *testing.T) {
	pairs := map[string]string{"__cflb": "fresh-cf", "__oailb": "fresh-lb"}
	merged := mergeRouteCookies("oai-did=device-1; __cflb=stale-cf", pairs)
	want := "oai-did=device-1; __cflb=fresh-cf; __oailb=fresh-lb"
	if merged != want {
		t.Fatalf("merged = %q, want %q", merged, want)
	}
	// 客户端原有 Cookie 留原位；池中 pair 顶替同名旧卡，缺的那张补在后面。
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

// --- 池内往返：发卡与收卡对账 ---

// seedPoolEntry 按真实采集路径把看见的 pair 折入内存池，道具也走正门。
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
	// 两次铸出相同 pair 就是同一张凭证，只记一笔；两个出口落同一节点也别虚报两套房。
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

// --- 请求侧：送卡上门 ---

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
	// 插件自己不写 turn-state 头，这支笔不归它。
	if got := outgoingHeader(resp); got != "" {
		t.Fatalf("the plugin wrote a turn-state header: %q", got)
	}
}

func TestSteerAttachesWithoutAClientTicket(t *testing.T) {
	// 复用的是 pair 凭证，不是给票续命；只要请求可归属，有无自带 state 都能领房卡。
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")

	resp := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", ""))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("an attributable request without a ticket was not steered: %q", cookie)
	}
}

func TestSteerRefusesNonCodexAccount(t *testing.T) {
	// 第一道门禁：pair 属 OpenAI，绝不能跟其他提供商的流量出门。
	// 能归属但非 Codex 的 auth id，与无法归属的一样不放行。
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
	// 全局池就是让任意处铸出的 pair 服务所有 Codex 账号；这里可跨账号，不可跨提供商。
	// 上一用例守的是不同提供商那条红线，别把全局池误盖成单人宿舍。
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

// --- 采集侧：收卡不问戏演得怎样 ---

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
	// pair 由边缘铸造，不靠服务状态领工资；静默响应和 312 带来的 pair 都要入池。
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
	// pair 是全局凭证，不落账号名下；响应没账号元数据也能把卡送进池，别索要房客族谱。
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
	// 携池条目出门的请求经 pendingAuth 捎回成绩：正常签名 state 标好，
	// 降级 state 标坏并降低下次选取优先级，房卡也有考勤。
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

// --- 探测侧：空手去，带卡回 ---

func TestProbeMintsBareAndPools(t *testing.T) {
	// 铸票必须不带 pair：带卡会钉住节点，定向请求的边缘不再发新 Cookie。
	// 要收新卡就空手去；响应 pair 收进全局池。
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
	state.mu.Unlock() // 此处立刻解锁不 defer；下面第二次采集还要拿锁，别揣钥匙堵门
	if !pooled {
		t.Fatalf("the minted pair was not pooled: %v", state.cookies)
	}

	// 下一次铸票也空手去；池是业务引导用的行李柜，不是探针回礼盒。
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
	// 耗尽或限流三元组休息 probeExitCooldown；成功者在 ttl - probeRenewThreshold 即应续采。
	// 否则 240s 模板会过期在 55 分钟午睡里。测试用短 ttl，让成功续期窗口明显早于失败冷却。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t) // 默认上菜 200 + 292
	upstream.setCookies = []string{"__cflb=cf; Path=/", "__oailb=lb; Path=/"}
	setUpstream(t, upstream.server.URL)

	var hitsA atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	cfg, cred, pool := harvestTestConfig(t)
	cfg.TTLSeconds = 300 // successRest = 300 - 90 = 210s << probeExitCooldown，成功者少坐冷板凳

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
	// 对照上例：312 不缩短出口休息，限的是 IP；窗口内再敲门只会多领 429 罚单。
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 312
	setUpstream(t, upstream.server.URL)

	var hitsA atomic.Int64
	exitA := newFakeProxy(t, &hitsA)
	cfg, cred, pool := harvestTestConfig(t)
	cfg.TTLSeconds = 300 // 与成功用例同短 ttl，只换结果不偷拨钟

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

// 312 若仍发 pair，房卡入池却不算 stored；边缘照发 Cookie，这个 bucket 的出口 IP 仍受限。
// 所以继续走下一出口，不能拿房卡冒充合格模板。
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

// 定向请求遇未知长度也可标 pair 良好：长度分类来自各套餐实测，健康 332/780
// 说明节点接受引导，不该因票换了身高就扣掉好评。
func TestSteeredPairMarksGoodOnOtherLength(t *testing.T) {
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	upstream.tsLen = 780 // 签过票但不在配置分类里，换身高不等于假票
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

// __oailb 的 JWT exp 才是网关真执行的退房钟：实测 exp-iat=3900，
// Max-Age/Expires 却报 3600；凭据自带期限压过运输单上的估时。
func TestRouteCookiesPrefersTheTokensOwnExpiry(t *testing.T) {
	exp := testNow.Add(3900 * time.Second).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iat":%d,"exp":%d}`, testNow.Unix(), exp)))
	jwt := "hdr." + payload + ".sig"
	set := routeCookiesFromResponseHeaders(setCookieHeaders("",
		"__oailb="+jwt+"; Max-Age=60", // 运输单报一分钟，票自己签 3900s，退房听票的
		"__cflb=cf"), testNow)
	if !set.expireAt.Equal(time.Unix(exp, 0).UTC()) {
		t.Fatalf("expireAt = %s, want the JWT's own exp %s, not the conservative Max-Age", set.expireAt, time.Unix(exp, 0).UTC())
	}
}

// 不是 JWT 的 __cflb 仍按属性走；Expires 是它的退房通知，别硬找不存在的内兜。
func TestRouteCookiesNonJwtFallsBackToAttributes(t *testing.T) {
	set := routeCookiesFromResponseHeaders(setCookieHeaders("",
		"__cflb=cf; Expires="+testNow.Add(time.Hour).UTC().Format(http.TimeFormat)), testNow)
	if !set.expireAt.Equal(testNow.Add(time.Hour).UTC().Truncate(time.Second)) {
		t.Fatalf("expireAt = %s, want the declared Expires for a non-JWT value", set.expireAt)
	}
}
