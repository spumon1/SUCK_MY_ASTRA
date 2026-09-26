package main

// 观测账本考 natural/injected 分账、盲区、有界环与快照往返。
// 最怕 injected 混进 natural：插件自己挑过的样本却拿来算自然降级率，就像裁判把自己投的票算民意。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func resetObservations(t *testing.T, dir string) pluginConfig {
	t.Helper()
	observations.mu.Lock()
	observations.byKey = make(map[string]*bucketObservation)
	observations.recent = nil
	observations.since = time.Now()
	observations.dirty = false
	observations.lastOut = time.Now()
	observations.writing = false
	observations.dir = dir
	observations.mu.Unlock()
	return pluginConfig{TemplateLength: 292, ReplaceLength: 312}
}

func observedBucket(t *testing.T, auth, model string) bucketObservation {
	t.Helper()
	buckets, _, _ := observationsSnapshot()
	for _, cell := range buckets {
		if cell.AuthID == auth && cell.Model == model {
			return cell
		}
	}
	t.Fatalf("no observation cell for (%s, %s)", auth, model)
	return bucketObservation{}
}

// 页面展示的每种读数各进自己的计数器，账房不许合并报销。
func TestObservationSplitsNaturalFromInjected(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 292, false) // 自然请求正常，没请向导也走对门
	recordObservation(cfg, "a.json", "gpt-5.5", 312, false) // 自然请求降级，记自然账别甩锅注入
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)    // 我们的模板被接纳，房卡刷开了
	recordObservation(cfg, "a.json", "gpt-5.5", 312, true)  // 带了我们的模板仍降级，房卡不是万能药
	recordObservation(cfg, "a.json", "gpt-5.5", 292, true)  // 虽有注入仍签新正常票，上游另开收据
	recordObservation(cfg, "a.json", "gpt-5.5", 99, false)  // 长度没认出来，先别乱发毕业证
	recordObservation(cfg, "a.json", "gpt-5.5", 101, true)  // 未知长度且我们已注入，账记自家这桌
	// 两个未知长度刻意不同；同长度第二次会被 noteSignedLen 学成此 bucket 的正常值，
	// 落到 InjectedNormal 就考不到当前分账题，不能让样本提前背答案。

	cell := observedBucket(t, "a.json", "gpt-5.5")
	for _, want := range []struct {
		name string
		got  int64
		n    int64
	}{
		{"NaturalNormal", cell.NaturalNormal, 1},
		{"NaturalLimited", cell.NaturalLimited, 1},
		{"NaturalOther", cell.NaturalOther, 1},
		{"InjectedSilent", cell.InjectedSilent, 1},
		{"InjectedLimited", cell.InjectedLimited, 1},
		{"InjectedNormal", cell.InjectedNormal, 1},
		{"InjectedOther", cell.InjectedOther, 1},
	} {
		if want.got != want.n {
			t.Errorf("%s = %d, want %d", want.name, want.got, want.n)
		}
	}
}

// 注入请求上的未知长度归 injected；旧逻辑落 NaturalOther，把自选流量塞进自然统计。
// 读者会把自然数字当比例，不能往这杯清水里偷偷兑汤。
func TestInjectedUnrecognisedLengthStaysOffTheNaturalSide(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 99, true)

	cell := observedBucket(t, "a.json", "gpt-5.5")
	if cell.InjectedOther != 1 {
		t.Errorf("InjectedOther = %d, want 1", cell.InjectedOther)
	}
	if cell.NaturalOther != 0 {
		t.Errorf("NaturalOther = %d, want 0: this observation was prompted by our own injection", cell.NaturalOther)
	}
	if cell.LastNaturalKind != "" {
		t.Errorf("LastNaturalKind = %q, want empty: nothing unprompted has been seen in this bucket", cell.LastNaturalKind)
	}
}

// 长度分类不是天条：2026-09-22 统一格式把原来 292 改成 780，硬白名单会永远记 other。
// 因此按 bucket 学习，未知长度再次出现便晋升 normal；换格式只付一次 other 学费，不罚终身。
func TestRecurringUnrecognisedLengthPromotesToNormal(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-6-astra", 780, false)
	cell := observedBucket(t, "a.json", "gpt-6-astra")
	if cell.NaturalOther != 1 || cell.NaturalNormal != 0 {
		t.Fatalf("first 780: NaturalOther=%d NaturalNormal=%d, want 1/0 -- a new signature must be seen before it is trusted",
			cell.NaturalOther, cell.NaturalNormal)
	}

	recordObservation(cfg, "a.json", "gpt-6-astra", 780, false)
	recordObservation(cfg, "a.json", "gpt-6-astra", 780, true)
	cell = observedBucket(t, "a.json", "gpt-6-astra")
	if cell.NaturalNormal != 1 || cell.InjectedNormal != 1 {
		t.Errorf("recurring 780: NaturalNormal=%d InjectedNormal=%d, want 1/1 -- the learned class applies on both sides of the split",
			cell.NaturalNormal, cell.InjectedNormal)
	}
	if cell.NaturalOther != 1 {
		t.Errorf("NaturalOther = %d, want still 1: the first sighting keeps its own record", cell.NaturalOther)
	}

	// 学习按 bucket 分班；另一组（account, model）第一次见 780 仍从 other 学起，
	// 签名属于上游，证据却不能从隔壁班抄。
	recordObservation(cfg, "b.json", "gpt-6-astra", 780, false)
	if cell := observedBucket(t, "b.json", "gpt-6-astra"); cell.NaturalOther != 1 || cell.NaturalNormal != 0 {
		t.Errorf("fresh bucket seeing 780: NaturalOther=%d NaturalNormal=%d, want 1/0", cell.NaturalOther, cell.NaturalNormal)
	}
}

// replace_length 是降级警铃，响再多也不能学成正常；始终 limited，不进候选表，坏习惯不发毕业证。
func TestDegradedLengthIsNeverLearned(t *testing.T) {
	cfg := resetObservations(t, "")

	for i := 0; i < observationLearnMin+2; i++ {
		recordObservation(cfg, "a.json", "gpt-5.5", 312, false)
	}
	cell := observedBucket(t, "a.json", "gpt-5.5")
	if cell.NaturalLimited != int64(observationLearnMin+2) || cell.NaturalNormal != 0 {
		t.Errorf("repeated 312: NaturalLimited=%d NaturalNormal=%d, want %d/0",
			cell.NaturalLimited, cell.NaturalNormal, observationLearnMin+2)
	}
	if len(cell.SignedLens) != 0 {
		t.Errorf("SignedLens = %v, want empty: the configured degraded length must never be a promotion candidate", cell.SignedLens)
	}
}

// 候选表有上限，来客轮着报新长度也不能无限加座；满员淘汰最少见的条目。
func TestSignedLensTableStaysBounded(t *testing.T) {
	cfg := resetObservations(t, "")

	for i := 0; i < observationLensMax+4; i++ {
		recordObservation(cfg, "a.json", "gpt-5.5", 500+i, false)
	}
	cell := observedBucket(t, "a.json", "gpt-5.5")
	if len(cell.SignedLens) > observationLensMax {
		t.Errorf("SignedLens holds %d entries, want at most %d", len(cell.SignedLens), observationLensMax)
	}
}

// --- 实服模型降级：统一票长后的另一只警铃 ---
// 格式统一后都签 780，限流不再写在长度脸上，而是 SSE 报非请求模型
// （x-codex-safety-buffering 回退接演）。header-init 尚有账号和引导上下文时布哨，
// 首个带 model 字段的载荷块定案，不等大结局。

func streamChunk(t *testing.T, chunk pluginapi.StreamChunkInterceptRequest) {
	t.Helper()
	raw, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}
	if _, errHook := interceptStreamChunk(raw); errHook != nil {
		t.Fatalf("interceptStreamChunk: %v", errHook)
	}
}

func resetModelScans() {
	pendingModelScans.mu.Lock()
	pendingModelScans.byID = make(map[string]pendingModelScanEntry)
	pendingModelScans.mu.Unlock()
}

func TestStreamedModelMismatchRecordsDowngrade(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessHarvestConfig(dir))
	resetHarvestState(t)
	resetObservations(t, "")
	resetModelScans()

	const requestID = "req-downgrade-1"
	req := request("codex-alpha.json", "gpt-6-astra", "")
	req.RequestID = requestID
	interceptAfter(t, req)

	// header-init 签一张看似正常的 780；旧长度降级暗号已经换岗。
	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:       requestID,
		Model:           "gpt-6-astra",
		ChunkIndex:      pluginapi.StreamChunkHeaderInitIndex,
		ResponseHeaders: harvestResponseHeaders(fakeToken(780, wallClock())),
	})

	// 首个载荷块亮出回退模型名牌，替身到场。
	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:  requestID,
		Model:      "gpt-6-astra",
		ChunkIndex: 0,
		Body: []byte("event: response.created\n" +
			`data: {"type":"response.created","response":{"id":"r1","model":"gpt-5.6-luna","status":"in_progress"}}` + "\n\n"),
	})

	cell := observedBucket(t, "codex-alpha.json", "gpt-6-astra")
	if cell.NaturalLimited != 1 {
		t.Fatalf("NaturalLimited = %d, want 1: a served-model switch is the degraded reading", cell.NaturalLimited)
	}
	if cell.LastSignedKind != observationLimited {
		t.Errorf("LastSignedKind = %q, want %q: the downgrade is the last signed state", cell.LastSignedKind, observationLimited)
	}
	_, feed, _ := observationsSnapshot()
	if len(feed) == 0 || feed[0].Kind != observationLimited || feed[0].Served != "gpt-5.6-luna" {
		t.Fatalf("feed[0] = %+v, want kind=limited served=gpt-5.6-luna", feed[0])
	}

	// 监视记录用一次就撤；后续块再报相同错配不能重复算账，response.completed 会重述同一对象。
	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:  requestID,
		Model:      "gpt-6-astra",
		ChunkIndex: 1,
		Body:       []byte(`data: {"type":"response.completed","response":{"model":"gpt-5.6-luna"}}`),
	})
	if cell := observedBucket(t, "codex-alpha.json", "gpt-6-astra"); cell.NaturalLimited != 1 {
		t.Errorf("NaturalLimited = %d after a second chunk, want still 1", cell.NaturalLimited)
	}
}

// 请求谁就服务谁是正常剧情，不新增读数来抢版面。
func TestStreamedModelMatchRecordsNothing(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessHarvestConfig(dir))
	resetHarvestState(t)
	resetObservations(t, "")
	resetModelScans()

	const requestID = "req-match-1"
	req := request("codex-alpha.json", "gpt-5.5", "")
	req.RequestID = requestID
	interceptAfter(t, req)
	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:       requestID,
		Model:           "gpt-5.5",
		ChunkIndex:      pluginapi.StreamChunkHeaderInitIndex,
		ResponseHeaders: harvestResponseHeaders(fakeToken(780, wallClock())),
	})
	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:  requestID,
		Model:      "gpt-5.5",
		ChunkIndex: 0,
		Body:       []byte(`data: {"type":"response.created","response":{"model":"gpt-5.5"}}`),
	})

	cell := observedBucket(t, "codex-alpha.json", "gpt-5.5")
	if cell.NaturalLimited != 0 || cell.NaturalOther != 1 {
		t.Errorf("match: NaturalLimited=%d NaturalOther=%d, want 0/1 -- only the header's 780 observation",
			cell.NaturalLimited, cell.NaturalOther)
	}
}

// 没布过哨的请求 ID 传来块就不管；同钩子的无关流别被硬拉来记考勤。
func TestStreamedChunkWithoutWatchIsIgnored(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessHarvestConfig(dir))
	resetHarvestState(t)
	resetObservations(t, "")
	resetModelScans()

	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:  "req-unknown",
		Model:      "gpt-6-astra",
		ChunkIndex: 0,
		Body:       []byte(`data: {"model":"gpt-5.6-luna"}`),
	})
	buckets, _, _ := observationsSnapshot()
	if len(buckets) != 0 {
		t.Fatalf("an unarmed request's chunk produced %d observation(s), want none", len(buckets))
	}
}

// servedModelFromChunk 从 SSE 载荷摘第一个 model 字段，先看首张名牌。
func TestServedModelFromChunk(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
		ok   bool
	}{
		{`data: {"type":"response.created","response":{"model":"gpt-6-astra"}}`, "gpt-6-astra", true},
		{`data: {"type":"response.created","response":{"model":""}}`, "", false},
		{`data: {"type":"response.output_text.delta","delta":"hi"}`, "", false},
		{"", "", false},
	} {
		got, ok := servedModelFromChunk([]byte(tc.body))
		if ok != tc.ok || got != tc.want {
			t.Errorf("servedModelFromChunk(%q) = %q,%v; want %q,%v", tc.body, got, ok, tc.want, tc.ok)
		}
	}
}

// 页面给 LastSigned* 算年龄，所以凡上游真签 state 都要更新。
// 注入请求仍回 292，是上游正常服务该账号的直接证据；旧逻辑当没证据，
// 健康 bucket 揣着证明还显示 blind，不能让证件在柜台里隐身。
func TestLastSignedTracksInjectedReadingsToo(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 292, true)

	cell := observedBucket(t, "a.json", "gpt-5.5")
	if cell.LastSignedKind != observationNormal || cell.LastSignedAt == "" {
		t.Errorf("LastSigned = %q at %q, want a normal reading with a timestamp", cell.LastSignedKind, cell.LastSignedAt)
	}
	if !cell.LastSignedWrote {
		t.Error("LastSignedWrote is false; the page needs to say this reading came from a request we touched")
	}
	if cell.LastNaturalKind != "" {
		t.Errorf("LastNaturalKind = %q, want empty: the natural side stays unprompted-only", cell.LastNaturalKind)
	}

	// 静默不算签发；注入后的静默只说明自己的模板被接纳，没人签新票，别凭空盖章。
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)
	if cell := observedBucket(t, "a.json", "gpt-5.5"); cell.LastSignedKind != observationNormal {
		t.Errorf("LastSignedKind = %q after a silent response, want it unchanged at normal", cell.LastSignedKind)
	}
}

// 小时历史用来答“比昨天更差吗”；终身累计只会报总账，不会记昨天吃了什么。
func TestHourlyHistoryRollsUpAndStaysBounded(t *testing.T) {
	cfg := resetObservations(t, "")
	recordObservation(cfg, "a.json", "gpt-5.5", 312, false)

	cell := observedBucket(t, "a.json", "gpt-5.5")
	if len(cell.Hourly) != 1 {
		t.Fatalf("Hourly has %d slot(s), want 1", len(cell.Hourly))
	}
	if cell.Hourly[0].NaturalLimited != 1 {
		t.Errorf("this hour's NaturalLimited = %d, want 1", cell.Hourly[0].NaturalLimited)
	}

	// 同小时第二次观测复用槽，不再开房；否则环装的是分钟，不是天数。
	recordObservation(cfg, "a.json", "gpt-5.5", 312, false)
	if cell := observedBucket(t, "a.json", "gpt-5.5"); len(cell.Hourly) != 1 {
		t.Errorf("Hourly has %d slot(s) after a second observation in the same hour, want 1", len(cell.Hourly))
	}

	now := time.Now()
	if got := observedBucket(t, "a.json", "gpt-5.5").rollup(now, 24*time.Hour); got.NaturalLimited != 2 {
		t.Errorf("24h rollup NaturalLimited = %d, want 2", got.NaturalLimited)
	}

	// 窗口外小时不相加，过期账本别塞进当日报表。
	stale := bucketObservation{Hourly: []hourlyObservation{
		{Hour: now.Add(-40 * time.Hour).UTC().Truncate(time.Hour).Format(time.RFC3339),
			observationCounts: observationCounts{NaturalLimited: 500}},
		{Hour: now.Add(-2 * time.Hour).UTC().Truncate(time.Hour).Format(time.RFC3339),
			observationCounts: observationCounts{NaturalLimited: 7}},
	}}
	if got := stale.rollup(now, 24*time.Hour); got.NaturalLimited != 7 {
		t.Errorf("24h rollup over a 40h-old slot = %d, want 7: the old hour must not be counted", got.NaturalLimited)
	}

	// 环满淘汰最老小时，不赶刚进门的新客。
	var ring bucketObservation
	for i := observationsHourlyMax + 10; i >= 0; i-- {
		ring.hourSlot(now.Add(-time.Duration(i)*time.Hour)).add(false, observationLimited)
	}
	if len(ring.Hourly) != observationsHourlyMax {
		t.Errorf("ring holds %d slot(s), want the cap of %d", len(ring.Hourly), observationsHourlyMax)
	}
	newest := now.UTC().Truncate(time.Hour).Format(time.RFC3339)
	if ring.Hourly[len(ring.Hourly)-1].Hour != newest {
		t.Errorf("newest slot is %q, want %q: eviction must drop the oldest",
			ring.Hourly[len(ring.Hourly)-1].Hour, newest)
	}
}

// addAll 手写易漏新计数器，漏了汇总就静默变零；遍历类型核对，别信账房口头说全记了。
func TestObservationCountsAddAllCoversEveryField(t *testing.T) {
	var src observationCounts
	value := reflect.ValueOf(&src).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() != reflect.Int64 {
			t.Fatalf("observationCounts.%s is a %s; this test assumes every counter is an int64",
				value.Type().Field(i).Name, field.Kind())
		}
		field.SetInt(int64(i + 1)) // 各值不同，抄错字段就会当场露馅
	}

	var dst observationCounts
	dst.addAll(src)
	if dst != src {
		t.Errorf("addAll dropped or misplaced a counter.\n got: %+v\nwant: %+v\n"+
			"every field of observationCounts needs a line in addAll", dst, src)
	}
}

// 未注入且静默占多数，也不说明服务状态；别把空气记满账本淹掉关键读数。
func TestObservationIgnoresUninterestingSilence(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 0, false)
	if buckets, recent, _ := observationsSnapshot(); len(buckets) != 0 || len(recent) != 0 {
		t.Errorf("a silent, untouched response was recorded: %d bucket(s), %d event(s)", len(buckets), len(recent))
	}

	// 注入之后的静默却说明模板被接纳，同样沉默，台词含义不同。
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)
	if cell := observedBucket(t, "a.json", "gpt-5.5"); cell.InjectedSilent != 1 {
		t.Errorf("InjectedSilent = %d, want 1: silence after an injection is how acceptance is seen", cell.InjectedSilent)
	}
}

// 没账号就无处入账，硬塞 bucket 会把甲客户限流记在乙客户桌上。
func TestObservationRequiresAFullKey(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "", "gpt-5.5", 312, false)
	recordObservation(cfg, "a.json", "", 312, false)
	recordObservation(cfg, "  ", "  ", 312, true)

	if buckets, _, _ := observationsSnapshot(); len(buckets) != 0 {
		t.Errorf("recorded %d cell(s) from observations with an incomplete key", len(buckets))
	}
}

// 直接钉住盲区：有模板时每请求都注入，上游不签新票，LastNatural 不动但 LastAt 前进。
// 页面据此显示自然观测年龄；若注入流量刷新 LastNatural，一小时前的正常就会冒充现做热菜。
func TestInjectedObservationsDoNotRefreshTheNaturalReading(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 292, false)
	first := observedBucket(t, "a.json", "gpt-5.5")
	if first.LastNaturalKind != observationNormal || first.LastNaturalAt == "" {
		t.Fatalf("natural reading not recorded: kind=%q at=%q", first.LastNaturalKind, first.LastNaturalAt)
	}

	time.Sleep(1100 * time.Millisecond) // RFC3339 只认整秒，等时钟跨过门槛
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)

	after := observedBucket(t, "a.json", "gpt-5.5")
	if after.LastNaturalAt != first.LastNaturalAt {
		t.Errorf("LastNaturalAt moved from %q to %q on injected traffic; the blind spot would be invisible",
			first.LastNaturalAt, after.LastNaturalAt)
	}
	if after.LastAt == first.LastAt {
		t.Error("LastAt did not move, so the two timestamps cannot be told apart")
	}
	if after.LastKind != observationSilent || !after.LastWrote {
		t.Errorf("last observation = (%s, wrote=%v), want (silent, true)", after.LastKind, after.LastWrote)
	}
}

// 手里有模板还收到 312 才是真警报：这个 bucket 不在插件能救的范围，房卡也治不了停电。
func TestInjectedLimitedIsCountedSeparately(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.6-sol", 312, true)
	cell := observedBucket(t, "a.json", "gpt-5.6-sol")
	if cell.InjectedLimited != 1 {
		t.Errorf("InjectedLimited = %d, want 1", cell.InjectedLimited)
	}
	if cell.NaturalLimited != 0 {
		t.Errorf("NaturalLimited = %d, want 0: this one was prompted and must not enter the natural rate", cell.NaturalLimited)
	}
}

func TestObservationFeedIsBoundedAndNewestFirst(t *testing.T) {
	cfg := resetObservations(t, "")

	for i := 0; i < observationsRecentMax+40; i++ {
		length := 292
		if i%2 == 0 {
			length = 312
		}
		recordObservation(cfg, "a.json", "gpt-5.5", length, false)
	}

	_, recent, _ := observationsSnapshot()
	if len(recent) != observationsRecentMax {
		t.Fatalf("feed holds %d events, want the cap of %d", len(recent), observationsRecentMax)
	}
	// 最后进来的是 i=max+39，奇数，所以这回票长 292，排队号别算错。
	if recent[0].Len != 292 {
		t.Errorf("feed[0].Len = %d, want the most recent event (292)", recent[0].Len)
	}
	if recent[0].Kind != observationNormal || recent[0].Wrote {
		t.Errorf("feed[0] = (%s, wrote=%v), want (normal, false)", recent[0].Kind, recent[0].Wrote)
	}
}

func TestObservationSnapshotRoundTrips(t *testing.T) {
	dir := t.TempDir()
	cfg := resetObservations(t, dir)

	recordObservation(cfg, "a.json", "gpt-5.5", 292, false)
	recordObservation(cfg, "b.json", "gpt-5.6-sol", 312, true)
	flushObservationsNow()

	path := filepath.Join(dir, observationsFileName)
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("no snapshot written: %v", errRead)
	}
	var snap observationSnapshot
	if errUnmarshal := json.Unmarshal(raw, &snap); errUnmarshal != nil {
		t.Fatalf("snapshot is not valid JSON: %v", errUnmarshal)
	}
	if snap.Version != observationsVersion {
		t.Errorf("snapshot version = %d, want %d", snap.Version, observationsVersion)
	}
	if len(snap.Buckets) != 2 || len(snap.Recent) != 2 {
		t.Fatalf("snapshot holds %d bucket(s) and %d event(s), want 2 and 2", len(snap.Buckets), len(snap.Recent))
	}

	// 清空账本再载入快照，计数要原样归队，存档不是装饰。
	observations.mu.Lock()
	observations.dir = ""
	observations.since = time.Time{}
	observations.mu.Unlock()
	loadObservations(dir)

	if cell := observedBucket(t, "b.json", "gpt-5.6-sol"); cell.InjectedLimited != 1 {
		t.Errorf("after reload InjectedLimited = %d, want 1", cell.InjectedLimited)
	}
	if cell := observedBucket(t, "a.json", "gpt-5.5"); cell.NaturalNormal != 1 {
		t.Errorf("after reload NaturalNormal = %d, want 1", cell.NaturalNormal)
	}
}

// 未来或未知快照格式直接丢弃，不猜；这些计数可抛弃，特意不设迁移，别替陌生账本算命。
func TestObservationSnapshotRejectsForeignVersion(t *testing.T) {
	dir := t.TempDir()
	resetObservations(t, dir)

	raw, _ := json.Marshal(observationSnapshot{
		Version: observationsVersion + 1,
		Buckets: []bucketObservation{{
			AuthID:            "a.json",
			Model:             "gpt-5.5",
			observationCounts: observationCounts{NaturalLimited: 99},
		}},
	})
	if errWrite := os.WriteFile(filepath.Join(dir, observationsFileName), raw, 0o600); errWrite != nil {
		t.Fatalf("seed snapshot: %v", errWrite)
	}

	observations.mu.Lock()
	observations.dir = ""
	observations.since = time.Time{}
	observations.mu.Unlock()
	loadObservations(dir)

	if buckets, _, _ := observationsSnapshot(); len(buckets) != 0 {
		t.Errorf("loaded %d cell(s) from a version-%d snapshot", len(buckets), observationsVersion+1)
	}
}

// 坏模型 ID 不能让 map 无限添桌，来客报乱码也要守容量。
func TestObservationBucketsAreCapped(t *testing.T) {
	cfg := resetObservations(t, "")

	for i := 0; i < observationsBucketMax+20; i++ {
		recordObservation(cfg, "a.json", "model-"+string(rune('a'+i%26))+string(rune('a'+i/26)), 312, false)
	}
	buckets, _, _ := observationsSnapshot()
	if len(buckets) > observationsBucketMax {
		t.Errorf("tally holds %d cells, above the cap of %d", len(buckets), observationsBucketMax)
	}
}

// 观测在采集路径自检前发生，得看见采集拒收的响应，尤其 312：
// 最关键的限流读数偏偏从不存模板，验票口不能兼任遮羞布。
func TestHarvestPathRecordsTheDegradedObservation(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resetHarvestState(t)
	resetObservations(t, "")

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	issued := wallClock().Add(-time.Minute)
	meta := map[string]any{testAuthKey: "codex-alpha.json"}
	harvestFromResponse(cfg, harvestResponseHeaders(fakeToken(312, issued)), meta, "gpt-5.5", "")

	cell := observedBucket(t, "codex-alpha.json", "gpt-5.5")
	if cell.NaturalLimited != 1 {
		t.Errorf("NaturalLimited = %d, want 1: the 312 was seen even though it was never stored", cell.NaturalLimited)
	}
	if cell.LastNaturalKind != observationLimited {
		t.Errorf("LastNaturalKind = %q, want %q", cell.LastNaturalKind, observationLimited)
	}
}

// dry_run 只看不碰；若把决定当注入，整批观测就站错分账队，纸上打拳不能算真出手。
func TestDryRunDecisionIsNotCountedAsAnInjection(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resetObservations(t, "")

	rememberRequestAuth("req-dry", "codex-alpha.json")
	// interceptAfterAuth 过 dry_run 检查才调 markRequestSteered；演习提前返回，不盖实战章。
	authID, steered, _ := recallRequestRecord("req-dry")
	if authID != "codex-alpha.json" {
		t.Fatalf("recall = %q, want the recorded account", authID)
	}
	if steered {
		t.Fatal("a request that was never marked reports as steered")
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()
	recordObservation(cfg, authID, "gpt-5.5", 312, steered)

	cell := observedBucket(t, "codex-alpha.json", "gpt-5.5")
	if cell.NaturalLimited != 1 || cell.InjectedLimited != 0 {
		t.Errorf("natural=%d injected=%d, want 1 and 0", cell.NaturalLimited, cell.InjectedLimited)
	}
}

// --- 状态文档：账本上桌 ---

// 计数要跟所属行一起到页面，不准邮寄到隔壁房间。
func TestStatusCarriesObservationsOnTheBucketRow(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, "")

	recordObservation(cfg, "codex-alpha.json", "gpt-5.5", 292, false)
	recordObservation(cfg, "codex-alpha.json", "gpt-5.5", 312, true)

	status := mustManagementStatus(t)
	bucket, found := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5")
	if !found {
		t.Fatal("no row for the observed bucket")
	}
	if bucket.Observed == nil {
		t.Fatal("the row carries no observations")
	}
	if bucket.Observed.NaturalNormal != 1 || bucket.Observed.InjectedLimited != 1 {
		t.Errorf("observed = natural_normal %d, injected_limited %d; want 1 and 1",
			bucket.Observed.NaturalNormal, bucket.Observed.InjectedLimited)
	}
	if bucket.Observed.LastNaturalKind != observationNormal {
		t.Errorf("last_natural_kind = %q, want %q: the injected 312 must not overwrite it",
			bucket.Observed.LastNaturalKind, observationNormal)
	}
	if status.ObservationsSince == "" {
		t.Error("observations_since is empty; a count with no start is not a rate")
	}
	if len(status.ObservationFeed) != 2 {
		t.Fatalf("feed holds %d events, want 2", len(status.ObservationFeed))
	}
	if !status.ObservationFeed[0].Wrote || status.ObservationFeed[0].Len != 312 {
		t.Errorf("feed[0] = (len %d, wrote %v), want the most recent (312, true)",
			status.ObservationFeed[0].Len, status.ObservationFeed[0].Wrote)
	}
}

// 从没观测过的 bucket 不挂空计数，页面才分得清“没客人”和“真计数为零”。
func TestStatusOmitsObservationsForUnseenBuckets(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resetObservations(t, "")
	// 先存一个 bucket 让矩阵有行可画；没行的话下方循环会考一张空白卷。
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	status := mustManagementStatus(t)
	// 种过数据的格子带计数；同账号但未见过的兄弟模型不带，别把无流量扮成真零值。
	seen := false
	for _, bucket := range status.Buckets {
		if bucket.AuthID == "codex-alpha.json" && bucket.Model == "gpt-5.6-sol" {
			seen = true
			if bucket.Observed != nil {
				t.Errorf("row (%s, %s) carries a tally before anything was observed", bucket.AuthID, bucket.Model)
			}
		}
	}
	if !seen {
		t.Fatal("the unobserved row never rendered; this assertion would pass vacuously")
	}
	if status.ObservationFeed == nil {
		t.Error("observation_feed is null rather than an empty array; the page has to special-case that")
	}
}

// 最容易隐身的模型被限流到从没存过模板，若还不在配置列表，矩阵连一行都不给。
// 这个页面本为看限流而建，不能把最惨的观众请出摄影范围。
func TestStatusGivesARowToAnObservedButUnconfiguredModel(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // 给 gpt-5.5 与 gpt-5.6-sol 安排座位
	cfg := resetObservations(t, "")

	recordObservation(cfg, "codex-alpha.json", "gpt-6-astra", 312, false)

	status := mustManagementStatus(t)
	bucket, found := mgmtBucketByKey(status, "codex-alpha.json", "gpt-6-astra")
	if !found {
		t.Fatal("no row for a model that was observed but is neither configured nor stored")
	}
	if bucket.Observed == nil || bucket.Observed.NaturalLimited != 1 {
		t.Fatalf("the drift row carries no throttling count: %+v", bucket.Observed)
	}
	if bucket.Ready {
		t.Error("the drift row reports ready, but nothing was ever stored for it")
	}
	// 这是漂移不是目标，不能计入进度；分母要由运营者点菜，系统别偷加人数。
	for _, model := range status.Models {
		if model == "gpt-6-astra" {
			t.Fatal("gpt-6-astra leaked into the configured models list")
		}
	}
}
