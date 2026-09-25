package main

// Tests for the observation tally: the natural/injected split, the blind spot
// it exists to expose, the bounded ring, and the snapshot round trip.
//
// The split is the part worth testing hardest. If injected observations leak
// into the natural counts, the dashboard reports a degradation rate computed
// over a sample the plugin itself selected -- which is the specific way this
// feature can lie to its operator.

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

// Every reading the dashboard renders, each landing in its own counter.
func TestObservationSplitsNaturalFromInjected(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 292, false) // unprompted, good
	recordObservation(cfg, "a.json", "gpt-5.5", 312, false) // unprompted, degraded
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)    // ours accepted
	recordObservation(cfg, "a.json", "gpt-5.5", 312, true)  // degraded despite ours
	recordObservation(cfg, "a.json", "gpt-5.5", 292, true)  // fresh good despite ours
	recordObservation(cfg, "a.json", "gpt-5.5", 99, false)  // unrecognised length
	recordObservation(cfg, "a.json", "gpt-5.5", 101, true)  // unrecognised, and ours went out
	// The two unrecognised lengths differ on purpose: a second sighting of the
	// SAME length is learned as this bucket's normal (noteSignedLen), which
	// would land on InjectedNormal instead and stop exercising this split.

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

// An unrecognised length on a request we injected into belongs on the injected
// side. It used to fall through to NaturalOther, which put our own traffic in
// the unprompted counts -- the one place a reader is entitled to treat the
// numbers as a rate.
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

// The upstream's length classes are not constants: when it unified the
// turn-state format on 2026-09-22 the same buckets that signed 292 began
// signing 780, and a fixed whitelist would file that healthy traffic under
// "other" forever. The tally therefore learns per bucket: a recurring
// unrecognised length promotes to normal, so a format change costs exactly
// one "other" sighting instead of a permanent misclassification.
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

	// Learning is per bucket: another (account, model) seeing 780 for the first
	// time starts from "other" again. The signature is upstream's, but the
	// evidence is this bucket's.
	recordObservation(cfg, "b.json", "gpt-6-astra", 780, false)
	if cell := observedBucket(t, "b.json", "gpt-6-astra"); cell.NaturalOther != 1 || cell.NaturalNormal != 0 {
		t.Errorf("fresh bucket seeing 780: NaturalOther=%d NaturalNormal=%d, want 1/0", cell.NaturalOther, cell.NaturalNormal)
	}
}

// The degraded signature is the one alarm the tally has, so it must never be
// learnable: however often a bucket signs replace_length, it stays "limited"
// and never enters the candidate table.
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

// The candidate table is bounded: a peer cycling through distinct lengths must
// not grow it without limit. Past the cap the rarest entry is dropped.
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

// --- served-model downgrade: the unified format's degraded signature --------
//
// Since the format moved, every response signs the same 780 and the throttle
// bit is no longer in the header length -- it is the SSE payload declaring a
// model other than the requested one (the x-codex-safety-buffering fallback
// answering the turn). The watch arms at header-init, where the relayed auth
// and steer context still exist, and the first payload chunk carrying a
// "model" field settles it.

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

	// Header-init signs a normal-looking 780 -- the signature that used to mean
	// degraded no longer carries it.
	streamChunk(t, pluginapi.StreamChunkInterceptRequest{
		RequestID:       requestID,
		Model:           "gpt-6-astra",
		ChunkIndex:      pluginapi.StreamChunkHeaderInitIndex,
		ResponseHeaders: harvestResponseHeaders(fakeToken(780, wallClock())),
	})

	// The first payload chunk declares the fallback model instead.
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

	// The watch is consumed: a later chunk repeating the mismatch must not
	// count again -- response.completed restates the same object every event.
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

// Serving the asked model is the common case and must produce no reading.
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

// A chunk naming a request the plugin never armed must do nothing -- otherwise
// unrelated streams on the same hook would spend effort or misattribute.
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

// servedModelFromChunk reads the first model field out of an SSE payload.
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

// LastSigned* is what the dashboard ages, and it must advance on ANY reading
// where the upstream put a state on the wire. A 292 signed on a request we had
// injected into is the upstream saying it serves this account normally -- the
// most direct evidence available, and it used to be filed as no evidence at
// all, leaving a healthy bucket showing "blind" while holding the proof.
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

	// Silence never counts as a signed state: under injection it means our own
	// template was accepted, which is nobody signing anything.
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)
	if cell := observedBucket(t, "a.json", "gpt-5.5"); cell.LastSignedKind != observationNormal {
		t.Errorf("LastSignedKind = %q after a silent response, want it unchanged at normal", cell.LastSignedKind)
	}
}

// The history exists so "is this worse than yesterday" has an answer. Lifetime
// totals cannot give one.
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

	// A second observation in the same hour reuses the slot rather than
	// opening another; otherwise the ring holds minutes, not days.
	recordObservation(cfg, "a.json", "gpt-5.5", 312, false)
	if cell := observedBucket(t, "a.json", "gpt-5.5"); len(cell.Hourly) != 1 {
		t.Errorf("Hourly has %d slot(s) after a second observation in the same hour, want 1", len(cell.Hourly))
	}

	now := time.Now()
	if got := observedBucket(t, "a.json", "gpt-5.5").rollup(now, 24*time.Hour); got.NaturalLimited != 2 {
		t.Errorf("24h rollup NaturalLimited = %d, want 2", got.NaturalLimited)
	}

	// Hours outside the window are excluded rather than summed in.
	stale := bucketObservation{Hourly: []hourlyObservation{
		{Hour: now.Add(-40 * time.Hour).UTC().Truncate(time.Hour).Format(time.RFC3339),
			observationCounts: observationCounts{NaturalLimited: 500}},
		{Hour: now.Add(-2 * time.Hour).UTC().Truncate(time.Hour).Format(time.RFC3339),
			observationCounts: observationCounts{NaturalLimited: 7}},
	}}
	if got := stale.rollup(now, 24*time.Hour); got.NaturalLimited != 7 {
		t.Errorf("24h rollup over a 40h-old slot = %d, want 7: the old hour must not be counted", got.NaturalLimited)
	}

	// The ring is capped. Past the cap the oldest hour goes, not the newest.
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

// addAll is hand-written, so a counter added to the struct and forgotten here
// would silently read as zero in every rollup. Walk the type instead of
// trusting the list.
func TestObservationCountsAddAllCoversEveryField(t *testing.T) {
	var src observationCounts
	value := reflect.ValueOf(&src).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() != reflect.Int64 {
			t.Fatalf("observationCounts.%s is a %s; this test assumes every counter is an int64",
				value.Type().Field(i).Name, field.Kind())
		}
		field.SetInt(int64(i + 1)) // distinct, so a copied-wrong field shows up
	}

	var dst observationCounts
	dst.addAll(src)
	if dst != src {
		t.Errorf("addAll dropped or misplaced a counter.\n got: %+v\nwant: %+v\n"+
			"every field of observationCounts needs a line in addAll", dst, src)
	}
}

// Silence with nothing injected is the majority of traffic and says nothing
// about serving state. Recording it would bury the readings that matter.
func TestObservationIgnoresUninterestingSilence(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 0, false)
	if buckets, recent, _ := observationsSnapshot(); len(buckets) != 0 || len(recent) != 0 {
		t.Errorf("a silent, untouched response was recorded: %d bucket(s), %d event(s)", len(buckets), len(recent))
	}

	// But silence AFTER we injected is the signal that the template was taken.
	recordObservation(cfg, "a.json", "gpt-5.5", 0, true)
	if cell := observedBucket(t, "a.json", "gpt-5.5"); cell.InjectedSilent != 1 {
		t.Errorf("InjectedSilent = %d, want 1: silence after an injection is how acceptance is seen", cell.InjectedSilent)
	}
}

// An observation with no account cannot be filed. Bucketing it anywhere would
// put one customer's throttling on another customer's row.
func TestObservationRequiresAFullKey(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "", "gpt-5.5", 312, false)
	recordObservation(cfg, "a.json", "", 312, false)
	recordObservation(cfg, "  ", "  ", 312, true)

	if buckets, _, _ := observationsSnapshot(); len(buckets) != 0 {
		t.Errorf("recorded %d cell(s) from observations with an incomplete key", len(buckets))
	}
}

// The blind spot, asserted directly. While a bucket holds a template every
// request is injected and the upstream signs nothing, so LastNatural stops
// advancing even though LastAt keeps moving. The dashboard ages the natural
// reading off these two fields; if injected traffic refreshed LastNatural,
// an hour-old "normal" would render as current.
func TestInjectedObservationsDoNotRefreshTheNaturalReading(t *testing.T) {
	cfg := resetObservations(t, "")

	recordObservation(cfg, "a.json", "gpt-5.5", 292, false)
	first := observedBucket(t, "a.json", "gpt-5.5")
	if first.LastNaturalKind != observationNormal || first.LastNaturalAt == "" {
		t.Fatalf("natural reading not recorded: kind=%q at=%q", first.LastNaturalKind, first.LastNaturalAt)
	}

	time.Sleep(1100 * time.Millisecond) // RFC3339 is second-resolution
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

// A 312 arriving while we hold a template is the one alarm here: the bucket
// cannot be rescued by what this plugin does.
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
	// Last one in was i = max+39, which is odd, so a 292.
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

	// Reload into a cleared tally: the counts must come back.
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

// A snapshot from a future or unknown format is dropped, not guessed at. There
// is deliberately no migration path: these are discardable counts.
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

// A malformed model id must not be able to grow the map without bound.
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

// The observation is taken before the harvest path's own checks, so it sees
// responses the harvester discards -- a 312 above all, which is the reading
// that matters most and is never stored as a template.
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

// dry_run exists to watch without touching anything. If a dry-run decision
// counted as an injection, every observation taken in that mode would be filed
// under the wrong half of the split.
func TestDryRunDecisionIsNotCountedAsAnInjection(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resetObservations(t, "")

	rememberRequestAuth("req-dry", "codex-alpha.json")
	// markRequestSteered is what interceptAfterAuth calls only past the dry_run
	// check; a dry run reaches its return without calling it.
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

// --- the status document ---------------------------------------------------

// The tally has to reach the page, attached to the row it belongs to.
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

// A bucket nothing has been seen for must not carry an empty tally, which the
// page would have to tell apart from a real zero.
func TestStatusOmitsObservationsForUnseenBuckets(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resetObservations(t, "")
	// A stored bucket gives the matrix a row to render. Without one the loop
	// below would pass over nothing.
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	status := mustManagementStatus(t)
	// The seeded cell carries its tally; the sibling cell -- same account, a
	// model nothing has been seen for -- must render without one, or the page
	// cannot tell "no traffic" apart from a real zero.
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

// The case that would otherwise be invisible: a model the upstream throttles so
// hard that no template ever lands has no store record, and if it is also not
// in the configured list it gets no matrix row either. Its throttling would be
// missing from the one page that exists to show throttling.
func TestStatusGivesARowToAnObservedButUnconfiguredModel(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // configures gpt-5.5 and gpt-5.6-sol
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
	// It is drift, not a target: counting it would report progress against a
	// denominator the operator never chose.
	for _, model := range status.Models {
		if model == "gpt-6-astra" {
			t.Fatal("gpt-6-astra leaked into the configured models list")
		}
	}
}
