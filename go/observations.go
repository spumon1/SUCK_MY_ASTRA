// Observation domain: what serving state the upstream actually handed back,
// per (account, model), and whether we had steered that request with a pooled
// pair.
//
// This exists because the plugin is the only thing that sees both halves. CPA's
// request logs record the response header but not which credential was chosen;
// the plugin knows the credential AND what it did to the outgoing request. The
// pairing is the whole point -- see observationKind below for why an
// unpaired count would mislead.
//
// Nothing here changes a request or a response. It is pure observation of
// traffic that was happening anyway, which is what makes it safe to run
// permanently while active probing stays off.
//
// What it keeps is deliberately shallow: lifetime counts since Since, the same
// counts per hour for the last two days, and a bounded ring of recent events.
// The hourly ring exists because lifetime totals cannot answer "is this worse
// than yesterday", which is the actual question. Anything finer -- per-request
// history, retention past two days, arbitrary ranges -- belongs in the decision
// log, which any cron can roll up at no storage cost. A plugin that grows a
// metrics database has stopped being a plugin.

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// observationsFileName sits at the top of store_dir, beside index.json and
	// runtime.json. scanStoreRecords only reads <auth_id>/<model>.json under the
	// account subdirectories, so a top-level file cannot be mistaken for a
	// bucket.
	observationsFileName = "observations.json"

	// observationsVersion guards the snapshot format. On a mismatch the file is
	// ignored and collection restarts from empty -- deliberately, and there will
	// never be migration code here. This is a discardable observation snapshot,
	// not contract data: the cost of dropping it is losing counts, and the cost
	// of carrying migrations for it forever is higher.
	//
	// 2: added the hourly history and split injected-other out of
	// natural_other, which changes what an existing natural_other means.
	observationsVersion = 2

	// observationsRecentMax bounds the live feed. It rides on the status
	// document, which the dashboard polls, so this is also a bound on that
	// document's size (~12 KB at 100).
	observationsRecentMax = 100

	// observationsBucketMax bounds the tally. A malformed or hostile model id
	// would otherwise grow the map without limit; past this the least recently
	// seen bucket is dropped.
	observationsBucketMax = 256

	// observationsHourlyMax bounds the history kept per bucket: two days, which
	// is enough to ask whether today is worse than yesterday and short enough
	// that the snapshot stays small. Only hours with traffic take a slot, so an
	// idle bucket costs nothing and the worst case is bounded by this times
	// observationsBucketMax.
	observationsHourlyMax = 48

	// observationLearnMin is how many times an unrecognised signed length must
	// appear in one bucket before the tally accepts it as that bucket's own
	// normal class. The upstream's classes are not stable constants -- on
	// 2026-09-22 it unified the turn-state format and every bucket's signature
	// moved (gpt-6-astra went 292 -> 780 in place), so a fixed whitelist would
	// file healthy traffic under "other" forever after every format change.
	// Two sightings is the smallest count that separates a recurring class from
	// a stray oddity.
	observationLearnMin = 2

	// observationLensMax bounds the candidate-length table kept per bucket.
	// Lengths arrive as arbitrary ints; without a cap a hostile or buggy peer
	// could grow the map without limit. The rarest entry is dropped first.
	observationLensMax = 8
)

// observationsFlushInterval is the floor between disk writes. The snapshot is
// whole-state rather than append-only, so writing more often buys nothing but a
// shorter loss window on a hard kill; a crash loses at most this much.
//
// A var rather than a const so the tests can force a flush instead of waiting a
// minute. Nothing in production reassigns it.
var observationsFlushInterval = 60 * time.Second

// The three things the upstream can do with the turn-state on a response.
// Deliberately about the UPSTREAM's act, not about our interpretation of it:
// "limited" says a 312 was signed, nothing about model quality. See the
// dashboard copy for the operational reading laid on top.
const (
	observationNormal  = "normal"  // template_length, or a length this bucket has learned
	observationLimited = "limited" // replace_length: a degraded state was signed
	observationSilent  = "silent"  // no state signed at all
	observationOther   = "other"   // a signed length this bucket has not seen before
)

// bucketObservation is one (account, model) cell.
//
// Counts are split by whether WE had steered the request with a pooled pair,
// because a combined rate is not a degradation rate and reporting one would
// mislead. The two sides answer different questions: the natural side is what
// the upstream does to unpinned traffic, and the steered side is the evidence
// that judges the pair itself -- a steered response signed normal is what
// stamps a pool entry good (markRouteCookieOutcomeLocked).
//
// Read them this way:
//
//	NaturalNormal    upstream signed a good state, unprompted -- it is serving us
//	NaturalLimited   upstream signed a degraded state, unprompted -- throttled
//	InjectedSilent   we steered and the upstream signed nothing.
//	InjectedLimited  we steered and it degraded us anyway. The actionable alarm:
//	                 either the pair went stale, or the account itself is
//	                 throttled -- the two are told apart by the natural side.
//	InjectedNormal   we steered and it signed a fresh good state regardless.
//	InjectedOther    we steered and it signed something unrecognised -- e.g. a
//	                 length outside the configured classes, which is what the
//	                 per-plan drift in FINDINGS.md looks like on this page.
type bucketObservation struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`

	observationCounts

	// Last* describe the most recent observation of any kind, silent ones
	// included. So this answers "is traffic flowing through this bucket",
	// which is a different question from "has the upstream told us anything",
	// and the dashboard needs both to tell injection blindness apart from an
	// account nobody is using.
	LastKind  string `json:"last_kind"`
	LastLen   int    `json:"last_len"`
	LastWrote bool   `json:"last_wrote"`
	LastAt    string `json:"last_at"`

	// LastSigned* describe the most recent observation in which the upstream
	// actually put a state on the wire -- whether or not we had injected into
	// that request. This is what the dashboard ages.
	//
	// Not LastNatural*, and the difference is load bearing: a 292 signed on a
	// request we injected into is still the upstream saying it serves this
	// account normally. Ageing only the unprompted readings would file that
	// evidence away as "blind", which is the opposite of what it shows.
	LastSignedKind  string `json:"last_signed_kind,omitempty"`
	LastSignedAt    string `json:"last_signed_at,omitempty"`
	LastSignedWrote bool   `json:"last_signed_wrote,omitempty"`

	// LastNatural* narrow that to the unprompted readings. Kept because the
	// injected/natural split is the whole reason these counts mean anything,
	// and an operator reading one row has to know which side it came from.
	LastNaturalKind string `json:"last_natural_kind,omitempty"`
	LastNaturalAt   string `json:"last_natural_at,omitempty"`

	// Hourly is the history: one entry per hour that saw traffic, oldest
	// first, capped at observationsHourlyMax. An idle bucket carries none.
	Hourly []hourlyObservation `json:"hourly,omitempty"`

	// SignedLens counts sightings of each signed length this bucket has shown
	// that matches neither configured class -- the learning table behind the
	// "other -> normal" promotion. Bounded at observationLensMax entries. Only
	// candidate normals land here: replace_length classifies before it could
	// ever be counted, so the degraded signature can never be learned away.
	SignedLens map[int]int `json:"signed_lens,omitempty"`
}

// observationCounts is the seven-way split of what happened, used for the
// lifetime tally and for each hour of history alike.
//
// One type and one add() for both, because the alternative -- two switches
// over the same cases -- fails by having a new kind wired into one and not the
// other, and that shows up only as history that quietly disagrees with the
// total. Embedded untagged, so these serialise flat: a caller reads
// observed.natural_normal, not observed.counts.natural_normal.
type observationCounts struct {
	NaturalNormal  int64 `json:"natural_normal"`
	NaturalLimited int64 `json:"natural_limited"`
	NaturalOther   int64 `json:"natural_other"`

	InjectedSilent  int64 `json:"injected_silent"`
	InjectedLimited int64 `json:"injected_limited"`
	InjectedNormal  int64 `json:"injected_normal"`
	InjectedOther   int64 `json:"injected_other"`
}

// add books one observation.
//
// The (silent, not-steered) pair never arrives -- recordObservation drops it
// as noise before this is reached -- so the last case is (other, not
// steered). Every steered case is named explicitly rather than falling
// through, because "we steered and got back something unrecognised" filed
// under NaturalOther would put our own traffic on the unprompted side of the
// split and corrupt the only counts that can be read as a rate.
func (c *observationCounts) add(wrote bool, kind string) {
	switch {
	case wrote && kind == observationSilent:
		c.InjectedSilent++
	case wrote && kind == observationLimited:
		c.InjectedLimited++
	case wrote && kind == observationNormal:
		c.InjectedNormal++
	case wrote:
		c.InjectedOther++
	case kind == observationNormal:
		c.NaturalNormal++
	case kind == observationLimited:
		c.NaturalLimited++
	default:
		c.NaturalOther++
	}
}

// addAll sums another set in. TestObservationCountsAddAllCoversEveryField walks
// the type to prove no counter is missed here.
func (c *observationCounts) addAll(o observationCounts) {
	c.NaturalNormal += o.NaturalNormal
	c.NaturalLimited += o.NaturalLimited
	c.NaturalOther += o.NaturalOther
	c.InjectedSilent += o.InjectedSilent
	c.InjectedLimited += o.InjectedLimited
	c.InjectedNormal += o.InjectedNormal
	c.InjectedOther += o.InjectedOther
}

// hourlyObservation is one hour of the same counts.
//
// The lifetime totals answer "how many since we started", which is the wrong
// shape for the question an operator actually has -- is this worse than it was
// yesterday. Only hours with traffic get an entry.
type hourlyObservation struct {
	Hour string `json:"hour"` // RFC3339, truncated to the hour, UTC
	observationCounts
}

// hourSlot returns the counters for now's hour, appending a slot if this is
// the first observation in it and dropping the oldest once the ring is full.
//
// The returned pointer aims into the slice, so it is only valid until the next
// append. Every caller uses it immediately, under the lock.
func (b *bucketObservation) hourSlot(now time.Time) *observationCounts {
	hour := now.UTC().Truncate(time.Hour).Format(time.RFC3339)

	// Observations arrive in time order, so the current hour is the last entry
	// essentially always. The scan behind it covers a clock stepping backwards,
	// which would otherwise open a second slot for an hour already present.
	for i := len(b.Hourly) - 1; i >= 0; i-- {
		if b.Hourly[i].Hour == hour {
			return &b.Hourly[i].observationCounts
		}
	}

	b.Hourly = append(b.Hourly, hourlyObservation{Hour: hour})
	if len(b.Hourly) > observationsHourlyMax {
		b.Hourly = b.Hourly[len(b.Hourly)-observationsHourlyMax:]
	}
	return &b.Hourly[len(b.Hourly)-1].observationCounts
}

// rollup sums the hours falling inside window. Hours are whole, so a 24h
// window covers the last 24 hour-slots rather than exactly 24 hours -- close
// enough for "is today worse than yesterday", and the alternative is keeping
// per-request timestamps this deliberately does not keep.
func (b bucketObservation) rollup(now time.Time, window time.Duration) observationCounts {
	cutoff := now.UTC().Add(-window)
	var out observationCounts
	for _, h := range b.Hourly {
		at, err := time.Parse(time.RFC3339, h.Hour)
		if err != nil || at.Before(cutoff) {
			continue
		}
		out.addAll(h.observationCounts)
	}
	return out
}

// observationSummary is a bucketObservation stripped of the key fields, for
// hanging off a status row that already carries auth_id and model. Repeating
// them there would put two sources of truth for the same key on one published
// document.
type observationSummary struct {
	observationCounts

	LastKind  string `json:"last_kind"`
	LastLen   int    `json:"last_len"`
	LastWrote bool   `json:"last_wrote"`
	LastAt    string `json:"last_at"`

	LastSignedKind  string `json:"last_signed_kind,omitempty"`
	LastSignedAt    string `json:"last_signed_at,omitempty"`
	LastSignedWrote bool   `json:"last_signed_wrote,omitempty"`

	LastNaturalKind string `json:"last_natural_kind,omitempty"`
	LastNaturalAt   string `json:"last_natural_at,omitempty"`

	// Recent24h is the hourly history rolled into one figure per counter. The
	// lifetime totals above can only answer "how many since we started", and
	// an operator comparing today with yesterday cannot get there from a pair
	// of numbers that only ever grow.
	//
	// The hours themselves are not published. They are on disk for whoever
	// wants to chart them; putting 48 slots per bucket on a document the
	// dashboard polls would grow it by more than the panel can use.
	Recent24h observationCounts `json:"recent_24h"`
}

func (b bucketObservation) summary(now time.Time) observationSummary {
	return observationSummary{
		observationCounts: b.observationCounts,
		LastKind:          b.LastKind,
		LastLen:           b.LastLen,
		LastWrote:         b.LastWrote,
		LastAt:            b.LastAt,
		LastSignedKind:    b.LastSignedKind,
		LastSignedAt:      b.LastSignedAt,
		LastSignedWrote:   b.LastSignedWrote,
		LastNaturalKind:   b.LastNaturalKind,
		LastNaturalAt:     b.LastNaturalAt,
		Recent24h:         b.rollup(now, 24*time.Hour),
	}
}

// observationEvent is one row of the live feed. Every field is structured --
// no free text. The status document is anonymously readable and a free-text
// channel on it is a leak waiting to be written; see probe_run.lines for the
// one that already exists and the constraint it carries.
type observationEvent struct {
	At     string `json:"at"`
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	Len    int    `json:"len"`
	Wrote  bool   `json:"wrote"`
	Kind   string `json:"kind"`
	// Served is the model the SSE payload declared when it differs from the
	// requested one -- the unified format's downgrade signature (the upstream
  // safety-buffering fallback actually serving the turn). Empty on every
	// length-classified event.
	Served string `json:"served,omitempty"`
}

// observationSnapshot is the whole persisted state, rewritten atomically. It is
// not appended to: a torn append would need recovery logic, and a 20 KB
// rewrite once a minute does not.
type observationSnapshot struct {
	Version   int                 `json:"version"`
	Since     string              `json:"since"`
	UpdatedAt string              `json:"updated_at"`
	Buckets   []bucketObservation `json:"buckets"`
	Recent    []observationEvent  `json:"recent"`
}

// observations holds the live tally.
//
// Its own mutex, deliberately NOT state.mu. handleStatus already avoids holding
// state.mu and the probe runner's lock at once, and adding a third lock under
// state.mu would reintroduce exactly that ordering hazard. Nothing in here ever
// takes state.mu, so it cannot participate in a cycle.
var observations = struct {
	mu      sync.Mutex
	since   time.Time
	byKey   map[string]*bucketObservation
	recent  []observationEvent
	dirty   bool
	lastOut time.Time // last successful flush
	writing bool      // a flush goroutine is in flight
	dir     string    // store_dir this tally was loaded for
}{byKey: make(map[string]*bucketObservation)}

// classifyObservation maps a response's turn-state length onto what the
// upstream did. Lengths come from config because they are observations about
// the upstream rather than protocol constants -- they differ by plan: a
// prolite account signed 292 while a self_serve_business_prolite account
// signed 332 on normal responses (both measured 2026-09-22), and the unified
// format the upstream rolled out the same day moved whole accounts to 780.
// This is the static half of the classifier: the per-bucket learned half sits
// in noteSignedLen, which promotes a recurring unrecognised length to normal
// so a format change reads as one "other" sighting instead of a permanent
// misclassification. An "other" streak on visibly healthy traffic still means
// the signature keeps changing, not that the account is failing -- see
// FINDINGS.md.
func classifyObservation(cfg pluginConfig, valueLen int) string {
	switch valueLen {
	case 0:
		return observationSilent
	case cfg.TemplateLength:
		return observationNormal
	case cfg.ReplaceLength:
		return observationLimited
	default:
		return observationOther
	}
}

// noteSignedLen counts one sighting of an unrecognised signed length and
// reports whether it has recurred enough to stand as this bucket's normal
// class. The count is taken before the verdict, so a length promotes on its
// SECOND appearance -- the first is filed as "other", which is what a brand
// new signature should look like on the feed.
//
// Only ever called on lengths that already classified "other": the configured
// degraded signature is decided before this runs, so it can neither be
// learned nor promoted. The caller holds observations.mu.
func (b *bucketObservation) noteSignedLen(l int) bool {
	if b.SignedLens == nil {
		b.SignedLens = make(map[int]int, observationLensMax)
	}
	b.SignedLens[l]++
	if len(b.SignedLens) > observationLensMax {
		// Drop the rarest candidate: a length seen once and never again is the
		// noise this table exists to absorb. Ties go to the smaller length so
		// eviction is deterministic rather than map-order dependent.
		rarest, rarestN := 0, 0
		for cand, n := range b.SignedLens {
			if cand == l {
				continue
			}
			if rarestN == 0 || n < rarestN || (n == rarestN && cand < rarest) {
				rarest, rarestN = cand, n
			}
		}
		delete(b.SignedLens, rarest)
	}
	return b.SignedLens[l] >= observationLearnMin
}

// recordObservation notes one response's turn-state length reading.
//
// wrote reports whether the request hook actually put a pooled pair on the way
// out -- not whether it wanted to. A dry_run decision is not a write, and
// counting it as one would make the whole steered/natural split meaningless in
// the mode an operator uses precisely to watch without touching anything.
//
// Called before the harvest path's own checks, so a response that carries no
// state at all still lands here: "we steered and the upstream then signed
// nothing" says the pair was accepted and no new state was owed -- a reading
// that is invisible if silence is not recorded.
func recordObservation(cfg pluginConfig, authID, model string, valueLen int, wrote bool) {
	recordEvent(authID, model, classifyObservation(cfg, valueLen), valueLen, wrote, "")
}

// recordDowngrade notes the unified format's degraded signature: the SSE
// payload declared a served model different from the requested one (the
// safety-buffering fallback answering the turn). Since the format moved, the
// turn-state length no longer carries the throttle bit -- every refusal path
// mints a normal 780 -- so degradation is read off the served-model field and
// filed under "limited", the same kind a 312 used to mean.
func recordDowngrade(authID, model, served string, tsLen int, wrote bool) {
	if strings.TrimSpace(served) == "" {
		return
	}
	recordEvent(authID, model, observationLimited, tsLen, wrote, served)
}

// recordEvent is the shared tail of both reading types: attribute the event to
// its (account, model) bucket, split the counter by kind and steered, age the
// cell, and push it onto the live feed. served is "" for length-classified
// events and the declared model on downgrade events.
func recordEvent(authID, model, kind string, valueLen int, wrote bool, served string) {
	authID = strings.TrimSpace(authID)
	model = strings.TrimSpace(model)
	if authID == "" || model == "" {
		// Unattributable. Counting it against some placeholder bucket would put
		// one account's throttling on another's row.
		return
	}
	if kind == observationSilent && !wrote {
		// Neither side did anything: no template went out, none came back. Most
		// traffic looks like this and it says nothing about serving state.
		return
	}

	now := time.Now()
	key := bucketKey(authID, model)

	observations.mu.Lock()
	cell := observations.byKey[key]
	if cell == nil {
		evictObservationBucketLocked()
		cell = &bucketObservation{AuthID: authID, Model: model}
		observations.byKey[key] = cell
	}
	if kind == observationOther && cell.noteSignedLen(valueLen) {
		// The static classes do not know this signature, but the bucket itself
		// does: it has signed this length before. Recurring means it is the
		// upstream's current format here, not a stray.
		kind = observationNormal
	}

	cell.observationCounts.add(wrote, kind)
	cell.hourSlot(now).add(wrote, kind)

	cell.LastKind = kind
	cell.LastLen = valueLen
	cell.LastWrote = wrote
	cell.LastAt = now.UTC().Format(time.RFC3339)

	// Anything that is not silence is the upstream telling us something, and it
	// counts as current evidence whether or not we had injected into that
	// request. Silence is the one reading that says nothing on its own -- under
	// injection it means our template was taken, which is not a state anyone
	// signed.
	if kind != observationSilent {
		cell.LastSignedKind = kind
		cell.LastSignedAt = cell.LastAt
		cell.LastSignedWrote = wrote
		if !wrote {
			cell.LastNaturalKind = kind
			cell.LastNaturalAt = cell.LastAt
		}
	}

	observations.recent = append(observations.recent, observationEvent{
		At:     cell.LastAt,
		AuthID: authID,
		Model:  model,
		Len:    valueLen,
		Wrote:  wrote,
		Kind:   kind,
		Served: served,
	})
	if len(observations.recent) > observationsRecentMax {
		observations.recent = observations.recent[len(observations.recent)-observationsRecentMax:]
	}
	observations.dirty = true
	dir := observations.dir
	due := now.Sub(observations.lastOut) >= observationsFlushInterval && !observations.writing
	if due {
		observations.writing = true
	}
	observations.mu.Unlock()

	if due && dir != "" {
		// Off the response path. Holding a hook open for a disk write would put
		// file latency on every upstream response.
		go flushObservations(dir)
	}
}

// evictObservationBucketLocked drops the least recently seen cell once the map
// is full. The caller holds observations.mu.
func evictObservationBucketLocked() {
	if len(observations.byKey) < observationsBucketMax {
		return
	}
	oldestKey, oldestAt := "", ""
	for key, cell := range observations.byKey {
		if oldestKey == "" || cell.LastAt < oldestAt {
			oldestKey, oldestAt = key, cell.LastAt
		}
	}
	if oldestKey != "" {
		delete(observations.byKey, oldestKey)
	}
}

// observationsSnapshot copies the tally out for the status document, sorted so
// the dashboard's rows do not reshuffle between polls.
func observationsSnapshot() ([]bucketObservation, []observationEvent, string) {
	observations.mu.Lock()
	defer observations.mu.Unlock()

	buckets := make([]bucketObservation, 0, len(observations.byKey))
	for _, cell := range observations.byKey {
		buckets = append(buckets, *cell)
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].AuthID != buckets[j].AuthID {
			return buckets[i].AuthID < buckets[j].AuthID
		}
		return buckets[i].Model < buckets[j].Model
	})

	// Newest first: the feed is read top-down by someone asking "what just
	// happened", not "what happened first".
	recent := make([]observationEvent, 0, len(observations.recent))
	for i := len(observations.recent) - 1; i >= 0; i-- {
		recent = append(recent, observations.recent[i])
	}

	since := ""
	if !observations.since.IsZero() {
		since = observations.since.UTC().Format(time.RFC3339)
	}
	return buckets, recent, since
}

// flushObservations writes the snapshot. The copy happens under the lock and
// the write outside it, so a slow disk cannot stall a response hook.
func flushObservations(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return
	}

	observations.mu.Lock()
	if !observations.dirty {
		observations.writing = false
		observations.mu.Unlock()
		return
	}
	snap := observationSnapshot{
		Version:   observationsVersion,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Recent:    append([]observationEvent(nil), observations.recent...),
	}
	if !observations.since.IsZero() {
		snap.Since = observations.since.UTC().Format(time.RFC3339)
	}
	for _, cell := range observations.byKey {
		snap.Buckets = append(snap.Buckets, *cell)
	}
	observations.dirty = false
	observations.mu.Unlock()

	sort.Slice(snap.Buckets, func(i, j int) bool {
		if snap.Buckets[i].AuthID != snap.Buckets[j].AuthID {
			return snap.Buckets[i].AuthID < snap.Buckets[j].AuthID
		}
		return snap.Buckets[i].Model < snap.Buckets[j].Model
	})

	data, errMarshal := json.MarshalIndent(snap, "", "  ")
	if errMarshal == nil {
		errWrite := atomicWrite(filepath.Join(dir, observationsFileName), append(data, '\n'))
		if errWrite != nil {
			// Not fatal and not retried: the tally lives in memory and the next
			// flush rewrites the whole thing anyway.
			log.Printf(logPrefix+"could not write %s: %v", observationsFileName, errWrite)
			observations.mu.Lock()
			observations.dirty = true
			observations.mu.Unlock()
		}
	}

	observations.mu.Lock()
	observations.lastOut = time.Now()
	observations.writing = false
	observations.mu.Unlock()
}

// loadObservations restores the tally for dir, or starts a fresh one. Called
// from configure, so a reconfigure that changes store_dir moves the tally with
// it rather than mixing two stores' counts.
func loadObservations(dir string) {
	dir = strings.TrimSpace(dir)

	observations.mu.Lock()
	defer observations.mu.Unlock()

	if observations.dir == dir && !observations.since.IsZero() {
		// Same store, already loaded. A reconfigure must not reset counts the
		// operator is watching.
		return
	}

	observations.dir = dir
	observations.byKey = make(map[string]*bucketObservation)
	observations.recent = nil
	observations.since = time.Now()
	observations.dirty = false
	// Start the clock now rather than at the zero time, so the first
	// observation after a load does not trigger an immediate write. Batching
	// from the first tick is the point: a restart should not cost a disk write
	// per response until the interval catches up.
	observations.lastOut = time.Now()

	if dir == "" {
		return
	}

	raw, errRead := os.ReadFile(filepath.Join(dir, observationsFileName))
	if errRead != nil || len(raw) == 0 {
		// Absent on first run, and that is the normal case -- not worth a log
		// line every time a fresh store_dir is configured.
		return
	}
	var snap observationSnapshot
	if errUnmarshal := json.Unmarshal(raw, &snap); errUnmarshal != nil {
		log.Printf(logPrefix+"%s is unreadable, observation counts restart from empty: %v", observationsFileName, errUnmarshal)
		return
	}
	if snap.Version != observationsVersion {
		log.Printf(logPrefix+"%s is version %d, want %d; observation counts restart from empty",
			observationsFileName, snap.Version, observationsVersion)
		return
	}
	for i := range snap.Buckets {
		cell := snap.Buckets[i]
		if strings.TrimSpace(cell.AuthID) == "" || strings.TrimSpace(cell.Model) == "" {
			continue
		}
		observations.byKey[bucketKey(cell.AuthID, cell.Model)] = &cell
	}
	if len(snap.Recent) > observationsRecentMax {
		snap.Recent = snap.Recent[len(snap.Recent)-observationsRecentMax:]
	}
	observations.recent = snap.Recent
	if parsed, errParse := time.Parse(time.RFC3339, snap.Since); errParse == nil && !parsed.IsZero() {
		observations.since = parsed
	}
}

// flushObservationsNow writes synchronously, for shutdown and reconfigure where
// there is no later flush to rely on.
func flushObservationsNow() {
	observations.mu.Lock()
	dir := observations.dir
	observations.writing = true
	observations.mu.Unlock()
	flushObservations(dir)
}

// deleteObservation drops one bucket's tally and its recent-feed rows. It is
// the per-bucket half of the dashboard's clear button: the pool has no
// per-bucket state, so the only thing "clear this bucket" can mean is "forget
// what we observed for it". Returns whether a row existed.
func deleteObservation(authID, model string) bool {
	key := bucketKey(authID, model)
	observations.mu.Lock()
	defer observations.mu.Unlock()
	if _, ok := observations.byKey[key]; !ok {
		return false
	}
	delete(observations.byKey, key)
	observations.recent = dropObservationEventsLocked(observations.recent, key)
	observations.dirty = true
	return true
}

// clearAllObservations drops every tally row and the feed. The pool-wide half
// of the same clear button.
func clearAllObservations() {
	observations.mu.Lock()
	defer observations.mu.Unlock()
	observations.byKey = make(map[string]*bucketObservation)
	observations.recent = nil
	observations.dirty = true
}

// dropObservationEventsLocked removes a bucket's rows from the recent feed.
// The caller holds observations.mu.
func dropObservationEventsLocked(events []observationEvent, key string) []observationEvent {
	out := events[:0]
	for _, e := range events {
		if bucketKey(e.AuthID, e.Model) == key {
			continue
		}
		out = append(out, e)
	}
	return out
}
