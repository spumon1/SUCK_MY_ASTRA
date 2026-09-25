// Route-cookie domain: the load-balancer cookies that steer a request onto a
// particular upstream gateway node.
//
// The model, as measured 2026-09-22 (FINDINGS.md): the upstream fronts many
// gateway nodes (chat.gateway.unified-N.api.openai.com). Which node a request
// lands on is decided by the __cflb/__oailb pair, not by the egress IP and not
// by the account -- the pair is a routing credential in its own right, usable
// by ANY account, and steering on it alone keeps the serving state normal.
// The turn-state ticket is consequently out of the picture entirely.
//
// So the pool below is GLOBAL: a set minted through one exit serves every
// account, and different exits mint different nodes -- "hitting the upstream
// from many IPs" is really "collecting many nodes". Which node a pair pins is
// written inside the cookie value itself (gatewayLabel extracts it), because
// the gateway needs nothing else to route on.
//
// Only the two load-balancer names are ever stored or replayed. A codex
// response sets other cookies too (device id, session material), and replaying
// those would pin one session's identity onto another client's traffic. The
// allowlist is what keeps "forward the upstream's cookies" from becoming
// "forward the upstream's account".

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// routeCookieWanted reports whether a Set-Cookie name is one of the
// load-balancer cookies this plugin replays. Comparison is on the name with
// leading underscores stripped and case folded, so _cflb, __cflb and any other
// underscore variant of the same cookie all match -- the exact spelling on the
// wire is whatever the upstream chose, and it is preserved verbatim when
// stored.
func routeCookieWanted(name string) bool {
	switch strings.ToLower(strings.TrimLeft(name, "_")) {
	case "cflb", "oailb":
		return true
	}
	return false
}

// routeCookieSet is the wire shape: the name=value pairs and the timing fields
// of one observed Set-Cookie batch. seenAt is when the upstream sent it;
// expireAt is the earliest declared deadline across the set (Max-Age or
// Expires, whichever lands first), or the zero time when no cookie declared one.
type routeCookieSet struct {
	pairs    map[string]string
	seenAt   time.Time
	expireAt time.Time
}

// routeCookiesFromResponseHeaders extracts the routing cookies out of an
// upstream response's Set-Cookie headers. A cookie whose declared deadline has
// already lapsed -- Max-Age<=0, or an Expires in the past -- is treated as a
// deletion rather than a value.
func routeCookiesFromResponseHeaders(headers http.Header, now time.Time) routeCookieSet {
	set := routeCookieSet{seenAt: now}
	for key, values := range headers {
		if !strings.EqualFold(key, "Set-Cookie") {
			continue
		}
		for _, line := range values {
			name, value, deadline := parseSetCookieLine(line, now)
			if name == "" || !routeCookieWanted(name) {
				continue
			}
			if !deadline.IsZero() && !deadline.After(now) {
				// A deletion: the upstream just asked every client to drop this
				// cookie. Never store a value it already retired.
				continue
			}
			if set.pairs == nil {
				set.pairs = map[string]string{}
			}
			set.pairs[name] = value
			if !deadline.IsZero() && (set.expireAt.IsZero() || deadline.Before(set.expireAt)) {
				set.expireAt = deadline
			}
		}
	}
	return set
}

// parseSetCookieLine splits one Set-Cookie value into name, value and the
// deadline the upstream declared for it. Two attribute spellings both count:
// Max-Age (seconds from now) and Expires (an absolute HTTP date). __cflb is
// issued with Expires only, so reading just Max-Age would treat its declared
// lifetime as absent -- and a deadline that came from the upstream itself is
// the one bound this plugin must not invent past. Attributes after the first
// ";" are scanned for those two only -- Path, Domain, SameSite and friends
// describe where a browser would send the cookie, none of which constrains
// this plugin's replay to the one host it harvested from.
//
// The value itself can sign a better deadline than the transport attributes:
// __oailb is a JWT whose own exp is what the gateway will actually enforce --
// measured exp-iat=3900 while Max-Age/Expires say 3600, and pairs have been
// observed serving past the attribute deadline. A credential's own claim wins
// over the header's hint when both are present; the attributes are the
// fallback for values that carry no claim. The returned time is the earlier of
// the two attribute declarations, or the JWT exp; zero when none exist.
func parseSetCookieLine(line string, now time.Time) (name, value string, deadline time.Time) {
	segments := strings.Split(line, ";")
	first := strings.TrimSpace(segments[0])
	eq := strings.Index(first, "=")
	if eq <= 0 {
		return "", "", time.Time{}
	}
	name = strings.TrimSpace(first[:eq])
	value = strings.TrimSpace(first[eq+1:])
	if !cookieNameSafe(name) || !cookieValueSafe(value) {
		return "", "", time.Time{}
	}
	for _, attr := range segments[1:] {
		attr = strings.TrimSpace(attr)
		switch {
		case len(attr) > 8 && strings.EqualFold(attr[:8], "max-age="):
			if parsed, err := strconv.ParseInt(strings.TrimSpace(attr[8:]), 10, 64); err == nil {
				d := now.Add(time.Duration(parsed) * time.Second)
				if deadline.IsZero() || d.Before(deadline) {
					deadline = d
				}
			}
		case len(attr) > 8 && strings.EqualFold(attr[:8], "expires="):
			// An unparseable date is ignored rather than honoured: a malformed
			// attribute must not become an absent deadline.
			if t, err := http.ParseTime(strings.TrimSpace(attr[8:])); err == nil {
				if deadline.IsZero() || t.Before(deadline) {
					deadline = t
				}
			}
		}
	}
	if t := jwtExpiresAt(value); !t.IsZero() {
		deadline = t
	}
	return name, value, deadline
}

// jwtExpiresAt reads the exp claim out of a JWT without verifying the
// signature -- the value is the upstream's own credential and its embedded
// deadline is the bound the gateway enforces, which is all this plugin needs
// from it. A non-JWT or claimless value yields the zero time.
func jwtExpiresAt(value string) time.Time {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0).UTC()
}

// cookieNameSafe rejects names that could not appear verbatim in a Cookie
// request header without smuggling structure into it.
func cookieNameSafe(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	return strings.IndexAny(name, "=; \t\r\n,") < 0
}

// cookieValueSafe does the same for the value half. An empty value is legal
// (a cleared-but-not-deleted cookie) and kept.
func cookieValueSafe(value string) bool {
	if len(value) > 4096 {
		return false
	}
	return strings.IndexAny(value, "; \t\r\n,") < 0
}

// usable reports whether the set may be sent upstream now. The window is the
// same ttl the pool is scored on: measured 2026-09-22, a minted pair kept
// serving for well over an hour -- the ~240s death in the earlier ticket
// measurements was the ticket's own limit, not the pair's. A declared deadline
// (Max-Age or Expires, observed at one hour) still shortens it: that number
// came from the upstream itself.
//
// seenAt in the future is rejected for the same reason a future template
// stamp was: it can only mean a skewed clock or a hand-edited record, and
// trusting it buys a replayed credential more life than it ever had.
func (s routeCookieSet) usable(now time.Time, ttl time.Duration) bool {
	if len(s.pairs) == 0 || s.seenAt.IsZero() || s.seenAt.After(now) {
		return false
	}
	if !now.Before(s.seenAt.Add(ttl)) {
		return false
	}
	if !s.expireAt.IsZero() && !now.Before(s.expireAt) {
		return false
	}
	return true
}

// header renders the set as one Cookie request-header value. Keys are sorted so
// the output is stable -- it doubles as the pool's dedupe key.
func (s routeCookieSet) header() string {
	return cookieHeaderValue(s.pairs)
}

// cookieHeaderValue renders a name=value map as a Cookie header value, sorted
// for determinism.
func cookieHeaderValue(pairs map[string]string) string {
	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+pairs[name])
	}
	return strings.Join(parts, "; ")
}

// mergeRouteCookies overlays the set onto a request's existing Cookie header,
// returning the merged value. Stored names win over same-named client pairs --
// a client pair that pins a different node is exactly the steer this exists to
// replace -- while names the pool does not cover are left in place, in the
// position the client sent them. An identical result means the caller does not
// need to touch the header at all.
func mergeRouteCookies(existing string, pairs map[string]string) string {
	if len(pairs) == 0 {
		return existing
	}
	type pair struct{ name, value string }
	var pairs2 []pair
	positions := map[string]int{}
	for _, segment := range strings.Split(existing, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		name, value := segment, ""
		if eq := strings.Index(segment, "="); eq >= 0 {
			name, value = strings.TrimSpace(segment[:eq]), segment[eq+1:]
		}
		if _, seen := positions[name]; seen {
			continue
		}
		positions[name] = len(pairs2)
		pairs2 = append(pairs2, pair{name, value})
	}
	for name, value := range pairs {
		if at, seen := positions[name]; seen {
			pairs2[at].value = value
			continue
		}
		positions[name] = len(pairs2)
		pairs2 = append(pairs2, pair{name, value})
	}
	var b strings.Builder
	for i, p := range pairs2 {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(p.name)
		b.WriteString("=")
		b.WriteString(p.value)
	}
	return b.String()
}

// --- the pool ----------------------------------------------------------------

// routeCookieGatewayRe pulls the node label out of a cookie value. The value
// itself carries the gateway's identity -- that is the entire reason a cookie
// can route on its own: the LB reads its own name off the pair. Observed shape
// is chat.gateway.unified-N.api.openai.com; the pattern is kept loose because
// the id is what matters, not the spelling around it.
var routeCookieGatewayRe = regexp.MustCompile(`(?i)(unified[-_.]?\d+|gateway[-_.][a-z0-9\-]+)`)

// gatewayLabel returns a short display name for the node this pair pins, or ""
// when neither value exposes one -- the pair still routes, it just has no
// pretty name. Falling back to a hash keeps anonymous-but-distinct entries
// tellable apart on the dashboard.
func gatewayLabel(pairs map[string]string) string {
	for _, name := range []string{"__oailb", "__cflb"} {
		if m := routeCookieGatewayRe.FindString(pairs[name]); m != "" {
			return m
		}
	}
	// Nothing readable in either value. The pair is still a distinct node;
	// label it by its own fingerprint so two such entries do not collapse into
	// one anonymous row.
	h := fnv.New32a()
	_, _ = h.Write([]byte(cookieHeaderValue(pairs)))
	return fmt.Sprintf("lb-%08x", h.Sum32())
}

// routeCookieEntry is one pooled pair plus its provenance and outcome marks.
type routeCookieEntry struct {
	// Pairs is the name=value set replayed verbatim on requests.
	Pairs map[string]string `json:"pairs"`
	// Gateway is the display label extracted from the pair values.
	Gateway string `json:"gateway,omitempty"`
	// Via is the exit URL that minted the pair (empty when it arrived on
	// ordinary business traffic, whose egress is the account's own). Kept so the
	// probe can re-dial a productive exit -- and masked anywhere it is printed.
	Via string `json:"via,omitempty"`
	// SeenAt is the last time the upstream sent this pair on a Set-Cookie.
	SeenAt string `json:"seen_at"`
	// ExpireAt is the earliest declared deadline (Max-Age or Expires), when any
	// was declared.
	ExpireAt string `json:"expire_at,omitempty"`
	// GoodAt is the last time a request carrying this pair got a normal serving
	// state back -- the strongest evidence the node is still accepting the
	// steer.
	GoodAt string `json:"good_at,omitempty"`
	// BadAt is the last time a steered request came back degraded. A single bad
	// mark is ambiguous (the account may be throttled rather than the node), so
	// the mark only deprioritises the entry, never deletes it.
	BadAt string `json:"bad_at,omitempty"`
}

// routeCookiePoolFile is the on-disk pool: one top-level JSON document beside
// the scope file. Earlier versions hung the pair on per-bucket records; the
// pool is account-agnostic now, so one file holds all of it.
const routeCookiePoolFile = "route-cookies.json"

const routeCookiePoolVersion = 1

type routeCookiePoolDoc struct {
	Version   int                `json:"version"`
	UpdatedAt string             `json:"updated_at"`
	Entries   []routeCookieEntry `json:"entries"`
}

// cookieEntryKey is the dedupe identity: the pair set itself, canonicalised.
// Two exits that land on the same node mint the same pairs and collapse to one
// entry -- which is correct, because they are the same credential.
func cookieEntryKey(pairs map[string]string) string {
	return cookieHeaderValue(pairs)
}

// entrySeen parses the entry's seen_at. Missing/unparsable reports zero.
func entrySeen(e routeCookieEntry) time.Time {
	t, _ := time.Parse(time.RFC3339, e.SeenAt)
	return t
}

// entryExpiry parses the declared deadline; zero when absent.
func entryExpiry(e routeCookieEntry) time.Time {
	t, _ := time.Parse(time.RFC3339, e.ExpireAt)
	return t
}

// entryUsable is the pool-side liveness check: the pair is inside its window
// measured from the last sighting, capped by any declared deadline. goodAt does
// NOT extend the window -- a pair observed serving normally 5 minutes ago but
// minted an hour ago is still gone, because the upstream rotates the values.
func entryUsable(e routeCookieEntry, now time.Time, ttl time.Duration) bool {
	set := routeCookieSet{pairs: e.Pairs, seenAt: entrySeen(e), expireAt: entryExpiry(e)}
	return set.usable(now, ttl)
}

// entryBad reports whether the entry carries a recent degraded mark.
func entryBad(e routeCookieEntry, now time.Time, penalty time.Duration) bool {
	bad, err := time.Parse(time.RFC3339, e.BadAt)
	if err != nil {
		return false
	}
	return now.Sub(bad) < penalty
}

// entryScore ranks entries for steering: proven-good evidence first (latest
// good_at), then freshest mint. Penalised entries sort below unpenalised ones
// regardless of score -- a node that just answered degraded is a worse bet than
// any untried one.
func entryScore(e routeCookieEntry, now time.Time) time.Time {
	if good, err := time.Parse(time.RFC3339, e.GoodAt); err == nil && good.After(entrySeen(e)) {
		return good
	}
	return entrySeen(e)
}

// routeCookieBadPenalty is how long a degraded mark deprioritises an entry.
// Short on purpose: a 312 is ambiguous evidence -- it may be the node or the
// account -- so the penalty is a nudge to try the rest of the pool, not a
// blacklist. Var so tests can shrink it.
var routeCookieBadPenalty = 90 * time.Second

// routeCookieFlushInterval bounds how often the pool file is rewritten. Marks
// and seenAt updates land on nearly every response; the file only has to be
// fresh enough that a restart does not mistake live pairs for dead ones.
var routeCookieFlushInterval = 15 * time.Second

// loadRouteCookiePool reads the pool file and folds in any pairs still hanging
// on legacy bucket records (the pre-pool format: <auth>/<model>.json with
// route_cookies fields). Loading is a one-shot at configure/startup -- every
// writer is in-process, so the in-memory pool is authoritative afterwards and
// no watch loop is needed.
func loadRouteCookiePool(dir string) map[string]*routeCookieEntry {
	out := make(map[string]*routeCookieEntry)
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return out
	}
	data, errRead := os.ReadFile(filepath.Join(dir, routeCookiePoolFile))
	if errRead == nil {
		var doc routeCookiePoolDoc
		if errUnmarshal := json.Unmarshal(data, &doc); errUnmarshal != nil {
			log.Printf(logPrefix+"%s unreadable, pool starts empty: %v", routeCookiePoolFile, errUnmarshal)
		} else if doc.Version != routeCookiePoolVersion {
			log.Printf(logPrefix+"%s is version %d, want %d; pool starts empty", routeCookiePoolFile, doc.Version, routeCookiePoolVersion)
		} else {
			for i := range doc.Entries {
				e := doc.Entries[i]
				if len(e.Pairs) == 0 {
					continue
				}
				out[cookieEntryKey(e.Pairs)] = &e
			}
		}
	} else if !os.IsNotExist(errRead) {
		log.Printf(logPrefix+"could not read %s: %v", routeCookiePoolFile, errRead)
	}
	// Legacy fold-in: records written by the per-bucket format carry the same
	// pairs. Idempotent, and it costs one directory scan at load time -- far
	// cheaper than losing a warm pool on upgrade.
	for _, e := range legacyRouteCookieEntries(dir) {
		key := cookieEntryKey(e.Pairs)
		if cur, ok := out[key]; !ok || entrySeen(e).After(entrySeen(*cur)) {
			out[key] = &e
		}
	}
	return out
}

// writeRouteCookiePool persists the pool atomically. Dead entries are pruned at
// write time so the file cannot grow without bound.
func writeRouteCookiePool(dir string, pool map[string]*routeCookieEntry, now time.Time, ttl time.Duration) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty")
	}
	doc := routeCookiePoolDoc{Version: routeCookiePoolVersion, UpdatedAt: now.UTC().Format(time.RFC3339)}
	for _, e := range pool {
		if entryUsable(*e, now, ttl) {
			doc.Entries = append(doc.Entries, *e)
		}
	}
	sort.Slice(doc.Entries, func(i, j int) bool { return doc.Entries[i].Gateway < doc.Entries[j].Gateway })
	data, errMarshal := json.MarshalIndent(doc, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	return atomicWrite(filepath.Join(dir, routeCookiePoolFile), append(data, '\n'))
}

// entrySecondsLeft is the display side of entryUsable: time until the pair's
// window closes, capped by whichever deadline lands first.
func entrySecondsLeft(e routeCookieEntry, now time.Time, ttl time.Duration) int64 {
	if !entryUsable(e, now, ttl) {
		return 0
	}
	deadline := entrySeen(e).Add(ttl)
	if expire := entryExpiry(e); !expire.IsZero() && expire.Before(deadline) {
		deadline = expire
	}
	return int64(deadline.Sub(now).Seconds())
}

// bestRouteCookie picks the entry to steer the next request with. Penalised
// entries (a recent degraded mark) sort below every unpenalised one; among the
// survivors the freshest evidence wins -- a pair the upstream just proved good
// beats a pair that merely exists. Returns ok=false when the pool has nothing
// usable at all.
func bestRouteCookie(pool map[string]*routeCookieEntry, now time.Time, ttl time.Duration) (routeCookieEntry, bool) {
	var best, fallback *routeCookieEntry
	var bestScore, fallbackScore time.Time
	for _, e := range pool {
		if !entryUsable(*e, now, ttl) {
			continue
		}
		score := entryScore(*e, now)
		if entryBad(*e, now, routeCookieBadPenalty) {
			if fallback == nil || score.After(fallbackScore) {
				fallback, fallbackScore = e, score
			}
			continue
		}
		if best == nil || score.After(bestScore) {
			best, bestScore = e, score
		}
	}
	if best != nil {
		return *best, true
	}
	// Every usable entry is penalised: a degraded mark is a nudge, not a veto --
	// an ambiguous 312 should not stop steering altogether.
	if fallback != nil {
		return *fallback, true
	}
	return routeCookieEntry{}, false
}

// --- pluginState plumbing -----------------------------------------------------
//
// The pool is the only reusable credential the plugin holds, so the helpers
// below are the whole of its lifecycle: fold a sighting in, pick the entry to
// steer with, stamp the outcome back onto the entry that was used, and get the
// file to disk often enough that a restart keeps warm pairs. Everything here
// runs under state.mu; the disk write inside the note path is deliberate --
// atomicWrite is a few milliseconds against a small file, once per
// routeCookieFlushInterval at most, which is a better trade than a flush
// goroutine for a store this size.

// noteRouteCookiesLocked folds one freshly observed pair into the pool. via is
// the probe exit that minted it -- recorded so a later renewal can re-dial the
// productive exit; empty for pairs collected off ordinary business traffic.
// The caller must hold state.mu.
func (s *pluginState) noteRouteCookiesLocked(set routeCookieSet, via string) {
	if len(set.pairs) == 0 || set.seenAt.IsZero() {
		return
	}
	key := cookieEntryKey(set.pairs)
	e := s.cookies[key]
	if e == nil {
		e = &routeCookieEntry{
			Pairs:   set.pairs,
			Gateway: gatewayLabel(set.pairs),
		}
		s.cookies[key] = e
	}
	if set.seenAt.After(entrySeen(*e)) {
		e.SeenAt = set.seenAt.UTC().Format(time.RFC3339)
	}
	if !set.expireAt.IsZero() {
		e.ExpireAt = set.expireAt.UTC().Format(time.RFC3339)
	}
	if via != "" {
		// Latest productive exit wins: it is the one the renewal wants back.
		e.Via = via
	}
	s.cookiesDirty = true
	s.flushRouteCookiesLocked(time.Now())
}

// flushRouteCookiesLocked persists the pool when it is dirty and the last
// write is at least routeCookieFlushInterval old. The caller must hold
// state.mu. A failed write keeps the dirty flag so the next note retries.
func (s *pluginState) flushRouteCookiesLocked(now time.Time) {
	if !s.cookiesDirty || s.config.StoreDir == "" {
		return
	}
	if !s.cookiesFlushed.IsZero() && now.Sub(s.cookiesFlushed) < routeCookieFlushInterval {
		return
	}
	if err := writeRouteCookiePool(s.config.StoreDir, s.cookies, now, s.config.ttl()); err != nil {
		log.Printf(logPrefix+"pool flush failed: %v", err)
		return
	}
	s.cookiesDirty = false
	s.cookiesFlushed = now
}

// bestRouteCookieLocked picks the pair the next steered request should carry.
// It also returns the pool key so the response hook can stamp the outcome onto
// exactly the entry that was used -- a second caller judging "best" again could
// land on a different entry once marks shift the scores. The caller must hold
// state.mu.
func (s *pluginState) bestRouteCookieLocked(now time.Time, ttl time.Duration) (routeCookieSet, string, bool) {
	e, ok := bestRouteCookie(s.cookies, now, ttl)
	if !ok {
		return routeCookieSet{}, "", false
	}
	return routeCookieSet{pairs: e.Pairs, seenAt: entrySeen(e), expireAt: entryExpiry(e)},
		cookieEntryKey(e.Pairs), true
}

// markRouteCookieOutcomeLocked stamps good_at or bad_at onto the entry a
// steered request carried, from the serving state the upstream signed for it.
// The pair's own question is narrow: did the node accept the steer and serve
// the request. A signed state that is not the known-degraded length is that
// evidence -- "other" counts too, because the length classes are per-plan
// measurements and a healthy 332 or 780 must not forfeit the pair's good mark.
// Only the known-degraded signature marks bad (ambiguous -- the account may be
// throttled rather than the node -- so it deprioritises, never deletes), and a
// silent response says nothing at all. The caller must hold state.mu.
func (s *pluginState) markRouteCookieOutcomeLocked(key, kind string, now time.Time) {
	e := s.cookies[key]
	if e == nil {
		return
	}
	switch kind {
	case observationLimited:
		e.BadAt = now.UTC().Format(time.RFC3339)
	case observationSilent:
		return
	default:
		e.GoodAt = now.UTC().Format(time.RFC3339)
	}
	s.cookiesDirty = true
	s.flushRouteCookiesLocked(now)
}

// poolSecondsLeftLocked is the dashboard's liveness number: the longest any
// entry can still be sent. The caller must hold state.mu.
func (s *pluginState) poolSecondsLeftLocked(now time.Time, ttl time.Duration) int64 {
	var left int64
	for _, e := range s.cookies {
		if l := entrySecondsLeft(*e, now, ttl); l > left {
			left = l
		}
	}
	return left
}
