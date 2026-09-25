// In-plugin offline harvester: collects __cflb/__oailb routing pairs straight
// from the upstream, without routing through CPA or touching any CPA state.
//
// # Why direct, and why that is safe
//
// The earlier design harvested by driving CPA: it disabled every Codex account
// but one (so a harvest on CPA's own response hook could be attributed), PATCHed
// a proxy into the credential, POSTed to CPA's /v1/responses, and restored all
// of that afterwards. It cost a real incident when a run died mid-flip and left
// credentials disabled, and it could never run alongside business traffic.
//
// This harvester instead reads each account's own access_token out of its
// credential file (a read-only management call, never a write) and calls
// https://chatgpt.com/backend-api/codex/responses directly, as that account,
// through that account's own exit. CPA never sees the request. What the
// response carries is a GLOBAL routing credential -- a minted pair works for
// any account -- so which credential minted it does not matter, and every
// account stays enabled.
//
// Three rules make it safe to run against live credentials:
//   - It never writes anything to CPA. The only CPA calls are two GETs:
//     auth-files (the account list) and auth-files/download (one token).
//   - It never refreshes a token. An expired token is skipped and left for CPA
//     to refresh in its own business; refreshing here could rotate the refresh
//     token and break live traffic. (Access tokens were measured good for days,
//     so this costs almost nothing.)
//   - Steering and collection now coexist in one process: the business role
//     reads the pool on the request hook while this goroutine fills it.
//
// # Renewal
//
// A minted pair is declared for one hour (oailb Max-Age=3600, cflb Expires=+1h,
// the oailb JWT itself signs iat+3900s) and measured serving well past the old
// ~240s ticket window. The run does not stop after the first fill: it keeps a
// background loop that mints fresh pairs once the pool's best entry drops under
// probeRenewThreshold of life left, so the pool stays warm for as long as CPA
// serves traffic. That is the operator's "到期前自动续一遍".
//
// # What must never leak out of this file
//
// probeRunState.Lines is rendered on a page that needs no key. No token,
// turn-state value, cookie value, or proxy userinfo may reach it: proxies
// render through probeShowProxy/maskProxyURL, account names through
// maskAuthLabel (they carry a customer email), and everything bound for Lines
// passes probeRedact as a second line of defence. The management key this file
// reads is never logged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The two read-only management routes this harvester uses. Named here rather
// than inline so a correction for a different CPA build is a one-line change.
// Nothing else is called on CPA -- there is deliberately no write route in this
// file any more.
const (
	probeRouteAuthFiles    = "/v0/management/auth-files"
	probeRouteAuthDownload = "/v0/management/auth-files/download"
)

// The upstream endpoint and the client identity a probe presents. Both are vars
// so a test can point them at an httptest server; production never writes them.
// probeUserAgent mirrors a real codex-tui build, and the call goes out as the
// same account CPA uses, from the same box -- so the upstream sees nothing it
// would not see from ordinary Codex traffic.
var (
	probeUpstreamURL = "https://chatgpt.com/backend-api/codex/responses"
	probeUserAgent   = "codex-tui/0.154.0 (Ubuntu 24.04; x86_64) OVH (codex-tui; 0.154.0)"
)

const (
	// probeMaxLines bounds the transcript. Keeping the last forty lines is enough
	// to say where a run is and why, and it means the run state cannot grow
	// without limit in a process meant to stay up for weeks.
	probeMaxLines = 40

	// probeFireTimeout bounds one upstream call. Only the response headers are
	// wanted and they arrive before the SSE body, so this is generous; it exists
	// to stop a hung exit pinning a goroutine.
	probeFireTimeout = 60 * time.Second
	probeMgmtTimeout = 30 * time.Second

	// probeMaxAccountsInFlight bounds how many CREDENTIALS are worked at once, not
	// how many requests are open. Each account is driven by a single goroutine
	// that walks its buckets one at a time, so this is also the ceiling on
	// simultaneous upstream requests -- and, more importantly, it guarantees one
	// account never has two requests in flight.
	//
	// That distinction is the whole point. The rate limit upstream enforces is
	// per account: on 2026-09-18 a run fired six buckets x ten exits with no
	// pacing, 60 requests in four seconds, ~7.5/s against each of two accounts,
	// and the upstream answered 21 of them with 429 -- a rate limit this probe
	// inflicted on itself, on credentials that had been answering normally a
	// moment earlier.
	probeMaxAccountsInFlight = 4

	// probeMaxBodyBytes caps what is read from a response. Only headers matter, so
	// this is just a small polite drain that lets a socket be reused without
	// pulling an SSE stream into the heap.
	probeMaxBodyBytes = 1 << 10

	// probeMgmtMaxBodyBytes caps management-API responses (auth-files, token
	// download). CPA's auth-files entries carry quota/cooldown/recent-request
	// payloads, so a handful of credentials is already tens of KB -- the old
	// 64KB cap truncated mid-document and surfaced as "unexpected end of JSON".
	// The documents are generated by our own CPA, so the cap only needs to stop
	// a misconfigured base_url pulling an unbounded response into memory.
	probeMgmtMaxBodyBytes = 4 << 20
)

// Renewal cadence. Vars so tests can shrink them; production never writes them.
// The pool is topped up once its best live entry has under probeRenewThreshold
// of life left, checked every probeRenewInterval. The cadence deliberately
// OVERLAPS the pair's declared hour rather than renewing at the edge:
// minting at T+(ttl-threshold) means the outgoing pair still has real life in
// hand, so a failed renewal costs overlap margin instead of a dead pool.
// Cost is one call per exit per renewal window, which is what keeps fresh
// pairs in the pool.
var (
	probeRenewInterval  = 20 * time.Second
	probeRenewThreshold = 120 * time.Second

	// probeExitCooldown is the minimum gap between two upstream calls on the same
	// (exit, account, model) triple when the call did NOT produce a pair, and
	// it is the whole answer to the defect this replaced: a target that could not
	// be filled was re-fired every tick forever. Measured on 2026-09-18, that was
	// 540 upstream calls an hour, every one of them a 312, all against
	// credentials that were already being throttled -- which is precisely the
	// pattern a rate limiter punishes.
	//
	// A SUCCESSFUL mint does not rest this long: it shortens to
	// probeSuccessRest, because the exit that just minted is exactly
	// the exit the renewal wants to redial when the pool ages out. The 55
	// minutes below is for a spent-or-throttled triple only -- an IP that just
	// answered 312 has nothing to give this window, so it sits out a
	// conservative hour-ish.
	probeExitCooldown = 55 * time.Minute

	// probeExitPause spaces the exits of one target apart. Without it a ten-entry
	// pool is ten back-to-back requests on one credential in about a second,
	// which is exactly how the 2026-09-18 run earned its 429s -- and the bigger
	// the pool the worse it gets, so the pool the operator added to improve
	// coverage was making the burst sharper instead.
	//
	// Two seconds costs nothing that matters: a triple is retried at most once
	// per probeExitCooldown, so a pass that takes a minute instead of four
	// seconds is invisible, while the burst it removes is not.
	probeExitPause = 2 * time.Second

	// probeRotatingAttempts is how many upstream calls one target may spend on
	// the rotating pool in a single visit, and probeRotatingCooldown is how
	// long that target rests afterwards if none of them produced a pair.
	//
	// These exist because a rotating proxy breaks the assumption the static
	// cooldown is built on. There, one URL is one IP, a 312 means that IP is
	// throttled, and re-dialing it inside the window is pointless -- so one
	// attempt per 55 minutes is exactly right. A rotating URL hands out a
	// different residential address on every connection (measured 2026-09-19:
	// twenty consecutive requests through one entry, twenty distinct addresses),
	// so the very retry the static rule forbids is the one thing that can clear a
	// 312. Applying the static window to a rotating pool throws away all but 1/N
	// of what it provides.
	//
	// The numbers are the operator's: ten attempts, then ten minutes. That is up
	// to 60 calls per target per hour, which is a real cost and is deliberately
	// chosen -- note it does NOT raise the instantaneous rate, which is what
	// actually earned the 429s on 2026-09-18: one goroutine per account and
	// probeExitPause between calls still cap a single credential at roughly one
	// request every two seconds.
	//
	// What is knowingly absent is an escalating backoff. An account throttled at
	// the account level answers 312 (not 429) indefinitely, and nothing here will
	// notice or slow down; the only automatic brake is the 429 path. That was the
	// operator's call.
	probeRotatingAttempts = 10
	probeRotatingCooldown = 10 * time.Minute

	// probeAccountBackoff is how long a credential is left alone after the
	// upstream signals an account-level refusal (429, or a rejected token).
	// Distinct from probeExitCooldown because the signal is distinct: a 312 says
	// "this exit's IP is throttled for this account", which the next exit may not
	// be, but a 429 says "you are asking too often" -- and answering that by
	// dialing a different IP is the one response guaranteed to make it worse.
	probeAccountBackoff = 10 * time.Minute
)

// probeRunState is the snapshot the dashboard polls. It carries progress and
// prose and no credential of any kind: see the file comment on Lines.
type probeRunState struct {
	Running    bool     `json:"running"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Done       int      `json:"done"`
	Total      int      `json:"total"`
	Current    string   `json:"current,omitempty"`
	Lines      []string `json:"lines,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// probeRunner holds the single in-process run. There is deliberately only one at
// a time: the run owns the renewal loop, and a second run would start a second
// loop minting the same pairs on the same credentials for no gain. The run
// no longer mutates any CPA state -- the harvest is a direct call to the
// upstream -- so a stop is a clean cancel with nothing to put back.
var probeRunner struct {
	mu     sync.Mutex
	run    probeRunState
	cancel context.CancelFunc
}

// probeTarget is one (account, payload-model) pair the harvester intends to
// fire. The minted pair itself is model-agnostic -- model only fills the
// upstream payload, so every target uses the first configured model.
type probeTarget struct {
	account string
	model   string
}

// probeCredential is one account's usable state, read once from its credential
// file. It holds a secret (accessToken) and must never be logged.
type probeCredential struct {
	name        string
	accessToken string
	accountID   string
	proxyURL    string
	expiresAt   time.Time
}

// probeRunStart validates the run and launches it in the background. It returns
// nil once the goroutine is on its way, or an error explaining the refusal --
// and a refusal changes nothing at all.
func probeRunStart() error {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	accounts := append([]string(nil), cfg.ProbeAccounts...)
	models := append([]string(nil), cfg.Models...)
	proxies := append([]string(nil), cfg.ProbeProxies...)
	rotating := append([]string(nil), cfg.ProbeProxiesRotating...)

	switch {
	case len(accounts) == 0:
		// No fallback to "all of them": minting spends one upstream request per
		// account and per renewal, so "nothing selected means everything" is the one
		// mistake that quietly burns quota on credentials the operator did not pick.
		return fmt.Errorf("probe_accounts is empty, so there is nothing to probe; refusing to widen an empty selection to every credential")
	case len(models) == 0:
		return fmt.Errorf("models is empty, so there is no payload to mint with")
	case strings.TrimSpace(cfg.ProbeManagementKey) == "":
		return fmt.Errorf("probe_management_key is not set; it is the Bearer for GET %s and %s, the two read-only calls that fetch the account list and each credential's token", probeRouteAuthFiles, probeRouteAuthDownload)
	case strings.TrimSpace(cfg.StoreDir) == "":
		return fmt.Errorf("store_dir is empty, so a minted pair has nowhere to be pooled for the business role to read")
	}

	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if probeRunner.run.Running {
		return fmt.Errorf("a probe is already running; stop it before starting another")
	}

	ctx, cancel := context.WithCancel(context.Background())
	probeRunner.cancel = cancel
	probeRunner.run = probeRunState{
		Running:   true,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	go probeSweep(ctx, cfg, accounts, models, proxies, rotating)
	return nil
}

// probeRunCancel asks the running probe to stop. It returns false when nothing
// was running. Cancellation ends the initial sweep and the renewal loop; there
// is no credential state to restore, because the offline harvest never changed
// any.
func probeRunCancel() bool {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if !probeRunner.run.Running || probeRunner.cancel == nil {
		return false
	}
	probeRunner.cancel()
	probeRunner.run.Lines = probeAppendLine(probeRunner.run.Lines, "stop requested; the probe will finish the current harvest and exit")
	return true
}

// probeRunSnapshot returns a copy of the run state, Lines included. The copy is
// what makes it safe to hand to a JSON encoder while the run keeps appending.
func probeRunSnapshot() probeRunState {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	out := probeRunner.run
	out.Lines = append([]string(nil), probeRunner.run.Lines...)
	return out
}

// probeRunUpdate mutates the run state under the one mutex that guards it.
func probeRunUpdate(mutate func(run *probeRunState)) {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	mutate(&probeRunner.run)
}

// probeRunLog appends one line to the transcript and mirrors it to the process
// log.
//
// Every line goes through probeRedact first. Callers are expected to have masked
// any proxy URL already, with maskProxyURL, and any account name with
// maskAuthLabel; this is the second line of defence, not the first, and it
// exists because Lines is served to a reader who has presented no key.
func probeRunLog(format string, args ...any) {
	line := probeRedact(fmt.Sprintf(format, args...))
	probeRunUpdate(func(run *probeRunState) {
		run.Lines = probeAppendLine(run.Lines, line)
	})
	log.Printf("%sprobe %s", logPrefix, line)
}

// probeRunFail records the reason a run stopped. The first error wins: what went
// wrong first is what the operator needs, and anything after it is a consequence.
func probeRunFail(errRun error) {
	if errRun == nil {
		return
	}
	message := probeRedact(errRun.Error())
	probeRunUpdate(func(run *probeRunState) {
		if run.Error == "" {
			run.Error = message
		}
		run.Lines = probeAppendLine(run.Lines, "error: "+message)
	})
	log.Printf("%sprobe error: %s", logPrefix, message)
}

// probeRunFinish marks the run over. It is the outermost defer in probeSweep and
// runs once the renewal loop has returned on cancel.
func probeRunFinish() {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	probeRunner.run.Running = false
	probeRunner.run.Current = ""
	probeRunner.run.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if probeRunner.cancel != nil {
		probeRunner.cancel()
		probeRunner.cancel = nil
	}
}

// probeAppendLine adds one timestamped line and keeps the transcript bounded.
func probeAppendLine(lines []string, line string) []string {
	lines = append(lines, time.Now().UTC().Format("15:04:05")+" "+line)
	if len(lines) > probeMaxLines {
		// Copied rather than resliced: a reslice would keep the whole original
		// backing array alive, which is the opposite of the point.
		lines = append([]string(nil), lines[len(lines)-probeMaxLines:]...)
	}
	return lines
}

// probeSweep is the whole run: read credentials, mint one pair per account once,
// then stay up renewing them. It is the only goroutine this file starts.
func probeSweep(ctx context.Context, cfg pluginConfig, accounts, models, proxies, rotating []string) {
	// Registered first, so it runs last: the run is not "finished" until the
	// renewal loop below has returned.
	defer probeRunFinish()
	// A panic in a native plugin takes the whole CPA process with it, so this
	// goroutine catches its own.
	defer func() {
		if recovered := recover(); recovered != nil {
			probeRunFail(fmt.Errorf("probe panicked: %v", recovered))
		}
	}()

	pool := newProbeClientPool()
	defer pool.closeIdle()
	client := newProbeClient(cfg)
	defer client.http.CloseIdleConnections()

	auths, errList := client.listCodexAuths(ctx)
	if errList != nil {
		probeRunFail(fmt.Errorf("could not list Codex credentials: %w", errList))
		return
	}
	// A selected account CPA does not know about would make the run quietly cover
	// less than was asked for, so it stops instead.
	known := make(map[string]bool, len(auths))
	for _, auth := range auths {
		known[auth.Name] = true
	}
	for _, account := range accounts {
		if !known[account] {
			probeRunFail(fmt.Errorf("selected account %q is not among CPA's Codex credentials; fix the selection rather than probing something CPA cannot serve", account))
			return
		}
	}

	now := time.Now()
	creds := probeDownloadCreds(ctx, client, accounts, now)
	if len(creds) == 0 {
		probeRunFail(fmt.Errorf("no usable credentials: every selected account's token was unreadable or already expired"))
		return
	}

	idxOf := probeAccountIndex(accounts)
	targets := probePendingTargets(cfg, accounts, models)
	probeRunUpdate(func(run *probeRunState) { run.Total = len(targets) })
	probeRunLog("offline harvest: %d account(s) to mint a pair each, %d static exit(s) + %d rotating entr(ies)", len(targets), len(proxies), len(rotating))
	if len(targets) > 0 {
		if cooling := probeFireBatch(ctx, cfg, pool, creds, targets, idxOf, proxies, rotating, true); cooling > 0 {
			// Said once per pass rather than per target per tick: the common case
			// after a recent sweep is that most exits are still inside the
			// window, and an operator who just pressed the button needs to be told
			// why nothing happened.
			probeRunLog("%d target(s) skipped: every exit already tried within the %s cooldown", cooling, probeExitCooldown)
		}
	} else {
		probeRunLog("no accounts in scope to mint with")
	}

	if ctx.Err() != nil {
		probeRunLog("stopped on request")
		return
	}

	// The run does not end here. Steering needs live pairs for as long as CPA
	// serves traffic, so the goroutine stays up and mints fresh pairs before
	// the pool's best entry expires -- the operator's "到期前自动续一遍". It
	// runs until the run is cancelled or the plugin reloads.
	probeRunLog("initial fill done; renewal active — the pool re-mints automatically within %s of the best entry's expiry", probeRenewThreshold)
	probeRunUpdate(func(run *probeRunState) { run.Current = "renewal active" })
	probeRenewLoop(ctx, pool)
}

// probeAccountIndex maps each selected account to its position, which is the
// index probeExits uses to assign the proxy pool in order.
func probeAccountIndex(accounts []string) map[string]int {
	idx := make(map[string]int, len(accounts))
	for i, name := range accounts {
		idx[name] = i
	}
	return idx
}

// probeFireBatch harvests a set of targets concurrently, bounded by
// probeMaxAccountsInFlight. countDone advances the progress bar (the initial fill wants
// it; a renewal tick does not, having no fixed Total). It is the shared fan-out
// for both callers so the concurrency rule lives in one place.
func probeFireBatch(ctx context.Context, cfg pluginConfig, pool *probeClientPool, creds map[string]probeCredential, targets []probeTarget, idxOf map[string]int, proxies, rotating []string, countDone bool) int {
	// Grouped by credential, and each credential gets ONE goroutine that walks its
	// targets in turn. Fanning out over targets instead let several targets of the
	// same account fire at once, which is how one credential saw ~7.5 requests a
	// second and answered with 429. One goroutine per account means one request
	// per account at a time, and probeExitPause spaces even those apart.
	byAccount := make(map[string][]probeTarget, len(creds))
	var order []string
	for _, target := range targets {
		if _, seen := byAccount[target.account]; !seen {
			order = append(order, target.account)
		}
		byAccount[target.account] = append(byAccount[target.account], target)
	}

	var cooling atomic.Int64
	sem := make(chan struct{}, probeMaxAccountsInFlight)
	var wg sync.WaitGroup
	for _, account := range order {
		cred, ok := creds[account]
		if !ok {
			// Its credential was unreadable or expired and already logged; count
			// its targets done so the progress bar reaches Total rather than
			// hanging short.
			if countDone {
				missing := len(byAccount[account])
				probeRunUpdate(func(run *probeRunState) { run.Done += missing })
			}
			continue
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(list []probeTarget, cred probeCredential, accountIdx int) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, target := range list {
				if ctx.Err() != nil {
					return
				}
				if !probeHarvestBucket(ctx, cfg, pool, cred, target.model, proxies, rotating, accountIdx) {
					cooling.Add(1)
				}
				if countDone {
					probeRunUpdate(func(run *probeRunState) { run.Done++ })
				}
			}
		}(byAccount[account], cred, idxOf[account])
	}
	wg.Wait()
	return int(cooling.Load())
}

// probeHarvestBucket mints a pair for one account by walking its exit
// sequence: every exit that is out of cooldown gets one try, and the walk
// stops at the first pooled pair. It is the one harvest path; the initial fill
// and the renewal loop both call it, and the claim guard keeps them off each
// other's targets.
//
// It reports whether any upstream call was actually made. A target whose every
// exit is still inside probeExitCooldown returns false without a word, which is
// what keeps the renewal loop from narrating the same skip once a minute.
func probeHarvestBucket(ctx context.Context, cfg pluginConfig, pool *probeClientPool, cred probeCredential, model string, proxies, rotating []string, accountIdx int) bool {
	key := bucketKey(cred.name, model)
	if !probeClaim(key) {
		// Another fire (the other loop, or an overtaking renewal tick) is already
		// on this exact target. Firing a second upstream call for it would spend
		// quota to overwrite a value with a near-identical one.
		return false
	}
	defer probeRelease(key)

	short := maskAuthLabel(cred.name)
	if !probeAccountReady(cred.name, time.Now()) {
		// The upstream asked for this credential to be left alone. Silent: the
		// renewal loop would otherwise say so once a minute per bucket.
		return false
	}

	// Static exits first. Each one is a distinct IP with its own once-per-window
	// budget, and an unspent budget simply expires -- so the perishable resource
	// goes first and the rotating pool, which can be tapped at any time, picks up
	// whatever is left.
	//
	// The empty pool must NOT become a direct attempt when a rotating pool exists.
	// An empty probe_proxies has always meant "go out over the box's own egress",
	// which is right when nothing else is configured and quite wrong once the
	// operator has moved their whole pool to probe_proxies_rotating: it would send
	// the harvest out over the server's own address behind their back.
	staticExits := probeExits(proxies, accountIdx)
	if len(proxies) == 0 && len(rotating) > 0 {
		staticExits = nil
	}

	fired := false
	for _, exit := range staticExits {
		if ctx.Err() != nil {
			return fired
		}
		// Space the exits apart. Only after a real attempt -- skipping a cooling
		// exit costs nothing and should not be paced.
		if fired && !probeSleep(ctx, probeExitPause) {
			return fired
		}
		now := time.Now()
		if !probeCooldownReady(exit, cred.name, model, now) {
			// Spent within the window. Silent on purpose: saying so would put one
			// line per bucket per tick into a forty-line transcript.
			continue
		}
		client, errClient := pool.get(exit)
		if errClient != nil {
			probeRunLog("%s %s: exit %s unusable, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errClient.Error()))
			continue
		}

		// Marked before the call rather than after: a request that times out, or
		// whose goroutine dies, still spent an attempt on this triple, and the
		// guarantee being kept is that the upstream sees at most one call per
		// triple per window.
		probeCooldownMark(exit, cred.name, model, now)
		fired = true

		res, errFire := probeFireUpstream(ctx, client, cred, model)
		if errFire != nil {
			// A transport failure means this exit did not carry the request at all;
			// the next one might.
			probeRunLog("%s %s: exit %s failed at transport, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errFire.Error()))
			continue
		}
		switch probeConsume(cfg, cred.name, short, model, res, exit) {
		case probeOutcomeStored:
			// The exit that just minted is the one the renewal wants again at
			// T+(ttl-threshold), so its rest is shortened from the spent-triple
			// window to exactly that. Leaving the full 55 minutes in place would
			// make the pair unrenewable: it dies at its declared deadline.
			probeCooldownSet(exit, cred.name, model, time.Now().Add(probeSuccessRest(cfg)))
			return true
		case probeOutcomeAccountLimited:
			// Account-level refusal: every remaining exit carries the same
			// credential, so walking on would only deepen it.
			probeAccountSetBackoff(cred.name, time.Now())
			return fired
		}
		// Not stored -- a 312. That is THIS EXIT's IP being
		// throttled for this account and model, not the bucket being unfillable,
		// so the next exit is a different IP and gets its turn. This is the fix
		// for the defect where a 312 ended the attempt outright and the rest of
		// the pool was never dialed at all.
	}

	if len(rotating) > 0 {
		stored, rotFired := probeHarvestRotating(ctx, cfg, pool, cred, short, model, rotating, accountIdx)
		fired = fired || rotFired
		if stored {
			return true
		}
	}
	return fired
}

// probeHarvestRotating spends up to probeRotatingAttempts calls on the rotating
// pool for one bucket, cycling through the configured entries.
//
// Cycling rather than picking one entry matters when the entries are separate
// credentials on one gateway, which is the common shape: it spreads the load
// across them while every individual call still gets a fresh address. The
// starting offset is the account index so two accounts working at once do not
// march in lockstep through the same entry.
//
// The budget is claimed up front, at the failure window, and only upgraded to
// the full window once a template is actually stored. Claiming first is the same
// guarantee the static path makes -- a run that is cancelled or dies midway has
// still spent these attempts, and must not come back and spend them again.
func probeHarvestRotating(ctx context.Context, cfg pluginConfig, pool *probeClientPool, cred probeCredential, short, model string, rotating []string, accountIdx int) (stored, fired bool) {
	now := time.Now()
	if !probeCooldownReady(probeRotatingExit, cred.name, model, now) {
		return false, false
	}
	probeCooldownSet(probeRotatingExit, cred.name, model, now.Add(probeRotatingCooldown))

	for attempt := 0; attempt < probeRotatingAttempts; attempt++ {
		if ctx.Err() != nil {
			return false, fired
		}
		if fired && !probeSleep(ctx, probeExitPause) {
			return false, fired
		}
		exit := rotating[(accountIdx+attempt)%len(rotating)]
		client, errClient := pool.get(exit)
		if errClient != nil {
			probeRunLog("%s %s: rotating exit %s unusable, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errClient.Error()))
			continue
		}
		fired = true

		res, errFire := probeFireUpstream(ctx, client, cred, model)
		if errFire != nil {
			probeRunLog("%s %s: rotating exit %s failed at transport, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errFire.Error()))
			continue
		}
		switch probeConsume(cfg, cred.name, short, model, res, exit) {
		case probeOutcomeStored:
			// Same renewal alignment as the static path: the gateway that just
			// minted is wanted again at T+(ttl-threshold), not in an hour.
			probeCooldownSet(probeRotatingExit, cred.name, model, time.Now().Add(probeSuccessRest(cfg)))
			return true, fired
		case probeOutcomeAccountLimited:
			// A 429 is the credential being told to slow down. No address the
			// gateway can hand out changes that, so the remaining attempts would
			// only deepen it.
			probeAccountSetBackoff(cred.name, time.Now())
			return false, fired
		}
		// A 312: this address is throttled for this bucket. Unlike a static exit,
		// the next attempt through the very same entry is a different address, so
		// it is worth making -- that is the entire reason this pool is separate.
	}
	if fired {
		probeRunLog("%s %s: rotating pool gave %d address(es), none of them a %d; resting this bucket for %s",
			short, model, probeRotatingAttempts, cfg.TemplateLength, probeRotatingCooldown)
	}
	return false, fired
}

// probeConsume decides what one upstream response means. The harvest target is
// the __cflb/__oailb pair itself: a 200 that set one is a stored result, and a
// degraded or failed response that set one still feeds the pool -- the pair is
// minted at the edge and does not depend on the serving state the turn got.
//
// Whatever the verdict, the pair goes into the GLOBAL pool keyed by its own
// value -- account-agnostic, so which credential happened to mint it does not
// matter. The outcome it reports is what tells the caller to stop walking the
// exits: anything else means this exit did not produce and the next one
// deserves a turn.
func probeConsume(cfg pluginConfig, name, short, model string, res probeFireResult, exit string) probeOutcome {
	if len(res.cookies.pairs) > 0 {
		state.mu.Lock()
		state.noteRouteCookiesLocked(res.cookies, exit)
		state.mu.Unlock()
	}
	switch res.status {
	case http.StatusTooManyRequests:
		// The credential is being told to slow down. Every remaining exit would
		// carry the same credential, so the walk stops here and the account
		// rests; continuing is what escalated a 312 into a wall of 429s.
		probeRunLog("%s %s: http=429 — upstream is rate limiting this credential, not this exit; stopping the walk and resting the account for %s",
			short, model, probeAccountBackoff)
		return probeOutcomeAccountLimited
	case http.StatusUnauthorized, http.StatusForbidden:
		// A rejected token is equally not the exit's fault.
		probeRunLog("%s %s: http=%d — the credential was refused, no exit can change that; resting the account for %s",
			short, model, res.status, probeAccountBackoff)
		return probeOutcomeAccountLimited
	}
	if res.status != http.StatusOK {
		probeRunLog("%s %s: http=%d via %s, no pair", short, model, res.status, probeShowProxy(exit))
		return probeOutcomeTryNext
	}
	stateLen := len(res.stateValue)
	if stateLen == cfg.ReplaceLength {
		// The upstream answered degraded for this exit's IP. Any pair it set was
		// still pooled above -- the edge mints the pair regardless of serving
		// state -- but the exit earns no success: the next exit is a different
		// node and gets its turn.
		probeRunLog("%s %s: http=200 via %s answered degraded (len=%d)%s — this exit's IP is throttled, trying next",
			short, model, probeShowProxy(exit), stateLen, pooledSuffix(res.cookies.pairs))
		return probeOutcomeTryNext
	}
	if len(res.cookies.pairs) == 0 {
		// A 200 with no Set-Cookie pair is the response a steered request gets --
		// we fire bare precisely so the edge assigns a node and mints one, so a
		// bare request coming back pairless means the edge declined to mint.
		probeRunLog("%s %s: http=200 via %s but no __cflb/__oailb was set", short, model, probeShowProxy(exit))
		return probeOutcomeTryNext
	}
	switch stateLen {
	case cfg.TemplateLength, 0:
		probeRunLog("%s %s: pooled a %s pair via %s", short, model, orDash(gatewayLabel(res.cookies.pairs)), probeShowProxy(exit))
	default:
		probeRunLog("%s %s: pooled a %s pair via %s (turn-state len=%d)", short, model, orDash(gatewayLabel(res.cookies.pairs)), probeShowProxy(exit), stateLen)
	}
	return probeOutcomeStored
}

// pooledSuffix renders the trailing note for a degraded response that still
// contributed a pair, so the transcript says the cookie was kept rather than
// implying the 312 discarded it.
func pooledSuffix(pairs map[string]string) string {
	if len(pairs) == 0 {
		return ""
	}
	return fmt.Sprintf(" (pair still pooled: %s)", orDash(gatewayLabel(pairs)))
}

// probeSuccessRest is how long a triple rests after a successful mint: until
// its template wants renewing (ttl - probeRenewThreshold), which is when the
// renewal loop queues the bucket anyway. Capped at probeExitCooldown: with a
// long configured ttl the renewal boundary can land PAST the spent-triple
// window, and a success must never rest longer than a failure.
func probeSuccessRest(cfg pluginConfig) time.Duration {
	rest := cfg.ttl() - probeRenewThreshold
	if rest < probeExitPause {
		return probeExitPause
	}
	if rest > probeExitCooldown {
		return probeExitCooldown
	}
	return rest
}

// probeDownloadCreds reads each selected account's usable state once. An account
// whose token is unreadable or already expired is dropped, with a line saying
// which -- never a stack trace with a token in it.
func probeDownloadCreds(ctx context.Context, client *probeClient, accounts []string, now time.Time) map[string]probeCredential {
	creds := make(map[string]probeCredential, len(accounts))
	for _, name := range accounts {
		if ctx.Err() != nil {
			return creds
		}
		short := maskAuthLabel(name)
		blob, errDownload := client.downloadAuth(ctx, name)
		if errDownload != nil {
			probeRunLog("%s: could not read credential: %s", short, probeRedact(errDownload.Error()))
			continue
		}
		cred, errParse := probeParseCredential(name, blob)
		if errParse != nil {
			probeRunLog("%s: credential unusable: %s", short, probeRedact(errParse.Error()))
			continue
		}
		// Never refresh. An expired access token is skipped and left for CPA to
		// refresh in the course of its own business; the next cycle reads the fresh
		// one. Refreshing here could rotate the refresh token and pull the
		// credential out from under live CPA traffic -- the one thing this whole
		// offline design exists to avoid.
		if !cred.expiresAt.IsZero() && !cred.expiresAt.After(now) {
			probeRunLog("%s: access token expired; skipping (not refreshed here — CPA refreshes it, next cycle harvests)", short)
			continue
		}
		creds[name] = cred
	}
	return creds
}

// probeRenewLoop keeps the store warm. Every probeRenewInterval it re-reads the
// live scope (so an edit on the dashboard takes effect without a restart), finds
// the in-scope buckets that are missing or under probeRenewThreshold of life,
// and re-harvests them. It returns on cancel.
func probeRenewLoop(ctx context.Context, pool *probeClientPool) {
	ticker := time.NewTicker(probeRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}

		state.mu.Lock()
		cfg := state.config
		state.mu.Unlock()
		accounts := append([]string(nil), cfg.ProbeAccounts...)
		models := append([]string(nil), cfg.Models...)
		proxies := append([]string(nil), cfg.ProbeProxies...)
		rotating := append([]string(nil), cfg.ProbeProxiesRotating...)
		if len(accounts) == 0 || len(models) == 0 {
			probeRunUpdate(func(run *probeRunState) { run.Current = "scope is empty; nothing to keep fresh" })
			continue
		}

		now := time.Now()
		left, poolLive := probePoolSecondsLeft(cfg, now)
		if poolLive && left >= probeRenewThreshold {
			probeRunUpdate(func(run *probeRunState) {
				run.Current = fmt.Sprintf("pool fresh (%s left on best pair); next check in %s", left.Round(time.Second), probeRenewInterval)
			})
			continue
		}
		idxOf := probeAccountIndex(accounts)
		var due []probeTarget
		involved := make(map[string]bool)
		for _, account := range accounts {
			// A credential the upstream told us to leave alone is skipped whole.
			if !probeAccountReady(account, now) {
				continue
			}
			// The pair is model-agnostic, so the bucket dimension collapses to
			// "mint once per usable credential": one model fills the payload.
			model := models[0]
			// Queue it only if some exit is actually allowed to fire. Without
			// this the loop would download credentials once a minute only to
			// find every triple still cooling.
			if !probeBucketHasEligibleExit(proxies, rotating, idxOf[account], account, model, now) {
				continue
			}
			due = append(due, probeTarget{account: account, model: model})
			involved[account] = true
		}
		if len(due) == 0 {
			probeRunUpdate(func(run *probeRunState) {
				run.Current = fmt.Sprintf("pool needs pairs but every exit is cooling or every account resting; next check in %s", probeRenewInterval)
			})
			continue
		}

		probeRunUpdate(func(run *probeRunState) {
			run.Current = fmt.Sprintf("minting fresh pair(s), best entry has %s left", left.Round(time.Second))
		})
		// Download only the accounts that actually have something due, in scope
		// order so the index still lines up with the proxy assignment.
		var accountList []string
		for _, account := range accounts {
			if involved[account] {
				accountList = append(accountList, account)
			}
		}
		client := newProbeClient(cfg)
		creds := probeDownloadCreds(ctx, client, accountList, now)
		probeFireBatch(ctx, cfg, pool, creds, due, idxOf, proxies, rotating, false)
		client.http.CloseIdleConnections()
	}
}

// probePoolSecondsLeft reports the longest life any pooled pair has left, and
// whether any usable pair exists at all. The pool is global, so "the pool
// needs a mint" is a single number, not a per-bucket question: the renewal
// loop fires when the best entry crosses under probeRenewThreshold.
func probePoolSecondsLeft(cfg pluginConfig, now time.Time) (time.Duration, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	var best int64
	for _, e := range state.cookies {
		if l := entrySecondsLeft(*e, now, cfg.ttl()); l > best {
			best = l
		}
	}
	return time.Duration(best) * time.Second, best > 0
}

// probePendingTargets lists the targets a manual run fires. The pair is
// account-agnostic and one usable credential is enough to mint it, but walking
// every selected account still earns its keep: each account's mint lands on
// whatever node the edge assigns, so more credentials means a pool spread over
// more nodes. The model is only payload -- the pair carries no model binding --
// so every target uses the first configured model.
func probePendingTargets(cfg pluginConfig, accounts, models []string) []probeTarget {
	model := ""
	if len(models) > 0 {
		model = models[0]
	}
	out := make([]probeTarget, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, probeTarget{account: account, model: model})
	}
	return out
}

// probeExits is the order one account tries the pool in: its assigned exit first
// (index i % N), then the rest in order, wrapping once. That satisfies both
// readings of "assign the pool in order" -- account i starts at exit i -- and
// gives every account a full fallback sequence if its first exit is down. An
// empty pool yields a single direct attempt (the empty string), which the client
// pool builds as a no-proxy transport.
func probeExits(proxies []string, accountIdx int) []string {
	if len(proxies) == 0 {
		return []string{""}
	}
	n := len(proxies)
	out := make([]string, 0, n)
	for k := 0; k < n; k++ {
		out = append(out, proxies[(accountIdx+k)%n])
	}
	return out
}

// probeActive prevents two harvests of the same bucket at once -- the initial
// fill and the renewal loop share one harvest path, and a slow upstream call
// could otherwise let a renewal tick fire a bucket a previous one is still on.
// The key is bucketKey, so the guard is per (account, model), never global: two
// different buckets still fire in parallel.
var probeActive = struct {
	mu  sync.Mutex
	set map[string]bool
}{set: map[string]bool{}}

func probeClaim(key string) bool {
	probeActive.mu.Lock()
	defer probeActive.mu.Unlock()
	if probeActive.set[key] {
		return false
	}
	probeActive.set[key] = true
	return true
}

func probeRelease(key string) {
	probeActive.mu.Lock()
	defer probeActive.mu.Unlock()
	delete(probeActive.set, key)
}

// probeCooldown records when each (exit, account, model) triple last had an
// upstream call spent on it.
//
// The exit belongs in the key because a 312 is the IP being throttled for that
// account and model, not the bucket being unfillable -- which is the entire
// reason a pool of exits exists. So a 312 on one exit says nothing about the
// next one, and only when every exit has had its turn is the bucket genuinely
// out of options for this window.
//
// Keying on the exit URL has a second, useful property: correcting a typo in a
// proxy changes the string, so the fixed exit is a new triple with no cooldown
// and is retried at once instead of sitting out the window.
// The table stores the moment a triple becomes eligible again, not the moment it
// was last fired. Storing the deadline is what lets one table serve two very
// different windows: a static exit (and any success) rests for
// probeExitCooldown, while a rotating pool that ran out of attempts without a
// 292 rests only probeRotatingCooldown -- see probeHarvestRotating for why those
// are not the same question.
var probeCooldown = struct {
	mu    sync.Mutex
	until map[string]time.Time
}{until: map[string]time.Time{}}

// probeRotatingExit is the pseudo-exit the rotating pool's cooldown is keyed on.
// It cannot collide with a real entry: a URL cannot contain a NUL byte, and the
// key separator is NUL.
//
// Keying the rotating pool on (account, model) rather than on each URL is the
// whole point of the split. A rotating URL is not an exit, it is a gateway to a
// fresh IP per request, so "this URL was already tried" says nothing useful --
// the next request through it is a different address. What is genuinely scarce
// there is the account's tolerance, and that is what this key measures.
const probeRotatingExit = "\x00rotating"

func probeCooldownKey(exit, account, model string) string {
	return exit + "\x00" + account + "\x00" + model
}

// probeCooldownReady reports whether this triple may be fired now. A triple that
// has never been fired is always ready, which is what makes a newly added exit
// eligible the moment it appears in the pool.
func probeCooldownReady(exit, account, model string, now time.Time) bool {
	probeCooldown.mu.Lock()
	defer probeCooldown.mu.Unlock()
	until, seen := probeCooldown.until[probeCooldownKey(exit, account, model)]
	return !seen || !now.Before(until)
}

// probeCooldownMark rests a triple for the standard window. This is the static
// path's only marker: one exit, one IP, one attempt per window.
func probeCooldownMark(exit, account, model string, now time.Time) {
	probeCooldownSet(exit, account, model, now.Add(probeExitCooldown))
}

// probeCooldownSet rests a triple until an explicit deadline, which the rotating
// path needs because its two outcomes deserve different windows.
func probeCooldownSet(exit, account, model string, until time.Time) {
	probeCooldown.mu.Lock()
	defer probeCooldown.mu.Unlock()
	probeCooldown.until[probeCooldownKey(exit, account, model)] = until
}

// probeAccountRest holds credentials the upstream has told us to leave alone.
// Keyed by account only: a 429 is about the credential, not about the exit it
// happened to arrive through, so every bucket and every exit of that account
// waits together.
var probeAccountRest = struct {
	mu    sync.Mutex
	until map[string]time.Time
}{until: make(map[string]time.Time)}

func probeAccountReady(account string, now time.Time) bool {
	probeAccountRest.mu.Lock()
	defer probeAccountRest.mu.Unlock()
	until, seen := probeAccountRest.until[account]
	return !seen || now.After(until)
}

func probeAccountSetBackoff(account string, now time.Time) {
	probeAccountRest.mu.Lock()
	defer probeAccountRest.mu.Unlock()
	probeAccountRest.until[account] = now.Add(probeAccountBackoff)
}

// probeOutcome is what one upstream answer means for the rest of the walk.
type probeOutcome int

const (
	// probeOutcomeStored: a template landed, this bucket is done.
	probeOutcomeStored probeOutcome = iota
	// probeOutcomeTryNext: this exit did not work out, but another might.
	probeOutcomeTryNext
	// probeOutcomeAccountLimited: the credential itself was refused. Stop the
	// walk and rest the account -- trying more exits is what turned a handful of
	// 312s into 21 429s.
	probeOutcomeAccountLimited
)

// probeBucketHasEligibleExit reports whether any exit is allowed to fire for this
// bucket. The renewal loop checks this before queueing anything: without it, a
// scope whose every triple is cooling would still download credentials and claim
// buckets once a minute just to discover it may do nothing.
func probeBucketHasEligibleExit(proxies, rotating []string, accountIdx int, account, model string, now time.Time) bool {
	// The rotating pool carries one shared key per (account, model), so it is a
	// single extra question rather than one per entry.
	if len(rotating) > 0 && probeCooldownReady(probeRotatingExit, account, model, now) {
		return true
	}
	// Mirrors probeHarvestBucket: with a rotating pool configured, an empty static
	// list is not an invitation to go out over the box's own address.
	if len(proxies) == 0 && len(rotating) > 0 {
		return false
	}
	for _, exit := range probeExits(proxies, accountIdx) {
		if probeCooldownReady(exit, account, model, now) {
			return true
		}
	}
	return false
}

// probeSleep waits for the given duration and reports whether the run is still
// wanted. It returns false as soon as the run is cancelled.
func probeSleep(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// --- upstream ------------------------------------------------------------

// probeFireResult is what one upstream answer gave us: the status, the
// turn-state it signed (possibly empty), and the routing pair it set. The
// pair is harvested on every status, not just 200 -- the upstream rotates
// __cflb/__oailb independently of whether it minted a state.
type probeFireResult struct {
	status     int
	stateValue string
	cookies    routeCookieSet
}

// probeFireUpstream makes one direct call to the upstream as one account and
// returns what the response carried. It reads only the headers: the turn-state
// and the Set-Cookie pair are there, and the SSE body is drained just enough to
// let the socket be reused before being dropped -- generating the completion
// would spend quota this probe has no use for. A transport error is returned as
// an error so the caller can fall through to the next exit; an HTTP status is
// not.
//
// The request goes out BARE, with no pooled pair attached, on purpose: a
// request that carries a live pair is pinned to that pair's node and the edge
// sets no new cookies for it -- measured 2026-09-22, steered requests come back
// with zero Set-Cookie pair. Minting is the whole point of this call, so the
// edge must be free to assign a node itself.
func probeFireUpstream(ctx context.Context, client *http.Client, cred probeCredential, model string) (probeFireResult, error) {
	payload := map[string]any{
		"model":  model,
		"stream": true,
		"store":  false,
		"input": []map[string]any{{
			"type": "message",
			"role": "user",
			"content": []map[string]any{{
				"type": "input_text",
				"text": "ping",
			}},
		}},
		"reasoning":           map[string]any{"effort": "low"},
		"tool_choice":         "auto",
		"parallel_tool_calls": false,
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return probeFireResult{}, errMarshal
	}

	callCtx, cancel := context.WithTimeout(ctx, probeFireTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodPost, probeUpstreamURL, bytes.NewReader(raw))
	if errNew != nil {
		return probeFireResult{}, errNew
	}
	request.Header.Set("Authorization", "Bearer "+cred.accessToken)
	if cred.accountID != "" {
		request.Header.Set("Chatgpt-Account-Id", cred.accountID)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Originator", "codex-tui")
	request.Header.Set("Session-Id", probeUUID())
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return probeFireResult{}, errDo
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, probeMaxBodyBytes))
	return probeFireResult{
		status:     response.StatusCode,
		stateValue: response.Header.Get(turnStateHeader),
		cookies:    routeCookiesFromResponseHeaders(response.Header, time.Now()),
	}, nil
}

// probeUUID returns a random v4 UUID for the Session-Id header, using the
// crypto/rand source already linked in. A failed read is near-impossible; the
// fallback keeps a probe firing rather than aborting on an unreachable branch.
func probeUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// --- credential parsing --------------------------------------------------

// probeParseCredential pulls the usable state out of a downloaded credential
// file: the access token, the account id (from the token's own claims, which is
// what the upstream expects in Chatgpt-Account-Id), the account's own exit, and
// the token's expiry. Nothing here is logged.
func probeParseCredential(name string, blob map[string]any) (probeCredential, error) {
	token := strings.TrimSpace(stringField(blob, "access_token"))
	if token == "" {
		return probeCredential{}, fmt.Errorf("no access_token in credential file")
	}
	claims := probeJWTClaims(token)
	cred := probeCredential{
		name:        name,
		accessToken: token,
		accountID:   probeAccountID(claims, blob),
		proxyURL:    strings.TrimSpace(stringField(blob, "proxy_url")),
	}
	if exp, ok := probeTokenExpiry(claims); ok {
		cred.expiresAt = exp
	}
	return cred, nil
}

// probeJWTClaims decodes a JWT's middle segment. The claims it reads -- exp and
// the account id -- are not secret; the token as a whole is, and is never logged.
func probeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	data, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
	if errDecode != nil {
		return nil
	}
	var claims map[string]any
	if errUnmarshal := json.Unmarshal(data, &claims); errUnmarshal != nil {
		return nil
	}
	return claims
}

// probeAccountID reads the chatgpt_account_id the upstream expects. It prefers
// the token's own auth claim (authoritative) and falls back to the file's
// top-level account_id.
func probeAccountID(claims, blob map[string]any) string {
	if claims != nil {
		if auth, ok := claims["https://api.openai.com/auth"].(map[string]any); ok {
			if id, ok := auth["chatgpt_account_id"].(string); ok && strings.TrimSpace(id) != "" {
				return strings.TrimSpace(id)
			}
		}
	}
	return strings.TrimSpace(stringField(blob, "account_id"))
}

// probeTokenExpiry reads the token's exp claim. A token with no readable exp
// returns ok=false and is treated as usable -- the upstream is the real arbiter,
// and a 401 there is handled like any other non-200.
func probeTokenExpiry(claims map[string]any) (time.Time, bool) {
	if claims == nil {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// stringField reads a string value from a decoded JSON object, tolerating a
// missing or non-string field by returning "".
func stringField(blob map[string]any, key string) string {
	if value, ok := blob[key].(string); ok {
		return value
	}
	return ""
}

// --- CPA read client -----------------------------------------------------

type probeAuthFile struct {
	Name      string          `json:"name"`
	AuthIndex json.RawMessage `json:"auth_index,omitempty"`
	Disabled  bool            `json:"disabled"`
	Provider  string          `json:"provider"`
	Type      string          `json:"type"`
}

type probeHTTPResult struct {
	status int
	body   []byte
}

// probeClient is the harvester's read-only connection to CPA's management API.
// It fetches the account list and each credential's token; it never writes.
type probeClient struct {
	baseURL string
	mgmtKey string
	http    *http.Client
}

func newProbeClient(cfg pluginConfig) *probeClient {
	// configure already fills an empty probe_base_url with defaultProbeBaseURL, so
	// this only catches a config built in-process -- a test, or a future caller
	// that skips configure. It reuses main.go's constant rather than repeating the
	// literal: two defaults that could drift apart is how a probe ends up talking
	// to the wrong port.
	base := strings.TrimRight(strings.TrimSpace(cfg.ProbeBaseURL), "/")
	if base == "" {
		base = defaultProbeBaseURL
	}
	return &probeClient{
		baseURL: base,
		mgmtKey: strings.TrimSpace(cfg.ProbeManagementKey),
		// Proxy is nil on purpose: this client talks to CPA's own loopback
		// listener, and honouring the box's http_proxy/all_proxy would send a
		// loopback call out through an exit that cannot reach it and come back as a
		// bogus 502. The per-exit clients for the upstream calls live in
		// probeClientPool, built the same way for the same reason.
		http: &http.Client{Transport: &http.Transport{Proxy: nil}},
	}
}

// call issues one request and returns the status alongside the body.
//
// A non-2xx comes back as a result, not as an error: 401 and 404 must stay
// distinguishable -- 401 is a rejected management key, 404 is a path this CPA
// build does not serve -- and collapsing them into "the call failed" sends
// whoever is debugging this down the wrong road. Only a transport failure is an
// error.
func (c *probeClient) call(ctx context.Context, method, path, token string, payload any, timeout time.Duration) (probeHTTPResult, error) {
	var body io.Reader
	if payload != nil {
		raw, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			return probeHTTPResult{}, errMarshal
		}
		body = bytes.NewReader(raw)
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, errNew := http.NewRequestWithContext(callCtx, method, c.baseURL+path, body)
	if errNew != nil {
		return probeHTTPResult{}, errNew
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, errDo := c.http.Do(request)
	if errDo != nil {
		return probeHTTPResult{}, errDo
	}
	defer func() { _ = response.Body.Close() }()

	// Bounded read, but the bound is generous: CPA's auth-files document in
	// v7.3.4 carries rich per-credential entries (recent_requests, quota,
	// model_quotas, cooldowns), so a modest account fleet already overflows a
	// small cap -- and a truncated body surfaces confusingly as a JSON syntax
	// error. Read one byte past the cap so "too large" is reported as such
	// rather than mistaken for a malformed document.
	raw, errRead := io.ReadAll(io.LimitReader(response.Body, probeMgmtMaxBodyBytes+1))
	if errRead != nil {
		return probeHTTPResult{status: response.StatusCode}, errRead
	}
	if len(raw) > probeMgmtMaxBodyBytes {
		return probeHTTPResult{status: response.StatusCode},
			fmt.Errorf("%s %s response exceeds %d bytes", method, path, probeMgmtMaxBodyBytes)
	}
	return probeHTTPResult{status: response.StatusCode, body: raw}, nil
}

// probeExplainStatus names which of the three things went wrong, in the words
// that point at the fix.
func probeExplainStatus(result probeHTTPResult, what string) error {
	switch result.status {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s: 401 unauthorized -- probe_management_key is wrong or not accepted; this is an auth failure, not a bad path", what)
	case http.StatusForbidden:
		return fmt.Errorf("%s: 403 forbidden -- the key was accepted but lacks access", what)
	case http.StatusNotFound:
		return fmt.Errorf("%s: 404 not found -- this CPA build does not serve that path (a bad key would have answered 401)", what)
	}
	return fmt.Errorf("%s: HTTP %d %s", what, result.status, probeTruncate(probeRedact(string(result.body)), 200))
}

// listCodexAuths returns CPA's Codex credentials, .bak copies excluded.
//
// The filter is provider when CPA reports one, the naming convention otherwise.
// A .bak file is an operator's backup copy and must never be probed.
func (c *probeClient) listCodexAuths(ctx context.Context) ([]probeAuthFile, error) {
	result, errCall := c.call(ctx, http.MethodGet, probeRouteAuthFiles, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return nil, errCall
	}
	if result.status != http.StatusOK {
		return nil, probeExplainStatus(result, "GET "+probeRouteAuthFiles)
	}
	var doc struct {
		Files []probeAuthFile `json:"files"`
	}
	if errUnmarshal := json.Unmarshal(result.body, &doc); errUnmarshal != nil {
		return nil, fmt.Errorf("GET %s returned a body that is not the expected {\"files\":[...]} document: %w", probeRouteAuthFiles, errUnmarshal)
	}
	out := make([]probeAuthFile, 0, len(doc.Files))
	for _, file := range doc.Files {
		name := strings.TrimSpace(file.Name)
		if name == "" || strings.Contains(name, ".bak") {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(file.Provider))
		kind := strings.ToLower(strings.TrimSpace(file.Type))
		lower := strings.ToLower(name)
		if provider != "codex" && kind != "codex" &&
			!(strings.HasPrefix(lower, "codex-") && strings.HasSuffix(lower, ".json")) {
			continue
		}
		file.Name = name
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// downloadAuth fetches one credential file whole. It is the only call that ever
// carries a token back into this process, so its body is never logged; callers
// pull the fields they need through probeParseCredential and drop the rest.
func (c *probeClient) downloadAuth(ctx context.Context, name string) (map[string]any, error) {
	path := probeRouteAuthDownload + "?name=" + url.QueryEscape(name)
	result, errCall := c.call(ctx, http.MethodGet, path, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return nil, errCall
	}
	if result.status != http.StatusOK {
		return nil, probeExplainStatus(result, "GET "+probeRouteAuthDownload)
	}
	var blob map[string]any
	if errUnmarshal := json.Unmarshal(result.body, &blob); errUnmarshal != nil {
		return nil, fmt.Errorf("GET %s returned a body that is not a JSON object: %w", probeRouteAuthDownload, errUnmarshal)
	}
	return blob, nil
}

// --- per-exit upstream clients -------------------------------------------

// probeClientPool holds one http.Client per exit, built once and shared across
// every fire that uses that exit. A scope of four accounts sharing two exits
// opens two transports, not eight.
type probeClientPool struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

func newProbeClientPool() *probeClientPool {
	return &probeClientPool{clients: map[string]*http.Client{}}
}

// get returns the client for one exit, building it once. An empty proxyURL is a
// direct connection -- and deliberately does NOT honour the box's
// http_proxy/all_proxy env, for the same reason newProbeClient does not: those
// exits are for the traffic CPA relays, not for a probe reaching out on its own.
func (p *probeClientPool) get(proxyURL string) (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.clients[proxyURL]; ok {
		return client, nil
	}
	transport := &http.Transport{Proxy: nil}
	if proxyURL != "" {
		parsed, errParse := url.Parse(proxyURL)
		if errParse != nil {
			return nil, fmt.Errorf("exit is not a valid URL: %w", errParse)
		}
		// net/http understands the "socks5" scheme but not the "socks5h" spelling,
		// and an unrecognised scheme is dialed as an HTTP proxy -- which a SOCKS
		// server answers with a protocol error, so the exit would look permanently
		// dead. The two differ only in where the target hostname is resolved, and
		// Go's socks5 dialer already hands the hostname to the proxy (what socks5h
		// asks for), so normalising is exact rather than approximate. The operator's
		// pool contains both spellings.
		if strings.EqualFold(parsed.Scheme, "socks5h") {
			parsed.Scheme = "socks5"
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	client := &http.Client{Transport: transport}
	p.clients[proxyURL] = client
	return client, nil
}

func (p *probeClientPool) closeIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, client := range p.clients {
		client.CloseIdleConnections()
	}
}

// --- redaction -----------------------------------------------------------

var (
	// Userinfo in any URL, which here means a proxy's credentials. Matched on the
	// scheme://...@ shape rather than against the configured list: a URL echoed
	// back inside an upstream error body has to be caught too, and that one is
	// never in any list we hold.
	probeURLAuthRE = regexp.MustCompile(`(?i)\b([a-z0-9+.\-]+://)[^/\s@]+@`)
	// A Fernet token base64url-encodes a leading 0x80 version byte, which always
	// renders as the literal prefix "gAAAAA" (FINDINGS.md). That makes a
	// turn-state greppable without decoding anything.
	probeTokenRE = regexp.MustCompile(`gAAAAA[A-Za-z0-9_\-=]{16,}`)
	// Any Bearer credential echoed back at us, ours included.
	probeBearerRE = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._\-]{16,}`)
)

// probeRedact strips anything credential-shaped out of text bound for Lines, the
// run error, or the process log.
func probeRedact(text string) string {
	text = probeTokenRE.ReplaceAllString(text, "<turn-state redacted>")
	text = probeBearerRE.ReplaceAllString(text, "${1}<redacted>")
	return probeURLAuthRE.ReplaceAllString(text, "${1}***@")
}

// probeShowProxy renders one exit safe to display, distinguishing "no exit set"
// from an exit that happens to mask to an empty string.
func probeShowProxy(raw string) string {
	if masked := maskProxyURL(raw); masked != "" {
		return masked
	}
	return "(direct)"
}

// probeTruncate bounds a quoted body, saying how much was dropped so nobody
// reads a cut-off JSON document as a malformed one.
func probeTruncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + fmt.Sprintf(" ...[+%d chars]", len(text)-limit)
}
