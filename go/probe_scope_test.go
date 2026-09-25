package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the probe-scope configuration: probe_accounts, probe_proxies, and
// the masking that keeps a proxy's userinfo out of everywhere it must not go.
//
// The load-bearing property in this file is the firewall: probe scope steers a
// probe run and nothing else. If any of these lists ever started filtering
// substitution, an account left off the list would silently stop being served
// while its bucket sat live on disk -- a failure that looks like the upstream
// misbehaving, not like a config change.
//
// Every proxy string here is fabricated and points at .invalid, which is
// reserved by RFC 2606 and can never resolve.

const (
	// A password we can grep the output for. Deliberately distinctive: the
	// assertions below check it appears nowhere, so it must not collide with
	// anything a formatter might legitimately emit.
	testProxySecret = "s3cr3t-never-log-me"
	testProxyWithPW = "socks5h://prober:" + testProxySecret + "@exit.invalid:1080"
)

// --- masking -------------------------------------------------------------

func TestMaskProxyURLNeverEchoesUserinfo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"userinfo is replaced wholesale", testProxyWithPW, "socks5h://***@exit.invalid:1080"},
		{"user without password still masked", "http://prober@exit.invalid:8080", "http://***@exit.invalid:8080"},
		{"no userinfo passes through", "socks5://exit.invalid:1080", "socks5://exit.invalid:1080"},
		{"empty stays empty", "", ""},
		// The important one. A value malformed enough that net/url rejects it is
		// exactly the one likely to be a password with a stray character in it,
		// so "we could not parse it, here it is verbatim" would publish the thing
		// this function exists to hide.
		{"unparsable is not echoed", "://" + testProxySecret, "<unparsable proxy url>"},
		{"schemeless is not echoed", "exit.invalid:1080", "<unparsable proxy url>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := maskProxyURL(tc.in)
			if got != tc.want {
				t.Fatalf("maskProxyURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, testProxySecret) {
				t.Fatalf("maskProxyURL leaked the password: %q", got)
			}
		})
	}
}

func TestMaskProxyURLsKeepsPositions(t *testing.T) {
	// Order is the probe's try order, so a masked list has to line up with the
	// real one entry for entry -- otherwise "the second proxy failed" on the
	// dashboard points at a different exit than the one that actually failed.
	in := []string{testProxyWithPW, "http://exit2.invalid:8080", "://broken"}
	got := maskProxyURLs(in)
	if len(got) != len(in) {
		t.Fatalf("maskProxyURLs returned %d entries for %d inputs", len(got), len(in))
	}
	if got[1] != "http://exit2.invalid:8080" {
		t.Fatalf("entry without userinfo was altered: %q", got[1])
	}
	for i, value := range got {
		if strings.Contains(value, testProxySecret) {
			t.Fatalf("masked entry %d leaked the password: %q", i, value)
		}
	}
}

// --- validation ----------------------------------------------------------

func TestNormaliseProbeScopeDropsAndReportsBadEntries(t *testing.T) {
	accounts, models, proxies, _, problems := normaliseProbeScope(
		[]string{"codex-a.json", "  codex-b.json  ", "", "notcodex.json", "codex-../escape.json"},
		[]string{"gpt-5.6-sol", " gpt-6-astra ", "", "gpt 5.5"},
		[]string{testProxyWithPW, "", "ftp://exit.invalid:21", "://broken"},
		nil,
	)

	wantAccounts := []string{"codex-a.json", "codex-b.json"}
	if !equalStrings(accounts, wantAccounts) {
		t.Fatalf("accounts = %v, want %v", accounts, wantAccounts)
	}
	wantModels := []string{"gpt-5.6-sol", "gpt-6-astra"}
	if !equalStrings(models, wantModels) {
		t.Fatalf("models = %v, want %v", models, wantModels)
	}
	if len(proxies) != 1 || proxies[0] != testProxyWithPW {
		t.Fatalf("proxies = %v, want just the one valid entry", maskProxyURLs(proxies))
	}

	// Five rejects: one account shape, one account traversal, one model with a
	// space, one unsupported scheme, one unparsable URL. The two empty strings
	// are dropped silently -- a blank line in a textarea is not a mistake worth
	// reporting. Counted rather than matched on wording so the messages stay
	// editable.
	if len(problems) != 5 {
		t.Fatalf("expected 5 complaints, got %d: %v", len(problems), problems)
	}
}

func TestProbeScopeProblemsNeverContainAPassword(t *testing.T) {
	// Every rejected proxy produces a complaint, and a complaint is a string
	// that ends up in the status document and in the log. Neither may carry the
	// userinfo of the entry that was rejected.
	_, _, _, _, problems := normaliseProbeScope(
		nil, nil,
		[]string{
			"ftp://prober:" + testProxySecret + "@exit.invalid:21",
			"://" + testProxySecret,
			"gopher://prober:" + testProxySecret + "@exit.invalid:70",
		},
		// The rotating list is held to the same rule, and its complaints must be
		// just as free of userinfo -- it is the same masking path or it is a leak.
		[]string{"gopher://prober:" + testProxySecret + "@rotate.invalid:70"},
	)
	if len(problems) == 0 {
		t.Fatal("expected complaints about three bad proxies, got none")
	}
	for _, problem := range problems {
		if strings.Contains(problem, testProxySecret) {
			t.Fatalf("a config error leaked the password: %q", problem)
		}
	}
}

func TestConfigureNeverFailsOnBadProbeScope(t *testing.T) {
	// Probe scope is not load bearing for substitution. A typo in it must not
	// stop the plugin registering, or a probe-time mistake would take the
	// business role down with it.
	dir := t.TempDir()
	cfg := fmt.Sprintf(`role: business
store_dir: %q
dry_run: false
log_decisions: false
probe_accounts:
  - not-a-codex-file.txt
probe_proxies:
  - ftp://exit.invalid:21
`, dir)
	if err := configureYAML(t, cfg); err != nil {
		t.Fatalf("configure rejected a config whose only fault was probe scope: %v", err)
	}

	state.mu.Lock()
	gotAccounts := len(state.config.ProbeAccounts)
	gotProxies := len(state.config.ProbeProxies)
	gotErrors := len(state.configErrors)
	state.mu.Unlock()

	if gotAccounts != 0 || gotProxies != 0 {
		t.Fatalf("invalid entries were kept: %d accounts, %d proxies", gotAccounts, gotProxies)
	}
	if gotErrors != 2 {
		t.Fatalf("expected 2 recorded config errors, got %d", gotErrors)
	}
}

// --- probe scope does not invalidate the pool ------------------------------

func TestProbeScopeChangeKeepsThePool(t *testing.T) {
	// Editing the scope on the dashboard is the commonest reason configure runs
	// at all. Clearing there would throw away live pairs every time the
	// operator ticked a box -- and a cleared pool looks exactly like "the probe
	// never ran".
	base := defaultConfig()
	base.Role = roleBusiness
	base.StoreDir = "/data/turn-state-store"
	base.Models = []string{"gpt-5.6-sol"}

	for _, tc := range []struct {
		name   string
		mutate func(*pluginConfig)
	}{
		{"probe_accounts changed", func(c *pluginConfig) { c.ProbeAccounts = []string{"codex-a.json"} }},
		{"probe_proxies changed", func(c *pluginConfig) { c.ProbeProxies = []string{testProxyWithPW} }},
		{"models changed", func(c *pluginConfig) { c.Models = []string{"gpt-6-astra"} }},
		{"ttl_seconds changed", func(c *pluginConfig) { c.TTLSeconds = c.TTLSeconds / 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := base
			tc.mutate(&next)
			if poolInvalidatedBy(base, next) {
				t.Fatal("a probe-scope edit cleared the pool")
			}
		})
	}

	// The control: a rule that really does invalidate the pool still must --
	// a different store_dir means a different store, and its pool file is not
	// this one's.
	moved := base
	moved.StoreDir = base.StoreDir + "-moved"
	if !poolInvalidatedBy(base, moved) {
		t.Fatal("a store_dir change no longer clears the pool; the control case is broken")
	}
}

// --- the firewall --------------------------------------------------------

func TestBusinessSteersForAnAccountOutsideTheProbeScope(t *testing.T) {
	// §2.4, pool edition: with probe_accounts and probe_proxies configured, the
	// business path must still steer for a Codex account that is NOT in the
	// list. The lists say which credentials the next probe run may borrow; they
	// say nothing about which accounts may use the pool.
	dir := t.TempDir()
	const (
		served = "codex-served.json" // steered, absent from the scope
		scoped = "codex-scoped.json" // the only account in probe_accounts
		model  = "gpt-5.6-sol"
	)

	cfg := fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: false
log_decisions: false
probe_accounts:
  - %s
probe_proxies:
  - %s
`, dir, scoped, testProxyWithPW)
	mustConfigure(t, cfg)
	seedPoolEntry(t, map[string]string{"__cflb": "cf", "__oailb": "lb"}, time.Now(), "")

	resp := interceptAfter(t, request(served, model, fakeTokenSeed(312, wallClock(), 0x77)))
	cookie := resp.Headers.Get("Cookie")
	if !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("probe_accounts filtered the business path: an out-of-scope Codex account was not steered (cookie %q)", cookie)
	}
}

func TestProbeScopeNeverCreatesABucket(t *testing.T) {
	// The mirror of the test above: naming an account in probe_accounts does not
	// conjure a bucket for it. Only a probe run writes the store.
	dir := t.TempDir()
	const (
		scoped = "codex-scoped.json"
		model  = "gpt-5.6-sol"
	)
	cfg := fmt.Sprintf(`role: business
store_dir: %q
dry_run: false
log_decisions: false
probe_accounts:
  - %s
probe_proxies:
  - %s
`, dir, scoped, testProxyWithPW)
	mustConfigure(t, cfg)

	state.mu.Lock()
	before := len(state.cookies)
	state.mu.Unlock()
	resp := interceptAfter(t, request(scoped, model, fakeTokenSeed(312, wallClock(), 0x21)))
	if cookie := resp.Headers.Get("Cookie"); cookie != "" {
		t.Fatalf("a request was steered with an empty pool (cookie %q)", cookie)
	}
	state.mu.Lock()
	after := len(state.cookies)
	state.mu.Unlock()
	if after != before {
		t.Fatalf("the business path minted into the pool: %d -> %d", before, after)
	}
}

// --- the keyless scope save ----------------------------------------------
//
// Saving the scope is what used to force a management key onto the dashboard:
// the host gives a plugin no way to persist its own config, so the only writable
// path was CPA's authenticated PATCH. These lock in the replacement -- the
// plugin writes its own scope file over a keyless route -- and, above all, that
// it did not become a way to wipe a proxy list by accident.

const opsScopePath = mgmtResourcePath + "ops/scope"

func scopeConfig(t *testing.T, dir string) string {
	t.Helper()
	return fmt.Sprintf(`role: probe
store_dir: %q
dry_run: true
log_decisions: false
probe_accounts:
  - codex-a.json
models:
  - gpt-5.6-sol
probe_proxies:
  - %s
`, dir, testProxyWithPW)
}

func TestScopeSaveRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, scopeConfig(t, dir))

	resp := driveResource(t, opsScopePath, url.Values{"fields": {"models"}, "model": {"gpt-5.5"}})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the scope saved without confirm=1; a bare navigation or a prefetch could rewrite the probe scope")
	}
	if _, errStat := os.Stat(filepath.Join(dir, scopeFileName)); !os.IsNotExist(errStat) {
		t.Fatal("a scope file was written despite the request being rejected")
	}
}

func TestScopeSaveRequiresFields(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, scopeConfig(t, dir))

	// No fields: this must not be read as "replace everything with nothing".
	resp := driveResource(t, opsScopePath, confirmed(nil))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when fields is missing", resp.StatusCode)
	}
	state.mu.Lock()
	proxies := len(state.config.ProbeProxies)
	state.mu.Unlock()
	if proxies != 1 {
		t.Fatalf("the proxy list was touched by a rejected save: %d entries left", proxies)
	}
}

func TestScopeSaveWritesFileAndAppliesLive(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, scopeConfig(t, dir))

	resp := driveResource(t, opsScopePath, confirmed(url.Values{
		"fields":  {"accounts,models"},
		"account": {"codex-x.json", "codex-y.json"},
		"model":   {"gpt-5.6-sol", "gpt-6-astra"},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", resp.StatusCode, resp.Body)
	}

	var out struct {
		Saved         bool     `json:"saved"`
		ProbeAccounts []string `json:"probe_accounts"`
		Models        []string `json:"models"`
		TargetsTotal  int      `json:"targets_total"`
	}
	if errUnmarshal := json.Unmarshal(resp.Body, &out); errUnmarshal != nil {
		t.Fatalf("decode save response: %v", errUnmarshal)
	}
	if !out.Saved || out.TargetsTotal != 4 {
		t.Fatalf("saved=%t targets_total=%d, want true and 4 (2 accounts x 2 models)", out.Saved, out.TargetsTotal)
	}

	// Live without waiting for the host's next reconfigure.
	state.mu.Lock()
	liveAccounts := append([]string(nil), state.config.ProbeAccounts...)
	state.mu.Unlock()
	if !equalStrings(liveAccounts, []string{"codex-x.json", "codex-y.json"}) {
		t.Fatalf("in-memory config not updated: %v", liveAccounts)
	}

	// And on disk, so it survives a restart.
	saved, errLoad := loadProbeScope(dir)
	if errLoad != nil || saved == nil {
		t.Fatalf("scope file not written: %v", errLoad)
	}
	if !equalStrings(saved.Models, []string{"gpt-5.6-sol", "gpt-6-astra"}) {
		t.Fatalf("scope file models = %v", saved.Models)
	}
}

func TestScopeSaveOnlyReplacesNamedFields(t *testing.T) {
	// The whole reason `fields` is required. Saving a model selection must not
	// clear a proxy list the page never sent -- those credentials exist nowhere
	// else once they are gone.
	dir := t.TempDir()
	mustConfigure(t, scopeConfig(t, dir))

	resp := driveResource(t, opsScopePath, confirmed(url.Values{
		"fields": {"models"},
		"model":  {"gpt-5.5"},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", resp.StatusCode, resp.Body)
	}

	saved, errLoad := loadProbeScope(dir)
	if errLoad != nil || saved == nil {
		t.Fatalf("scope file not written: %v", errLoad)
	}
	if len(saved.Proxies) != 1 || saved.Proxies[0] != testProxyWithPW {
		t.Fatalf("the proxy list did not survive a models-only save: %v", maskProxyURLs(saved.Proxies))
	}
	if !equalStrings(saved.Accounts, []string{"codex-a.json"}) {
		t.Fatalf("the account list did not survive a models-only save: %v", saved.Accounts)
	}

	// An explicit clear still works.
	resp = driveResource(t, opsScopePath, confirmed(url.Values{"fields": {"proxies"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("explicit clear: status = %d", resp.StatusCode)
	}
	saved, _ = loadProbeScope(dir)
	if saved == nil || len(saved.Proxies) != 0 {
		t.Fatal("fields=proxies with no proxy params should clear the list")
	}
}

func TestSavedScopeOverridesConfigYAML(t *testing.T) {
	// CPA rewrites config.yaml on its own, so a reconfigure after a save is not
	// hypothetical. If config.yaml won, the operator would watch their selection
	// revert with nothing on screen to explain it.
	dir := t.TempDir()
	if errWrite := writeProbeScope(dir, probeScope{
		Accounts:  []string{"codex-saved.json"},
		Models:    []string{"gpt-6-astra"},
		UpdatedAt: "2026-09-18T00:00:00Z",
	}); errWrite != nil {
		t.Fatalf("write scope: %v", errWrite)
	}

	mustConfigure(t, scopeConfig(t, dir))

	state.mu.Lock()
	accounts := append([]string(nil), state.config.ProbeAccounts...)
	models := append([]string(nil), state.config.Models...)
	proxies := len(state.config.ProbeProxies)
	state.mu.Unlock()

	if !equalStrings(accounts, []string{"codex-saved.json"}) {
		t.Fatalf("config.yaml won over the saved scope: %v", accounts)
	}
	if !equalStrings(models, []string{"gpt-6-astra"}) {
		t.Fatalf("models came from config.yaml, not the saved scope: %v", models)
	}
	// The saved scope is authoritative in full, not merged: it recorded no
	// proxies, so there are none, even though config.yaml lists one.
	if proxies != 0 {
		t.Fatalf("proxies leaked in from config.yaml: %d", proxies)
	}
}

func TestScopeSaveKeepsThePool(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, fmt.Sprintf(`role: business
store_dir: %q
dry_run: false
log_decisions: false
probe_accounts:
  - codex-a.json
models:
  - gpt-5.6-sol
`, dir))
	seedPoolEntry(t, map[string]string{"__cflb": "cf", "__oailb": "lb"}, time.Now(), "")

	// Prime the in-memory view by serving one request through the pool.
	interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x11)))

	resp := driveResource(t, opsScopePath, confirmed(url.Values{
		"fields":  {"accounts"},
		"account": {"codex-b.json"},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The pair is still there and still used. Ticking a box on the dashboard
	// must not throw away a live credential.
	out := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x22)))
	if cookie := out.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("the pair was lost when the scope was saved (cookie: %q)", cookie)
	}
}

// equalStrings compares two string slices by value. Written out rather than
// reached for via reflect so a failure prints something readable.
func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// --- the two pools ---------------------------------------------------------

func TestScopeSaveRoundTripsTheRotatingPool(t *testing.T) {
	// The rotating pool is persisted, applied live, and -- above all -- kept
	// SEPARATE from the static one. Merging them would silently hand one pool's
	// retry rule to the other, which is the whole defect the split fixes.
	dir := t.TempDir()
	mustConfigure(t, scopeConfig(t, dir))

	resp := driveResource(t, opsScopePath, confirmed(url.Values{
		"fields":         {"rotating"},
		"rotating_proxy": {"socks5://gw:pw@rotate.invalid:1080", "http://gw2.invalid:8080"},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, resp.Body)
	}

	state.mu.Lock()
	rotating := append([]string(nil), state.config.ProbeProxiesRotating...)
	static := append([]string(nil), state.config.ProbeProxies...)
	state.mu.Unlock()

	if len(rotating) != 2 {
		t.Fatalf("rotating pool = %v, want the two saved entries", len(rotating))
	}
	// scopeConfig seeds exactly one static proxy; saving only the rotating field
	// must not disturb it.
	if len(static) != 1 {
		t.Fatalf("static pool = %d entries, want 1 -- saving one pool rewrote the other", len(static))
	}

	// And it survives a reload, which is what the renewal loop actually reads.
	mustConfigure(t, scopeConfig(t, dir))
	state.mu.Lock()
	reloaded := len(state.config.ProbeProxiesRotating)
	state.mu.Unlock()
	if reloaded != 2 {
		t.Fatalf("rotating pool after reload = %d, want 2; it was not persisted", reloaded)
	}
}

func TestScopeSaveRejectsAnUnknownField(t *testing.T) {
	// "fields" is the guard against an empty query meaning "clear everything", so
	// a typo in it must fail loudly rather than silently save nothing.
	dir := t.TempDir()
	mustConfigure(t, scopeConfig(t, dir))

	resp := driveResource(t, opsScopePath, confirmed(url.Values{"fields": {"rotaing"}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a misspelled field", resp.StatusCode)
	}
}

func TestRotatingPoolComplaintsAreMaskedToo(t *testing.T) {
	// Both pools share normaliseProxyList precisely so this cannot drift: a bad
	// rotating entry must be reported by field and position, never by value.
	_, _, _, _, problems := normaliseProbeScope(nil, nil, nil,
		[]string{"gopher://gw:" + testProxySecret + "@rotate.invalid:70"})
	if len(problems) == 0 {
		t.Fatal("an unsupported scheme in the rotating pool produced no complaint")
	}
	for _, problem := range problems {
		if strings.Contains(problem, testProxySecret) {
			t.Fatalf("a rotating-pool complaint carried the password: %s", problem)
		}
		if !strings.Contains(problem, "probe_proxies_rotating") {
			t.Fatalf("complaint does not name which pool it came from: %s", problem)
		}
	}
}
