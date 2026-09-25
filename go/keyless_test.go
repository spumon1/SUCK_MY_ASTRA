package main

// Tests for the keyless action surface: the four dashboard actions (dry_run,
// role, clear, selftest) served under the unauthenticated resource prefix, the
// confirm=1 guard that stands in for a key on those GET-with-side-effects routes,
// and the runtime override that persists dry_run and role across a restart.
//
// The security contract these lock in: the four actions are keyless by the
// operator's explicit choice, but nothing that emits a secret is. The config
// route (proxy userinfo) must stay an authenticated management route, never a
// resource, and that is asserted here alongside the keyless routes.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

const (
	opsDryRunPath   = mgmtResourcePath + "ops/dry-run"
	opsRolePath     = mgmtResourcePath + "ops/role"
	opsClearPath    = mgmtResourcePath + "ops/clear"
	opsSelftestPath = mgmtResourcePath + "ops/selftest"
)

// driveResource drives one resource (unauthenticated, GET) request with a query,
// which driveManagement cannot do -- it hard-codes an empty Query, and the whole
// point of the keyless routes is that they read their parameters from the query.
func driveResource(t *testing.T, path string, query url.Values) mgmtResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Method":  http.MethodGet,
		"Path":    path,
		"Headers": http.Header{},
		"Query":   query,
		"Body":    nil,
	})
	if err != nil {
		t.Fatalf("marshal resource request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementHandle, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.handle) GET %s: %v", path, errHandle)
	}
	var resp mgmtResponse
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
			t.Fatalf("decode resource response: %v", errUnmarshal)
		}
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return resp
}

func confirmed(extra url.Values) url.Values {
	q := url.Values{"confirm": {"1"}}
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return q
}

func readOverrideFile(t *testing.T, dir string) runtimeOverride {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, runtimeOverrideFileName))
	if err != nil {
		t.Fatalf("read %s: %v", runtimeOverrideFileName, err)
	}
	var ov runtimeOverride
	if err := json.Unmarshal(data, &ov); err != nil {
		t.Fatalf("decode %s: %v", runtimeOverrideFileName, err)
	}
	return ov
}

// The four actions must be resources (unauthenticated), never management routes,
// and the config route -- the one that emits proxy secrets -- must be the exact
// opposite. Registration is the contract; a rename or a move that flipped either
// direction would either put a key back on the four actions or publish the
// proxy passwords, and this catches both.
func TestKeylessRoutesRegisteredUnauthenticated(t *testing.T) {
	reg := driveManagementRegister(t)

	resourcePaths := make(map[string]mgmtRoute)
	for _, r := range reg.Resources {
		resourcePaths[r.Path] = r
	}
	routePaths := make(map[string]bool)
	for _, r := range reg.Routes {
		routePaths[r.Path] = true
	}

	for _, p := range []string{"/ops/dry-run", "/ops/role", "/ops/clear", "/ops/selftest"} {
		res, ok := resourcePaths[p]
		if !ok {
			t.Errorf("%s is not registered as a resource; a keyless action must be, or it would still demand a management key", p)
			continue
		}
		if res.Menu != "" {
			t.Errorf("%s declares Menu %q; the actions are fetched by script, not navigated to, and a menu entry misrepresents them", p, res.Menu)
		}
		if routePaths[p] {
			t.Errorf("%s is also a management route; the keyless action must live only on the unauthenticated resource prefix", p)
		}
	}

	// The config route emits proxy userinfo. It must be an authenticated route and
	// must never appear as a resource, or the passwords go anonymous.
	for _, r := range reg.Resources {
		if strings.HasSuffix(r.Path, "/config") {
			t.Errorf("config route %q is registered as a resource; it emits proxy secrets and must stay behind the key", r.Path)
		}
	}
}

// confirm=1 is the whole guard on a GET that changes state. Without it, the
// action must do nothing and say so, so a bare navigation, a prefetch or a
// crawler cannot fire it.
func TestKeylessActionRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // dry_run: true

	resp := driveResource(t, opsDryRunPath, url.Values{"value": {"off"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dry-run without confirm returned %d, want 400 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if st := mustManagementStatus(t); !st.DryRun {
		t.Error("dry_run changed even though the action was refused for lack of confirm=1")
	}
}

// A destructive action refused for lack of confirm must not delete anything.
func TestKeylessClearRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, dir)
	recordObservation(cfg, "codex-x.json", "gpt-5.5", 292, false)

	resp := driveResource(t, opsClearPath, url.Values{"all": {"1"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("clear without confirm returned %d, want 400", resp.StatusCode)
	}
	found := false
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.AuthID == "codex-x.json" && bucket.Model == "gpt-5.5" && bucket.Observed != nil {
			found = true
		}
	}
	if !found {
		t.Error("observation row deleted despite the clear being refused for lack of confirm=1")
	}
}

// The resource prefix is GET-only in the host; the handler enforces it too so a
// POST that somehow reaches it is a clean 405, not a silent state change.
func TestKeylessActionRejectsNonGet(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resp := driveManagement(t, http.MethodPost, opsDryRunPath, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST to a keyless action returned %d, want 405", resp.StatusCode)
	}
}

// dry_run flips without a key and the change survives a restart: the override
// file is written, and a later configure that reads a config.yaml still saying
// dry_run:true must come up with dry_run:false because the override wins.
func TestKeylessDryRunTogglesAndPersists(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // dry_run: true

	resp := driveResource(t, opsDryRunPath, confirmed(url.Values{"value": {"off"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless dry-run off returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if st := mustManagementStatus(t); st.DryRun {
		t.Error("dry_run is still on right after a keyless off")
	}

	ov := readOverrideFile(t, dir)
	if ov.DryRun == nil || *ov.DryRun {
		t.Errorf("runtime override did not record dry_run=false: %+v", ov)
	}

	// Simulate a restart: configure again from a config.yaml that still says
	// dry_run:true. The override must override it.
	mustConfigure(t, probeRoleConfig(dir))
	if st := mustManagementStatus(t); st.DryRun {
		t.Error("dry_run reverted to config.yaml on restart; the runtime override was not applied")
	}
}

func TestKeylessDryRunRejectsBadValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resp := driveResource(t, opsDryRunPath, confirmed(url.Values{"value": {"maybe"}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dry-run with a bad value returned %d, want 400", resp.StatusCode)
	}
	if st := mustManagementStatus(t); !st.DryRun {
		t.Error("dry_run changed on an unrecognised value; a typo must not silently turn it off")
	}
}

// role switches without a key and persists the same way dry_run does.
func TestKeylessRoleSwitchesAndPersists(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir)) // role: probe

	resp := driveResource(t, opsRolePath, confirmed(url.Values{"value": {"business"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless role switch returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if st := mustManagementStatus(t); st.Role != roleBusiness {
		t.Errorf("role is %q right after a keyless switch to business", st.Role)
	}

	ov := readOverrideFile(t, dir)
	if ov.Role == nil || *ov.Role != roleBusiness {
		t.Errorf("runtime override did not record role=business: %+v", ov)
	}

	mustConfigure(t, probeRoleConfig(dir)) // config.yaml still says probe
	if st := mustManagementStatus(t); st.Role != roleBusiness {
		t.Errorf("role reverted to %q on restart; the runtime override was not applied", st.Role)
	}
}

func TestKeylessRoleRejectsUnknownValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	resp := driveResource(t, opsRolePath, confirmed(url.Values{"value": {"supervisor"}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("role with an unknown value returned %d, want 400", resp.StatusCode)
	}
	if st := mustManagementStatus(t); st.Role != roleProbe {
		t.Errorf("role changed to %q on an unknown value; only probe/business are allowed", st.Role)
	}
}

// Clearing one bucket via the query works and deletes the file, the same as the
// POST route with a JSON body.
func TestKeylessClearOneBucket(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, dir)
	recordObservation(cfg, "codex-x.json", "gpt-5.5", 292, false)

	resp := driveResource(t, opsClearPath, confirmed(url.Values{
		"auth_id": {"codex-x.json"}, "model": {"gpt-5.5"},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless clear returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var res mgmtClearResult
	if err := json.Unmarshal(resp.Body, &res); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if res.Cleared != 1 {
		t.Errorf("cleared %d buckets, want 1", res.Cleared)
	}
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.AuthID == "codex-x.json" && bucket.Model == "gpt-5.5" && bucket.Observed != nil {
			t.Error("observation row still present after keyless clear")
		}
	}
}

// Clearing everything via ?all=1 wipes the route-cookie pool and every
// observation row.
func TestKeylessClearAll(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	cfg := resetObservations(t, dir)
	for _, m := range []string{"gpt-5.5", "gpt-5.6-sol"} {
		recordObservation(cfg, "codex-x.json", m, 292, false)
	}
	state.mu.Lock()
	state.noteRouteCookiesLocked(routeCookieSet{
		pairs:  map[string]string{"__cflb": "a", "__oailb": "b"},
		seenAt: time.Now(),
	}, "")
	poolLen := len(state.cookies)
	state.mu.Unlock()
	if poolLen == 0 {
		t.Fatal("pool entry was not recorded")
	}

	resp := driveResource(t, opsClearPath, confirmed(url.Values{"all": {"1"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless clear all returned %d, want 200", resp.StatusCode)
	}
	var res mgmtClearResult
	if err := json.Unmarshal(resp.Body, &res); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if res.Cleared != 1 {
		t.Errorf("cleared=%d, want 1 (the pool)", res.Cleared)
	}
	state.mu.Lock()
	poolLen = len(state.cookies)
	state.mu.Unlock()
	if poolLen != 0 {
		t.Errorf("pool still holds %d entries after clear all", poolLen)
	}
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.Observed != nil {
			t.Errorf("observation for %s/%s survived clear all", bucket.AuthID, bucket.Model)
		}
	}
}

// The runtime override is layered on top of config.yaml at configure time, and
// only the fields it actually set are applied. Writing an override before the
// first configure -- the deploy-then-restart order -- must take effect.
func TestRuntimeOverrideLayeredOnConfigure(t *testing.T) {
	dir := t.TempDir()
	if err := writeRuntimeOverride(dir, roleBusiness, false); err != nil {
		t.Fatalf("writeRuntimeOverride: %v", err)
	}
	// config.yaml says role: probe, dry_run: true. The override says business/false.
	mustConfigure(t, probeRoleConfig(dir))
	st := mustManagementStatus(t)
	if st.Role != roleBusiness {
		t.Errorf("role is %q, want business from the override", st.Role)
	}
	if st.DryRun {
		t.Error("dry_run is true, want false from the override")
	}
}

// A malformed override must not take down registration: configure falls back to
// the config-file values instead.
func TestRuntimeOverrideMalformedIsIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, runtimeOverrideFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad override: %v", err)
	}
	mustConfigure(t, probeRoleConfig(dir)) // must not fail
	st := mustManagementStatus(t)
	if st.Role != roleProbe || !st.DryRun {
		t.Errorf("a malformed override was not ignored: role=%q dry_run=%v (want probe/true from config.yaml)", st.Role, st.DryRun)
	}
}

func TestParseBoolParam(t *testing.T) {
	cases := []struct {
		in    string
		value bool
		ok    bool
	}{
		{"on", true, true}, {"true", true, true}, {"1", true, true}, {"yes", true, true},
		{"off", false, true}, {"false", false, true}, {"0", false, true}, {"no", false, true},
		{"ON", true, true}, {" off ", false, true},
		{"", false, false}, {"maybe", false, false}, {"2", false, false},
	}
	for _, c := range cases {
		value, ok := parseBoolParam(c.in)
		if value != c.value || ok != c.ok {
			t.Errorf("parseBoolParam(%q) = (%v, %v), want (%v, %v)", c.in, value, ok, c.value, c.ok)
		}
	}
}

func TestQueryTrue(t *testing.T) {
	for _, in := range []string{"1", "true", "on", "yes", "TRUE", " 1 "} {
		if !queryTrue(in) {
			t.Errorf("queryTrue(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "0", "false", "off", "no", "2", "maybe"} {
		if queryTrue(in) {
			t.Errorf("queryTrue(%q) = true, want false", in)
		}
	}
}
