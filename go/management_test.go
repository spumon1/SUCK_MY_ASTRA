package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

// Paths are spelled out rather than imported from the implementation. These
// tests are the contract for the management surface: renaming a route in
// production should break them loudly, not have them follow along.
const (
	mgmtStatusPath   = "/v0/management/codex-turn-state/status"
	mgmtClearPath    = "/v0/management/codex-turn-state/buckets/clear"
	mgmtSelftestPath = "/v0/management/codex-turn-state/selftest"
	mgmtConfigPath   = "/v0/management/codex-turn-state/config"
	mgmtResourcePath = "/v0/resource/plugins/codex-turn-state/"

	// The probe runner's controls, on the unauthenticated resource prefix where
	// the rest of the keyless actions live.
	opsProbeStartPath  = mgmtResourcePath + "ops/probe/start"
	opsProbeCancelPath = mgmtResourcePath + "ops/probe/cancel"

	// The scope editor's menu, on the same unauthenticated prefix. Unlike its
	// neighbours it only reads, so it takes no confirm=1 -- which is itself part
	// of the contract asserted below.
	opsChoicesPath = mgmtResourcePath + "ops/choices"
)

// --- wire shapes ---------------------------------------------------------
//
// Decoded into local structs so the tests do not bind to internal type names.
// The pluginapi management types carry no JSON tags, so they travel under their
// Go field names -- StatusCode, Headers, Body -- which is what these mirror.

type mgmtResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

type mgmtRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type mgmtRegistration struct {
	Routes    []mgmtRoute `json:"routes"`
	Resources []mgmtRoute `json:"resources"`
}

type mgmtBucket struct {
	AuthID      string `json:"auth_id"`
	Model       string `json:"model"`
	Ready       bool   `json:"ready"`
	Len         int    `json:"len"`
	Enabled     bool   `json:"enabled"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	SecondsLeft int64  `json:"seconds_left"`
	// Observed is absent on a bucket nothing has been seen for, which is why
	// this is a pointer: "no traffic" and "normal" must stay distinguishable.
	Observed *mgmtObserved `json:"observed"`
}

type mgmtObserved struct {
	NaturalNormal   int64  `json:"natural_normal"`
	NaturalLimited  int64  `json:"natural_limited"`
	InjectedSilent  int64  `json:"injected_silent"`
	InjectedLimited int64  `json:"injected_limited"`
	LastKind        string `json:"last_kind"`
	LastWrote       bool   `json:"last_wrote"`
	LastNaturalKind string `json:"last_natural_kind"`
	LastNaturalAt   string `json:"last_natural_at"`
}

type mgmtObservationEvent struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	Len    int    `json:"len"`
	Wrote  bool   `json:"wrote"`
	Kind   string `json:"kind"`
}

type mgmtCounters struct {
	Harvest int64 `json:"harvest"`
	Steer   int64 `json:"steer"`
	Pass    int64 `json:"pass"`
	Skip    int64 `json:"skip"`
}

type mgmtStatus struct {
	Role           string       `json:"role"`
	DryRun         bool         `json:"dry_run"`
	TTLSeconds     int          `json:"ttl_seconds"`
	TemplateLength int          `json:"template_length"`
	ReplaceLength  int          `json:"replace_length"`
	StoreDir       string       `json:"store_dir"`
	Models         []string     `json:"models"`
	Buckets        []mgmtBucket `json:"buckets"`
	TargetsTotal   int          `json:"targets_total"`
	TargetsReady   int          `json:"targets_ready"`
	// AccountsSource is "host" when the credential list came from
	// host.auth.list and "store" when it had to be inferred from what the store
	// already holds. Under "store" a never-probed account is invisible, so the
	// distinction is what stops an empty matrix reading as "nothing to probe".
	AccountsSource    string                 `json:"accounts_source"`
	AccountsError     string                 `json:"accounts_error"`
	StoreError        string                 `json:"store_error"`
	Counters          mgmtCounters           `json:"counters"`
	ObservationsSince string                 `json:"observations_since"`
	ObservationFeed   []mgmtObservationEvent `json:"observation_feed"`
	ProbeAccounts     []string               `json:"probe_accounts"`
	// ProbeProxies is plaintext, and that is the contract now rather than an
	// oversight -- see TestStatusShowsProbeProxiesInTheClear for why it changed
	// and what still stays masked. ProbeProxyCount survived the change.
	ProbeProxyCount int      `json:"probe_proxy_count"`
	ProbeProxies    []string `json:"probe_proxies"`
}

type mgmtClearResult struct {
	Cleared int `json:"cleared"`
}

// mgmtSelftestResult mirrors the selftest body. Harvested is spelled out here
// even though it is always false: the field existing and reading false is the
// contract, so it has to be decoded to be asserted.
//
// AuthID is a request-side echo, never a discovery.
//
// Reading back which credential answered is not possible: CPA's
// HostModelExecutionResponse carries only StatusCode, Headers and Body, with no
// account identity anywhere, and no auth-id response header exists to look for.
// An earlier revision guessed at header names; that whole approach was removed
// because it could only ever invent an answer.
//
// The direction that does work is the request side.
// pluginapi.HostModelExecutionRequest.AuthID "optionally locks execution to an
// exact credential ID" and the host forwards it verbatim
// (internal/pluginhost/host_callbacks.go:330). So the plugin does not learn
// which account was used -- it decides, and echoes back what it asked for.
//
// Targeted exists because auth_id alone is ambiguous. An empty auth_id could be
// read as "the scheduler picked nothing", which never happens; what it actually
// means is "we did not specify one, and cannot find out which was used".
// targeted:false says that out loud, so nobody reads an empty string as a
// finding. See TestSelftestEchoesTargetingHonestly and
// TestSelftestAuthIDIsNeverFabricated.
type mgmtSelftestResult struct {
	Reached    bool   `json:"reached"`
	StatusCode int    `json:"status_code"`
	Model      string `json:"model"`
	AuthID     string `json:"auth_id"`
	Targeted   bool   `json:"targeted"`
	Harvested  bool   `json:"harvested"`
	Note       string `json:"note"`
	Error      string `json:"error"`
}

// --- drivers -------------------------------------------------------------

// decodeMgmtEnvelope unwraps the plugin's ok/error envelope. Kept separate from
// main_test.go's interceptAfter so a failing management call reports the
// plugin's own error text instead of a generic decode failure.
func decodeMgmtEnvelope(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v (raw: %s)", err, truncateMgmtLog(raw))
	}
	if !env.OK {
		t.Fatalf("plugin returned an error envelope: %+v", env.Error)
	}
	return env.Result
}

// truncateMgmtLog keeps a failure message readable when a body is large. It also
// means a leaked token would not be splashed across the full test log.
func truncateMgmtLog(raw []byte) string {
	const limit = 200
	if len(raw) <= limit {
		return string(raw)
	}
	return string(raw[:limit]) + "..."
}

// driveManagement drives one management.handle call end to end.
func driveManagement(t *testing.T, method, path string, body []byte) mgmtResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Method":  method,
		"Path":    path,
		"Headers": http.Header{},
		"Query":   url.Values{},
		"Body":    body,
	})
	if err != nil {
		t.Fatalf("marshal management request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementHandle, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.handle) %s %s: %v", method, path, errHandle)
	}
	var resp mgmtResponse
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
			t.Fatalf("decode management response: %v", errUnmarshal)
		}
	}
	// Zero means 200 per the SDK contract; normalise so callers compare one
	// value rather than two.
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return resp
}

// driveManagementJSON drives a call whose body is a JSON object.
func driveManagementJSON(t *testing.T, method, path string, payload any) mgmtResponse {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return driveManagement(t, method, path, body)
}

// driveManagementRegister drives management.register and returns the declared routes.
func driveManagementRegister(t *testing.T) mgmtRegistration {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Plugin":           map[string]any{"Name": "codex-turn-state"},
		"BasePath":         "/v0/management",
		"ResourceBasePath": "/v0/resource/plugins/codex-turn-state",
	})
	if err != nil {
		t.Fatalf("marshal management registration request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementRegister, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.register): %v", errHandle)
	}
	var reg mgmtRegistration
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &reg); errUnmarshal != nil {
			t.Fatalf("decode management registration: %v", errUnmarshal)
		}
	}
	return reg
}

// mustManagementStatus fetches and decodes the status document.
func mustManagementStatus(t *testing.T) mgmtStatus {
	t.Helper()
	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("decode status: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	return status
}

// probeRoleConfig is a probe-role config pointed at dir. businessConfig already
// exists in main_test.go; this is its counterpart.
func probeRoleConfig(dir string) string {
	return fmt.Sprintf(`role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: true
log_decisions: false
models:
  - gpt-5.5
  - gpt-5.6-sol
`, dir)
}

// businessConfigWithModels is businessConfig (main_test.go) plus a models list.
// The self-test validates its model against that list in either role, so a
// business-role fixture without one could only ever produce a 400 and would
// never reach the behaviour under test.
func businessConfigWithModels(dir string) string {
	return fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: true
log_decisions: false
models:
  - gpt-5.5
  - gpt-5.6-sol
`, dir)
}

// probeRoleConfigModels is probeRoleConfig with a caller-chosen model list, so
// a test can vary the width of the readiness matrix.
func probeRoleConfigModels(dir string, models ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
dry_run: true
log_decisions: false
models:
`, dir)
	for _, model := range models {
		fmt.Fprintf(&b, "  - %s\n", model)
	}
	return b.String()
}

// seedMgmtBucket records one observation for the bucket and returns a fake
// token the caller can hunt for in bodies -- it must never appear on the wire.
func seedMgmtBucket(t *testing.T, dir, authID, model string, issued time.Time) string {
	t.Helper()
	recordObservation(defaultConfig(), authID, model, 292, false)
	return fakeToken(292, issued)
}

// observedCellCount is the observation-row analogue of a store snapshot: a
// rejected call must leave the tally exactly as it found it.
func observedCellCount() int {
	cells, _, _ := observationsSnapshot()
	return len(cells)
}

// mgmtBucketByKey finds one bucket in a status document.
func mgmtBucketByKey(status mgmtStatus, authID, model string) (mgmtBucket, bool) {
	for _, bucket := range status.Buckets {
		if bucket.AuthID == authID && bucket.Model == model {
			return bucket, true
		}
	}
	return mgmtBucket{}, false
}

// --- 1. secrecy ----------------------------------------------------------

// The whole design rests on values never leaving the store. The status document
// is the most likely place to leak one by accident, because it is assembled
// from the very records that hold them.
func TestManagementStatusNeverLeaksTokenValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-5 * time.Minute)
	secrets := []string{
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued),
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued),
		seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued),
	}

	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200", resp.StatusCode)
	}
	body := string(resp.Body)
	for i, secret := range secrets {
		// A 40-character prefix is far past the point where a collision could
		// be accidental, and short enough to catch a truncated leak.
		needle := secret[:40]
		if strings.Contains(body, needle) {
			t.Errorf("status body leaked token %d", i)
		}
	}
	// Guard against the assertion passing because the body is empty or the
	// buckets never made it in: the test must be looking at real data.
	if len(resp.Body) == 0 {
		t.Fatal("status body is empty; the leak assertions above proved nothing")
	}
	// The status document enumerates *target* buckets -- configured models
	// crossed with the accounts seen -- so missing ones show up as not-ready
	// rather than being absent. Asserting a total would therefore be asserting
	// that arithmetic, not that the leak checks saw real data. Checking the
	// seeded buckets are present and ready is the assertion that matters.
	status := mustManagementStatus(t)
	for _, want := range [][2]string{
		{"codex-alpha.json", "gpt-5.5"},
		{"codex-alpha.json", "gpt-5.6-sol"},
		{"codex-beta.json", "gpt-5.5"},
	} {
		bucket, ok := mgmtBucketByKey(status, want[0], want[1])
		if !ok || !bucket.Ready {
			t.Fatalf("seeded bucket %s/%s is not reported ready; the leak assertions above were not exercised against real records", want[0], want[1])
		}
	}
}

// The resource shell is served on the unauthenticated prefix. It must therefore
// be a fixed asset: the moment it renders anything derived from runtime state,
// that state is public. Byte equality across a store mutation is the assertion
// that keeps it honest.
func TestResourceShellIsStaticAndDataFree(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	before := driveManagement(t, http.MethodGet, mgmtResourcePath, nil)
	if before.StatusCode != http.StatusOK {
		t.Fatalf("resource shell returned %d, want 200", before.StatusCode)
	}
	if len(before.Body) == 0 {
		t.Fatal("resource shell body is empty; nothing was actually served")
	}

	issued := wallClock().Add(-time.Minute)
	secret := seedMgmtBucket(t, dir, "codex-secret-account.json", "gpt-5.6-sol", issued)

	after := driveManagement(t, http.MethodGet, mgmtResourcePath, nil)
	if string(before.Body) != string(after.Body) {
		t.Error("resource shell changed after the store changed; it is rendering runtime state on an unauthenticated route")
	}

	shell := string(after.Body)
	for _, forbidden := range []string{
		secret[:40],
		"codex-secret-account.json",
		dir,
	} {
		if strings.Contains(shell, forbidden) {
			t.Errorf("resource shell embedded runtime data: %q", truncateMgmtLog([]byte(forbidden)))
		}
	}
}

// --- 2. capability and route declaration ---------------------------------

func TestRegistrationAdvertisesManagementAPI(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	raw, err := json.Marshal(map[string]any{
		"config_yaml":    []byte(probeRoleConfig(dir)),
		"schema_version": 6,
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodPluginRegister, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(plugin.register): %v", errHandle)
	}
	var reg struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &reg); errUnmarshal != nil {
			t.Fatalf("decode registration: %v", errUnmarshal)
		}
	}
	enabled, ok := reg.Capabilities["management_api"].(bool)
	if !ok {
		t.Fatalf("registration does not declare management_api at all; capabilities: %v", reg.Capabilities)
	}
	if !enabled {
		t.Error("management_api is false; the management routes will never be mounted")
	}
}

// This is the sharpest footgun on the management surface. CPA's
// routeDeclaresLegacyMenuResource (internal/pluginhost/management.go:156) treats
// any GET route carrying a Menu label as a *legacy resource*, and re-registers
// it under /v0/resource/plugins/<id>/ -- which is not management-authenticated.
// Putting a Menu on the status route would therefore publish the whole status
// document, silently, with no other symptom.
func TestManagementDataRoutesCarryNoMenu(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	if len(reg.Routes) == 0 {
		t.Fatal("no management routes declared; this test would pass vacuously")
	}
	for _, route := range reg.Routes {
		if strings.TrimSpace(route.Menu) != "" {
			t.Errorf("management route %s %s carries Menu=%q, which demotes it to the unauthenticated resource prefix",
				route.Method, route.Path, route.Menu)
		}
	}
}

// Exactly one resource may carry a Menu, and it is the dashboard shell.
//
// The invariant is about the Menu, not the resource count. There are two
// resources now -- the shell and an anonymous /status the shell fetches -- and
// there may be more later. What must never grow is the set of *menu-bearing*
// ones: a Menu turns a resource into a management-centre entry, and every such
// entry lives on the unauthenticated /v0/resource prefix. One page is intended
// to be reachable without a key (the user asked for a no-login dashboard);
// anything else acquiring a Menu would be an accident that quietly publishes it.
func TestManagementRegisterExposesExactlyOneMenuResource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	if len(reg.Resources) == 0 {
		t.Fatal("no resources declared; this test would pass vacuously")
	}

	var withMenu []mgmtRoute
	for _, res := range reg.Resources {
		if strings.TrimSpace(res.Menu) != "" {
			withMenu = append(withMenu, res)
		}
	}
	if len(withMenu) != 1 {
		t.Fatalf("declared %d resources with a Menu, want exactly 1 (the shell); the rest must stay off the menu", len(withMenu))
	}
	if withMenu[0].Path != "/dashboard" {
		t.Errorf("the menu-bearing resource is %q, want /dashboard", withMenu[0].Path)
	}
}

// The anonymous /status resource is the dashboard's data source: same handler
// and same JSON as the authenticated management status, reachable without a key
// because the resource prefix is not authenticated. It must NOT carry a Menu --
// a Menu is for pages an operator navigates to, and this is a fetch target; the
// menu-bearing entry is the dashboard alone (see the test above).
func TestManagementRegisterExposesAnonymousStatusResource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	var status *mgmtRoute
	for i := range reg.Resources {
		if reg.Resources[i].Path == "/status" {
			status = &reg.Resources[i]
			break
		}
	}
	if status == nil {
		t.Fatal("no /status resource declared; the dashboard has nothing to fetch from")
	}
	if strings.TrimSpace(status.Menu) != "" {
		t.Errorf("the /status resource carries Menu=%q; it is a fetch target, not a page", status.Menu)
	}
}

// The status document served on the anonymous resource path is the same one the
// authenticated route returns, so it must be held to the same secrecy bar. The
// account filenames it exposes are the user's informed choice; the token values
// are never anyone's choice. This re-runs the no-leak check against the resource
// path specifically, because that is the one an unauthenticated caller reaches.
func TestAnonymousStatusResourceNeverLeaksTokenValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	secrets := []string{
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued),
		seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.6-sol", issued),
	}

	resp := driveManagement(t, http.MethodGet, "/v0/resource/plugins/codex-turn-state/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous status returned %d, want 200: %s", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	if len(resp.Body) == 0 {
		t.Fatal("anonymous status body is empty; the leak check below would prove nothing")
	}
	for i, secret := range secrets {
		if strings.Contains(string(resp.Body), secret[:40]) {
			t.Errorf("anonymous status leaked token %d", i)
		}
	}
	// Prove the body is the real status document, not an error or a stub, so
	// the leak assertions were exercised against actual bucket data.
	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("anonymous status body is not a status document: %v", err)
	}
	if b, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5"); !ok || !b.Ready {
		t.Error("seeded bucket missing from anonymous status; leak check saw no real data")
	}
}

// The clear endpoint takes an account and a model straight from a request body
// and turns them into a filesystem path. Without sanitising, "auth_id": ".."
// walks out of the store and deletes whatever is next door.
func TestClearBucketRejectsPathTraversal(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	// The sentinel sits one level above the store, exactly where "../<model>"
	// lands. Its name matches the <model>.json shape so a successful traversal
	// would actually remove it.
	sentinel := filepath.Join(base, "sentinel.json")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	cases := []struct {
		name   string
		authID string
		model  string
	}{
		{"parent via auth", "..", "sentinel"},
		{"parent via model", "codex-alpha.json", "../sentinel"},
		{"nested parent", "../..", "sentinel"},
		{"slash in auth", "codex/../..", "sentinel"},
		{"backslash in auth", `..\..`, "sentinel"},
		{"absolute model", "codex-alpha.json", filepath.ToSlash(sentinel)},
		{"empty auth", "", "gpt-5.5"},
		{"empty model", "codex-alpha.json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagementJSON(t, http.MethodPost, mgmtClearPath, map[string]any{
				"auth_id": tc.authID,
				"model":   tc.model,
			})
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("traversal accepted: status %d, want 4xx", resp.StatusCode)
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatalf("sentinel outside the store was removed: %v", err)
			}
		})
	}

	// The legitimate bucket must still be there: a blanket refusal that also
	// broke normal clears would pass every assertion above. "There" is an
	// observation row now -- the per-bucket file store is gone.
	if _, ok := mgmtBucketByKey(mustManagementStatus(t), "codex-alpha.json", "gpt-5.5"); !ok {
		t.Fatal("the ordinary bucket was collateral damage")
	}
}

func TestClearBucketRejectsMalformedBody(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))
	before := observedCellCount()

	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("this is not json")},
		{"empty body", nil},
		{"empty object", []byte(`{}`)},
		{"model without auth", []byte(`{"model":"gpt-5.5"}`)},
		{"auth without model", []byte(`{"auth_id":"codex-alpha.json"}`)},
		{"all and auth together", []byte(`{"all":true,"auth_id":"codex-alpha.json","model":"gpt-5.5"}`)},
		{"json array", []byte(`["codex-alpha.json"]`)},
		{"wrong types", []byte(`{"auth_id":42,"model":true}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagement(t, http.MethodPost, mgmtClearPath, tc.body)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("malformed body accepted: status %d, want 4xx", resp.StatusCode)
			}
		})
	}
	if observedCellCount() != before {
		t.Error("a rejected clear still modified the tally")
	}
}

// --- 4. selftest ---------------------------------------------------------
//
// This route used to be /probe and claimed to harvest. It cannot: a request
// issued through host.model.execute is marked to skip the calling plugin's own
// interceptors (host_callbacks_unix.go:43 -> host_callbacks.go:304 -> :306), so
// the response never reaches interceptResponse and nothing is ever stored. It
// is now a connectivity self-test, and the tests below encode that.

// The self-test says nothing about buckets, so it is not a probe-role
// operation. Refusing it under role: business would only stop an operator
// checking whether the business role can still reach upstream -- which is
// exactly when they most want to ask.
func TestSelftestWorksRegardlessOfRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(dir string) string
	}{
		{"probe", probeRoleConfig},
		{"business", func(dir string) string { return businessConfigWithModels(dir) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mustConfigure(t, tc.cfg(dir))

			resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})
			// Without a host API the call cannot succeed, so the assertion is
			// about *why* it failed: never because of the role.
			if resp.StatusCode == http.StatusConflict {
				t.Errorf("selftest refused with 409 under role %s: %s", tc.name, truncateMgmtLog(resp.Body))
			}
			if strings.Contains(strings.ToLower(string(resp.Body)), "role") {
				t.Errorf("selftest under role %s blamed the role: %s", tc.name, truncateMgmtLog(resp.Body))
			}
		})
	}
}

// The model must be one the operator configured. Firing at an arbitrary string
// would spend quota on a model nobody is tracking.
func TestSelftestRejectsUnconfiguredModel(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-4-turbo"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("selftest with an unconfigured model returned %d, want 400", resp.StatusCode)
	}
	// A configured one must get past this guard, or the assertion above would
	// hold for the wrong reason.
	next := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})
	if next.StatusCode == http.StatusBadRequest {
		t.Error("a configured model was also rejected as unconfigured")
	}
}

// Without a host API there is nothing to execute against. A self-test reports
// its finding in the body rather than as an HTTP error -- 200 means "the
// self-test ran", and `reached` carries the answer -- so what has to hold here
// is that it reports honestly: it did not reach, it harvested nothing, and it
// left the store alone. Claiming reached on a call that never left the process
// is the failure this guards against.
func TestSelftestFailsClosedWithoutHostAPI(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})

	// 503, and deliberately not 200 or a loose >= 400.
	//
	// This assertion was rewritten three times while the endpoint was being
	// built -- >= 400, then 200 with reached:false, then back to 503 -- so the
	// reasoning is recorded here rather than left to be re-derived. It is
	// settled: do not widen or relax it.
	//
	// Two failures look similar from the outside and are not:
	//
	//   no host callback table  -- the self-test never ran. The plugin did not
	//                              get its host interface, so nothing was
	//                              attempted. This says nothing whatsoever
	//                              about upstream.
	//   host present, no answer -- the self-test ran and the path is broken.
	//                              That is what reached:false means, and it is
	//                              reported with 200 because the self-test
	//                              itself succeeded in finding out.
	//
	// Reporting the first as 200 + reached:false sends an operator to check the
	// network, the credentials and the upstream, when the actual fault is that
	// the plugin was loaded wrong. That is an expensive detour, and it lands
	// hardest during a 3am incident -- which is exactly when someone reaches
	// for a self-test. 503 Service Unavailable is the accurate statement: this
	// service is unavailable, not the one behind it.
	//
	// The 503 body comes from managementError, which carries only `error`.
	// There is deliberately no `note`: note explains why a run that *did*
	// happen stored nothing, and no run happened here.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("selftest with no host API returned %d, want 503: %s", resp.StatusCode, truncateMgmtLog(resp.Body))
	}

	var result mgmtSelftestResult
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		t.Fatalf("decode selftest result: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	if result.Reached {
		t.Error("selftest claimed it reached upstream with no host API available")
	}
	if result.Harvested {
		t.Error("selftest claimed a harvest; it structurally cannot harvest")
	}
	if strings.TrimSpace(result.Error) == "" {
		t.Error("the 503 carries no explanation, leaving the operator with no reason")
	}
	if n := poolEntryCount(); n != 0 {
		t.Errorf("a failed selftest still pooled %d entries", n)
	}
}

func TestSelftestRejectsMalformedBody(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("nope")},
		{"empty body", nil},
		{"no model", []byte(`{}`)},
		{"empty model", []byte(`{"model":""}`)},
		{"wrong type", []byte(`{"model":42}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagement(t, http.MethodPost, mgmtSelftestPath, tc.body)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("malformed selftest body accepted: status %d, want 4xx", resp.StatusCode)
			}
		})
	}
}

// auth_id is caller-supplied and gets interpolated into an outbound request, so
// it goes through the same sanitiser as a store path. The cases mirror
// TestClearBucketRejectsPathTraversal: one rule for "is this identifier safe to
// pass on" rather than two that can drift apart.
//
// The ordering matters as much as the rejection. The sanitiser runs before the
// host-availability check, so a bad auth_id gets its own specific 400 instead
// of being masked by the 503 -- an operator who typo'd an account name is told
// that, not told the plugin is unloaded.
func TestSelftestRejectsUnsafeAuthID(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	cases := []struct {
		name   string
		authID string
	}{
		{"parent", ".."},
		{"nested parent", "../.."},
		{"slash", "codex/../.."},
		{"backslash", `..\..`},
		{"leading slash", "/etc/passwd"},
		{"embedded null", "codex\x00.json"},
	}
	// An all-whitespace auth_id is deliberately absent from that list. The
	// implementation trims before testing for emptiness, so "   " means "I did
	// not ask to target anything" -- identical to omitting the field -- rather
	// than an unsafe value. Rejecting it would make a blank form field an error
	// instead of a default.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{
				"model":   "gpt-5.5",
				"auth_id": tc.authID,
			})
			// 400 specifically, not merely "an error": a 503 here would mean
			// the unsafe value slipped past the sanitiser and was only stopped
			// by the missing host API, which would not stop it in production.
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("unsafe auth_id %q returned %d, want 400: %s",
					tc.authID, resp.StatusCode, truncateMgmtLog(resp.Body))
			}
		})
	}

	// A well-formed account name must get *past* the sanitiser, or every
	// assertion above would hold for the wrong reason. It stops at the 503
	// because this process has no host API -- which is the proof it got through.
	ok := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{
		"model":   "gpt-5.5",
		"auth_id": "codex-alpha.json",
	})
	if ok.StatusCode == http.StatusBadRequest {
		t.Errorf("a well-formed auth_id was rejected as unsafe: %s", truncateMgmtLog(ok.Body))
	}

	// Deliberately not tested: whether a *nonexistent* account is rejected.
	// The implementation passes an unknown id straight through and lets the
	// scheduler answer, rather than keeping a second view of the credential
	// list that could disagree with the real one. Asserting a 4xx here would
	// pin a contract that does not exist.
}

// managementFuncBody returns the source text of one top-level function in
// management.go. Used by the assertions below, which pin properties that cannot
// be reached behaviourally: the self-test bails at the host-availability check
// long before it builds a response, so anything downstream of that check is
// only observable in the source.
func managementFuncBody(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "func "+name+"(")
	if start < 0 {
		t.Fatalf("management.go has no func %s; the selftest contract requires it", name)
	}
	// Top-level functions close with a brace in column zero.
	end := strings.Index(text[start:], "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of func %s", name)
	}
	return text[start : start+end]
}

// auth_id must only ever be echoed from what the caller asked for.
//
// CPA reports no credential identity on the way back: HostModelExecutionResponse
// carries only StatusCode, Headers and Body, and a sweep of the CPA source found
// no auth-id response header of any name. This is settled, not merely
// unconfirmed -- there is nothing to look for. So any auth_id the plugin did
// not receive as input is fabricated -- and a fabricated account name in a
// self-test result is worse than an empty one, because an operator will act on
// it: check that account's quota, disable it, hand it to a colleague. The empty
// string is honest and `targeted` says why it is empty.
//
// Asserted at source level because the response is only built after the
// host-availability check, which a unit test cannot get past.
func TestSelftestAuthIDIsNeverFabricated(t *testing.T) {
	body := managementFuncBody(t, "runSelftest")

	assignments := 0
	for idx := 0; ; {
		at := strings.Index(body[idx:], "AuthID")
		if at < 0 {
			break
		}
		at += idx
		idx = at + len("AuthID")

		rest := strings.TrimLeft(body[idx:], " \t")
		var value string
		switch {
		case strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, ":="):
			value = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "="):
			value = strings.TrimLeft(rest[1:], " \t")
		default:
			continue
		}
		assignments++
		// authID is the sanitised value taken from the request body. Anything
		// else -- a header lookup, a helper that inspects the response -- is a
		// guess dressed up as an answer.
		if !strings.HasPrefix(value, "authID") {
			line := strings.Count(body[:at], "\n")
			t.Errorf("runSelftest assigns AuthID from %q (about %d lines into the function); "+
				"it must come from the caller-supplied authID, because CPA reports no credential on the response",
				truncateMgmtLog([]byte(value[:min(50, len(value))])), line)
		}
	}
	if assignments == 0 {
		t.Error("no assignment to AuthID found in runSelftest; this test would pass vacuously")
	}
}

// The echo must be verbatim and `targeted` must be derived from it.
//
// Nothing else covers this. If the echo ever crosses wires -- reporting the
// account the caller did not name -- a self-test run against a suspect account
// would come back describing a healthy different one, and the operator would
// clear the wrong credential. And if `targeted` were hard-coded or computed
// from something other than "was an auth_id supplied", an empty auth_id would
// stop being readable: the whole point of the flag is that auth_id:"" plus
// targeted:false means "we never asked", which is a different statement from
// anything the scheduler did.
//
// Source level for the same reason as the tests around it: the response is
// built after the host-availability check, which a unit test cannot pass.
func TestSelftestEchoesTargetingHonestly(t *testing.T) {
	body := managementFuncBody(t, "runSelftest")

	at := strings.Index(body, "selftestResponse{")
	if at < 0 {
		t.Fatal("runSelftest builds no selftestResponse; this test would pass vacuously")
	}
	end := strings.Index(body[at:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the selftestResponse literal")
	}
	literal := body[at : at+end]

	// The echo is the sanitised request value, unmodified.
	if !strings.Contains(literal, "AuthID:") {
		t.Error("the selftestResponse does not set AuthID, so the caller is never told which account was targeted")
	} else if !strings.Contains(literal, "AuthID:    authID") && !strings.Contains(literal, "AuthID: authID") {
		t.Errorf("AuthID is not echoed verbatim from the request; literal was:\n%s", literal)
	}

	// targeted must be "did the caller supply one", nothing else.
	if !strings.Contains(literal, `Targeted:  authID != ""`) && !strings.Contains(literal, `Targeted: authID != ""`) {
		t.Errorf(`Targeted is not derived from 'authID != ""'; it must say whether the caller asked, not anything about the outcome. Literal was:`+"\n%s", literal)
	}
}

// Targeting must actually be applied, not merely reported.
//
// targeted:true is a claim that this self-test exercised one specific
// credential. If auth_id is validated and echoed but never put on the outbound
// HostModelExecutionRequest, the scheduler picks whichever account it likes and
// the result describes a request that was never made. An operator testing a
// suspect account would read a clean result for a different one -- the exact
// wrong conclusion, delivered confidently.
//
// HostModelExecutionRequest.AuthID is documented as "optionally locks execution
// to an exact credential ID" and is passed through verbatim by the host
// (internal/pluginhost/host_callbacks.go:330), so setting it is all that is
// required.
func TestSelftestTargetingIsActuallyApplied(t *testing.T) {
	body := managementFuncBody(t, "runSelftest")

	at := strings.Index(body, "HostModelExecutionRequest{")
	if at < 0 {
		t.Fatal("runSelftest builds no HostModelExecutionRequest; this test would pass vacuously")
	}
	end := strings.Index(body[at:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the HostModelExecutionRequest literal")
	}
	literal := body[at : at+end]

	if !strings.Contains(literal, "AuthID:") {
		t.Error("the outbound HostModelExecutionRequest does not set AuthID, " +
			"so auth_id is validated and echoed but never applied: targeted:true would describe a request that was never targeted")
	}
}

// harvested must be a hard-coded false, never a computed value.
//
// The self-test genuinely cannot harvest -- the host marks its request to skip
// this plugin's own interceptors -- so any code that decides the field at
// runtime is expressing a belief that is false, and would eventually report a
// harvest that did not happen. An operator trusting that would then stop
// probing. Because the field can only be observed on a successful call, and a
// unit test has no host API to produce one, this is asserted at the source
// level: every assignment to Harvested must be the literal false.
func TestSelftestNeverClaimsHarvest(t *testing.T) {
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	text := string(src)

	const field = "Harvested"
	if !strings.Contains(text, field) {
		t.Fatalf("management.go has no %s field; the selftest contract requires one reported as false", field)
	}

	assignments := 0
	for idx := 0; ; {
		at := strings.Index(text[idx:], field)
		if at < 0 {
			break
		}
		at += idx
		idx = at + len(field)

		rest := strings.TrimLeft(text[idx:], " \t")
		// Struct-literal form "Harvested: <value>" and assignment form
		// "Harvested = <value>" are the two ways the value gets set. A field
		// declaration ("Harvested bool `json:...`") and prose in comments are
		// neither, and are skipped.
		var value string
		switch {
		case strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, ":="):
			value = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "="):
			value = strings.TrimLeft(rest[1:], " \t")
		default:
			continue
		}
		assignments++
		if !strings.HasPrefix(value, "false") {
			line := 1 + strings.Count(text[:at], "\n")
			t.Errorf("management.go:%d assigns %s a computed value (%q); it must be the literal false, because the selftest structurally cannot harvest",
				line, field, truncateMgmtLog([]byte(value[:min(40, len(value))])))
		}
	}
	if assignments == 0 {
		t.Error("no assignment to Harvested found; this test would pass vacuously")
	}
}

// --- 5. unknown paths and malformed input --------------------------------

func TestManagementUnknownPathReturns404(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	// "/v0/management/codex-turn-state" and "" are deliberately absent: the
	// implementation maps any path ending in the plugin id -- and the empty
	// path -- onto the data-free dashboard shell (isDashboardPath in
	// management.go), because the resource route arrives as the plugin root.
	// Serving the shell there is a choice, not a bug, and the shell carries no
	// data. These are the paths that must genuinely 404.
	for _, path := range []string{
		"/v0/management/codex-turn-state/nope",
		"/v0/management/other-plugin/status",
		"/v0/management/codex-turn-state/status/extra",
		"/v0/management/codex-turn-state/buckets",
	} {
		t.Run(path, func(t *testing.T) {
			resp := driveManagement(t, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("unknown path %q returned %d, want 404", path, resp.StatusCode)
			}
		})
	}
}

// A wrong method on a known path must not fall through to the handler.
func TestManagementRejectsWrongMethod(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))
	before := observedCellCount()

	cases := []struct{ method, path string }{
		{http.MethodPost, mgmtStatusPath},
		{http.MethodDelete, mgmtStatusPath},
		{http.MethodGet, mgmtClearPath},
		{http.MethodGet, mgmtSelftestPath},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := driveManagement(t, tc.method, tc.path, nil)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("%s %s returned %d, want 4xx", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
	if observedCellCount() != before {
		t.Error("a wrong-method call still modified the tally")
	}
}

// handleMethod must not panic on input the host would never send but an
// attacker on the management port could.
func TestManagementHandleSurvivesMalformedInput(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	for _, raw := range [][]byte{
		nil,
		[]byte(""),
		[]byte("{"),
		[]byte("[]"),
		[]byte(`{"Method":42}`),
		[]byte(`{"Path":null,"Method":null}`),
	} {
		// A panic here fails the test by unwinding; an error return is a
		// perfectly good outcome too. The only unacceptable result is a crash,
		// which would take the whole CPA process down with it.
		if _, err := handleMethod(pluginabi.MethodManagementHandle, raw); err != nil {
			t.Logf("management.handle rejected %q: %v", truncateMgmtLog(raw), err)
		}
	}
}

// --- 6. counters ---------------------------------------------------------

// Counters are process-global and every other test in this package also drives
// decisions, so the assertions compare deltas. Absolute values would make this
// test depend on execution order.
func TestManagementCountersTrackDecisions(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	resetHarvestState(t)

	issued := wallClock().Add(-time.Minute)
	seedPoolEntry(t, map[string]string{"__cflb": "cf", "__oailb": "lb"}, time.Now(), "")

	base := mustManagementStatus(t).Counters

	// Two attributable Codex requests: both steered -- the pool is global, so
	// the second account rides the same pair rather than passing.
	interceptAfter(t, request("codex-alpha.json", "gpt-5.5", fakeToken(312, issued)))
	interceptAfter(t, request("codex-beta.json", "gpt-5.6-sol", fakeToken(312, issued)))
	// No auth id: one skip.
	noAuth := request("", "gpt-5.5", fakeToken(312, issued))
	interceptAfter(t, noAuth)

	after := mustManagementStatus(t).Counters
	if got := after.Steer - base.Steer; got != 2 {
		t.Errorf("steer delta = %d, want 2", got)
	}
	if got := after.Skip - base.Skip; got != 1 {
		t.Errorf("skip delta = %d, want 1", got)
	}
}

// --- status content ------------------------------------------------------

func TestStatusReflectsConfiguredValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	status := mustManagementStatus(t)
	if status.Role != roleProbe {
		t.Errorf("role = %q, want %q", status.Role, roleProbe)
	}
	if !status.DryRun {
		t.Error("dry_run = false, want true")
	}
	if status.TTLSeconds != 3600 {
		t.Errorf("ttl_seconds = %d, want 3600", status.TTLSeconds)
	}
	if status.TemplateLength != 292 || status.ReplaceLength != 312 {
		t.Errorf("lengths = %d/%d, want 292/312", status.TemplateLength, status.ReplaceLength)
	}
	if len(status.Models) != 2 {
		t.Errorf("models = %v, want the 2 configured", status.Models)
	}
}

// The per-bucket len reports the *length* of the stored value, never the value.
// A length is a safe thing to publish -- it is the whole tell this plugin keys
// on, 292 against 312 -- but a field sitting right next to the token is exactly
// where one gets pasted by accident, so this asserts both halves: the number is
// a plausible length, and the document still carries no token.
func TestStatusBucketLenIsALengthNotAValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	secret := seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)

	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), secret[:40]) {
		t.Fatal("status leaked the token value alongside its length")
	}

	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	stored, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5")
	if !ok {
		t.Fatal("the seeded bucket is missing from status")
	}
	if stored.Len != 292 {
		t.Errorf("len = %d for a stored 292-character template, want 292", stored.Len)
	}
	// A bucket that was never harvested has no value and so no length.
	missing, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.6-sol")
	if !ok {
		t.Fatal("the unharvested target bucket is missing from status")
	}
	if missing.Len != 0 {
		t.Errorf("len = %d for a bucket that was never harvested, want 0", missing.Len)
	}
}

// --- 6b. upstream error classification -----------------------------------
//
// reached is decided in three tiers, and the whole point is to stop a working
// path being reported as a broken one:
//
//	1. an upstream error body parses   -> reached, because only the upstream
//	                                      produces that schema
//	2. "failed with status N" is found -> reached, with the code
//	3. neither                         -> a genuine transport failure
//
// handleSelftest bails at the host-availability check long before it gets here,
// so these exercise the two classifiers directly. They are unexported but in
// this package, so no seam is needed.

// The messages below were captured from the real deployment, not invented.
// Keeping the exact strings matters: the classifier is parsing someone else's
// output, and a plausible-looking paraphrase would test a format nobody sends.
const (
	// Observed verbatim on OVH.
	msgOverloaded = `host_call_failed: {"error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later.","param":null},"sequence_number":2}`
	// Observed on OVH; the message text was truncated in capture, so it is
	// completed here. The error fields -- the only part the classifier reads --
	// are as recorded.
	msgServerError = `host_call_failed: {"error":{"type":"server_error","code":"server_error","message":"An error occurred while processing your request.","param":null},"sequence_number":1}`
)

func TestUpstreamErrorClassification(t *testing.T) {
	cases := []struct {
		name       string
		message    string
		wantBody   bool
		wantCode   string
		wantType   string
		wantStatus int  // 0 when no status should be recovered
		wantOKStat bool //nolint:revive // mirrors the classifier's second return
	}{
		{
			// The case this whole tier exists for. server_is_overloaded is the
			// same signal as a 312 degraded state (FINDINGS.md): recovering the
			// code is what tells an operator to wait rather than to go hunting
			// for a broken link. Reported as reached=false, it sent people to
			// check the network while the real answer was "it is overloaded".
			name:     "overloaded, no status",
			message:  msgOverloaded,
			wantBody: true,
			wantCode: "server_is_overloaded",
			wantType: "service_unavailable_error",
		},
		{
			name:     "server_error, no status",
			message:  msgServerError,
			wantBody: true,
			wantCode: "server_error",
			wantType: "server_error",
		},
		{
			name:       "body and status together",
			message:    `host_call_failed: {"error":{"type":"rate_limit_error","code":"rate_limit_exceeded","message":"slow down"}} failed with status 429`,
			wantBody:   true,
			wantCode:   "rate_limit_exceeded",
			wantType:   "rate_limit_error",
			wantStatus: 429,
			wantOKStat: true,
		},
		{
			name:       "status only, no body",
			message:    "host_call_failed: request failed with status 502",
			wantBody:   false,
			wantStatus: 502,
			wantOKStat: true,
		},
		{
			// Tier 3: nothing recoverable, so reached=false is the honest answer.
			name:    "transport failure",
			message: "host_call_failed: dial tcp 127.0.0.1:8317: connect: connection refused",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, okBody := upstreamErrorFrom(tc.message)
			if okBody != tc.wantBody {
				t.Fatalf("upstreamErrorFrom ok = %t, want %t", okBody, tc.wantBody)
			}
			if okBody {
				if got := strings.TrimSpace(body.Error.Code); got != tc.wantCode {
					t.Errorf("upstream_error_code = %q, want %q", got, tc.wantCode)
				}
				if got := strings.TrimSpace(body.Error.Type); got != tc.wantType {
					t.Errorf("upstream_error_type = %q, want %q", got, tc.wantType)
				}
			}

			status, okStatus := statusFromExecutionError(tc.message)
			if okStatus != tc.wantOKStat {
				t.Fatalf("statusFromExecutionError ok = %t, want %t", okStatus, tc.wantOKStat)
			}
			if okStatus && status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}

			// The tier rule: either signal means the request arrived.
			if reached := okBody || okStatus; reached != (tc.wantBody || tc.wantOKStat) {
				t.Errorf("reached would be %t, want %t", reached, tc.wantBody || tc.wantOKStat)
			}
		})
	}
}

// An unrelated JSON object appearing in a message is not the upstream
// answering. Treating it as one would flip reached to true on a pure transport
// failure -- the opposite of the bug this tier was added to fix, and harder to
// spot because it reports success.
func TestUpstreamErrorFromRejectsUnrelatedJSON(t *testing.T) {
	for _, message := range []string{
		`host_call_failed: {"foo":"bar"}`,
		`host_call_failed: {}`,
		`host_call_failed: {"error":{}}`,
		`host_call_failed: {"error":{"type":"","code":"","message":""}}`,
		`host_call_failed: not json at all`,
		`host_call_failed: {"sequence_number":2}`,
	} {
		t.Run(message, func(t *testing.T) {
			if _, ok := upstreamErrorFrom(message); ok {
				t.Error("an unrelated JSON object was accepted as an upstream error body")
			}
		})
	}
}

// The status marker is the complete phrase "failed with status ", not a bare
// "status ". Upstream messages are now embedded in the same string, and they
// contain prose: "check status page" would otherwise be mined for an HTTP code.
// Loosening this match reintroduces that silently, so it is pinned here.
func TestStatusFromExecutionErrorRequiresTheFullPhrase(t *testing.T) {
	rejected := []string{
		// The discriminating case: a digit follows "status " inside upstream
		// prose, so a matcher keyed on the bare word would mine 503 out of a
		// sentence and report it as the HTTP result. Only the full phrase
		// rejects this. If this case is ever softened, the loose matcher passes
		// again and the misreading returns unannounced.
		`host_call_failed: {"error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Overloaded -- check status 503 page for updates."}}`,
		"host_call_failed: status 429",
		"host_call_failed: http status 500",
		"host_call_failed: failed with status",
		"host_call_failed: failed with status abc",
		// Outside the plausible HTTP range: a number that is not a status code.
		"host_call_failed: failed with status 42",
		"host_call_failed: failed with status 900",
	}
	for _, message := range rejected {
		t.Run(message, func(t *testing.T) {
			if status, ok := statusFromExecutionError(message); ok {
				t.Errorf("recovered status %d from a message that carries none", status)
			}
		})
	}

	// Reverse control: the real phrasing must still be recognised, or every
	// assertion above would hold for the wrong reason.
	accepted := map[string]int{
		"host_call_failed: request failed with status 429": 429,
		"host_call_failed: request failed with status 500": 500,
		"host_call_failed: request failed with status 100": 100,
		"host_call_failed: request failed with status 599": 599,
	}
	for message, want := range accepted {
		t.Run(message, func(t *testing.T) {
			status, ok := statusFromExecutionError(message)
			if !ok {
				t.Fatalf("the documented phrasing was not recognised")
			}
			if status != want {
				t.Errorf("status = %d, want %d", status, want)
			}
		})
	}
}

// The two upstream fields carry no omitempty, so the response shape is constant
// whether or not a code was recovered. A field that vanishes when empty makes a
// dashboard read "undefined" rather than "no code", and makes a missing field
// indistinguishable from a field that was never implemented.
func TestSelftestUpstreamFieldsHaveNoOmitempty(t *testing.T) {
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	for _, field := range []string{"upstream_error_code", "upstream_error_type"} {
		tag := `json:"` + field + `"`
		if !strings.Contains(string(src), tag) {
			t.Errorf("%s is not declared with a bare %s tag; an omitempty here would make the response shape vary", field, tag)
		}
	}
}

// --- 6c. 312 degraded state is attributed but never stored ---------------
//
// A 312 is the throttled/degraded state, not a template (FINDINGS.md): it is
// what the upstream issues under load, the same signal as server_is_overloaded.
// The harvest path runs attribution over it anyway -- only so the log can name
// *which* account is throttled, "account X is degraded" rather than "auth=-" --
// but it must never reach the store. Storing a 312 and later injecting it would
// replay a degraded token, which the upstream rejects as
// "could not be decrypted". This is the store's half of that rule; the
// classifier's half is tested in the upstream-error section above.

// harvestResponseHeaders builds the response headers a probe would see, with the
// turn-state value the caller wants attributed.
func harvestResponseHeaders(value string) http.Header {
	h := http.Header{}
	h.Set(testHeader, value)
	return h
}

// resetHarvestState clears the in-memory bucket cache and the route-cookie
// pool. harvestFromResponse short-circuits a repeat write when the cache
// already holds the same value for a key (Codex mints a fresh token per turn,
// so an identical one means a replay), and both caches are process-global and
// not reset between tests. A test that drives the harvest path must start from
// a clean slate or a prior test's entry could suppress the write under
// examination -- or lend its cookies to an account they do not belong to.
func resetHarvestState(t *testing.T) {
	t.Helper()
	state.mu.Lock()
	state.cookies = make(map[string]*routeCookieEntry)
	state.cookiesDirty = false
	state.mu.Unlock()
	t.Cleanup(func() {
		state.mu.Lock()
		state.cookies = make(map[string]*routeCookieEntry)
		state.cookiesDirty = false
		state.mu.Unlock()
	})
}

// --- 6d. sole-account attribution: the cross-account firewall ------------
//
// When a request or response carries no selected_auth_id, the plugin may infer
// the account from the spec §7 invariant that a probe enables exactly one Codex
// account at a time. That inference is the single most dangerous line in the
// codebase: infer wrong and account A's template is written under, or injected
// into, account B -- a direct breach of §0 rule 1 (a state is never shared
// across accounts). The tests here exist to make that failure impossible to
// introduce silently. The `count != 1` refusal in soleEnabledCodexAuth is the
// firewall; the 2+ cases below are the ones that must never regress.
//
// codexAuthLister is a package-level seam (management.go). Every test that
// swaps it MUST restore it and drop the cache, or the fake account list leaks
// into every later test. resetAuthCache() is required after each swap because
// the lookup sits behind a 2-second cache.

// withAuthList installs a fake credential list for the duration of one test and
// guarantees restoration. Centralising the swap/restore means no individual
// test can forget the defer -- the failure mode the coordinator flagged.
func withAuthList(t *testing.T, accounts []codexAuth, err error) {
	t.Helper()
	codexAuthLister = func() ([]codexAuth, error) {
		return accounts, err
	}
	resetAuthCache()
	t.Cleanup(func() {
		codexAuthLister = listCodexAuths
		resetAuthCache()
	})
}

func enabledAccounts(names ...string) []codexAuth {
	out := make([]codexAuth, len(names))
	for i, name := range names {
		out[i] = codexAuth{AuthID: name, Enabled: true}
	}
	return out
}

// harvestNoAuthMeta is the metadata a minimal probe request carries: none. The
// account is absent, which is exactly what forces the inference path.
var harvestNoAuthMeta = map[string]any{}

// --- 7. the readiness matrix --------------------------------------------

// Degradation must be visible. A unit test has no host API, so host.auth.list
// always fails here and the account list falls back to whatever the store
// happens to hold -- which is precisely the state where the page is most
// misleading if it says nothing: a never-probed account is invisible, so an
// empty or short matrix reads as "there is nothing to probe" when it means "we
// could not ask what there is".
//
// Silent degradation has been the recurring failure on this surface, so this
// asserts both halves: the source is named, and the reason is carried.
func TestStatusReportsDegradedAccountSource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	status := mustManagementStatus(t)
	if status.AccountsSource != "store" {
		t.Errorf("accounts_source = %q with no host API, want %q", status.AccountsSource, "store")
	}
	if strings.TrimSpace(status.AccountsError) == "" {
		t.Error("accounts_error is empty on the degraded path, so the fallback is silent")
	}
}

// The matrix is the set of buckets we intend to fill, not the set already
// filled. Straight after a deploy nothing is harvested, and that is exactly
// when an operator needs to see "0 of N" and pick something to act on.
func TestStatusMatrixCoversEveryTarget(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol"))

	issued := wallClock().Add(-time.Minute)
	// Two accounts become visible through the store (the degraded path derives
	// them from records), crossed with two configured models: a 2x2 matrix of
	// which only three cells are filled.
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued)

	status := mustManagementStatus(t)
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
	if status.TargetsTotal != 4 {
		t.Errorf("targets_total = %d for 2 accounts x 2 models, want 4", status.TargetsTotal)
	}

	// The unharvested cell must be present and honest about being empty.
	gap, ok := mgmtBucketByKey(status, "codex-beta.json", "gpt-5.6-sol")
	if !ok {
		t.Fatal("the never-harvested combination is missing from the matrix; the page would not show it as a gap")
	}
	if gap.Ready {
		t.Error("a never-harvested cell reports ready")
	}
	if gap.Len != 0 {
		t.Errorf("a never-harvested cell reports len = %d, want 0", gap.Len)
	}
	if gap.IssuedAt != "" || gap.ExpiresAt != "" {
		t.Errorf("a never-harvested cell carries timestamps: issued=%q expires=%q", gap.IssuedAt, gap.ExpiresAt)
	}
	if gap.SecondsLeft != 0 {
		t.Errorf("a never-harvested cell reports seconds_left = %d, want 0", gap.SecondsLeft)
	}

	// Reverse control: widen the model list and the matrix must widen with it.
	// Without this, an implementation that just listed on-disk records would
	// satisfy every assertion above.
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol", "gpt-6-astra"))
	wider := mustManagementStatus(t)
	if wider.TargetsTotal != 6 {
		t.Errorf("targets_total = %d after adding a third model to 2 accounts, want 6", wider.TargetsTotal)
	}
}

// The page re-fetches on a timer. Unstable ordering would make rows and columns
// jump under the operator's cursor mid-read.
func TestStatusBucketOrderIsStable(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.6-sol", "gpt-5.5"))

	issued := wallClock().Add(-time.Minute)
	// Seeded out of order on purpose, so a pass-through of map or disk order
	// would not accidentally come out sorted.
	seedMgmtBucket(t, dir, "codex-zulu.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-mike.json", "gpt-5.6-sol", issued)

	first := mustManagementStatus(t)
	second := mustManagementStatus(t)

	if len(first.Buckets) != len(second.Buckets) {
		t.Fatalf("two consecutive calls returned %d and %d buckets", len(first.Buckets), len(second.Buckets))
	}
	for i := range first.Buckets {
		if first.Buckets[i].AuthID != second.Buckets[i].AuthID || first.Buckets[i].Model != second.Buckets[i].Model {
			t.Fatalf("order changed between calls at index %d: %s/%s then %s/%s",
				i, first.Buckets[i].AuthID, first.Buckets[i].Model,
				second.Buckets[i].AuthID, second.Buckets[i].Model)
		}
	}
	// Stable is not enough on its own -- a consistently wrong order is stable
	// too. The contract is (auth_id, model) lexicographic.
	for i := 1; i < len(first.Buckets); i++ {
		prev, cur := first.Buckets[i-1], first.Buckets[i]
		if prev.AuthID > cur.AuthID || (prev.AuthID == cur.AuthID && prev.Model > cur.Model) {
			t.Errorf("buckets are not sorted by (auth_id, model): %s/%s precedes %s/%s",
				prev.AuthID, prev.Model, cur.AuthID, cur.Model)
		}
	}
}

// An empty store must not produce a bare empty array with no explanation. On
// the degraded path there is genuinely nothing to list -- the accounts can only
// come from records that do not exist -- so the empty matrix is correct, but it
// has to arrive labelled. "We could not ask" and "there is nothing to probe"
// render identically otherwise, and this is the defect that motivated the
// accounts_source field.
func TestStatusEmptyStoreStillNamesItsSource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	status := mustManagementStatus(t)
	if status.AccountsSource != "store" {
		t.Errorf("accounts_source = %q, want %q", status.AccountsSource, "store")
	}
	if strings.TrimSpace(status.AccountsError) == "" {
		t.Error("an empty matrix arrived with no accounts_error, so it reads as 'nothing to probe'")
	}
	if status.TargetsReady != 0 {
		t.Errorf("targets_ready = %d on an empty store, want 0", status.TargetsReady)
	}
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
}

// --- 9. the probe scope's secrets, and the one that stopped being one -----
//
// Three values live in the probe scope that nothing else does: the proxy list,
// which is now published in the clear on purpose, and the two bearers the probe
// runner uses, which are published nowhere at all. Both halves are pinned below,
// because they are easy to confuse and the second is what makes the first
// survivable.

const (
	// Distinctive on purpose: the assertions below check these strings appear
	// nowhere, so they must not collide with anything a formatter might emit.
	testProbeManagementKey = "mk-probe-management-never-show-me"
)

// probeConfigWithSecrets is probeRoleConfig plus every secret-bearing probe
// field: a proxy carrying a password (testProxyWithPW, probe_scope_test.go) and
// the bearer. One fixture drives both halves of the contract -- the proxy list
// rendered verbatim, the key rendered nowhere.
func probeConfigWithSecrets(dir string) string {
	return probeRoleConfig(dir) + fmt.Sprintf(`probe_accounts:
  - codex-a.json
probe_proxies:
  - %s
probe_management_key: %s
`, testProxyWithPW, testProbeManagementKey)
}

// The proxy list is served in the clear, which is a deliberate reversal of what
// this document used to do. The masked field made the editor write-only: a
// textarea seeded with "socks5h://***@exit:1080" can only be saved by retyping
// every entry, so every scope edit cost the whole proxy list. The operator
// instructed that it show the real values.
//
// What this pins is the reversal itself, so a later "surely this should be
// masked" tidy-up breaks loudly rather than quietly restoring the unusable
// editor. Masking everywhere else is covered by probe_scope_test.go and by
// TestProbeKeysAreNeverDisplayedOrLogged below.
func TestStatusShowsProbeProxiesInTheClear(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeConfigWithSecrets(dir))

	status := mustManagementStatus(t)
	if status.ProbeProxyCount != 1 {
		t.Fatalf("probe_proxy_count = %d, want 1; the count stays alongside the list", status.ProbeProxyCount)
	}
	if len(status.ProbeProxies) != 1 || status.ProbeProxies[0] != testProxyWithPW {
		t.Fatalf("probe_proxies = %v, want the configured entry verbatim", status.ProbeProxies)
	}

	// The anonymous resource path serves the same document, and it is the route
	// that actually publishes this. Asserting only the keyed path would miss the
	// half that matters.
	resp := driveManagement(t, http.MethodGet, mgmtResourcePath+"status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous status returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var anonymous mgmtStatus
	if err := json.Unmarshal(resp.Body, &anonymous); err != nil {
		t.Fatalf("decode anonymous status: %v", err)
	}
	if len(anonymous.ProbeProxies) != 1 || anonymous.ProbeProxies[0] != testProxyWithPW {
		t.Fatalf("anonymous probe_proxies = %v, want the same verbatim entry", anonymous.ProbeProxies)
	}

	// The field that was replaced must be gone rather than kept alongside: a
	// page reading the old name would show masks while the real values sat in
	// the same document, which is the worst of both.
	if strings.Contains(string(resp.Body), "probe_proxies_masked") {
		t.Error("status still carries probe_proxies_masked; the masked field was replaced, not supplemented")
	}
}

// The two probe keys exist so the dashboard can start a run without anyone
// typing a key. That only holds up if the keys themselves never come back out:
// the status document is anonymously readable, and a configure log line gets
// copied into tickets. Neither may carry one in any form -- there is no masked
// rendering of these, because no caller has any business seeing one.
func TestProbeKeysAreNeverDisplayedOrLogged(t *testing.T) {
	dir := t.TempDir()

	// configure is the only place the keys are read, so its log line is the one
	// that could leak them.
	logged := captureLog(t, func() { mustConfigure(t, probeConfigWithSecrets(dir)) })
	if strings.TrimSpace(logged) == "" {
		t.Fatal("configure logged nothing; the leak assertions below would prove nothing")
	}
	for _, secret := range []string{testProbeManagementKey} {
		if strings.Contains(logged, secret) {
			t.Error("the configure log line carried a probe key verbatim")
		}
	}
	// Presence, and only presence. "Is it configured at all" is the one question
	// an operator answers from a log; anything more is a hint.
	for _, want := range []string{"probe_management_key=set"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the configure log line does not report %q, so a missing key would be invisible: %s", want, logged)
		}
	}

	// Every place the configuration is rendered: both status routes, and the
	// keyed config route, which returns the configuration verbatim and is the
	// one most likely to grow a field by accident.
	for name, path := range map[string]string{
		"management status": mgmtStatusPath,
		"anonymous status":  mgmtResourcePath + "status",
		"config":            mgmtConfigPath,
	} {
		resp := driveManagement(t, http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d, want 200 (body: %s)", name, resp.StatusCode, truncateMgmtLog(resp.Body))
		}
		if len(resp.Body) == 0 {
			t.Fatalf("%s body is empty; the assertions below would prove nothing", name)
		}
		body := string(resp.Body)
		for _, secret := range []string{testProbeManagementKey} {
			if strings.Contains(body, secret) {
				t.Errorf("%s leaked a probe key", name)
			}
		}
		// The field name matters as much as the value. A key rendered as "" or
		// as "***" reads as "nothing configured" while the plugin is in fact
		// holding one, and it invites the next person to fill the field in for
		// real.
		for _, field := range []string{"probe_management_key"} {
			if strings.Contains(body, field) {
				t.Errorf("%s carries a %q field; these are never displayed, not even empty or masked", name, field)
			}
		}
	}
}

// The probe runner's two controls are keyless by choice -- the whole point of
// the button is that nobody types a key to press it -- so they must be
// resources. Being GETs that spend quota and stop a run in flight, they must
// also refuse to fire without confirm=1, or a bare navigation or a link prefetch
// could do either.
func TestProbeRunRoutesAreKeylessResourcesGuardedByConfirm(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeConfigWithSecrets(dir))

	reg := driveManagementRegister(t)
	if len(reg.Resources) == 0 {
		t.Fatal("no resources declared; this test would pass vacuously")
	}
	resources := make(map[string]mgmtRoute, len(reg.Resources))
	for _, res := range reg.Resources {
		resources[res.Path] = res
	}
	managementRoutes := make(map[string]bool, len(reg.Routes))
	for _, route := range reg.Routes {
		managementRoutes[route.Path] = true
	}

	for _, path := range []string{"/ops/probe/start", "/ops/probe/cancel"} {
		res, ok := resources[path]
		if !ok {
			t.Errorf("%s is not registered as a resource, so it would demand a management key the dashboard does not have", path)
			continue
		}
		// A Menu on a GET route is what demotes one to the resource prefix by
		// accident. These belong there on purpose, and a Menu would also
		// misrepresent them as pages to navigate to.
		if strings.TrimSpace(res.Menu) != "" {
			t.Errorf("%s declares Menu %q; it is fetched by the page, not navigated to", path, res.Menu)
		}
		if managementRoutes[path] {
			t.Errorf("%s is also a management route; a keyless action must live only on the unauthenticated prefix", path)
		}
	}

	// Asserted again here, beside the routes being added: adding a route is
	// exactly when the config route gets copied into the resource list by
	// mistake, and that response returns the configuration verbatim.
	for _, res := range reg.Resources {
		if strings.HasSuffix(res.Path, "/config") {
			t.Errorf("config route %q is registered as a resource; it must stay behind the management key", res.Path)
		}
	}

	for _, path := range []string{opsProbeStartPath, opsProbeCancelPath} {
		resp := driveResource(t, path, url.Values{})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s without confirm=1 returned %d, want 400 (body: %s)", path, resp.StatusCode, truncateMgmtLog(resp.Body))
		}
	}
	// And nothing started. A refused request that still kicked off a run would
	// be the exact failure confirm=1 exists to prevent.
	if snapshot := probeRunSnapshot(); snapshot.Running {
		t.Error("a probe run is in flight after two requests that were refused for lack of confirm=1")
	}
}

// --- /ops/choices --------------------------------------------------------
//
// The scope editor's menu replaces three hand-typed lists with checkboxes, so
// the properties worth pinning are the ones that decide whether the operator can
// trust what they tick:
//
//   - it answers with no key and no confirm, or the page renders empty boxes;
//   - `selected` mirrors the saved scope, or a save silently drops whatever the
//     page failed to re-tick;
//   - `label` never carries the customer's email, because this route is
//     anonymously readable;
//   - a credential list that cannot be fetched still renders, with the reason.

// choicesCPAFile is one entry of the auth-files listing the fake publishes.
// Fields are a map rather than a struct so a case can publish a document with
// the wrong shape if it ever needs to.
type choicesCPAFile map[string]any

// choicesCPA stands in for CPA's GET /v0/management/auth-files, the only call
// /ops/choices makes.
//
// Local to this file rather than probe_runner_test.go's fakeCPA, which stamps
// provider "codex" on every entry it publishes: two of the cases below turn on
// entries the filter must reject, and one of those is a non-Codex provider.
type choicesCPA struct {
	server *httptest.Server

	// Everything below is read by the server goroutine and written by the test
	// goroutine, so it all lives under one mutex rather than relying on the
	// happens-before edge a request round trip happens to provide.
	mu sync.Mutex
	// status is what the listing answers with. 401 is a case, not a malfunction:
	// it is what a stale probe_management_key produces in production.
	status int
	files  []choicesCPAFile
	// hold blocks the handler until the test closes it, standing in for a CPA
	// that has accepted the connection and stopped answering.
	hold chan struct{}
	// authSeen records the Authorization headers received, so a test can assert
	// the route really presents the configured key rather than having reached an
	// unauthenticated listing by accident.
	authSeen []string
}

func newChoicesCPA(t *testing.T, files ...choicesCPAFile) *choicesCPA {
	t.Helper()
	fake := &choicesCPA{status: http.StatusOK, files: files}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		hold, status, files := fake.hold, fake.status, fake.files
		fake.authSeen = append(fake.authSeen, r.Header.Get("Authorization"))
		fake.mu.Unlock()

		// Outside the lock: a stalled handler holding it would block every other
		// request instead of just this one.
		if hold != nil {
			<-hold
		}
		if r.URL.Path != probeRouteAuthFiles {
			http.Error(w, `{"error":"no such route"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			// Shaped like CPA's own refusal, body and all: a response body is one
			// of the things that could carry something quotable into the error
			// string the page renders.
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// refuse makes the listing answer with status and an error body.
func (f *choicesCPA) refuse(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

// stall makes every request block until the test ends, so the plugin's own
// timeout is the only thing that can end the call.
func (f *choicesCPA) stall(t *testing.T) {
	t.Helper()
	gate := make(chan struct{})
	f.mu.Lock()
	f.hold = gate
	f.mu.Unlock()
	t.Cleanup(func() { close(gate) })
}

func (f *choicesCPA) authHeaders() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.authSeen...)
}

// The credentials the fake publishes. Spelled in the production shape --
// codex-<hex>-<email>-<tier>.json -- because the masking under test is defined
// against exactly that shape. The addresses are at example.com, which RFC 2606
// reserves, so nothing here is a real customer.
const (
	choicesAuthPro  = "codex-620f5a42-luo.swmu@example.com-pro.json"
	choicesAuthPlus = "codex-aa11bb22-someone@example.com-plus.json"
	// A backup copy, which must never become a checkbox: ticking one would put an
	// operator's backup into a sweep that enables credentials.
	choicesAuthBak = "codex-620f5a42-luo.swmu@example.com-pro.json.bak"
	// Not a Codex credential at all. CPA holds these alongside; probing one would
	// spend a request on a provider this plugin knows nothing about.
	choicesAuthOther = "gemini-someone@example.com.json"
)

// choicesConfig is a probe-role config pointed at a fake CPA. Written here
// rather than reusing probeTestConfig so these cases do not move when the
// runner's fixtures do.
func choicesConfig(dir, baseURL, mgmtKey string, accounts, models []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "role: probe\nstore_dir: %q\nlog_decisions: false\ndry_run: true\n", dir)
	fmt.Fprintf(&b, "probe_base_url: %q\n", baseURL)
	fmt.Fprintf(&b, "probe_management_key: %q\n", mgmtKey)
	for _, block := range []struct {
		key    string
		values []string
	}{{"probe_accounts", accounts}, {"models", models}} {
		if len(block.values) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s:\n", block.key)
		for _, value := range block.values {
			fmt.Fprintf(&b, "  - %q\n", value)
		}
	}
	return b.String()
}

type mgmtChoiceAccount struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Disabled bool   `json:"disabled"`
	Selected bool   `json:"selected"`
}

type mgmtChoiceModel struct {
	Name     string `json:"name"`
	Selected bool   `json:"selected"`
}

// mgmtChoices mirrors the wire shape the dashboard decodes. Error is spelled
// without omitempty on the production side; decoding it here as a plain string
// is what would break if that changed to a pointer or vanished when empty.
type mgmtChoices struct {
	Accounts []mgmtChoiceAccount `json:"accounts"`
	Models   []mgmtChoiceModel   `json:"models"`
	Error    string              `json:"error"`
}

// mustChoices fetches /ops/choices exactly as the dashboard does: a bare GET on
// the unauthenticated prefix, no key, no confirm, no parameters.
func mustChoices(t *testing.T) (mgmtChoices, mgmtResponse) {
	t.Helper()
	resp := driveResource(t, opsChoicesPath, url.Values{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d, want 200 (body: %s)", opsChoicesPath, resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var out mgmtChoices
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("decode choices: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	return out, resp
}

func choiceAccountByName(choices mgmtChoices, name string) (mgmtChoiceAccount, bool) {
	for _, account := range choices.Accounts {
		if account.Name == name {
			return account, true
		}
	}
	return mgmtChoiceAccount{}, false
}

// The route is keyless like the rest of /ops, and -- unlike the rest of /ops --
// takes no confirm=1. Both halves matter: a key would leave the dashboard, which
// holds none, with empty checkboxes, and a confirm requirement would do the same,
// because the page fetches this on load before there is anything to confirm.
func TestChoicesIsAKeylessResourceNeedingNoConfirm(t *testing.T) {
	dir := t.TempDir()
	fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
	mustConfigure(t, choicesConfig(dir, fake.server.URL, "mk-choices", nil, []string{"gpt-5.5"}))

	reg := driveManagementRegister(t)
	if len(reg.Resources) == 0 {
		t.Fatal("no resources declared; this test would pass vacuously")
	}
	var declared *mgmtRoute
	for index, res := range reg.Resources {
		if res.Path == "/ops/choices" {
			declared = &reg.Resources[index]
		}
	}
	if declared == nil {
		t.Fatal("/ops/choices is not registered as a resource, so it would demand a management key the dashboard does not have")
	}
	// A Menu on a GET route is the documented way one gets silently re-registered
	// under the resource prefix. This one belongs there on purpose, and a Menu
	// would also misrepresent a fetched document as a page to navigate to.
	if strings.TrimSpace(declared.Menu) != "" {
		t.Errorf("/ops/choices declares Menu %q; it is fetched by the page, not navigated to", declared.Menu)
	}
	for _, route := range reg.Routes {
		if route.Path == "/ops/choices" {
			t.Error("/ops/choices is also a management route; a keyless route must live only on the unauthenticated prefix")
		}
	}

	// The fetch itself: no key, no confirm, and a body that decodes.
	choices, _ := mustChoices(t)
	if len(choices.Models) == 0 {
		t.Error("choices returned no models on a keyless fetch; the checkboxes would render empty")
	}
}

// The listing is CPA's, filtered to Codex credentials, with the saved scope
// already ticked. Each assertion below stands for one way the editor would
// mislead: an unfiltered list offers a checkbox that cannot be probed, and a
// missing `selected` makes the next save drop whatever the operator did not
// re-tick from memory.
func TestChoicesListsCPACredentialsAndMarksTheScope(t *testing.T) {
	dir := t.TempDir()
	const mgmtKey = "mk-choices-never-show-me"
	fake := newChoicesCPA(t,
		// Out of order on purpose: the page must not reshuffle between refreshes.
		choicesCPAFile{"name": choicesAuthPlus, "provider": "codex", "disabled": true},
		choicesCPAFile{"name": choicesAuthPro, "provider": "codex", "disabled": false},
		choicesCPAFile{"name": choicesAuthBak, "provider": "codex"},
		choicesCPAFile{"name": choicesAuthOther, "provider": "gemini"},
	)
	mustConfigure(t, choicesConfig(dir, fake.server.URL, mgmtKey,
		[]string{choicesAuthPro},
		// One known model and one the fallback menu has never heard of, so the
		// union is exercised in both directions at once.
		[]string{"gpt-5.5", "gpt-local-only"}))

	choices, resp := mustChoices(t)
	if choices.Error != "" {
		t.Fatalf("choices reported an error against a healthy CPA: %q", choices.Error)
	}

	// --- accounts ---
	gotNames := make([]string, 0, len(choices.Accounts))
	for _, account := range choices.Accounts {
		gotNames = append(gotNames, account.Name)
	}
	// Sorted by name -- which puts the "620f..." credential ahead of the
	// "aa11..." one the fake published first -- and neither the .bak copy nor the
	// non-Codex credential is present.
	wantNames := []string{choicesAuthPro, choicesAuthPlus}
	if len(gotNames) != len(wantNames) {
		t.Fatalf("accounts = %v, want exactly %v (a .bak copy or a non-Codex credential leaked into the menu)", gotNames, wantNames)
	}
	for index, want := range wantNames {
		if gotNames[index] != want {
			t.Fatalf("accounts = %v, want %v in that order", gotNames, wantNames)
		}
	}

	selected, _ := choiceAccountByName(choices, choicesAuthPro)
	if !selected.Selected {
		t.Error("the account in probe_accounts came back unselected; the page would render the saved scope as empty")
	}
	if selected.Disabled {
		t.Error("an enabled credential came back disabled")
	}
	unselected, _ := choiceAccountByName(choices, choicesAuthPlus)
	if unselected.Selected {
		t.Error("an account that is not in probe_accounts came back selected; ticking it was nobody's decision")
	}
	// CPA's own flag, passed through rather than used as a filter: a disabled
	// credential is still a legitimate target, and hiding it would look like the
	// account had been deleted.
	if !unselected.Disabled {
		t.Error("a credential CPA reports as disabled came back enabled")
	}

	// --- models ---
	wantModels := []struct {
		name     string
		selected bool
	}{
		{"gpt-5.5", true},        // configured and in the fallback menu
		{"gpt-5.6-sol", false},   // menu only
		{"gpt-6-astra", false},   // menu only
		{"gpt-local-only", true}, // configured by hand, unknown to the menu
	}
	if len(choices.Models) != len(wantModels) {
		t.Fatalf("models = %+v, want %d entries (the union of the configured list and the fallback menu, de-duplicated)", choices.Models, len(wantModels))
	}
	for index, want := range wantModels {
		got := choices.Models[index]
		if got.Name != want.name {
			t.Fatalf("models[%d] = %q, want %q; the union must be sorted so the checkboxes do not reshuffle", index, got.Name, want.name)
		}
		if got.Selected != want.selected {
			t.Errorf("model %q selected=%v, want %v", got.Name, got.Selected, want.selected)
		}
	}

	// --- what must not be in the body ---
	body := string(resp.Body)
	if strings.Contains(body, mgmtKey) {
		t.Error("the choices body carries probe_management_key; this route answers without any key at all")
	}
	if strings.Contains(body, "probe_management_key\"") {
		t.Error("the choices body carries a probe_management_key field; these are never displayed, not even empty")
	}
	// The fetch really was authenticated. Without this the test would still pass
	// against a route that reached an unauthenticated listing by accident.
	headers := fake.authHeaders()
	if len(headers) == 0 {
		t.Fatal("the fake CPA saw no request; the accounts above came from somewhere else")
	}
	if headers[0] != "Bearer "+mgmtKey {
		t.Errorf("CPA was called with Authorization %q, want the configured probe_management_key as a bearer", headers[0])
	}
}

// The labels are the whole reason this route can be keyless. A credential
// filename carries a customer's email address, and this document is readable by
// anyone who can reach the plugin, so what the page *displays* must not contain
// one.
//
// The four shapes below are the ones that decide whether the rule holds: the
// normal one, a name with no email at all, a name with extra dashes, and the
// empty string. The last two cases pin the safety property directly -- an email
// in the final position, which a first-and-last rule applied in the wrong order
// would publish.
func TestMaskAuthLabel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "the normal codex-<hex>-<email>-<tier>.json shape",
			in:   "codex-620f5a42-luo.swmu@gmail.com-pro.json",
			want: "620f5a42…pro",
		},
		{
			name: "no email in the name at all",
			in:   "codex-620f5a42-pro.json",
			want: "620f5a42…pro",
		},
		{
			// An email containing a dash splits into parts, and the middle carries
			// a tag nobody needs to see. First and last survive; the rest does not.
			name: "extra dashes around the email",
			in:   "codex-620f5a42-luo-swmu@gmail.com-team-pro.json",
			want: "620f5a42…pro",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			// The case the ordering exists for: drop the email parts first, and
			// only then take first and last. The other order publishes the address.
			name: "email in the final position",
			in:   "codex-620f5a42-luo@gmail.com.json",
			want: "620f5a42",
		},
		{
			name: "nothing but an email",
			in:   "codex-luo@gmail.com.json",
			want: "…",
		},
	}
	for _, c := range cases {
		got := maskAuthLabel(c.in)
		if got != c.want {
			t.Errorf("%s: maskAuthLabel(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		// Belt and braces, and cheap: whatever the shape, an "@" in a label means
		// an address reached a page that needs no key.
		if strings.Contains(got, "@") {
			t.Errorf("%s: maskAuthLabel(%q) = %q, which still carries an email address", c.name, c.in, got)
		}
	}
}

// A credential list that cannot be fetched must still leave a usable page: 200,
// an empty account list, the models half intact, and a sentence saying why. A
// 5xx here would blank the whole editor over a setting the operator could fix in
// ten seconds if anything told them what it was.
func TestChoicesDegradesWhenCredentialListUnavailable(t *testing.T) {
	t.Run("management key unset", func(t *testing.T) {
		dir := t.TempDir()
		fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
		mustConfigure(t, choicesConfig(dir, fake.server.URL, "", nil, []string{"gpt-5.5"}))

		choices, _ := mustChoices(t)
		if len(choices.Accounts) != 0 {
			t.Errorf("accounts = %+v, want [] when the credential list could not be fetched", choices.Accounts)
		}
		if !strings.Contains(choices.Error, "probe_management_key") {
			t.Errorf("error = %q; it must name the setting that is missing, or the operator has nothing to act on", choices.Error)
		}
		// The models half needs no CPA call, so it must survive a failure of the
		// half that does.
		if len(choices.Models) != len(knownCodexModels) {
			t.Errorf("models = %+v, want the fallback menu; a credential fetch failure must not take the model list with it", choices.Models)
		}
		// No request should have been made at all: firing an unauthenticated GET
		// and reporting CPA's 401 would blame the server for a setting on this side.
		if headers := fake.authHeaders(); len(headers) != 0 {
			t.Errorf("CPA was called %d time(s) with no key configured; the refusal must be local", len(headers))
		}
	})

	t.Run("cpa rejects the key", func(t *testing.T) {
		dir := t.TempDir()
		const mgmtKey = "mk-choices-stale-never-show-me"
		fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
		fake.refuse(http.StatusUnauthorized)
		mustConfigure(t, choicesConfig(dir, fake.server.URL, mgmtKey, []string{choicesAuthPro}, []string{"gpt-5.5"}))

		choices, resp := mustChoices(t)
		if len(choices.Accounts) != 0 {
			t.Errorf("accounts = %+v, want [] after a 401", choices.Accounts)
		}
		if !strings.Contains(choices.Error, "401") {
			t.Errorf("error = %q; a 401 must be reported as one, because it means a wrong key rather than a wrong path", choices.Error)
		}
		if len(choices.Models) == 0 {
			t.Error("the model list went missing along with the accounts")
		}
		// The failure path is the one most likely to quote something back. It must
		// not quote the key.
		if strings.Contains(string(resp.Body), mgmtKey) {
			t.Error("the error body carries probe_management_key verbatim")
		}
	})
}

// An unresponsive CPA must not hang the dashboard. The page cannot render until
// this returns, so "eventually" is not good enough: the fetch is bounded, and
// what comes back is the same graceful degradation as any other fetch failure.
func TestChoicesDoesNotHangOnUnresponsiveCPA(t *testing.T) {
	dir := t.TempDir()
	fake := newChoicesCPA(t, choicesCPAFile{"name": choicesAuthPro, "provider": "codex"})
	fake.stall(t)
	mustConfigure(t, choicesConfig(dir, fake.server.URL, "mk-choices", nil, []string{"gpt-5.5"}))

	previous := choicesFetchTimeout
	choicesFetchTimeout = 100 * time.Millisecond
	t.Cleanup(func() { choicesFetchTimeout = previous })

	// Driven by hand rather than through mustChoices: the call has to happen on
	// another goroutine so this one can time it out, and t.Fatal must not be
	// called from there -- it would stop the wrong goroutine and leave the test
	// hanging on exactly the failure it is meant to report.
	request, errMarshal := json.Marshal(map[string]any{
		"Method": http.MethodGet, "Path": opsChoicesPath,
		"Headers": http.Header{}, "Query": url.Values{}, "Body": nil,
	})
	if errMarshal != nil {
		t.Fatalf("marshal resource request: %v", errMarshal)
	}

	type outcome struct {
		raw []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		raw, err := handleMethod(pluginabi.MethodManagementHandle, request)
		done <- outcome{raw: raw, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("handleMethod(management.handle) GET %s: %v", opsChoicesPath, got.err)
		}
		var resp mgmtResponse
		if result := decodeMgmtEnvelope(t, got.raw); len(result) > 0 {
			if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
				t.Fatalf("decode resource response: %v", errUnmarshal)
			}
		}
		if resp.StatusCode != 0 && resp.StatusCode != http.StatusOK {
			t.Fatalf("a timed-out fetch returned %d, want 200 with the reason in the body", resp.StatusCode)
		}
		var choices mgmtChoices
		if err := json.Unmarshal(resp.Body, &choices); err != nil {
			t.Fatalf("decode choices: %v (body: %s)", err, truncateMgmtLog(resp.Body))
		}
		if choices.Error == "" {
			t.Error("a timed-out fetch reported no error; the page would render an empty account list as if CPA held none")
		}
		if len(choices.Models) == 0 {
			t.Error("the model list went missing on a timeout, though it needs no CPA call")
		}
	case <-time.After(10 * time.Second):
		// Generous on purpose: what is asserted is "bounded", not "fast".
		t.Fatal("/ops/choices did not return against an unresponsive CPA")
	}
}
