package main

// Contract tests for the shapes this plugin publishes rather than merely uses.
//
// The other test files assert behaviour: given this request, expect that
// decision. These assert *surface*: the exact set of JSON keys each
// anonymously readable document can emit, the exact set of paths reachable
// without a key, and the exact set of config fields the host is told about.
// They are deliberately brittle. A behavioural test answers "does it still
// work"; these answer "did the published surface change", and the only correct
// way to make one fail is to change the literal alongside the code and think
// about what it now exposes.
//
// SHAPE, NOT CONTENT. Every assertion here is about which keys exist. None of
// it can tell whether a value put into one of them is safe. Several fields are
// free-text channels -- probe_run.lines, store_error, accounts_error,
// config_errors, and every "detail"/"note" on the proxy check -- and those rest
// entirely on probeRedact, maskProxyURL and the denylist assertions in
// TestAnonymousStatusResourceNeverLeaksTokenValues. Do not read a green run
// here as "nothing leaks".
//
// Why the file exists: statusResponse carries a long comment warning that every
// field on it is anonymously readable, and managementRegister carries another
// warning that anything in Resources is keyless. Both were prose. The nearest
// thing to enforcement was TestAnonymousStatusResourceNeverLeaksTokenValues
// (management_test.go), which greps the response for the specific tokens it
// seeded -- a denylist, which by construction cannot catch a field nobody
// thought to seed. Verified: grafting a probe_management_key field onto
// statusResponse passes that test and every other test in the suite.

import (
	"encoding"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// --- 1. the anonymous status document ------------------------------------

// statusResponsePublicFields is every JSON key path handleStatus can emit, and
// therefore every key path readable without a credential: the same document
// answers /v0/management/codex-turn-state/status and the unauthenticated
// /v0/resource/plugins/codex-turn-state/status, with no per-route filtering.
//
// Nested paths are "parent.child". Slice elements are flattened onto the slice
// key, so a field on statusBucket appears as "buckets.<field>" once rather than
// per element.
//
// Adding a line here is the act of publishing that field. Before you do:
// probe_management_key is the one value on this plugin that is never displayed
// anywhere, masked or otherwise, and proxy URLs carry userinfo.
var statusResponsePublicFields = []string{
	"accounts_error",
	"accounts_source",
	"buckets",
	"buckets.auth_id",
	"buckets.enabled",
	"buckets.len",
	"buckets.model",
	// The observation tally. Counters, a closed set of kind strings
	// (normal/limited/silent/other), lengths and timestamps -- nothing that can
	// hold a credential. Reviewed field by field when they were added.
	//
	// bucketObservation.Hourly is deliberately NOT here: the per-hour history
	// lives in the snapshot on disk and is rolled up into recent_24h for the
	// page. Publishing 48 slots per bucket would grow a polled document for
	// data the panel does not draw.
	"buckets.observed",
	"buckets.observed.injected_limited",
	"buckets.observed.injected_normal",
	"buckets.observed.injected_other",
	"buckets.observed.injected_silent",
	"buckets.observed.last_at",
	"buckets.observed.last_kind",
	"buckets.observed.last_len",
	"buckets.observed.last_natural_at",
	"buckets.observed.last_natural_kind",
	// The most recent reading in which the upstream signed anything, injected
	// or not. Same classes of value as last_natural_*: a timestamp, a kind from
	// the closed set, and a bool.
	"buckets.observed.last_signed_at",
	"buckets.observed.last_signed_kind",
	"buckets.observed.last_signed_wrote",
	"buckets.observed.last_wrote",
	"buckets.observed.natural_limited",
	"buckets.observed.natural_normal",
	"buckets.observed.natural_other",
	"buckets.observed.recent_24h",
	"buckets.observed.recent_24h.injected_limited",
	"buckets.observed.recent_24h.injected_normal",
	"buckets.observed.recent_24h.injected_other",
	"buckets.observed.recent_24h.injected_silent",
	"buckets.observed.recent_24h.natural_limited",
	"buckets.observed.recent_24h.natural_normal",
	"buckets.observed.recent_24h.natural_other",
	"buckets.ready",
	// A lifetime in seconds for the account's pooled __cflb/__oailb pair --
	// never a cookie value.
	"buckets.route_cookies_seconds_left",
	"config_errors",
	"counters",
	"counters.harvest",
	"counters.pass",
	"counters.skip",
	"counters.steer",
	"counters_since",
	"dry_run",
	"generated_at",
	"models",
	// The live feed. auth_id here is the credential filename, which carries a
	// customer email -- but it is already published on every buckets row, so
	// this adds no new class of value. What it DOES newly publish is a
	// per-account request timestamp, and therefore an activity pattern. That
	// was a deliberate call for a loopback-bound panel; it would not be one for
	// anything reachable.
	"observation_feed",
	"observation_feed.at",
	"observation_feed.auth_id",
	"observation_feed.kind",
	"observation_feed.len",
	"observation_feed.model",
	// The model the stream actually served when it differed from the request --
	// the unified format's downgrade signature. A model id, same class of value
	// as observation_feed.model.
	"observation_feed.served",
	"observation_feed.wrote",
	"observations_since",
	"probe_accounts",
	"probe_proxies",
	"probe_proxies_rotating",
	"probe_proxy_count",
	"probe_proxy_rotating_count",
	"probe_run",
	"probe_run.current",
	"probe_run.done",
	"probe_run.error",
	"probe_run.finished_at",
	"probe_run.lines",
	"probe_run.running",
	"probe_run.started_at",
	"probe_run.total",
	"replace_length",
	"role",
	"store_dir",
	"store_error",
	"targets_ready",
	"targets_total",
	"template_length",
	"ttl_seconds",
}

// choicesResponsePublicFields is the scope editor's menu, served keyless on
// /ops/choices. accounts.name is the credential filename in full, which carries
// a customer email; accounts.label is the masked form the page displays. Both
// are published -- the route answers without a key and the page needs the real
// filename to post back -- which is exactly why the shape is pinned.
var choicesResponsePublicFields = []string{
	"accounts",
	"accounts.disabled",
	"accounts.label",
	"accounts.name",
	"accounts.selected",
	"error",
	"models",
	"models.name",
	"models.selected",
}

// proxyCheckResponsePublicFields is the exit diagnostic, served keyless on
// /ops/proxy-check. results.proxy is a proxy URL and goes out through
// probeShowProxy; results.detail is free text off an upstream error. Neither
// is protected by this assertion -- see the SHAPE, NOT CONTENT note above --
// but a new field on this document is a new keyless field either way.
var proxyCheckResponsePublicFields = []string{
	"blocked",
	"checked",
	"dead",
	"direct",
	"distinct_ips",
	"mismatches",
	"ms",
	"note",
	"ok",
	"other",
	"results",
	"results.colo",
	"results.country",
	"results.detail",
	"results.exit_ip",
	"results.index",
	"results.mismatch",
	"results.ms",
	"results.pool",
	"results.proxy",
	"results.rotated",
	"results.status_code",
	"results.verdict",
	"static_checked",
	"timed_out",
}

// TestAnonymouslyReadableShapesArePinned walks each document's type -- not a
// marshalled instance -- so that omitempty fields are counted too. An instance
// only shows what happened to be populated, and "the leak is in a field that is
// empty in the fixture" is exactly the case worth catching.
func TestAnonymouslyReadableShapesArePinned(t *testing.T) {
	for _, doc := range []struct {
		name  string
		typ   reflect.Type
		want  []string
		route string
	}{
		{"statusResponse", reflect.TypeOf(statusResponse{}), statusResponsePublicFields, "/status"},
		{"choicesResponse", reflect.TypeOf(choicesResponse{}), choicesResponsePublicFields, "/ops/choices"},
		{"proxyCheckResponse", reflect.TypeOf(proxyCheckResponse{}), proxyCheckResponsePublicFields, "/ops/proxy-check"},
	} {
		t.Run(doc.name, func(t *testing.T) {
			got := jsonFieldPaths(t, doc.typ, "")
			assertSetEqual(t, doc.name+" fields", got, doc.want,
				"this document is served on "+doc.route+", which needs no credential; "+
					"if the new field can carry a secret it does not belong on this struct at all")
		})
	}
}

// --- 2. the walker itself -------------------------------------------------

// The pins above are only worth their brittleness if the walk underneath them
// actually descends. A jsonFieldPaths that quietly returned the top level would
// keep every assertion green while publishing whole nested structs unchecked,
// so it gets its own fixture rather than being trusted.

type walkerProbeInner struct {
	Alpha  string `json:"alpha"`
	Omit   string `json:"-"`
	hidden string //nolint:unused // present so the walk is seen to skip it
}

// walkerProbeEmbedded is embedded untagged, the shape bucketObservation uses
// for its counters. Unexported on purpose: encoding/json still promotes the
// exported fields of an embedded unexported struct type, and that is the case
// most likely to be got wrong.
type walkerProbeEmbedded struct {
	Promoted string `json:"promoted"`
}

type walkerProbeOuter struct {
	walkerProbeEmbedded
	Top      int                `json:"top"`
	Nested   walkerProbeInner   `json:"nested"`
	List     []walkerProbeInner `json:"list"`
	Pointer  *walkerProbeInner  `json:"pointer"`
	Names    []string           `json:"names"`
	Untagged bool
}

func TestJSONFieldPathsDescends(t *testing.T) {
	got := jsonFieldPaths(t, reflect.TypeOf(walkerProbeOuter{}), "")
	want := []string{
		"Untagged", // no tag: encoding/json falls back to the Go field name
		"list",
		"list.alpha", // slice elements flatten onto the slice key
		"names",      // a []string is a leaf
		"nested",
		"nested.alpha",
		"pointer", // a *struct is followed
		"pointer.alpha",
		"promoted", // embedded untagged: promoted to the parent, NOT nested
		"top",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the walk does not descend as the pins above assume.\n got: %v\nwant: %v", got, want)
	}
	for _, path := range got {
		if strings.Contains(path, "Omit") || strings.Contains(path, "hidden") {
			t.Errorf("walk emitted %q; json:\"-\" and unexported fields are never serialised", path)
		}
	}

	// The list above is still only my reading of encoding/json's rules, and the
	// promotion rule for an embedded unexported struct type is the kind of thing
	// a person gets wrong from memory. Ask the marshaller instead of trusting
	// the reading: at the top level the two must agree exactly.
	raw, err := json.Marshal(walkerProbeOuter{})
	if err != nil {
		t.Fatalf("marshalling the probe: %v", err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(raw, &emitted); err != nil {
		t.Fatalf("unmarshalling the probe: %v", err)
	}
	var actual []string
	for key := range emitted {
		actual = append(actual, key)
	}
	var walked []string
	for _, path := range got {
		if !strings.Contains(path, ".") {
			walked = append(walked, path)
		}
	}
	sort.Strings(actual)
	sort.Strings(walked)
	if !reflect.DeepEqual(walked, actual) {
		t.Errorf("the walk and encoding/json disagree about the top-level keys; every pin in this file "+
			"is a claim about what ships, so the walk has to match the marshaller.\n walked: %v\nmarshalled: %v",
			walked, actual)
	}
}

// jsonFieldPaths returns every JSON key path encoding/json can produce for typ,
// recursing through structs, pointers and slice/array elements.
//
// It fails the test on any shape whose keys cannot be read off the type: a map,
// an interface, a []byte (json.RawMessage serialises as whatever it holds), or
// anything with its own MarshalJSON/MarshalText. Silently treating one of those
// as a leaf would make every pin above under-report, which is the one failure
// this file cannot afford.
func jsonFieldPaths(t *testing.T, typ reflect.Type, prefix string) []string {
	t.Helper()
	var out []string
	collectJSONFields(t, typ, prefix, &out)
	sort.Strings(out)
	return out
}

func collectJSONFields(t *testing.T, typ reflect.Type, prefix string, out *[]string) {
	t.Helper()

	typ = derefType(typ)
	if typ.Kind() != reflect.Struct {
		t.Fatalf("collectJSONFields called on %s, which is not a struct", typ)
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]

		if field.Anonymous && name == "" {
			// encoding/json promotes an untagged embedded struct's exported
			// fields onto the parent rather than nesting them -- including when
			// the embedded type itself is unexported, which is why this runs
			// ahead of the PkgPath check below. Modelling it is not optional:
			// pinning "observed.counts.natural_normal" for a key that ships as
			// "observed.natural_normal" would make every list in this file
			// describe a document that does not exist, and the pins would then
			// be green about the wrong surface.
			//
			// A tagged embed is a different thing -- encoding/json nests it
			// under the tag name -- and falls through to the ordinary path.
			embedded := derefType(field.Type)
			if embedded.Kind() != reflect.Struct {
				t.Fatalf("%s embeds the non-struct %s; encoding/json's rules there are subtle "+
					"(an unexported one is dropped outright) and nothing in this plugin does it, "+
					"so this walk refuses to guess", typ, field.Type)
			}
			rejectOpaque(t, embedded, typ.String()+"."+field.Name)
			collectJSONFields(t, embedded, prefix, out)
			continue
		}

		if field.PkgPath != "" {
			continue // unexported: never serialised
		}
		if name == "" {
			name = field.Name
		}

		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		*out = append(*out, path)

		descendJSONField(t, field.Type, path, out, typ.String()+"."+field.Name)
	}
}

func descendJSONField(t *testing.T, typ reflect.Type, path string, out *[]string, where string) {
	t.Helper()

	typ = derefType(typ)
	rejectOpaque(t, typ, where)

	switch typ.Kind() {
	case reflect.Struct:
		collectJSONFields(t, typ, path, out)
	case reflect.Slice, reflect.Array:
		// Elements flatten onto the slice's own key: one entry per field, not
		// one per element. A nested slice keeps flattening.
		descendJSONField(t, typ.Elem(), path, out, where+" element")
	}
}

// rejectOpaque fails on a type whose emitted keys are not determined by the
// type. Called at every level, including slice elements, because []map[string]X
// hides exactly as much as map[string]X does.
func rejectOpaque(t *testing.T, typ reflect.Type, where string) {
	t.Helper()

	var (
		jsonMarshaler = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
		textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	)
	for _, iface := range []reflect.Type{jsonMarshaler, textMarshaler} {
		if typ.Implements(iface) || reflect.PointerTo(typ).Implements(iface) {
			t.Fatalf("%s is a %s with its own %s; its JSON keys are not readable off the type. "+
				"If it serialises to a single scalar (time.Time does, as an RFC3339 string), say so here "+
				"and allow it; if it serialises to an object, its fields need pinning of their own.",
				where, typ, iface.Name())
		}
	}

	switch typ.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("%s is a %s, whose keys cannot be pinned by walking the type; "+
			"an open-ended container on an anonymously readable document needs its own assertion", where, typ.Kind())
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s is a %s (json.RawMessage or []byte); it serialises as whatever it happens to hold, "+
				"which is not something this walk can pin", where, typ)
		}
	}
}

func derefType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

// --- 3. the keyless surface ----------------------------------------------

// keylessResourcePaths is every path registered under the resource prefix.
// Registration *is* the grant: the host serves that prefix without
// authentication, so a new entry in managementRegister's Resources list is a
// new keyless endpoint whether or not anyone meant it to be one.
//
// TestManagementRegisterExposesExactlyOneMenuResource already stops a resource
// from acquiring a Menu (which would publish it into the management centre).
// This pins the weaker but wider property: the set itself.
var keylessResourcePaths = []string{
	"/dashboard",
	"/ops/choices",
	"/ops/clear",
	"/ops/dry-run",
	"/ops/probe/cancel",
	"/ops/probe/start",
	"/ops/proxy-check",
	"/ops/role",
	"/ops/scope",
	"/ops/selftest",
	"/status",
}

// authenticatedRoutes is the management surface that stays behind a key.
// routeConfig is the load-bearing one: it returns the configuration verbatim,
// which is where a probe bearer would surface. It must never move to the
// resource list, and it must never acquire a Menu (a GET route with a Menu is
// re-registered under the resource prefix by the host).
var authenticatedRoutes = []string{
	"GET /codex-turn-state/cloud-status",
	"GET /codex-turn-state/config",
	"GET /codex-turn-state/status",
	"POST /codex-turn-state/buckets/clear",
	"POST /codex-turn-state/selftest",
	"POST /codex-turn-state/modeltrace",
	"POST /codex-turn-state/gateway-sweep",
}

// The registration does not vary by role -- managementRegister reads nothing
// off the config -- so one configured role exercises it fully.
func TestKeylessSurfaceIsPinned(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)

	var gotResources []string
	for _, res := range reg.Resources {
		gotResources = append(gotResources, res.Path)
	}
	assertSetEqual(t, "keyless resource paths", gotResources, keylessResourcePaths,
		"every path here is served without a credential; adding one is a deliberate act")

	var gotRoutes []string
	for _, route := range reg.Routes {
		gotRoutes = append(gotRoutes, route.Method+" "+route.Path)
	}
	assertSetEqual(t, "authenticated management routes", gotRoutes, authenticatedRoutes,
		"moving one of these to the resource list would publish it")
}

// --- 4. the declared configuration ----------------------------------------

// configFieldNames is what the host is told this plugin accepts, in order. The
// host renders these, so a rename is a user-visible change to a YAML key and a
// removal silently stops the field being offered.
//
// This pins names, not descriptions. The descriptions are prose shown to an
// operator and they drift like any other prose -- two of them were wrong about
// roles until the commit that added this file's sibling fixes.
var configFieldNames = []string{
	"role",
	"store_dir",
	"template_length",
	"replace_length",
	"ttl_seconds",
	"dry_run",
	"log_decisions",
	"models",
	"probe_accounts",
	"probe_proxies",
	"probe_proxies_rotating",
	"probe_management_key",
	"probe_base_url",
	"cloud_mint", // 新增插件自有配置，不改变已有字段顺序。
}

func TestDeclaredConfigFieldsArePinned(t *testing.T) {
	fields := pluginRegistration().Metadata.ConfigFields

	var got []string
	for _, field := range fields {
		got = append(got, field.Name)
	}
	if !reflect.DeepEqual(got, configFieldNames) {
		t.Errorf("declared config fields changed.\n got: %v\nwant: %v\n"+
			"Order matters here because the host renders them in it.", got, configFieldNames)
	}

	// A field declared with no description is one the operator meets with no
	// explanation, and several of these carry warnings about probe scope that
	// are the only place that rule is stated to a reader of the UI.
	for _, field := range fields {
		if strings.TrimSpace(field.Description) == "" {
			t.Errorf("config field %q is declared without a description", field.Name)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func assertSetEqual(t *testing.T, what string, got, want []string, why string) {
	t.Helper()

	if len(got) == 0 {
		t.Fatalf("%s: nothing was declared, so this assertion would pass vacuously", what)
	}

	seen := make(map[string]bool, len(want))
	for _, entry := range want {
		seen[entry] = true
	}
	for _, entry := range got {
		if !seen[entry] {
			t.Errorf("%s gained %q -- %s", what, entry, why)
		}
		delete(seen, entry)
	}
	var missing []string
	for entry := range seen {
		missing = append(missing, entry)
	}
	sort.Strings(missing)
	for _, entry := range missing {
		t.Errorf("%s lost %q; update the literal if the removal is intended", what, entry)
	}
}
