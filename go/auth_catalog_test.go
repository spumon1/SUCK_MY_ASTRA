package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// --- the catalog seam --------------------------------------------------------
//
// The steering gate judges the selected credential by what the host reports
// about it -- provider first, then type, filename last. These tests pin the
// precedence, because the failure they guard is directional: a codex-named
// file holding another provider's credential would carry OpenAI's routing
// cookies onto the wrong upstream, and only the reported provider catches it.

// withAuthCatalog installs a fake full credential catalog for the duration of
// one test. The gate reads it through a 2-second cache, so the cache is reset
// on both install and cleanup -- a stale catalog must never leak across cases.
func withAuthCatalog(t *testing.T, files []pluginapi.HostAuthFileEntry, err error) {
	t.Helper()
	authCatalogLister = func() ([]pluginapi.HostAuthFileEntry, error) {
		return files, err
	}
	resetAuthCache()
	t.Cleanup(func() {
		authCatalogLister = listAuthCatalog
		resetAuthCache()
	})
}

func TestEntryIsCodexProviderPrecedence(t *testing.T) {
	cases := []struct {
		name string
		file pluginapi.HostAuthFileEntry
		want bool
	}{
		// Provider is authoritative: it outranks the filename in both
		// directions.
		{"provider codex, plain name", pluginapi.HostAuthFileEntry{Name: "work.json", Provider: "codex"}, true},
		{"provider codex, case-insensitive", pluginapi.HostAuthFileEntry{Name: "work.json", Provider: "Codex"}, true},
		{"provider gemini, codex name", pluginapi.HostAuthFileEntry{Name: "codex-evil.json", Provider: "gemini"}, false},
		{"provider unknown, codex name", pluginapi.HostAuthFileEntry{Name: "codex-x.json", Provider: "unknown"}, false},
		// Type is the fallback only when provider is empty.
		{"type codex, provider empty", pluginapi.HostAuthFileEntry{Name: "work.json", Type: "codex"}, true},
		{"type gemini, codex name", pluginapi.HostAuthFileEntry{Name: "codex-evil.json", Type: "gemini"}, false},
		// Both empty: the filename convention is all there is.
		{"codex name, nothing reported", pluginapi.HostAuthFileEntry{Name: "codex-a.json"}, true},
		{"codex id, nothing reported", pluginapi.HostAuthFileEntry{ID: "codex-b.json"}, true},
		{"plain name, nothing reported", pluginapi.HostAuthFileEntry{Name: "work.json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := entryIsCodex(tc.file); got != tc.want {
				t.Fatalf("entryIsCodex(%+v) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

// The fix for the silent no-steer case: a Codex credential whose file is not
// named like one must still be steered, because the host says it is Codex.
func TestSteerUsesProviderNotFilename(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "work-account.json", Name: "work-account.json", Provider: "codex"},
	}, nil)

	resp := interceptAfter(t, request("work-account.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("a provider-verified Codex account under a plain filename was not steered: %q", cookie)
	}
}

// The leak this gate exists for: the filename says codex, the provider says
// gemini -- the provider wins, and the pair stays off the request.
func TestSteerRefusesCodexNamedForeignCredential(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-evil.json", Name: "codex-evil.json", Provider: "gemini"},
	}, nil)

	resp := interceptAfter(t, request("codex-evil.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("a codex-named foreign credential carried the pool pair: %q", cookie)
	}
}

// A catalog that answers but does not know the selected auth is a race or an
// inconsistency, not a licence to steer on the filename alone.
func TestSteerRefusesAuthAbsentFromCatalog(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-a.json", Name: "codex-a.json", Provider: "codex"},
	}, nil)

	resp := interceptAfter(t, request("codex-ghost.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("an auth the catalog does not list carried the pool pair: %q", cookie)
	}
}

// Degraded mode: when the catalog itself cannot be read, the filename
// convention is the only signal left and the legacy behaviour holds.
func TestSteerFallsBackToFilenameWhenCatalogDown(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, nil, errors.New("host API unavailable"))

	resp := interceptAfter(t, request("codex-a.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("the filename fallback did not steer a codex-named account: %q", cookie)
	}
	resp2 := interceptAfter(t, request("gemini-someone.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp2.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("the filename fallback steered a foreign-named account: %q", cookie)
	}
}

// The index is matched before the id: it survives a rename, which is exactly
// when the reported name would mislead.
func TestSteerMatchesBySelectedAuthIndex(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "original.json", Name: "original.json", AuthIndex: "idx-9", Provider: "codex"},
		{ID: "codex-decoy.json", Name: "codex-decoy.json", AuthIndex: "idx-4", Provider: "gemini"},
	}, nil)

	// A codex-named id that does not resolve, with the index pointing at the
	// real codex entry: the index decides, so this steers.
	req := request("renamed.json", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77))
	req.Metadata[selectedAuthIndexMetadataKey] = "idx-9"
	resp := interceptAfter(t, req)
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("an index-verified Codex account was not steered: %q", cookie)
	}

	// The mirror, and the case that actually proves precedence: the reported id
	// names the CODEX entry while the index names the GEMINI one. Only an
	// index-first lookup refuses the steer -- an id-first one would attach the
	// pair onto gemini traffic.
	req2 := request("original.json", "gemini-3", fakeTokenSeed(312, wallClock(), 0x77))
	req2.Metadata[selectedAuthIndexMetadataKey] = "idx-4"
	resp2 := interceptAfter(t, req2)
	if cookie := resp2.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("the index pointed at a foreign provider yet the pair was attached: %q", cookie)
	}
}

// An index-only request -- no selected_auth_id at all -- is still attributable.
func TestSteerAttributesByIndexAlone(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-a.json", Name: "codex-a.json", AuthIndex: "idx-9", Provider: "codex"},
	}, nil)

	req := pluginapi.RequestInterceptRequest{
		Model:    "gpt-5.6-sol",
		Metadata: map[string]any{selectedAuthIndexMetadataKey: "idx-9"},
		Headers:  http.Header{},
	}
	resp := interceptAfter(t, req)
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("an index-only Codex request was not steered: %q", cookie)
	}
}

// The sole-account inference and the gate now speak the same language: an
// inferred account whose catalog entry says codex steers even when its file is
// not named like one; one whose entry says otherwise is refused.
func TestSoleAccountInferenceVerifiedByCatalog(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	withAuthList(t, enabledAccounts("work.json"), nil)
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "work.json", Name: "work.json", Provider: "codex"},
	}, nil)

	resp := interceptAfter(t, request("", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); !strings.Contains(cookie, "__cflb=cf") {
		t.Fatalf("the sole Codex account under a plain filename was not steered: %q", cookie)
	}
}

func TestSoleAccountInferenceRefusedByCatalog(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))
	seedPoolEntry(t, map[string]string{"__cflb": "cf"}, time.Now(), "")
	// The codex list counts it (filename fallback), the catalog says gemini:
	// the gate believes the provider, and the pair stays off.
	withAuthList(t, enabledAccounts("codex-suspect.json"), nil)
	withAuthCatalog(t, []pluginapi.HostAuthFileEntry{
		{ID: "codex-suspect.json", Name: "codex-suspect.json", Provider: "gemini"},
	}, nil)

	resp := interceptAfter(t, request("", "gpt-5.6-sol", fakeTokenSeed(312, wallClock(), 0x77)))
	if cookie := resp.Headers.Get("Cookie"); strings.Contains(cookie, "cf") {
		t.Fatalf("an inferred account the catalog calls foreign carried the pair: %q", cookie)
	}
}
