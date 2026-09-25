// Credential catalog: what Codex accounts the host knows about, and the short
// cache the harvest path reads them through.
//
// This lives on its own because the dependency ran the wrong way. The functions
// below were in management.go, which made the request interceptor -- the
// hottest path in the plugin -- reach into the management surface to answer
// "which account is this". Management is meant to expose capabilities, not
// supply them. The catalog is the capability; management and the interceptors
// are two consumers of it.
//
// Moving the file does not by itself enforce that: this is all one package and
// nothing stops a future edit from reaching back the other way. What it does is
// put the boundary somewhere a reader can see it.
//
// Moved verbatim out of management.go and main.go in edd3de3; the type was
// renamed from statusAccount in b9da52e. No behaviour changed in either.

package main

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// codexAuth is one Codex credential as the host reports it: the filename it is
// stored under, and whether it can serve a request right now (a disabled
// credential and an unavailable one are both reported as not enabled -- see
// listCodexAuths for why the distinction is not kept).
//
// It carries no json tags and is never serialised. It was called statusAccount
// while it lived in management.go, which read as though the catalog existed to
// fill the status page; the status page is one caller. soleEnabledCodexAuth on
// the request path is another, and that one is not a status concern at all.
type codexAuth struct {
	AuthID  string
	Enabled bool
}

// The credential list is cached for the harvest path, which would otherwise ask
// the host once per upstream response. The window is deliberately tiny: the one
// thing that changes during a probe run is exactly which account is enabled, and
// attributing an observation to an account that was switched off two seconds ago is
// the failure this cache must not cause.
//
// handleStatus deliberately does not use it. The dashboard is read by a person
// deciding what to do next, it is requested rarely, and it should show the
// credential states as they are rather than as they were.
const authListCacheTTL = 2 * time.Second

var (
	authListMu      sync.Mutex
	authListCache   []codexAuth
	authListErr     error
	authListFetched time.Time
)

// codexAuthLister returns the current Codex credentials. It is a package
// variable rather than a direct call so tests can inject a fixed list and
// exercise the attribution fallbacks on both the harvest and substitution
// paths -- above all the two-accounts case, where refusing to guess is what
// keeps one account's tally off another account's row. Production leaves
// it pointed at the real host-backed lister.
var codexAuthLister = listCodexAuths

// authCatalogLister is the same seam for the FULL credential list. The
// steering gate needs the non-Codex entries too: "in the list under another
// provider" and "not in the list" are different answers, and the first one is
// the credential the pool must never be steered onto.
var authCatalogLister = listAuthCatalog

// cachedCodexAuths is codexAuthLister behind a short cache. The lookup happens
// under the mutex so a burst of concurrent responses produces one call rather
// than one each.
func cachedCodexAuths() ([]codexAuth, error) {
	authListMu.Lock()
	defer authListMu.Unlock()
	if !authListFetched.IsZero() && time.Since(authListFetched) < authListCacheTTL {
		return authListCache, authListErr
	}
	authListCache, authListErr = codexAuthLister()
	authListFetched = time.Now()
	return authListCache, authListErr
}

var (
	authCatalogMu      sync.Mutex
	authCatalogCache   []pluginapi.HostAuthFileEntry
	authCatalogErr     error
	authCatalogFetched time.Time
)

// cachedAuthCatalog is authCatalogLister behind the same short window the codex
// list uses. It serves the steering gate, the hottest read the catalog has.
func cachedAuthCatalog() ([]pluginapi.HostAuthFileEntry, error) {
	authCatalogMu.Lock()
	defer authCatalogMu.Unlock()
	if !authCatalogFetched.IsZero() && time.Since(authCatalogFetched) < authListCacheTTL {
		return authCatalogCache, authCatalogErr
	}
	authCatalogCache, authCatalogErr = authCatalogLister()
	authCatalogFetched = time.Now()
	return authCatalogCache, authCatalogErr
}

// resetAuthCache clears the cached credential views so the next lookup goes
// back to the listers immediately. It exists for tests: after injecting a new
// lister they must drop the 2-second cache, or a stale entry from a previous
// case would answer instead. Not used in production, where the caches are
// meant to persist for their full window.
func resetAuthCache() {
	authListMu.Lock()
	authListCache = nil
	authListErr = nil
	authListFetched = time.Time{}
	authListMu.Unlock()
	authCatalogMu.Lock()
	authCatalogCache = nil
	authCatalogErr = nil
	authCatalogFetched = time.Time{}
	authCatalogMu.Unlock()
}

// listAuthCatalog returns every credential the host knows about, unfiltered --
// the raw material both the Codex-only list and the steering gate derive from.
func listAuthCatalog() ([]pluginapi.HostAuthFileEntry, error) {
	var listed struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if errCall := hostCallJSON("host.auth.list", map[string]any{}, &listed); errCall != nil {
		return nil, errCall
	}
	return listed.Files, nil
}

// listCodexAuths returns every Codex credential the host knows about, sorted by
// name, with the enabled state it reports.
func listCodexAuths() ([]codexAuth, error) {
	files, errList := listAuthCatalog()
	if errList != nil {
		return nil, errList
	}
	var out []codexAuth
	for _, file := range files {
		if !isCodexAuth(file) {
			continue
		}
		name := strings.TrimSpace(file.Name)
		if name == "" {
			continue
		}
		// An unavailable credential cannot answer a request either, so it is
		// reported the same way a disabled one is: the operator's question is
		// "can this bucket be filled right now", not "which flag is set".
		out = append(out, codexAuth{AuthID: name, Enabled: !file.Disabled && !file.Unavailable})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AuthID < out[j].AuthID })
	return out, nil
}

func isCodexAuth(file pluginapi.HostAuthFileEntry) bool {
	if strings.EqualFold(strings.TrimSpace(file.Provider), "codex") ||
		strings.EqualFold(strings.TrimSpace(file.Type), "codex") {
		return true
	}
	// Provider is not always populated on file-backed credentials; the naming
	// convention is the fallback the harvester uses too.
	name := strings.ToLower(strings.TrimSpace(file.Name))
	return strings.HasPrefix(name, "codex-") && strings.HasSuffix(name, ".json")
}

// soleEnabledCodexAuth returns the name of the only enabled Codex credential.
// It reports the enabled count alongside so a refusal can say why, and returns
// an empty name whenever the count is anything but one -- the caller must not
// guess, so "none" and "several" are the same answer here.
func soleEnabledCodexAuth() (string, int, error) {
	accounts, errList := cachedCodexAuths()
	if errList != nil {
		return "", 0, errList
	}
	name := ""
	count := 0
	for _, account := range accounts {
		if !account.Enabled {
			continue
		}
		count++
		name = account.AuthID
	}
	if count != 1 {
		return "", count, nil
	}
	return name, 1, nil
}

// selectedAuthIsCodex reports whether the credential the scheduler picked is a
// Codex account, judged by the host's own records rather than by what the file
// happens to be named. The stable auth index is matched first, then the
// reported id/name -- the same pair CPA publishes as selected_auth_index and
// selected_auth_id.
//
// resolved=false means the catalog itself could not be read; the caller then
// falls back to the filename convention, the only signal left. resolved=true
// with codex=false covers both "the entry exists under another provider" and
// "the catalog knows no such credential": the scheduler can only select what
// the host registered, so absence is a race or an inconsistency, never a
// licence to guess.
func selectedAuthIsCodex(authID, authIndex string) (codex, resolved bool) {
	files, errList := cachedAuthCatalog()
	if errList != nil {
		return false, false
	}
	for i := range files {
		if authIndex != "" && files[i].AuthIndex == authIndex {
			return entryIsCodex(files[i]), true
		}
	}
	for i := range files {
		if authID != "" && (files[i].ID == authID || files[i].Name == authID) {
			return entryIsCodex(files[i]), true
		}
	}
	return false, true
}

// entryIsCodex judges one catalog entry. Provider is authoritative whenever the
// host reports one -- a codex-named file holding another provider's credential
// must NOT pass, or OpenAI's routing cookies would ride onto the wrong
// upstream. Type is the fallback when provider is empty, and the filename
// convention applies only when the host reports neither, the case where the
// convention is all there is. This is deliberately stricter than isCodexAuth's
// any-signal OR: that one fills a dashboard, this one guards a credential.
func entryIsCodex(file pluginapi.HostAuthFileEntry) bool {
	if provider := strings.ToLower(strings.TrimSpace(file.Provider)); provider != "" {
		return provider == "codex"
	}
	if kind := strings.ToLower(strings.TrimSpace(file.Type)); kind != "" {
		return kind == "codex"
	}
	return looksCodexAuthID(file.Name) || looksCodexAuthID(file.ID)
}
