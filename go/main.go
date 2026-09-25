// Package main implements a CLIProxyAPI native plugin that steers official
// Codex traffic onto healthy upstream gateway nodes by replaying the
// load-balancer cookies (__cflb/__oailb) the upstream itself issues.
//
// The mechanism, measured 2026-09-22 (FINDINGS.md): the upstream fronts many
// gateway nodes (chat.gateway.unified-N.api.openai.com). Which node a request
// lands on is decided by the routing cookies on it -- a node-independent,
// account-independent credential -- and a request carrying a live pair from a
// good node keeps being served normally. The X-Codex-Turn-State ticket this
// plugin used to harvest and substitute turned out to be unnecessary for
// that: the cookie alone steers. So this plugin does exactly three things:
//
//   - collect    every upstream response's Set-Cookie __cflb/__oailb pairs into
//     a GLOBAL pool (account-agnostic: one pair works for any account).
//   - steer      on every attributable request, merge the pool's best live
//     pair into the outgoing Cookie header.
//   - observe    record what serving state the upstream actually signed
//     (the configured normal/degraded classes, plus whatever signature each
//     bucket has learned as its own) per (account, model), and
//     deprioritise a pair whose steered requests keep coming back degraded.
//
// The probe runner is the collector's offline half: it dials the upstream once
// per configured exit using any working credential, because each exit IP lands
// on a different node and mints a different pair -- "hitting many IPs" is
// really "collecting many nodes". It is OFF BY DEFAULT, started by hand
// through /ops/probe/start; sending traffic an account did not ask for is the
// kind of thing accounts get banned for, so the standing policy is
// passive-first: take what responses carry, dial exits only on request.
//
// Rules enforced here:
//  1. a request is steered only when the account can be determined --
//     selected_auth_id, or a sole enabled Codex credential. Without that the
//     request might not be Codex traffic at all, and replaying OpenAI cookies
//     onto another provider's upstream would leak them.
//  2. only __cflb/__oailb are ever replayed -- device/session cookies are
//     filtered at capture and never leave the process.
//  3. a pair is usable for ttl_seconds (default 3900) from when it was last
//     seen, shortened by the credential's own deadline -- the __oailb JWT's
//     exp when the value carries one, else the declared Max-Age/Expires.
//     Cookie values are never logged: the pair is credential material.
//
// What role still means: business attaches cookies; probe leaves every request
// exactly as it found it. Both roles collect and observe.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

// cliproxy_invoke_host calls back into the host. The host owns the response
// buffer, so every non-NULL ptr it hands back must go to cliproxy_release_host.
static int cliproxy_invoke_host(const cliproxy_host_api* host, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (host == NULL || host->call == NULL) {
		return 1;
	}
	return host->call(host->host_ctx, method, request, request_len, response);
}

static void cliproxy_release_host(const cliproxy_host_api* host, void* ptr, size_t len) {
	if (host == NULL || host->free_buffer == NULL || ptr == NULL) {
		return;
	}
	host->free_buffer(ptr, len);
}

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// turnStateHeader is read on responses only: its signed length is the serving-
// state signal the observation tally classifies. The plugin never writes it.
const turnStateHeader = "X-Codex-Turn-State"

// selectedAuthMetadataKey mirrors cliproxyexecutor.SelectedAuthMetadataKey.
// It is inlined so the plugin does not depend on the executor package.
const selectedAuthMetadataKey = "selected_auth_id"

// selectedAuthIndexMetadataKey mirrors cliproxyexecutor.SelectedAuthIndexMetadataKey,
// published alongside the id. The index is the stabler of the two: it survives
// a credential rename, which is exactly when the name would mislead.
const selectedAuthIndexMetadataKey = "selected_auth_index"

const logPrefix = "[codex-turn-state] "

// The two roles. A process is one of them for the whole of a config generation;
// switching is done by editing config.yaml and letting the host reconfigure.
const (
	roleProbe    = "probe"
	roleBusiness = "business"
)

// runtimeOverrideFileName holds the two fields the dashboard can change without a
// management key: role and dry_run. It lives in the store dir and is layered over
// the config-file values on every configure. It exists so a change made from the
// keyless dashboard survives the CPA restart that a role switch requires anyway
// (capability renegotiation); without it, a restart would silently revert role
// and dry_run to config.yaml and undo the operator's last action. It carries no
// secret -- a role string and a bool -- so it is not sensitive to read.
const runtimeOverrideFileName = "runtime.json"

var state = pluginState{
	config:  defaultConfig(),
	cookies: make(map[string]*routeCookieEntry),
}

// hostAPI is the *C.cliproxy_host_api the host passes to cliproxy_plugin_init,
// kept so the management handlers can call back into the host. It is written
// once during init and read from handler goroutines, hence the atomic.
var hostAPI unsafe.Pointer

// hostAPIAvailable reports whether the host handed over a callback table. It is
// worth asking separately from just letting hostCall fail: "the plugin cannot
// make any outbound call" and "the upstream did not answer" are different
// findings, and a diagnostic that reported the first as the second would send
// the operator looking at the network when the problem is the load.
func hostAPIAvailable() bool {
	return atomic.LoadPointer(&hostAPI) != nil
}

// hostCall invokes a host callback and returns its raw RPC envelope. A nil host
// API means the plugin was loaded by something that never handed one over, which
// is a configuration problem rather than a request failure -- the management
// routes that need it say so rather than pretending the call returned nothing.
func hostCall(method string, request []byte) ([]byte, error) {
	raw := atomic.LoadPointer(&hostAPI)
	if raw == nil {
		return nil, fmt.Errorf("host API unavailable: this plugin was initialised without one")
	}
	host := (*C.cliproxy_host_api)(raw)

	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var requestPtr *C.uint8_t
	if len(request) > 0 {
		requestPtr = (*C.uint8_t)(unsafe.Pointer(&request[0]))
	}

	var response C.cliproxy_buffer
	rc := C.cliproxy_invoke_host(host, cMethod, requestPtr, C.size_t(len(request)), &response)
	// request is Go memory handed to C for the duration of the call; the host
	// copies it out before returning, but it must not be collected mid-call.
	runtime.KeepAlive(request)

	if response.ptr != nil {
		defer C.cliproxy_release_host(host, response.ptr, response.len)
	}
	if rc != 0 {
		return nil, fmt.Errorf("host call %s failed with code %d", method, int(rc))
	}
	if response.ptr == nil || response.len == 0 {
		return nil, nil
	}
	return C.GoBytes(response.ptr, C.int(response.len)), nil
}

// decisionCounters tallies what the plugin did, for the management status page.
// Outcomes only -- never a cookie value.
type decisionCounters struct {
	// Harvest counts responses that contributed a pair to the pool.
	Harvest int64 `json:"harvest"`
	// Steer counts requests that left this process carrying a pooled pair.
	Steer int64 `json:"steer"`
	Pass  int64 `json:"pass"`
	Skip  int64 `json:"skip"`
}

type pluginState struct {
	mu     sync.Mutex
	config pluginConfig
	// cookies is the GLOBAL pool of live routing pairs, keyed by the pair set
	// itself (cookieEntryKey). The pair is account-agnostic, so the pool is not
	// partitioned by anything: writers are the response hooks and the probe,
	// readers are the request hook picking the best live entry.
	cookies map[string]*routeCookieEntry
	// cookiesDirty tracks whether the pool has unsaved changes; the file is
	// flushed at most once per routeCookieFlushInterval and once at shutdown.
	cookiesDirty   bool
	cookiesFlushed time.Time
	// counts and countsAt back the management status page. They are reset when a
	// role change invalidates what the tallies describe.
	counts   decisionCounters
	countsAt time.Time
	// configErrors holds complaints about the probe scope -- a malformed account
	// name, model id or proxy URL. They are collected rather than returned from
	// configure: probe scope is not load bearing for steering, and refusing to
	// register over a typo in a field the request path never reads would take
	// the production role down for a probe-time mistake. They surface on the
	// status page instead, where the operator who typed them will see them.
	configErrors []string
}

type pluginConfig struct {
	CloudMint cloudMintConfig `yaml:"cloud_mint"`
	// Role is "probe" or "business". Empty means "business": that is the role
	// that steers requests, which is what every deployed process is for; the
	// probe role is kept only as "touch nothing" for a collection-only box.
	Role string `yaml:"role"`
	// StoreDir is the directory holding the cookie pool file and the other
	// plugin-owned documents (runtime.json, probe-scope.json, observations.json).
	StoreDir string `yaml:"store_dir"`
	// TemplateLength and ReplaceLength are the two serving-state lengths the
	// observation tally was calibrated on: 292 was a normal state, 312 degraded,
	// both on the pre-unification format. They are classifiers now -- nothing
	// is stored or substituted off them -- and they are anchors rather than a
	// whitelist: a recurring unrecognised length is learned as its bucket's own
	// normal (see noteSignedLen), which is what keeps a format change like the
	// 292 -> 780 unification from misclassifying healthy traffic forever.
	TemplateLength int `yaml:"template_length"`
	ReplaceLength  int `yaml:"replace_length"`
	// TTLSeconds bounds how long a pooled pair stays usable, measured from when
	// it was last seen, shortened by the credential's own deadline -- the JWT's
	// exp when the value carries one, else the declared Max-Age/Expires.
	TTLSeconds int `yaml:"ttl_seconds"`
	// DryRun logs decisions without rewriting the outgoing Cookie header.
	DryRun bool `yaml:"dry_run"`
	// LogDecisions emits one line per steer/collect decision.
	LogDecisions bool `yaml:"log_decisions"`
	// Models is the list of model ids the dashboard offers and the probe uses
	// for its minting payload. It is no longer a harvest dimension -- the pair
	// is account-agnostic, so probing per model would just repeat the same
	// request.
	Models []string `yaml:"models"`
	// ProbeAccounts narrows which credentials a probe run may borrow. One
	// usable credential is enough for the whole run -- the minted pair is not
	// bound to the account that minted it -- so this is a borrowing order, not
	// a coverage list.
	ProbeAccounts []string `yaml:"probe_accounts"`
	// ProbeProxies is the ordered list of exits the probe dials. Each exit IP
	// lands on a different gateway node and mints a different pair, so the
	// pool's coverage is exactly the exit list.
	//
	// These values may carry userinfo. Everything that logs or complains about
	// them goes through maskProxyURL; the status document now reports them in the
	// clear at the operator's explicit instruction (see statusResponse).
	ProbeProxies []string `yaml:"probe_proxies"`
	// ProbeProxiesRotating is the same idea for exits whose address changes on
	// every connection -- a residential gateway rather than a fixed IP.
	//
	// They are a separate list because they are a different resource, not a
	// different flavour of the same one. A static exit is one IP: it mints one
	// node per visit. A rotating entry hands out a fresh address per request,
	// so each attempt may mint a DIFFERENT node -- which is why the rotating
	// path spends a whole attempt budget per visit instead of one call.
	//
	// Same secrecy rule as ProbeProxies: masked in every log line, served in the
	// clear on the status document at the operator's instruction.
	ProbeProxiesRotating []string `yaml:"probe_proxies_rotating"`
	// The two fields below exist for one reason: so the dashboard can run a probe
	// without the operator ever typing a key. That was the requirement, not a
	// convenience -- a run needs a bearer for the management calls, and prompting
	// for it on every run is exactly the friction the keyless dashboard exists to
	// remove. Typing it into an anonymously readable page would be worse than
	// leaving it in config.yaml, so it lives here and is read only by the probe
	// runner.
	//
	// ProbeManagementKey is the Bearer for /v0/management/*, used for the two
	// read-only calls that list the accounts and download one token.
	//
	// It is a secret, and is held to a stricter rule than the proxy list ever was:
	// it never reaches a log line (the configure line says set/unset and nothing
	// else), never reaches statusResponse, and never reaches configResponse. There
	// is no masked rendering of it anywhere, because there is no caller that has
	// any business seeing it.
	ProbeManagementKey string `yaml:"probe_management_key"`
	// ProbeBaseURL is where the probe runner sends both. It defaults to CPA's own
	// loopback listener because the plugin runs inside CPA: a probe talks to the
	// process hosting it, not out across the network.
	ProbeBaseURL string `yaml:"probe_base_url"`
}

// defaultProbeBaseURL is CPA's own loopback listener. It is the default rather
// than a required setting because the overwhelmingly common case -- the only one
// deployed -- is the plugin probing the process it is loaded into.
const defaultProbeBaseURL = "http://127.0.0.1:8317"

func defaultConfig() pluginConfig {
	return pluginConfig{
		CloudMint:      defaultCloudMintConfig(),
		Role:           "",
		StoreDir:       "",
		TemplateLength: 292,
		ReplaceLength:  312,
		// Measured 2026-09-22: the __oailb JWT signs exp-iat=3900 (the deadline
		// the gateway actually enforces; Max-Age/Expires declare only 3600 and
		// pairs have served past it). The default follows the credential's own
		// claim -- the pair's window is now bounded by that exp, not by the
		// transport attributes.
		TTLSeconds:   3900,
		DryRun:       false,
		LogDecisions: true,
		ProbeBaseURL: defaultProbeBaseURL,
	}
}

// isProbe reports whether this process is the collection-only half.
func (c pluginConfig) isProbe() bool {
	return strings.EqualFold(strings.TrimSpace(c.Role), roleProbe)
}

// ttl is the configured pool-entry lifetime as a duration.
func (c pluginConfig) ttl() time.Duration {
	return time.Duration(c.TTLSeconds) * time.Second
}

// maskProxyURL renders a proxy URL safe to log or hand to an unauthenticated
// reader. Userinfo is replaced wholesale rather than partially: a password's
// length is itself a hint, and a "first two characters" style mask has leaked
// more than it hid often enough to not be worth the readability.
//
// An unparsable value returns a fixed placeholder rather than itself. That is
// the important case: a URL malformed enough that net/url rejects it is exactly
// the one likely to be a password with a stray character in it, and echoing the
// input back "because we could not parse it" would publish the thing this
// function exists to hide.
func maskProxyURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse != nil || parsed.Host == "" {
		return "<unparsable proxy url>"
	}
	if parsed.User == nil {
		return parsed.String()
	}
	// Spliced in by hand rather than via url.User("***"): URL.String()
	// percent-encodes userinfo, so that route renders the mask as %2A%2A%2A --
	// safe, but unreadable in exactly the place an operator is trying to tell
	// two exits apart.
	stripped := *parsed
	stripped.User = nil
	out := stripped.String()
	marker := parsed.Scheme + "://"
	if !strings.HasPrefix(out, marker) {
		// An opaque or otherwise unexpected shape. Splicing into something we do
		// not recognise risks emitting a mangled URL that still contains part of
		// the original, so refuse rather than guess.
		return "<unparsable proxy url>"
	}
	return marker + "***@" + out[len(marker):]
}

// secretPresence renders a secret for a log line, and "set" or "unset" is the
// entire vocabulary. It exists for probe_management_key, which is never
// displayed anywhere -- not even masked. A length or a first-few-
// characters rendering is the obvious alternative and is rejected for the same
// reason maskProxyURL rejects it: both are hints, and the only question an
// operator ever has to answer from a log is whether the key is configured at all.
func secretPresence(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unset"
	}
	return "set"
}

// maskProxyURLs masks a whole list, preserving order so a masked entry can be
// matched against its position in the real list.
func maskProxyURLs(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		out = append(out, maskProxyURL(value))
	}
	return out
}

// proxySchemes are the exits CPA can actually dial. Anything else is a typo
// worth reporting: an unsupported scheme fails at request time, deep inside a
// probe run, where it looks like the upstream refusing rather than the config
// being wrong.
var proxySchemes = map[string]bool{"http": true, "https": true, "socks5": true, "socks5h": true}

// normaliseProbeScope trims and validates the probe-scope lists, returning the
// cleaned values and one human-readable complaint per rejected entry.
//
// Rejected entries are dropped from the returned list, not silently kept: a
// proxy URL we cannot parse would be PATCHed onto a live account verbatim, and
// an account name that is not a credential filename would steer a probe run at
// nothing. But the complaint is carried out so the operator learns which entry
// went and why -- a scope that quietly shrinks is how a probe run "completes"
// while covering less than the operator believes.
func normaliseProbeScope(accounts, models, proxies, rotating []string) ([]string, []string, []string, []string, []string) {
	var problems []string

	cleanAccounts := make([]string, 0, len(accounts))
	for _, raw := range accounts {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		// Shape only. Whether the file exists is deliberately not checked here:
		// configure runs before CPA has necessarily loaded every credential, and
		// a "no such account" at this point would be wrong as often as right.
		if !strings.HasPrefix(strings.ToLower(name), "codex-") || !strings.HasSuffix(strings.ToLower(name), ".json") {
			problems = append(problems, fmt.Sprintf("probe_accounts: %q is not a Codex credential filename (expected codex-*.json)", name))
			continue
		}
		if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			problems = append(problems, fmt.Sprintf("probe_accounts: %q contains a path component", name))
			continue
		}
		cleanAccounts = append(cleanAccounts, name)
	}

	cleanModels := make([]string, 0, len(models))
	for _, raw := range models {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, " \t\r\n") {
			problems = append(problems, fmt.Sprintf("models: %q contains whitespace", name))
			continue
		}
		cleanModels = append(cleanModels, name)
	}

	cleanProxies, proxyProblems := normaliseProxyList(proxies, "probe_proxies")
	problems = append(problems, proxyProblems...)
	cleanRotating, rotatingProblems := normaliseProxyList(rotating, "probe_proxies_rotating")
	problems = append(problems, rotatingProblems...)

	return cleanAccounts, cleanModels, cleanProxies, cleanRotating, problems
}

// normaliseProxyList validates one pool. Both pools get identical treatment --
// they differ in how the prober SPENDS them, never in what counts as a valid
// entry -- so they share this rather than keeping two copies that could drift on
// which schemes are accepted.
//
// field names the list in every complaint, because "unsupported scheme" is
// useless to an operator looking at two textareas.
func normaliseProxyList(proxies []string, field string) ([]string, []string) {
	var problems []string
	clean := make([]string, 0, len(proxies))
	for index, raw := range proxies {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		parsed, errParse := url.Parse(candidate)
		switch {
		case errParse != nil || parsed.Host == "":
			// Reported by its position in the configured list, never by value:
			// an entry too malformed to parse is the one most likely to be a
			// mistyped password, and the index is enough to find it.
			problems = append(problems, fmt.Sprintf("%s[%d]: not a valid URL", field, index))
			continue
		case !proxySchemes[strings.ToLower(parsed.Scheme)]:
			problems = append(problems, fmt.Sprintf("%s: unsupported scheme %q in %s (want http, https, socks5 or socks5h)", field, parsed.Scheme, maskProxyURL(candidate)))
			continue
		}
		clean = append(clean, candidate)
	}
	return clean, problems
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registerRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

// registrationCapability mirrors the host's rpcCapabilities JSON. Note that the
// stream chunk interceptor is advertised as "response_stream_interceptor", not
// the name of its Go interface -- getting that wrong is a silent no-op.
type registrationCapability struct {
	RequestInterceptor        bool `json:"request_interceptor"`
	ResponseInterceptor       bool `json:"response_interceptor"`
	StreamChunkInterceptor    bool `json:"response_stream_interceptor"`
	WebSocketResponseObserver bool `json:"websocket_response_observer"`
	ManagementAPI             bool `json:"management_api"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	// The host API is how the management handlers reach host.auth.list and
	// host.model.execute. It is handed over exactly once, before any other call,
	// and the host owns the allocation for the plugin's lifetime.
	if host != nil {
		atomic.StorePointer(&hostAPI, unsafe.Pointer(host))
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	cloudPoolFillerStop()
	currentCloudMintService().close()
	// Best effort, and only that: a docker kill never calls this, so the real
	// upper bound on lost observations stays observationsFlushInterval, and on
	// unflushed pool entries routeCookieFlushInterval. flushObservationsNow
	// runs before taking state.mu because it acquires a different lock.
	flushObservationsNow()

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.cookiesDirty && state.config.StoreDir != "" {
		if err := writeRouteCookiePool(state.config.StoreDir, state.cookies, time.Now(), state.config.ttl()); err != nil {
			log.Printf(logPrefix+"pool flush on shutdown failed: %v", err)
		}
	}
	state.cookies = make(map[string]*routeCookieEntry)
	state.cookiesDirty = false
	state.cookiesFlushed = time.Time{}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodRequestInterceptBefore:
		// Auth is not selected yet, so no bucket can be derived. Never touch
		// the header here.
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	case pluginabi.MethodRequestInterceptAfter:
		return interceptAfterAuth(request)
	case pluginabi.MethodResponseInterceptAfter:
		return interceptResponse(request)
	case pluginabi.MethodResponseInterceptStreamChunk:
		return interceptStreamChunk(request)
	case pluginabi.MethodWebSocketResponseEvent:
		return observeWebSocketEvent(request)
	case pluginabi.MethodManagementRegister:
		return managementRegister(request)
	case pluginabi.MethodManagementHandle:
		return managementHandle(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req registerRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	if req.SchemaVersion < 2 {
		return fmt.Errorf("codex-turn-state requires host schema version 2 or newer")
	}
	cfg := defaultConfig()
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return errUnmarshal
		}
	}

	if err := cfg.CloudMint.validate(); err != nil {
		return err
	}

	// Layer the keyless dashboard override on top of the config-file values.
	// role and dry_run are the two fields the dashboard changes without a
	// management key; persisting and re-applying them here is what lets a flip
	// survive the CPA restart a role change requires. The override only carries a
	// field the operator actually set, so an untouched field keeps its
	// config.yaml value. Everything below (role validation, the probe store_dir
	// check) then runs on the merged result, so an override cannot smuggle in an
	// invalid role.
	if ov, okOverride := readRuntimeOverride(strings.TrimSpace(cfg.StoreDir)); okOverride {
		if ov.Role != nil {
			cfg.Role = *ov.Role
		}
		if ov.DryRun != nil {
			cfg.DryRun = *ov.DryRun
		}
	}

	// An empty role means business: the half that neither writes nor harvests.
	// The deploy order installs the .so before config.yaml gains a role, and a
	// plugin that refuses to register in that window would look like a broken
	// build rather than an unfinished deploy.
	role := strings.ToLower(strings.TrimSpace(cfg.Role))
	switch role {
	case "":
		role = roleBusiness
	case roleProbe, roleBusiness:
	default:
		return fmt.Errorf("role must be %q or %q, got %q", roleProbe, roleBusiness, cfg.Role)
	}
	cfg.Role = role
	cfg.StoreDir = strings.TrimSpace(cfg.StoreDir)
	// Trimmed for the same reason store_dir is: a YAML value that picked up a
	// trailing newline or a stray space would be sent as part of the bearer and
	// come back as a 401, which reads as "the key is wrong" rather than "the key
	// has whitespace on it".
	cfg.ProbeManagementKey = strings.TrimSpace(cfg.ProbeManagementKey)
	// An explicitly empty probe_base_url is pinned to the default rather than left
	// empty: an absent key already yields the default (defaultConfig supplies it
	// before the unmarshal), so letting `probe_base_url: ""` mean something
	// different would be a distinction nobody intends, and it would surface as a
	// transport error deep inside a probe run.
	if cfg.ProbeBaseURL = strings.TrimSpace(cfg.ProbeBaseURL); cfg.ProbeBaseURL == "" {
		cfg.ProbeBaseURL = defaultProbeBaseURL
	}

	if cfg.TemplateLength < 1 {
		return fmt.Errorf("template_length must be greater than zero")
	}
	if cfg.ReplaceLength < 1 {
		return fmt.Errorf("replace_length must be greater than zero")
	}
	if cfg.TemplateLength == cfg.ReplaceLength {
		return fmt.Errorf("template_length and replace_length must differ, both are %d", cfg.TemplateLength)
	}
	if cfg.TTLSeconds < 1 {
		return fmt.Errorf("ttl_seconds must be greater than zero")
	}
	// A probe with nowhere to write is a probe that silently collects nothing,
	// which is worse than failing loudly at configure time.
	if cfg.isProbe() && cfg.StoreDir == "" {
		return fmt.Errorf("role %q requires store_dir", roleProbe)
	}

	// Probe scope is validated but never fatal. These three lists steer a probe
	// run; none of them is consulted when deciding a substitution, so a typo here
	// must not stop the business role from registering. The complaints ride out
	// on the status page instead.
	var scopeProblems []string
	cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies, cfg.ProbeProxiesRotating, scopeProblems =
		normaliseProbeScope(cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies, cfg.ProbeProxiesRotating)

	// A saved scope overrides config.yaml outright. The dashboard is the editing
	// surface now, so the alternative -- config.yaml quietly winning -- would
	// mean the operator saves a selection, sees it applied, and then watches it
	// revert at the next reconfigure with nothing to explain why. CPA rewrites
	// config.yaml on its own, so that reconfigure is not hypothetical.
	//
	// config.yaml still supplies the starting values: it is what the scope is
	// before anything has ever been saved.
	scopeSource := "config.yaml"
	if saved, errScope := loadProbeScope(cfg.StoreDir); errScope != nil {
		scopeProblems = append(scopeProblems,
			"probe scope file unreadable, falling back to config.yaml: "+errScope.Error())
	} else if saved != nil {
		var savedProblems []string
		cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies, cfg.ProbeProxiesRotating, savedProblems =
			normaliseProbeScope(saved.Accounts, saved.Models, saved.Proxies, saved.Rotating)
		scopeProblems = append(scopeProblems, savedProblems...)
		scopeSource = scopeFileName + " (saved " + saved.UpdatedAt + ")"
	}

	state.mu.Lock()
	// The host reconfigures far more often than the config actually changes:
	// five times during startup alone, and again every time CPA rewrites
	// config.yaml on its own. swapConfigLocked clears the pool only on a change
	// that invalidates it, so a no-op reconfigure keeps it intact. The pool is
	// then (re)loaded: the file is the persistent copy and loading it also folds
	// in any legacy per-bucket cookie fields -- one cheap scan, idempotent.
	cloudChanged := state.config.CloudMint != cfg.CloudMint || state.config.DryRun != cfg.DryRun || state.config.Role != cfg.Role
	cleared, _ := swapConfigLocked(cfg)
	state.cookies = loadRouteCookiePool(cfg.StoreDir)
	state.cookiesDirty = false
	state.cookiesFlushed = time.Time{}
	state.configErrors = scopeProblems
	state.mu.Unlock()
	if cloudChanged {
		resetCloudMintService()
		cloudPoolFillerReconfigure(cfg)
	}

	// Outside state.mu: loadObservations takes its own lock and must never be
	// reached while holding this one. It is a no-op when store_dir has not
	// changed, which matters because the host reconfigures constantly and the
	// operator is watching these counts.
	loadObservations(cfg.StoreDir)

	pool := "pool kept"
	if cleared {
		pool = "pool cleared"
	}
	// Counts, not contents. probe_proxies may carry userinfo, so the only safe
	// thing to say about it in a log line is how many there are -- that rule is
	// unchanged by the status document now showing them, because a log is copied
	// into tickets and chat windows and the status document is not.
	//
	// The probe key gets less than that: set or unset, via secretPresence.
	// probe_base_url is not a secret and is printed, because "the probe cannot
	// reach CPA" is diagnosed from exactly that value.
	log.Printf(logPrefix+"configured role=%s store_dir=%q template_length=%d replace_length=%d ttl_seconds=%d dry_run=%t models=%d probe_accounts=%d probe_proxies=%d probe_proxies_rotating=%d probe_base_url=%q probe_management_key=%s scope_from=%s (%s)",
		cfg.Role, cfg.StoreDir, cfg.TemplateLength, cfg.ReplaceLength, cfg.TTLSeconds, cfg.DryRun,
		len(cfg.Models), len(cfg.ProbeAccounts), len(cfg.ProbeProxies), len(cfg.ProbeProxiesRotating), cfg.ProbeBaseURL,
		secretPresence(cfg.ProbeManagementKey), scopeSource, pool)
	for _, problem := range scopeProblems {
		// One line each, and loud: a dropped scope entry means the next probe run
		// covers less than whoever edited the config believes it does.
		log.Printf(logPrefix+"config error (probe scope, not fatal): %s", problem)
	}
	return nil
}

// poolInvalidatedBy reports whether moving from oldCfg to newCfg makes the
// pooled pairs unusable. The pool is keyed by nothing but the pair values
// themselves, so almost nothing invalidates it: store_dir moving means the
// file on disk is a different store's. ttl_seconds is deliberately absent --
// usability is re-judged against the current ttl on every read, so a shorter
// ttl takes effect immediately and a longer one does not resurrect dead pairs
// (their seenAt is still what it was).
func poolInvalidatedBy(oldCfg, newCfg pluginConfig) bool {
	return oldCfg.StoreDir != newCfg.StoreDir
}

// swapConfigLocked installs cfg as the running config and updates the derived
// state that depends on it. The caller must hold state.mu. It returns whether
// the pool was cleared and whether the role changed, for the caller's logging.
func swapConfigLocked(cfg pluginConfig) (cleared, roleChanged bool) {
	cleared = poolInvalidatedBy(state.config, cfg)
	roleChanged = !strings.EqualFold(state.config.Role, cfg.Role)
	state.config = cfg
	if cleared {
		state.cookies = make(map[string]*routeCookieEntry)
		state.cookiesDirty = false
		state.cookiesFlushed = time.Time{}
	}
	// Tallies describe one role's behaviour, and the two roles cannot produce
	// the same mix: probe never steers, because its request hook returns
	// untouched. Carrying a count across the switch would leave the status page
	// attributing one role's decisions to the other.
	if roleChanged {
		state.counts = decisionCounters{}
		state.countsAt = time.Now()
	}
	return cleared, roleChanged
}

func pluginRegistration() registration {
	// Every hook is advertised in both roles, and the response side is the part
	// that changed.
	//
	// It used to be probe-only, back when harvesting meant reading CPA's own
	// responses and substituting would have destroyed the very state being
	// collected. The harvester is offline now -- it calls the upstream directly
	// and never touches these hooks -- so that exclusion protects nothing and
	// costs something real: a bucket the probe cannot fill (every exit throttled)
	// stays empty, its requests therefore go upstream untouched, and the upstream
	// mints a turn-state on each one that nobody was listening for.
	//
	// Reading it is free -- the request was happening anyway, no quota is spent --
	// and it is self-limiting: once the pool holds a live pair the request hook
	// steers with it, the edge stops minting fresh pairs, and this side goes
	// quiet until the pair lapses. See harvestFromResponse.
	//
	// The request hook stays declared in both roles too: it deliberately does
	// nothing under probe, and declaring it keeps the roles on one code path so
	// "probe rewrote a request" is something the logs can rule out rather than
	// something the host never offered. The management routes are declared in
	// both roles because the status page is how an operator checks a role switch
	// actually took.
	capabilities := registrationCapability{
		RequestInterceptor:        true,
		ManagementAPI:             true,
		ResponseInterceptor:       true,
		StreamChunkInterceptor:    true,
		WebSocketResponseObserver: true,
	}

	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "Codex Cloud Mint",
			Version:          "0.3.3-ws-chain",
			Author:           "arden-aaai",
			GitHubRepository: "https://github.com/arden-aaai/cpa-plugin-codex-turn-state",
			ConfigFields: []pluginapi.ConfigField{

				{
					Name:        "role",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{roleProbe, roleBusiness},
					Description: "Whether this process rewrites requests. \"business\" merges the pool's best live __cflb/__oailb pair into attributable Codex requests; \"probe\" leaves every request exactly as it found it. Empty means business. Both roles collect pairs and observe serving states off upstream responses -- role does not switch that off.",
				},
				{
					Name:        "store_dir",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Directory holding the route-cookie pool file (route-cookies.json) and the other plugin-owned documents (runtime.json, probe-scope.json, observations.json). Required for role=probe.",
				},
				{
					Name:        "template_length",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Turn-state length classifying a NORMAL serving state (default 292). An anchor, not a whitelist: each bucket learns its own recurring signature. Observation only -- nothing is stored or substituted off it.",
				},
				{
					Name:        "replace_length",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Turn-state length classifying a DEGRADED serving state (default 312). Observation only -- nothing is stored or substituted off it.",
				},
				{
					Name:        "ttl_seconds",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "How long a pooled __cflb/__oailb pair stays usable, measured from when it was last seen and shortened by the pair's own declared deadline (default 3600, matching the upstream's declared one-hour Max-Age/Expires).",
				},
				{
					Name:        "dry_run",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Log decisions without rewriting the outgoing Cookie header.",
				},
				{
					Name:        "log_decisions",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Emit one log line per harvest or steer decision.",
				},
				{
					Name:        "models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Official model ids the probe uses for its minting payload. Recorded so the running config and the probe script cannot drift apart; the pair itself is model-agnostic.",
				},
				{
					Name:        "probe_accounts",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Credential filenames the probe run may borrow. PROBE SCOPE ONLY: the business path never reads this, and one usable credential is enough -- a minted pair is not bound to the account that minted it.",
				},
				{
					Name:        "probe_proxies",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Ordered exits the probe tries per bucket, applied to the probed account's own proxy_url. PROBE SCOPE ONLY; never read by the business path. May contain credentials, so it is masked in every log line; the status document shows it in the clear at the operator's explicit request.",
				},
				{
					Name:        "probe_proxies_rotating",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Exits whose address changes on every connection (a residential gateway). PROBE SCOPE ONLY; never read by the business path. Separate from probe_proxies because a rotating entry is re-dialed on a 312 -- the next request is a different address -- while a static one is not. Masked in every log line.",
				},
				{
					Name:        "probe_management_key",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Bearer the probe runner sends to /v0/management/*, for the two read-only calls that list the accounts and download one token. PROBE SCOPE ONLY; never read by the business path. It exists so the dashboard needs no key from the operator, and it is NEVER displayed anywhere, masked or otherwise -- not on the status page, not in the config response, not in a log line (which reports only set/unset).",
				},
				{
					Name:        "probe_base_url",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Where the probe runner sends the above (default http://127.0.0.1:8317, CPA's own loopback listener). PROBE SCOPE ONLY; never read by the business path. Not a secret.",
				},
				{
					Name:        "cloud_mint",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "云端打票（默认关闭）：enabled/url/proxy_url/proxy_env/key_env/transport/gateway/ticket_length/ttl_seconds/wait_ms/timeout_ms。密钥只从环境变量读取；冷启动短等待，未就绪返回 503。",
				},
			},
		},
		Capabilities: capabilities,
	}
}

// interceptAfterAuth runs once the scheduler has picked a credential, so both
// halves of the bucket key are known.
func interceptAfterAuth(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// The probe must leave requests exactly as it found them. Attaching a pooled
	// pair here would pin the request onto a node the edge already knows -- the
	// fresh pair the probe exists to collect would never be minted.
	if cfg.isProbe() {
		return noop()
	}

	authID := metadataString(req.Metadata, selectedAuthMetadataKey)
	authIndex := metadataString(req.Metadata, selectedAuthIndexMetadataKey)
	model := pickModel(req.Model, req.RequestedModel)
	value := headerValue(req.Headers, turnStateHeader)

	// Hand the account across to the response hook, which cannot see it: CPA
	// gives the two hooks different metadata maps, so this is the only point in
	// the request where the harvest side can learn which credential served it.
	// Recorded before any of the decisions below, and deliberately even for a
	// request this plugin is going to leave completely alone -- that is
	// precisely the request whose response carries a fresh state and Set-Cookie
	// pair worth collecting, because nothing was steered into it.
	//
	// Only the observed name is relayed. An inferred one is a guess that belongs
	// to this request's own decision, not something to hand to another hook that
	// would then record it as fact.
	rememberRequestAuth(req.RequestID, authID)
	if cfg.CloudMint.Enabled {
		return okEnvelope(interceptCloudMint(req, cfg))
	}

	// The same metadata gap the collection side has, mirrored here. A minimal
	// request carries no metadata, so selected_auth_id is absent
	// (publishSelectedAuthMetadata early-returns on an empty map,
	// conductor_execution.go:1726). Real Codex traffic sends session metadata and
	// never enters this branch, but a metadata-less request under a single-account
	// deployment would otherwise never be steered -- a real defect.
	//
	// Inferred under the same condition harvesting uses: exactly one enabled
	// Codex account. Note what that is now and is not. The offline probe no
	// longer switches accounts on and off, so a single enabled account is a
	// property of how the operator happens to have CPA configured, not an
	// invariant this plugin establishes or can rely on. It is checked on every
	// call for that reason. With two enabled, a guess would pin the routing
	// cookies onto a request that may not be Codex at all, so anything but a
	// clean sole account leaves authID empty and the request untouched.
	if authID == "" && model != "" {
		if sole, _, errSole := soleEnabledCodexAuth(); errSole == nil && sole != "" {
			authID = sole
		}
	}

	// Rule 1: steer only onto attributable Codex traffic. The pair is a routing
	// credential of OpenAI's -- replaying it onto a request heading for another
	// provider's upstream would leak it there. "Attributable" means the host's
	// own credential catalog verifies the selected auth as Codex -- the
	// sole-inferred name above is checked the same way, never trusted on its
	// own. The filename convention (looksCodexAuthID) survives only for when
	// the catalog itself cannot be read: a codex-named file holding another
	// provider's credential is precisely the leak this rule exists for, and
	// only the provider the host registered catches it.
	codex := false
	if authID != "" || authIndex != "" {
		if verified, resolved := selectedAuthIsCodex(authID, authIndex); resolved {
			codex = verified
		} else {
			codex = looksCodexAuthID(authID)
		}
	}
	if !codex {
		if value != "" || authID != "" {
			logDecision("skip", authID, model, len(value), "request not attributable to a Codex account")
		}
		return noop()
	}
	cloudRememberRequest(req, pluginapi.RequestInterceptResponse{})

	now := time.Now()
	state.mu.Lock()
	set, pairKey, haveCookies := state.bestRouteCookieLocked(now, cfg.ttl())
	state.mu.Unlock()
	if !haveCookies {
		logDecision("pass", authID, model, len(value), "no live route-cookie pair in the pool")
		return noop()
	}

	current := headerValue(req.Headers, "Cookie")
	merged := mergeRouteCookies(current, set.pairs)
	if merged == current {
		logDecision("pass", authID, model, len(value), "route cookies already current")
		return noop()
	}

	if cfg.DryRun {
		logDecision("steer", authID, model, len(value), "route cookies ready but withheld (dry_run)")
		return noop()
	}
	// Relay the exact pool key so the response hook stamps good/bad onto the
	// entry this request actually carried -- re-picking "best" on the response
	// side could land on a different entry once marks shift the scores.
	markRequestSteered(req.RequestID, pairKey)
	logDecision("steer", authID, model, len(value), "route cookies merged")

	out := pluginapi.RequestInterceptResponse{}
	out.ClearHeaders = append(out.ClearHeaders, "Cookie")
	out.Headers = http.Header{}
	out.Headers.Set("Cookie", merged)
	cloudRememberRequest(req, out)
	return okEnvelope(out)
}

// interceptResponse is the in-band harvest point for non-streaming responses.
// It never modifies the response: an empty ResponseInterceptResponse leaves
// every header and the body exactly as the upstream sent them.
//
// Runs in both roles. CPA hands this hook the RAW upstream headers -- the
// stripping in downstreamHeadersAfterInterceptors happens afterwards and only
// affects what the client sees -- so the turn-state is visible here even though
// the client never receives it.
func interceptResponse(raw []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if cloudHasRequestLog(req.RequestID) || headerValue(req.ResponseHeaders, turnStateHeader) != "" {
		cloudLogResponse(req.RequestID, req.ResponseHeaders, "")
		cloudLogResponseBody(req.RequestID, req.Body)
	}
	harvestFromResponse(cfg, req.ResponseHeaders, req.Metadata, pickModel(req.Model, req.RequestedModel), req.RequestID)
	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

// interceptStreamChunk is the in-band harvest point for SSE responses, which is
// the path real Codex traffic actually takes. Response headers are only
// populated on the header-init call. Payload chunks get one cheap check: the
// first "model" field in the stream is what the upstream actually served, and
// under the unified turn-state format a mismatch against the requested model is
// the degraded signature (the safety-buffering fallback answering the turn) --
// everything else is returned untouched without even looking at it. The watch
// is armed per request at header-init and fires once, so the steady-state cost
// per chunk is one map lookup.
//
// Runs in both roles, and on the header-init chunk CPA supplies the raw upstream
// headers alongside the same metadata the request hook saw, so the harvest is
// attributed to the account CPA actually selected rather than inferred.
func interceptStreamChunk(raw []byte) ([]byte, error) {
	var req pluginapi.StreamChunkInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	if req.ChunkIndex != pluginapi.StreamChunkHeaderInitIndex {
		cloudLogStreamChunk(req.RequestID, req.Body)
		noteServedModelChunk(req)
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if cloudHasRequestLog(req.RequestID) || headerValue(req.ResponseHeaders, turnStateHeader) != "" {
		cloudLogResponse(req.RequestID, req.ResponseHeaders, "")
	}
	harvestFromResponse(cfg, req.ResponseHeaders, req.Metadata, pickModel(req.Model, req.RequestedModel), req.RequestID)
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

// WS 仅记录严格解析的 created 声明及终止事件，不逐片段刷屏或输出账号文件名。
func observeWebSocketEvent(raw []byte) ([]byte, error) {
	var event pluginapi.WebSocketResponseEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}
	if cloudObserveWSChain(event) {
		return okEnvelope(struct{}{})
	}
	if event.EventType == "error" || event.EventType == "response.failed" {
		cloudRecordLog("WS 异常", "账号 #%s · %s · 请求模型 %s", cloudFingerprint(event.AuthID), event.EventType, cloudSafeLabel(pickModel(event.Model, event.RequestedModel)))
	}
	return okEnvelope(struct{}{})
}

// pendingAuth correlates the two halves of one request.
//
// The request hook knows which credential CPA selected; the response hook does
// not, and the reason is not that the name is unavailable but that CPA hands the
// two hooks DIFFERENT maps. handlers_interceptors.go:565 passes the executor's
// req.Metadata -- the map publishSelectedAuthMetadata writes into -- while :595
// passes the handler's opts.Metadata, which it never touches. Both are called
// "Metadata", which is why the older comment here claimed they were the same
// object; measured on 2026-09-18, the response side is always auth=-.
//
// Both hooks do carry the same RequestID (:556 and :584), so that is the join
// key. This is not an inference: the value relayed is the account CPA itself
// selected, merely carried across a hook boundary that drops it.
type pendingAuthEntry struct {
	authID string
	// steered reports whether the request actually went upstream carrying a
	// pooled pair we put there. Set after the decision, not with it: a dry_run
	// decision is not a write, and the observation tally's whole
	// natural-vs-steered split collapses if intent is counted as action.
	steered bool
	// pairKey is the pool key (cookieEntryKey) of the pair attached, so the
	// response hook can stamp good_at/bad_at onto exactly that entry.
	pairKey string
	seenAt  time.Time
}

var pendingAuth = struct {
	mu   sync.Mutex
	byID map[string]pendingAuthEntry
}{byID: make(map[string]pendingAuthEntry)}

const (
	// pendingAuthTTL bounds how long a request may take between its two hooks.
	// A streamed Codex turn can run for minutes, so this is generous; it exists
	// to stop a request that never produced a response from leaking an entry.
	pendingAuthTTL = 15 * time.Minute
	// pendingAuthMax triggers a sweep. Entries are small and short-lived, so this
	// only matters if responses stop arriving entirely.
	pendingAuthMax = 4096
)

// rememberRequestAuth records the credential the request hook saw.
//
// Called on every request, including the ones where no account was observed.
// That case has to clear any entry already under this id rather than return:
// if CPA retries a request under the same RequestID and the second pass
// carries no selected_auth_id, leaving the first pass's entry in place would
// file the retry's response against the FIRST account -- one customer's
// throttling recorded on another's row. Dropping the entry loses the
// observation instead, which is the right way to be wrong here.
func rememberRequestAuth(requestID, authID string) {
	if requestID == "" {
		return
	}
	now := time.Now()
	pendingAuth.mu.Lock()
	defer pendingAuth.mu.Unlock()
	if authID == "" {
		delete(pendingAuth.byID, requestID)
		return
	}
	if len(pendingAuth.byID) >= pendingAuthMax {
		for key, entry := range pendingAuth.byID {
			if now.Sub(entry.seenAt) > pendingAuthTTL {
				delete(pendingAuth.byID, key)
			}
		}
	}
	// Whole-entry replacement, which resets steered to false. Load bearing: the
	// decision this id's response should be judged against is the one this
	// pass is about to make, and carrying a previous pass's steered flag
	// forward would mark a request we left alone as one we steered.
	pendingAuth.byID[requestID] = pendingAuthEntry{authID: authID, seenAt: now}
}

// markRequestSteered records that the request hook really did put a pooled
// pair on the outgoing request, and which entry it was. Separate from
// rememberRequestAuth because the account is known before the decision and the
// decision is known after.
//
// A missing entry is not an error: rememberRequestAuth only records an OBSERVED
// account, so a request attributed by inference has nothing to mark. The
// observation is then dropped for want of attribution, which is the right
// outcome -- a guessed account on a throttling tally would blame the wrong
// customer.
func markRequestSteered(requestID, pairKey string) {
	if requestID == "" {
		return
	}
	pendingAuth.mu.Lock()
	defer pendingAuth.mu.Unlock()
	if entry, ok := pendingAuth.byID[requestID]; ok {
		entry.steered = true
		entry.pairKey = pairKey
		pendingAuth.byID[requestID] = entry
	}
}

// recallRequestRecord returns what the request hook recorded for this request
// and forgets it: one request yields one response, so holding the entry
// afterwards is pure leak. An entry older than pendingAuthTTL is treated as
// absent.
func recallRequestRecord(requestID string) (authID string, steered bool, pairKey string) {
	if requestID == "" {
		return "", false, ""
	}
	pendingAuth.mu.Lock()
	defer pendingAuth.mu.Unlock()
	entry, ok := pendingAuth.byID[requestID]
	if !ok {
		return "", false, ""
	}
	delete(pendingAuth.byID, requestID)
	if time.Since(entry.seenAt) > pendingAuthTTL {
		return "", false, ""
	}
	return entry.authID, entry.steered, entry.pairKey
}

// pendingModelScan is the same correlation pendingAuth does at the
// request/response boundary, extended one step further into the stream. Under
// the unified turn-state format the degraded signal is no longer a length --
// every refusal path mints the same 780 -- it is the SSE payload declaring a
// served model different from the requested one (the x-codex-safety-buffering
// fallback answering the turn). The entry is armed at header-init, where
// authID/steered/pairKey are all resolved, and consumed by the first payload
// chunk that yields a "model" field.
type pendingModelScanEntry struct {
	authID  string
	model   string // the model asked for upstream
	tsLen   int    // the turn-state length this response signed, for feed context
	steered bool
	pairKey string
	seenAt  time.Time
}

var pendingModelScans = struct {
	mu   sync.Mutex
	byID map[string]pendingModelScanEntry
}{byID: make(map[string]pendingModelScanEntry)}

// pendingModelScanMaxChunk bounds how deep into a stream the watch stays
// armed: response.created is always the first SSE event, so a chunk this far
// in without a model field means the stream has nothing to tell us and the
// entry is dropped rather than carried to the end of the stream.
const pendingModelScanMaxChunk = 8

// rememberModelScan arms the watch for one request. Entries are TTL'd by the
// same sweep pendingAuth uses; a stream that ends without ever declaring a
// model leaves one to be reclaimed there.
func rememberModelScan(requestID, authID, model string, tsLen int, steered bool, pairKey string) {
	if requestID == "" || authID == "" || model == "" {
		return
	}
	now := time.Now()
	pendingModelScans.mu.Lock()
	defer pendingModelScans.mu.Unlock()
	if len(pendingModelScans.byID) >= pendingAuthMax {
		for key, entry := range pendingModelScans.byID {
			if now.Sub(entry.seenAt) > pendingAuthTTL {
				delete(pendingModelScans.byID, key)
			}
		}
	}
	pendingModelScans.byID[requestID] = pendingModelScanEntry{
		authID: authID, model: model, tsLen: tsLen, steered: steered, pairKey: pairKey, seenAt: now,
	}
}

// recallModelScan consumes the watch. One request yields one verdict -- the
// first declared model IS the answer, so the entry never survives being read.
func recallModelScan(requestID string) (pendingModelScanEntry, bool) {
	pendingModelScans.mu.Lock()
	defer pendingModelScans.mu.Unlock()
	entry, ok := pendingModelScans.byID[requestID]
	if ok {
		delete(pendingModelScans.byID, requestID)
		if time.Since(entry.seenAt) > pendingAuthTTL {
			return pendingModelScanEntry{}, false
		}
	}
	return entry, ok
}

// dropModelScan disarms a watch without a verdict -- the stream ran past the
// scan window without declaring a model.
func dropModelScan(requestID string) {
	pendingModelScans.mu.Lock()
	delete(pendingModelScans.byID, requestID)
	pendingModelScans.mu.Unlock()
}

// noteServedModelChunk is the payload-chunk path of the stream hook. It must
// stay cheap: one map lookup per chunk while a watch is armed, and the first
// extraction ends the watch. Nothing on this path takes state.mu -- a per-chunk
// lock on the steering mutex would put hook latency on every stream's every
// chunk; the one exception is the rare mismatch below, which pays it once.
func noteServedModelChunk(req pluginapi.StreamChunkInterceptRequest) {
	if req.RequestID == "" {
		return
	}
	if req.ChunkIndex > pendingModelScanMaxChunk {
		dropModelScan(req.RequestID)
		return
	}
	served, ok := servedModelFromChunk(req.Body)
	if !ok {
		return
	}
	entry, found := recallModelScan(req.RequestID)
	if !found {
		return
	}
	if served == entry.model {
		// The upstream served what was asked; the watch is over either way.
		return
	}
	recordDowngrade(entry.authID, entry.model, served, entry.tsLen, entry.steered)
	logDecision("downgrade", entry.authID, entry.model, entry.tsLen, "served="+served)
	if entry.steered && entry.pairKey != "" {
		// A downgrade on a steered request says the node did not serve the asked
		// model -- same weight as a degraded signature on the old format.
		state.mu.Lock()
		state.markRouteCookieOutcomeLocked(entry.pairKey, observationLimited, time.Now())
		state.mu.Unlock()
	}
}

// servedModelFromChunk extracts the first "model" field of a payload chunk. On
// a Codex SSE stream that is response.created's declared model -- the first
// event, before any output item -- so the first match is the verdict and no
// event-name parsing is needed. A value split across a chunk boundary is
// missed on both sides; that is rare enough (the field sits inside a ~1 KB
// opening event) that buffering tails would buy nothing.
func servedModelFromChunk(body []byte) (string, bool) {
	const needle = `"model":"`
	i := bytes.Index(body, []byte(needle))
	if i < 0 {
		return "", false
	}
	rest := body[i+len(needle):]
	j := bytes.IndexByte(rest, '"')
	if j <= 0 {
		return "", false
	}
	return string(rest[:j]), true
}

// harvestFromResponse is where the pool and the observation tally are fed.
// It never modifies the response, and everything it rejects still costs
// nothing: a Set-Cookie pair rides on any response, including a degraded one.
func harvestFromResponse(cfg pluginConfig, headers http.Header, metadata map[string]any, model, requestID string) {
	value := headerValue(headers, turnStateHeader)
	now := time.Now()
	cookies := routeCookiesFromResponseHeaders(headers, now)

	// Take the request-side record first, and unconditionally. It is consumed
	// on read, and both the observation below and the outcome marking further
	// down need it -- reading it twice would hand the second caller nothing.
	relayedAuth, steered, pairKey := recallRequestRecord(requestID)

	authID := metadataString(metadata, selectedAuthMetadataKey)
	if authID == "" {
		// Expected on this hook, not exceptional: the response side is handed a
		// different metadata map than the request side, so the name is never
		// there. Recover it by RequestID from what the request hook recorded --
		// see pendingAuth. Still the account CPA selected, not a guess.
		authID = relayedAuth
	}

	// Last resort for the account name, and dead code under role: business.
	//
	// Normally the name comes off the metadata above, or is relayed by
	// RequestID from what the request hook recorded (see pendingAuth). Only a
	// request that carried no metadata at all gets this far, because the host
	// publishes selected_auth_id only when the request brought a map of its
	// own (publishSelectedAuthMetadata early-returns on an empty one,
	// conductor_execution.go:1726).
	//
	// The isProbe gate then closes it entirely on the deployment this runs in:
	// role is business permanently, and the probe is triggered through
	// /ops/probe/start rather than by switching role, so nothing sets probe.
	// Measured 2026-09-20 over 3.3h of live traffic: 15 buckets, every one
	// attributed observed, none inferred. Do not spend effort here.
	//
	// Response-side inference is also the weaker of the two: enabled is
	// !Disabled && !Unavailable behind a 2s cache (cachedCodexAuths), so an
	// account that entered cooldown after dispatch still reads as enabled.
	// Any signed state qualifies -- not just the two configured lengths:
	// those are per-plan measurements, and gating attribution on them would
	// silently stop working the day the upstream signs a different size.
	if authID == "" && model != "" && len(value) > 0 && cfg.isProbe() {
		if sole, _, errSole := soleEnabledCodexAuth(); errSole == nil && sole != "" {
			authID = sole
		}
	}

	// Before the empty check, deliberately. A response carrying no state at all
	// is the signal that the pair we steered with was ACCEPTED -- the upstream
	// had no reason to sign a new one. Skipping silence would leave every
	// healthy bucket looking unobserved. See bucketObservation.
	recordObservation(cfg, authID, model, len(value), steered)

	// A freshly observed __cflb/__oailb pair enters the GLOBAL pool. The pair is
	// account-agnostic, so this needs no bucket key at all: any live pair serves
	// any account's next request.
	if len(cookies.pairs) > 0 {
		state.mu.Lock()
		state.noteRouteCookiesLocked(cookies, "")
		state.mu.Unlock()
		logDecision("harvest", authID, model, len(value), "route-cookie pair pooled")
	}

	// Stamp the outcome back onto the pair this request carried, when it carried
	// one. A normal state is evidence the steered node serves well; a degraded
	// one deprioritises the entry for the next pick (ambiguous -- the account
	// may be the throttled half -- so it is a nudge, never a delete).
	if steered && pairKey != "" {
		kind := classifyObservation(cfg, len(value))
		state.mu.Lock()
		state.markRouteCookieOutcomeLocked(pairKey, kind, now)
		state.mu.Unlock()
	}

	// Arm the served-model watch for the payload chunks that follow. The
	// header-init harvest above read the length signature; the unified format's
	// degraded signal lives in the stream body instead, and this is where the
	// request id, resolved account and steer context all exist at once.
	rememberModelScan(requestID, authID, model, len(value), steered, pairKey)
}

// runtimeOverride is the persisted form of the two dashboard-settable fields.
// Both are pointers so "absent" is distinct from "set to the zero value": a file
// that only ever recorded a dry_run flip must not also assert role="" (business)
// and silently switch the role. Only a field that was actually written is applied.
type runtimeOverride struct {
	Role   *string `json:"role,omitempty"`
	DryRun *bool   `json:"dry_run,omitempty"`
}

// readRuntimeOverride loads the dashboard override from dir. A missing file is the
// normal case (fresh deploy, nobody has touched the dashboard) and returns
// ok=false with no error noise. A malformed file is treated the same way rather
// than failing configure: a corrupt override must never take down registration,
// and falling back to config.yaml is the safe direction.
func readRuntimeOverride(dir string) (runtimeOverride, bool) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return runtimeOverride{}, false
	}
	data, errRead := os.ReadFile(filepath.Join(dir, runtimeOverrideFileName))
	if errRead != nil {
		return runtimeOverride{}, false
	}
	var ov runtimeOverride
	if errUnmarshal := json.Unmarshal(data, &ov); errUnmarshal != nil {
		log.Printf(logPrefix+"ignoring malformed %s: %v", runtimeOverrideFileName, errUnmarshal)
		return runtimeOverride{}, false
	}
	if ov.Role == nil && ov.DryRun == nil {
		return runtimeOverride{}, false
	}
	return ov, true
}

// writeRuntimeOverride records the dashboard's current role and dry_run so a
// restart keeps them. It always writes both fields as a full snapshot of what the
// dashboard controls, so a later role flip cannot lose an earlier dry_run flip.
func writeRuntimeOverride(dir string, role string, dryRun bool) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty, cannot persist the dashboard override")
	}
	ov := runtimeOverride{Role: &role, DryRun: &dryRun}
	data, errMarshal := json.MarshalIndent(ov, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	return atomicWrite(filepath.Join(dir, runtimeOverrideFileName), append(data, '\n'))
}

// scopeFileName holds the probe scope the dashboard edits. It lives beside the
// store because that is the one directory this plugin owns and can write.
//
// It exists because the host offers no way for a plugin to persist its own
// config: there is a host.auth.save callback and nothing equivalent for
// configuration. Saving through CPA's own
// PATCH /v0/management/plugins/<id>/config is the alternative, and that route is
// authenticated -- which would put a management key in front of the one screen
// the operator asked to be keyless. Owning the file ourselves is what removes
// the key from the page entirely.
const scopeFileName = "probe-scope.json"

// probeScope is the editable half of the configuration: which buckets the next
// probe run covers and which exits it tries. None of it is read by the business
// path.
type probeScope struct {
	Accounts []string `json:"probe_accounts"`
	Models   []string `json:"models"`
	Proxies  []string `json:"probe_proxies"`
	// Absent in files written before the pools were split, which decodes to nil
	// and is exactly right: everything saved back then was a static exit.
	Rotating  []string `json:"probe_proxies_rotating,omitempty"`
	UpdatedAt string   `json:"updated_at"`
}

// loadProbeScope reads the saved scope, or returns nil when none exists. A
// missing file is the normal state before the operator has saved anything, not
// an error.
func loadProbeScope(dir string) (*probeScope, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	data, errRead := os.ReadFile(filepath.Join(dir, scopeFileName))
	if errRead != nil {
		if os.IsNotExist(errRead) {
			return nil, nil
		}
		return nil, errRead
	}
	var scope probeScope
	if errUnmarshal := json.Unmarshal(data, &scope); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return &scope, nil
}

// writeProbeScope persists the scope atomically. The file carries proxy
// userinfo, so it is written with the same 0600 the bucket files get -- see
// atomicWrite, which creates via os.CreateTemp and renames into place.
func writeProbeScope(dir string, scope probeScope) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty, so there is nowhere to save the probe scope")
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	data, errMarshal := json.MarshalIndent(scope, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	return atomicWrite(filepath.Join(dir, scopeFileName), append(data, '\n'))
}

// pickModel resolves the model the same way on both sides of the plugin. The
// probe and the business role must agree exactly, or an observation recorded
// under one name would never be found under the other.
func pickModel(model, requestedModel string) string {
	if resolved := strings.TrimSpace(model); resolved != "" {
		return resolved
	}
	return strings.TrimSpace(requestedModel)
}

// headerValue finds a header case-insensitively. http.Header.Get would only
// match the canonical spelling, and these headers reach the plugin through a
// JSON round trip that preserves whatever key the host used.
func headerValue(headers http.Header, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

// looksCodexAuthID reports whether a selected_auth_id names a Codex credential
// file -- the filename convention isCodexAuth falls back on when the host does
// not report a provider. On the steering path it is the degraded check used
// only when the credential catalog cannot be read at all; when the catalog
// answers, the provider it registered decides instead (selectedAuthIsCodex).
func looksCodexAuthID(authID string) bool {
	name := strings.ToLower(strings.TrimSpace(authID))
	return strings.HasPrefix(name, "codex-") && strings.HasSuffix(name, ".json")
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// logDecision records lengths and bucket identity only. The state value itself
// is a credential-adjacent secret and never reaches the logs.
func logDecision(decision, authID, model string, valueLen int, reason string) {
	if decision == "" {
		return
	}
	state.mu.Lock()
	enabled := state.config.LogDecisions
	// Counted regardless of log_decisions: the status page should still report
	// what the plugin is doing when the operator has quietened the log.
	switch decision {
	case "harvest":
		state.counts.Harvest++
	case "steer":
		state.counts.Steer++
	case "pass":
		state.counts.Pass++
	case "skip":
		state.counts.Skip++
	}
	state.mu.Unlock()
	if !enabled {
		return
	}
	log.Printf(logPrefix+"%s auth=%s model=%s len=%d (%s)", decision, orDash(authID), orDash(model), valueLen, reason)
}

func noop() ([]byte, error) {
	return okEnvelope(pluginapi.RequestInterceptResponse{})
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, errMarshal := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	if errMarshal != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"encode error"}}`)
	}
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
