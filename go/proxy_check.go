// proxy_check.go -- "can this exit reach OpenAI?", answered for the whole pool
// at once.
//
// # Why this exists
//
// The probe walks probe_proxies in order and gives up on an exit that fails,
// which is the right behaviour during a run but a terrible diagnostic: a pool
// where half the exits are dead still harvests, just slower and with fewer
// chances per bucket, and nothing on the page says so. This route answers the
// question directly, for every exit, without waiting for a probe run.
//
// # Why it costs no quota
//
// The reachability request carries NO Authorization and NO Chatgpt-Account-Id.
// An unauthenticated POST to the codex endpoint is answered 401 by OpenAI --
// measured, not assumed -- and a 401 is the success case here: it proves the
// request travelled through the exit, terminated TLS at OpenAI's edge, and was
// answered by the API rather than by the proxy, a captive portal or an
// interception box. No credential is touched, so a run is safe while business
// traffic and a probe are both live, and it cannot be the thing that trips a
// rate limit on an account.
//
// # Why the trace request is on chatgpt.com and not a third-party service
//
// Cloudflare's /cdn-cgi/trace on the same host reports the address the upstream
// actually sees, plus its country and edge datacenter. Asking ipinfo.io instead
// would add a dependency, and would report the exit for a request to ipinfo.io
// -- not necessarily the one OpenAI sees. It is best-effort: the verdict belongs
// to the API request alone, so a trace failure costs the address, never the
// answer.
//
// # What must never leak out of this file
//
// The results render on a page that needs no key, so every proxy goes out
// through probeShowProxy (userinfo replaced wholesale) and every error string
// through probeRedact. The exit address IS reported in the clear: it is strictly
// less sensitive than the proxy URL the status document already serves in the
// clear at the operator's instruction, and seeing it is the whole point -- a
// pool of twenty credentials on one gateway that resolves to three addresses is
// three exits wearing twenty hats, which nothing else on this page would reveal.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// proxyCheckTraceURL is Cloudflare's trace endpoint on the very host the probe
// talks to -- see the package comment for why not a third party. A var, not a
// const, for the same reason probeUpstreamURL is: the tests point it at a fake.
var proxyCheckTraceURL = "https://chatgpt.com/cdn-cgi/trace"

const (
	// One request's budget. Short on purpose: this is a liveness check, and an
	// exit that needs more than this to answer is not one the probe wants to
	// spend a bucket's attempt on either.
	proxyCheckRequestTimeout = 8 * time.Second

	// The whole batch's budget. The host serves this synchronously, so it has to
	// finish well inside any reasonable management timeout. With the parallelism
	// below, a pool of twenty answers in seconds when healthy and still returns a
	// complete document when every exit is a black hole.
	proxyCheckBudget = 45 * time.Second

	// Enough to make a large pool fast, low enough that twenty exits opening at
	// once does not look like a burst to a shared gateway. This spends no quota,
	// so unlike the probe's pacing there is no account-level limit to respect --
	// the only constraint is the gateway itself.
	proxyCheckParallel = 6

	// Only the status line and a few trace fields matter; bodies are drained to
	// let the socket be reused and otherwise dropped.
	proxyCheckMaxBody = 4 << 10

	// The model named in the unauthenticated body. The upstream rejects on the
	// missing credential before it ever looks at this, so it exists only to make
	// the request well-formed.
	proxyCheckFallbackModel = "gpt-5.5"
)

// The verdicts. Deliberately more than a boolean: "could not connect" and
// "connected and was refused" send an operator to completely different places --
// the first to the proxy vendor, the second to the exit's reputation -- and
// collapsing them into "failed" is what makes a pool look mysteriously broken.
const (
	// Which list an entry came from. These are the wire values the dashboard
	// keys its labels on.
	proxyPoolStatic   = "static"
	proxyPoolRotating = "rotating"

	proxyVerdictOK          = "ok"
	proxyVerdictBlocked     = "blocked"
	proxyVerdictRateLimited = "ratelimited"
	proxyVerdictUnexpected  = "unexpected"
	proxyVerdictDead        = "dead"
)

type proxyCheckResult struct {
	// Index is 1-based and matches the exit's position within its own pool, which
	// is also the order the probe tries them in. It is the only stable handle the
	// page has: a pool of twenty credentials on one gateway masks to twenty
	// identical strings, so the position is what tells them apart.
	Index int    `json:"index"`
	Pool  string `json:"pool"`
	Proxy string `json:"proxy"`
	// Rotated reports that two samples of this entry came back with different
	// addresses. Mismatch is set only when that DISPROVES the declaration.
	//
	// The evidence is deliberately one-directional. Two different addresses prove
	// an entry declared static is really rotating -- no fixed exit can do that.
	// Two identical addresses prove nothing about an entry declared rotating: a
	// small pool repeats by chance, and a gateway may hold an address for a few
	// seconds. So only the provable direction is ever flagged; the other would be
	// a false alarm telling the operator to undo a correct configuration.
	Rotated    bool   `json:"rotated"`
	Mismatch   string `json:"mismatch,omitempty"`
	Verdict    string `json:"verdict"`
	StatusCode int    `json:"status_code,omitempty"`
	MS         int64  `json:"ms"`
	ExitIP     string `json:"exit_ip,omitempty"`
	Country    string `json:"country,omitempty"`
	Colo       string `json:"colo,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type proxyCheckResponse struct {
	Checked    int `json:"checked"`
	OK         int `json:"ok"`
	Blocked    int `json:"blocked"`
	Dead       int `json:"dead"`
	Other      int `json:"other"`
	Mismatches int `json:"mismatches"`
	// DistinctIPs counts addresses across the STATIC pool only. Counting rotating
	// entries here would be meaningless -- they are supposed to differ every time,
	// so the number would just restate how many rotating entries there are. The
	// figure exists to answer one question, "are several static entries secretly
	// the same exit", and that question does not apply to a gateway.
	StaticChecked int                `json:"static_checked"`
	DistinctIPs   int                `json:"distinct_ips"`
	MS            int64              `json:"ms"`
	TimedOut      bool               `json:"timed_out,omitempty"`
	Direct        bool               `json:"direct,omitempty"`
	Note          string             `json:"note,omitempty"`
	Results       []proxyCheckResult `json:"results"`
}

// runProxyCheck tests every configured exit and reports one row each.
//
// It reads the pool the plugin actually holds, never a list supplied by the
// caller. That is not a limitation to work around: proxy URLs carry passwords,
// and this route is a keyless GET, so accepting them as query parameters would
// write the pool's credentials into the host's access log and into browser
// history. The dashboard tells the operator to save first instead.
func runProxyCheck() pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	model := proxyCheckFallbackModel
	if len(cfg.Models) > 0 {
		model = cfg.Models[0]
	}

	// One flat list carrying which pool each entry came from, so the whole batch
	// still runs through a single bounded worker set.
	type target struct {
		pool  string
		index int
		url   string
	}
	var targets []target
	for i, raw := range cfg.ProbeProxies {
		targets = append(targets, target{pool: proxyPoolStatic, index: i + 1, url: raw})
	}
	for i, raw := range cfg.ProbeProxiesRotating {
		targets = append(targets, target{pool: proxyPoolRotating, index: i + 1, url: raw})
	}

	out := proxyCheckResponse{Results: []proxyCheckResult{}}
	if len(targets) == 0 {
		// Both pools empty is a real configuration, not an error: probeHarvestBucket
		// turns it into a single direct attempt, so that is exactly what gets checked
		// here. Answering "nothing to check" would be wrong about what the probe will
		// actually do. Note this is only true when BOTH are empty -- a rotating pool
		// with no static entries does NOT fall back to direct, and neither does this.
		targets = append(targets, target{pool: proxyPoolStatic, index: 1, url: ""})
		out.Direct = true
		out.Note = "两个代理池都是空的 —— 探测会走本机直连，所以这里测的就是直连出口。"
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyCheckBudget)
	defer cancel()

	// Its own pool, discarded at the end. Sharing the probe run's clients would
	// couple a diagnostic to a live run's connection state, and these transports
	// have no reason to outlive the answer.
	pool := newProbeClientPool()
	defer pool.closeIdle()

	results := make([]proxyCheckResult, len(targets))
	gate := make(chan struct{}, proxyCheckParallel)
	var wg sync.WaitGroup
	started := time.Now()
	for slot, tgt := range targets {
		wg.Add(1)
		// Each goroutine writes its own element of a slice that is never resized,
		// so the results need no mutex.
		go func(slot int, t target) {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			results[slot] = proxyCheckOne(ctx, pool, t.pool, t.index, t.url, model)
		}(slot, tgt)
	}
	wg.Wait()

	out.MS = time.Since(started).Milliseconds()
	out.Results = results
	out.Checked = len(results)
	out.TimedOut = ctx.Err() != nil

	seen := map[string]bool{}
	for _, row := range results {
		switch row.Verdict {
		case proxyVerdictOK:
			out.OK++
		case proxyVerdictDead:
			out.Dead++
		case proxyVerdictBlocked, proxyVerdictRateLimited:
			out.Blocked++
		default:
			out.Other++
		}
		if row.Mismatch != "" {
			out.Mismatches++
		}
		if row.Pool == proxyPoolStatic {
			out.StaticChecked++
			if row.ExitIP != "" {
				seen[row.ExitIP] = true
			}
		}
	}
	out.DistinctIPs = len(seen)

	// Counts only. The exits themselves are masked in the response and still have
	// no business in a log line, which gets copied into tickets and chat windows.
	log.Printf(logPrefix+"proxy check: %d entr(ies) -> %d ok, %d refused, %d unreachable, %d other; %d misdeclared; %d distinct static address(es) in %dms",
		out.Checked, out.OK, out.Blocked, out.Dead, out.Other, out.Mismatches, out.DistinctIPs, out.MS)

	return jsonResponse(http.StatusOK, out)
}

// proxyCheckOne runs both requests for a single exit. The trace comes first so
// that a dead exit is reported with whatever the trace managed to learn, and so
// the timing attributed to the exit measures the request that decides the
// verdict rather than both.
func proxyCheckOne(ctx context.Context, pool *probeClientPool, poolName string, index int, raw, model string) proxyCheckResult {
	out := proxyCheckResult{Index: index, Pool: poolName, Proxy: probeShowProxy(raw), Verdict: proxyVerdictDead}

	client, errClient := pool.get(raw)
	if errClient != nil {
		// A malformed exit never reaches the network. Saying so precisely matters:
		// otherwise a typo in the pool is indistinguishable from a dead vendor.
		out.Detail = "这条代理地址本身有问题：" + probeRedact(errClient.Error())
		return out
	}

	// Two samples, so the declared pool can be checked against what the entry
	// actually does. Both are best-effort; a trace outage costs the address and
	// the verification, never the verdict.
	if trace := proxyCheckTrace(ctx, client); trace != nil {
		out.ExitIP, out.Country, out.Colo = trace["ip"], trace["loc"], trace["colo"]
		if second := proxyCheckTrace(ctx, client); second != nil && second["ip"] != "" && out.ExitIP != "" {
			out.Rotated = second["ip"] != out.ExitIP
		}
	}
	// Only the direction that is actually proof. See proxyCheckResult.Rotated.
	if out.Rotated && poolName == proxyPoolStatic && raw != "" {
		out.Mismatch = "这条在静态池里，但两次采样给了不同地址 —— 它其实是轮换的，应该移到轮换池。"
	}

	started := time.Now()
	status, errReach := proxyCheckReach(ctx, client, model)
	out.MS = time.Since(started).Milliseconds()
	if errReach != nil {
		out.Detail = "连不上：" + probeRedact(errReach.Error())
		return out
	}

	out.StatusCode = status
	switch status {
	case http.StatusUnauthorized:
		out.Verdict = proxyVerdictOK
		out.Detail = "通。401 正是不带凭据时该有的答复，说明请求确实走到了 OpenAI。"
	case http.StatusForbidden:
		out.Verdict = proxyVerdictBlocked
		out.Detail = "连得上，但上游拒绝（403）—— 多半是这个出口地址被挡了。"
	case http.StatusTooManyRequests:
		out.Verdict = proxyVerdictRateLimited
		out.Detail = "连得上，但被限速（429）—— 这个出口短期内请求太多。"
	default:
		out.Verdict = proxyVerdictUnexpected
		out.Detail = fmt.Sprintf("连得上，上游回了 %d（不带凭据时预期是 401）。", status)
	}
	return out
}

// proxyCheckReach is the request the verdict rests on: the probe's own endpoint,
// the probe's own headers, and deliberately no credential. See the package
// comment for why 401 is success.
func proxyCheckReach(ctx context.Context, client *http.Client, model string) (int, error) {
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
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return 0, errMarshal
	}

	callCtx, cancel := context.WithTimeout(ctx, proxyCheckRequestTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodPost, probeUpstreamURL, bytes.NewReader(raw))
	if errNew != nil {
		return 0, errNew
	}
	// Everything the probe sends except Authorization and Chatgpt-Account-Id. The
	// headers are kept identical so the check exercises the same path the probe
	// will: an edge that rejects on User-Agent or Originator should fail here too,
	// rather than passing a check and then failing every harvest.
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Originator", "codex-tui")
	request.Header.Set("Session-Id", probeUUID())
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return 0, errDo
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, proxyCheckMaxBody))
	return response.StatusCode, nil
}

// proxyCheckTrace reads Cloudflare's trace document through one exit. It returns
// nil on any failure -- this is decoration, and the caller must not treat a
// missing address as a bad exit.
func proxyCheckTrace(ctx context.Context, client *http.Client) map[string]string {
	callCtx, cancel := context.WithTimeout(ctx, proxyCheckRequestTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodGet, proxyCheckTraceURL, nil)
	if errNew != nil {
		return nil
	}
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return nil
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, proxyCheckMaxBody))
		return nil
	}

	// key=value, one per line. Only three of them are worth showing, and pulling
	// exactly those keeps anything new Cloudflare adds from reaching the page.
	out := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, proxyCheckMaxBody))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		switch key {
		case "ip", "loc", "colo":
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
