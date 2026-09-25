package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCloudMintResolverOnlyReadsSelectedCredential(t *testing.T) {
	old := cloudHostCall
	t.Cleanup(func() { cloudHostCall = old })
	var calls []string
	cloudHostCall = func(method string, payload any, out any) error {
		calls = append(calls, method)
		lookup, ok := payload.(pluginapi.HostAuthGetRequest)
		if !ok || lookup.AuthIndex != "index-A" {
			t.Fatalf("wrong lookup: %#v", payload)
		}
		switch method {
		case "host.auth.get_runtime":
			*out.(*pluginapi.HostAuthGetRuntimeResponse) = pluginapi.HostAuthGetRuntimeResponse{Auth: pluginapi.HostAuthFileEntry{ID: "A", Name: "A.json", Provider: "codex"}}
		case "host.auth.get":
			*out.(*pluginapi.HostAuthGetResponse) = pluginapi.HostAuthGetResponse{AuthIndex: "index-A", Name: "A.json", JSON: json.RawMessage(`{"type":"codex","access_token":"access-A","refresh_token":"never-send","account_id":"account-A"}`)}
		default:
			t.Fatalf("unexpected host mutation: %s", method)
		}
		return nil
	}
	req := pluginapi.RequestInterceptRequest{Metadata: map[string]any{selectedAuthMetadataKey: "A", "selected_auth_index": "index-A"}}
	got, err := resolveCloudCredentials(req)
	if err != nil || got.AccessToken != "access-A" || got.AccountID != "account-A" {
		t.Fatalf("resolve: %#v %v", got, err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls=%v", calls)
	}
	req.Metadata[selectedAuthMetadataKey] = "B"
	if _, err = resolveCloudCredentials(req); err == nil {
		t.Fatal("cross-account lookup accepted")
	}
	if len(calls) != 3 {
		t.Fatal("mismatched account must not read physical credentials")
	}
}

func TestCloudMintHookInjectsHeadersAndPreservesUnrelatedCookies(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cloudTestResult(now, "gpt-6-sol"))
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.CloudMint.Enabled = true
	cfg.CloudMint.URL = server.URL
	cfg.CloudMint.WaitMS = 1000
	t.Setenv(cfg.CloudMint.KeyEnv, "key")
	old := cloudCredentialResolver
	t.Cleanup(func() { cloudCredentialResolver = old; resetCloudMintService() })
	cloudCredentialResolver = func(pluginapi.RequestInterceptRequest) (cloudMintCredentials, error) {
		return cloudMintCredentials{AuthID: "A", AccessToken: "access-A"}, nil
	}
	resetCloudMintService()
	seed := "other=keep; __cflb=old; __oailb=" + cloudTestResult(now, "gpt-6-sol").Cookies["__oailb"]
	req := pluginapi.RequestInterceptRequest{RequestID: "mint-hook-test", Model: "gpt-6-sol", Headers: http.Header{"Cookie": []string{seed}}}
	out := interceptCloudMint(req, cfg)
	if out.Terminate {
		t.Fatal("unexpected rejection")
	}
	if out.Headers.Get(turnStateHeader) != cloudTestTicket(now) {
		t.Fatal("ticket not injected")
	}
	if !strings.Contains(out.Headers.Get("Cookie"), "other=keep") || strings.Contains(out.Headers.Get("Cookie"), "__cflb=old") {
		t.Fatal("cookie merge invalid")
	}
	if out.Headers.Get("X-Relay-Mint") != "" || out.Headers.Get("X-Relay-Key") != "" {
		t.Fatal("control headers leaked to business")
	}
	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)
	cloudLogResponse(req.RequestID, http.Header{}, "")
	if !strings.Contains(logs.String(), "模型 gpt-6-sol → 未返回") || !strings.Contains(logs.String(), "返回网关 未返回") {
		t.Fatalf("missing unknown labels: %s", logs.String())
	}
	if strings.Contains(logs.String(), cloudTestTicket(now)) {
		t.Fatal("business log leaked ticket")
	}
	cfg.DryRun = true
	if result := interceptCloudMint(req, cfg); result.Terminate || len(result.Headers) > 0 {
		t.Fatal("dry run modified request")
	}
}

func TestCloudMintColdWaitBoundedAndWorkCancelable(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(canceled) }))
	defer server.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = server.URL
	cfg.WaitMS = 20
	t.Setenv(cfg.KeyEnv, "key")
	service := newCloudMintService()
	defer service.close()
	before := time.Now()
	_, err := service.get(cfg, cloudMintCredentials{AuthID: "A", AccessToken: "access"}, "gpt-6-sol")
	if err == nil || time.Since(before) > time.Second {
		t.Fatal("business wait not bounded")
	}
	<-started
	service.close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("worker not canceled")
	}
}

func TestCloudMintRejectsRedirectAndCoolsFailures(t *testing.T) {
	var followed, calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = source.URL
	cfg.WaitMS = 1000
	t.Setenv(cfg.KeyEnv, "relay-key")
	service := newCloudMintService()
	defer service.close()
	creds := cloudMintCredentials{AuthID: "A", AccessToken: "access"}
	for i := 0; i < 2; i++ {
		if _, err := service.get(cfg, creds, "gpt-6-sol"); err == nil {
			t.Fatal("redirect accepted")
		}
	}
	if followed.Load() != 0 || calls.Load() != 1 {
		t.Fatalf("followed=%d calls=%d", followed.Load(), calls.Load())
	}
}

func TestCloudMintConfigurationRejectsUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?key=secret", "https://example.com/#secret"} {
		cfg := defaultCloudMintConfig()
		cfg.Enabled = true
		cfg.URL = endpoint
		if cfg.validate() == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
}

func TestCloudMintCacheDoesNotCrossModelsOrTokenVersions(t *testing.T) {
	var calls atomic.Int32
	now := time.Now().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(cloudTestResult(now, r.Header.Get("X-Mint-Model")))
	}))
	defer server.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = server.URL
	cfg.WaitMS = 1000
	t.Setenv(cfg.KeyEnv, "key")
	service := newCloudMintService()
	defer service.close()
	for i, model := range []string{"gpt-6-sol", "gpt-6-luna", "gpt-6-sol"} {
		token := "old"
		if i == 2 {
			token = "refreshed"
		}
		entry, err := service.get(cfg, cloudMintCredentials{AuthID: "A", AccessToken: token}, model)
		if err != nil || entry.Model != model {
			t.Fatal(fmt.Sprint(entry.Model, err))
		}
	}
	if calls.Load() != 3 {
		t.Fatal("cache crossed model or token version")
	}
}

func TestCloudMintBusinessLogConfirmsOnlyCompleteCreatedEvent(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	entry, err := validateCloudMint(cloudTestResult(now, "gpt-6-sol"), defaultCloudMintConfig(), "gpt-6-sol", now)
	if err != nil {
		t.Fatal(err)
	}
	cloudRememberInjection("created-log", entry)
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	cloudLogResponse("created-log", http.Header{}, "")
	cloudLogStreamChunk("created-log", []byte("data: {\"type\":\"other\",\"model\":\"gpt-6-sol\"}\n\n"))
	if strings.Contains(output.String(), "业务模型确认") {
		t.Fatal("wrong event confirmed")
	}
	event := []byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\",\"model\":\"gpt-6-sol\"}}\n\n")
	cloudLogStreamChunk("created-log", event[:len(event)-1])
	if strings.Contains(output.String(), "业务模型确认") {
		t.Fatal("partial event confirmed")
	}
	cloudLogStreamChunk("created-log", event[len(event)-1:])
	if !strings.Contains(output.String(), "业务模型确认") || !strings.Contains(output.String(), "模型 gpt-6-sol") {
		t.Fatal("model confirmation absent")
	}
	if strings.Contains(output.String(), entry.Ticket) {
		t.Fatal("ticket leaked")
	}
}

func TestCloudMintDoesNotGuessProviderFromFilename(t *testing.T) {
	previous := cloudHostCall
	t.Cleanup(func() { cloudHostCall = previous })
	cloudHostCall = func(method string, _ any, out any) error {
		if method != "host.auth.get_runtime" {
			t.Fatalf("must not read token for other provider: %s", method)
		}
		*out.(*pluginapi.HostAuthGetRuntimeResponse) = pluginapi.HostAuthGetRuntimeResponse{Auth: pluginapi.HostAuthFileEntry{ID: "codex-misnamed.json", Name: "codex-misnamed.json", Provider: "claude"}}
		return nil
	}
	req := pluginapi.RequestInterceptRequest{Metadata: map[string]any{selectedAuthMetadataKey: "codex-misnamed.json", "selected_auth_index": "index"}}
	if _, err := resolveCloudCredentials(req); err != errCloudNotCodex {
		t.Fatalf("unexpected result: %v", err)
	}
}
