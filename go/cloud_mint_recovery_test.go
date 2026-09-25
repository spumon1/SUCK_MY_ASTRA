package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// 模拟宿主已选中该账号；仅暴露虚构文件，不触及真实凭据。
func cloudRecoveryHost(t *testing.T, runtime *pluginapi.HostAuthFileEntry) *atomic.Int32 {
	t.Helper()
	var reads atomic.Int32
	previous := cloudHostCall
	t.Cleanup(func() { cloudHostCall = previous })
	cloudHostCall = func(method string, payload any, out any) error {
		lookup, ok := payload.(pluginapi.HostAuthGetRequest)
		if !ok || lookup.AuthIndex != "recovery-index" {
			t.Fatalf("unexpected credential lookup: %#v", payload)
		}
		switch method {
		case "host.auth.get_runtime":
			*out.(*pluginapi.HostAuthGetRuntimeResponse) = pluginapi.HostAuthGetRuntimeResponse{Auth: *runtime}
		case "host.auth.get":
			reads.Add(1)
			*out.(*pluginapi.HostAuthGetResponse) = pluginapi.HostAuthGetResponse{
				AuthIndex: "recovery-index", Name: "recovery.json",
				JSON: json.RawMessage(`{"type":"codex","access_token":"synthetic-access","account_id":"synthetic-account"}`),
			}
		default:
			t.Fatalf("unexpected host method: %s", method)
		}
		return nil
	}
	return &reads
}

func cloudRecoveryRequest() pluginapi.RequestInterceptRequest {
	return pluginapi.RequestInterceptRequest{RequestID: "recovery-request", Model: "gpt-6-sol",
		Metadata: map[string]any{selectedAuthMetadataKey: "recovery", "selected_auth_index": "recovery-index"}}
}

func TestCloudMintSelectedCredentialCanRecover(t *testing.T) {
	for _, tc := range []struct {
		name string
		next time.Time
	}{
		{"expired cooldown", time.Now().Add(-time.Minute)},
		{"other model cooldown", time.Now().Add(time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := pluginapi.HostAuthFileEntry{ID: "recovery", Name: "recovery.json", Provider: "codex",
				Status: "error", Unavailable: true, NextRetryAfter: tc.next}
			reads := cloudRecoveryHost(t, &runtime)
			creds, err := resolveCloudCredentials(cloudRecoveryRequest())
			if err != nil {
				t.Fatalf("host-selected credential was rejected by stale aggregate status: %v", err)
			}
			if creds.AuthID != "recovery" || creds.AccessToken != "synthetic-access" || reads.Load() != 1 {
				t.Fatal("selected credential was not read exactly once")
			}
		})
	}
}

func TestCloudMintRecoveryStillRejectsDisabledOrMismatchedCredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*pluginapi.HostAuthFileEntry)
	}{
		{"disabled flag", func(r *pluginapi.HostAuthFileEntry) { r.Disabled = true }},
		{"disabled status", func(r *pluginapi.HostAuthFileEntry) { r.Status = "disabled" }},
		{"different account", func(r *pluginapi.HostAuthFileEntry) { r.ID, r.Name = "other", "other.json" }},
		{"different provider", func(r *pluginapi.HostAuthFileEntry) { r.Provider = "claude" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := pluginapi.HostAuthFileEntry{ID: "recovery", Name: "recovery.json", Provider: "codex"}
			tc.alter(&runtime)
			reads := cloudRecoveryHost(t, &runtime)
			if _, err := resolveCloudCredentials(cloudRecoveryRequest()); err == nil {
				t.Fatal("disabled or mismatched credential was accepted")
			}
			if reads.Load() != 0 {
				t.Fatal("credential file must not be read after identity/disable rejection")
			}
		})
	}
}

func cloudRecoveryServer(t *testing.T, calls *atomic.Int32) (string, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-release:
			json.NewEncoder(w).Encode(cloudTestResult(time.Now().Truncate(time.Second), "gpt-6-sol"))
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { unblock(); server.Close() })
	return server.URL, unblock
}

func TestCloudMintCold503RecoversFromReadyCache(t *testing.T) {
	runtime := pluginapi.HostAuthFileEntry{ID: "recovery", Name: "recovery.json", Provider: "codex"}
	cloudRecoveryHost(t, &runtime)
	previous := cloudCredentialResolver
	cloudCredentialResolver = resolveCloudCredentials
	resetCloudMintService()
	t.Cleanup(func() { cloudCredentialResolver = previous; resetCloudMintService() })
	var calls atomic.Int32
	url, unblock := cloudRecoveryServer(t, &calls)
	cfg := defaultConfig()
	cfg.CloudMint.Enabled, cfg.CloudMint.URL, cfg.CloudMint.WaitMS = true, url, 20
	t.Setenv(cfg.CloudMint.KeyEnv, "synthetic-relay-key")
	req := cloudRecoveryRequest()
	first := interceptCloudMint(req, cfg)
	if !first.Terminate || first.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("cold request must preserve bounded-wait 503")
	}
	service := currentCloudMintService()
	service.mu.Lock()
	var done <-chan struct{}
	for _, job := range service.jobs {
		done = job.done
	}
	service.mu.Unlock()
	if done == nil {
		t.Fatal("cold 503 must leave a live mint job")
	}
	// 首次 503 后，宿主冷却到期仍可能保留 Unavailable 摘要。
	runtime.Unavailable, runtime.Status = true, "error"
	runtime.NextRetryAfter = time.Now().Add(-time.Second)
	unblock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background mint did not finish")
	}
	assertCloudRecoveryCacheReady(t, service)
	second := interceptCloudMint(req, cfg)
	if second.Terminate || second.Headers.Get(turnStateHeader) == "" {
		t.Fatalf("ready ticket still rejected after host retry: status=%d body=%s", second.StatusCode, second.ResponseBody)
	}
	if calls.Load() != 1 || !strings.Contains(second.Headers.Get("Cookie"), "__oailb=") {
		t.Fatal("recovery must use the existing ticket and its pair, not remint")
	}
}

func assertCloudRecoveryCacheReady(t *testing.T, service *cloudMintService) {
	t.Helper()
	rows := service.dashboardRows()
	if len(rows) != 1 || rows[0].State != "ready" {
		t.Fatalf("mint must be ready before retry: %#v", rows)
	}
}
