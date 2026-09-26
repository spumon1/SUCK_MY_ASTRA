package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func cloudTestTicket(now time.Time) string {
	raw := make([]byte, 585)
	raw[0] = 0x80
	binary.BigEndian.PutUint64(raw[1:9], uint64(now.Unix()))
	return base64.RawURLEncoding.EncodeToString(raw)
}

func cloudTestResult(now time.Time, model string) cloudMintResult {
	claims, _ := json.Marshal(map[string]any{"exp": now.Add(time.Hour).Unix(), "aud": "chat.gateway.unified-88.api.openai.com"})
	pair := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".test"
	return cloudMintResult{Transport: "sse", Gateway: "unified-88", ExpiresAt: now.Add(time.Hour),
		Cookies: map[string]string{"__cflb": "pair-test", "__oailb": pair},
		Tickets: map[string]cloudMintTicket{model: {TurnState: cloudTestTicket(now), TicketLen: 780,
			ServedModel: model, IssuedAt: now, ExpiresAt: now.Add(240 * time.Second)}}}
}

func TestCloudMintValidateFailsClosed(t *testing.T) {
	cfg := defaultCloudMintConfig()
	now := time.Now().Truncate(time.Second)
	valid := cloudTestResult(now, "gpt-6-sol")
	if _, err := validateCloudMint(valid, cfg, "gpt-6-sol", now); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		alter func(*cloudMintResult)
	}{
		{"model", func(r *cloudMintResult) {
			v := r.Tickets["gpt-6-sol"]
			v.ServedModel = "gpt-6-luna"
			r.Tickets["gpt-6-sol"] = v
		}},
		{"transport", func(r *cloudMintResult) { r.Transport = "websocket" }},
		{"pair", func(r *cloudMintResult) { delete(r.Cookies, "__oailb") }},
		{"gateway", func(r *cloudMintResult) { r.Gateway = "unified-199" }},
		{"ticket expired", func(r *cloudMintResult) { v := r.Tickets["gpt-6-sol"]; v.ExpiresAt = now; r.Tickets["gpt-6-sol"] = v }},
		{"pair expired", func(r *cloudMintResult) { r.ExpiresAt = now }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := cloudTestResult(now, "gpt-6-sol")
			tc.alter(&r)
			if _, err := validateCloudMint(r, cfg, "gpt-6-sol", now); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
}

func TestCloudMintLogNeverLeaksTicketOrCookie(t *testing.T) {
	ticket := cloudTestTicket(time.Now().Add(-22 * time.Second))
	sent := cloudLogView{TicketLen: 780, Fingerprint: cloudFingerprint(ticket), Gateway: "unified-199"}
	got := cloudLogView{TicketLen: 780, Fingerprint: cloudFingerprint(ticket + "different"), Gateway: "unified-88", AgeSeconds: 22, HasAge: true}
	line := formatCloudMintLog(sent, got)
	for _, want := range []string{"票长 780", "这张票龄 22s", "未见模型", "网关变化", "unified-199", "unified-88"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}
	if strings.Contains(line, ticket) || strings.Contains(line, ticket[:20]) {
		t.Fatal("raw ticket leaked")
	}
	got.Gateway = ""
	if strings.Contains(formatCloudMintLog(sent, got), "网关未变") {
		t.Fatal("unknown gateway presented as unchanged")
	}
}

// 云端结果只认宿主选中的账号工牌；不猜身份，更不替凭据改户口。
func TestCloudMintHookPreservesCallerTicket(t *testing.T) {
	cfg := defaultConfig()
	cfg.CloudMint = defaultCloudMintConfig()
	cfg.CloudMint.Enabled = true
	req := pluginapi.RequestInterceptRequest{Model: "gpt-6-sol", Headers: http.Header{turnStateHeader: []string{"caller-state"}}}
	out := interceptCloudMint(req, cfg)
	if out.Terminate || len(out.Headers) > 0 {
		t.Fatal("caller state changed")
	}
}

// 云端打票只接有归属的 Codex 请求；模型名空白、带别名分隔符或凭据解析失败，
// 身份不明就原样放行，503 不能兼职乱抓人的门卫。
func TestCloudMintPassesThroughUnattributableRequests(t *testing.T) {
	cfg := defaultConfig()
	cfg.CloudMint = defaultCloudMintConfig()
	cfg.CloudMint.Enabled = true
	old := cloudCredentialResolver
	t.Cleanup(func() { cloudCredentialResolver = old })
	var resolverErr error
	cloudCredentialResolver = func(pluginapi.RequestInterceptRequest) (cloudMintCredentials, error) {
		return cloudMintCredentials{}, resolverErr
	}
	for _, tc := range []struct {
		name string
		req  pluginapi.RequestInterceptRequest
		err  error
	}{
		{"empty model", pluginapi.RequestInterceptRequest{RequestID: "foreign-empty"}, errCloudNotCodex},
		{"aliased model", pluginapi.RequestInterceptRequest{RequestID: "foreign-alias", Model: "openai/gpt-4o:free"}, errCloudNotCodex},
		{"lookup failure", pluginapi.RequestInterceptRequest{RequestID: "foreign-error", Model: "claude-sonnet-4-5"}, errors.New("credential lookup unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverErr = tc.err
			out := interceptCloudMint(tc.req, cfg)
			if out.Terminate || len(out.Headers) > 0 {
				t.Fatalf("unattributable request was touched: %+v", out)
			}
		})
	}
	// 已认出 Codex 凭据但模型名不能打票时，按约定回 503；不偷放行，也不给请求整容。
	resolverErr = nil
	cloudCredentialResolver = func(pluginapi.RequestInterceptRequest) (cloudMintCredentials, error) {
		return cloudMintCredentials{AuthID: "a", AccessToken: "t"}, nil
	}
	out := interceptCloudMint(pluginapi.RequestInterceptRequest{RequestID: "codex-odd", Model: "weird/model"}, cfg)
	if !out.Terminate || out.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unmintable codex request must still fail closed: %+v", out)
	}
}

func TestCloudMintConcurrentRequestsShareOneCall(t *testing.T) {
	var calls atomic.Int32
	now := time.Now().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Relay-Key") != "relay-secret" || r.Header.Get("Authorization") != "Bearer access-secret" {
			t.Error("wrong credentials")
		}
		if r.Header.Get("X-Mint-Model") != "gpt-6-sol" {
			t.Error("wrong model")
		}
		time.Sleep(30 * time.Millisecond)
		json.NewEncoder(w).Encode(cloudTestResult(now, "gpt-6-sol"))
	}))
	defer server.Close()
	cfg := defaultCloudMintConfig()
	cfg.Enabled = true
	cfg.URL = server.URL
	cfg.WaitMS = 1000
	t.Setenv(cfg.KeyEnv, "relay-secret")
	service := newCloudMintService()
	defer service.close()
	creds := cloudMintCredentials{AuthID: "auth", AccessToken: "access-secret", AccountID: "account"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry, err := service.get(cfg, creds, "gpt-6-sol")
			if err != nil || entry.Ticket == "" {
				t.Errorf("get: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("want one call, got %d", calls.Load())
	}
}
