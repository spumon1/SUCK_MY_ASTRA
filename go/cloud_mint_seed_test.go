package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCloudMintSeedForwardsOnlyRoutePairToFC(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	result := cloudTestResult(now, "gpt-6-sol")
	seed := "__cflb=" + result.Cookies["__cflb"] + "; __oailb=" + result.Cookies["__oailb"]
	var received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.CloudMint.Enabled, cfg.CloudMint.URL = true, server.URL
	t.Setenv(cfg.CloudMint.KeyEnv, "local-test-key")
	old := cloudCredentialResolver
	cloudCredentialResolver = func(pluginapi.RequestInterceptRequest) (cloudMintCredentials, error) {
		return cloudMintCredentials{AuthID: "test-account", AccessToken: "local-token"}, nil
	}
	resetCloudMintService()
	t.Cleanup(func() { cloudCredentialResolver = old; resetCloudMintService() })
	req := pluginapi.RequestInterceptRequest{RequestID: "seed-forward", Model: "gpt-6-sol",
		Headers: http.Header{"Cookie": {seed + "; __cf_bm=private; session=secret"}}}
	out := interceptCloudMint(req, cfg)
	if out.Terminate || received != seed {
		t.Fatalf("route-only Cookie not forwarded; terminate=%v", out.Terminate)
	}
	if !strings.Contains(out.Headers.Get("Cookie"), "session=secret") {
		t.Fatal("business cookies changed")
	}
}

func TestCloudMintSeedInvalidPairNeverCallsFC(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(cloudTestResult(time.Now(), "gpt-6-sol"))
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.CloudMint.Enabled, cfg.CloudMint.URL = true, server.URL
	t.Setenv(cfg.CloudMint.KeyEnv, "local-key")
	old := cloudCredentialResolver
	cloudCredentialResolver = func(pluginapi.RequestInterceptRequest) (cloudMintCredentials, error) {
		return cloudMintCredentials{AuthID: "test-account", AccessToken: "local-token"}, nil
	}
	resetCloudMintService()
	t.Cleanup(func() { cloudCredentialResolver = old; resetCloudMintService() })
	req := pluginapi.RequestInterceptRequest{RequestID: "seed-invalid", Model: "gpt-6-sol", Headers: http.Header{"Cookie": {"__cflb=partial"}}}
	if !interceptCloudMint(req, cfg).Terminate {
		t.Fatal("invalid seed did not fail closed")
	}
	if calls.Load() != 0 {
		t.Fatal("FC was called with invalid seed")
	}
}

func TestCloudMintSeedValidationAndCacheIsolation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	valid := cloudTestResult(now, "gpt-6-sol").Cookies
	cookie := "__cflb=" + valid["__cflb"] + "; __oailb=" + valid["__oailb"]
	for _, tc := range []struct {
		raw, gateway string
		valid        bool
	}{
		{cookie, "unified-88", true},
		{cookie + "; session=keep", "unified-88", true},
		{cookie, "unified-15", false},
		{cookie + "; __cflb=duplicate", "unified-88", false},
		{"__cflb=only", "unified-88", false},
		{"__cflb=a; __oailb=unified-88", "unified-88", false},
		{strings.Replace(cookie, "pair-test", "bad\x00value", 1), "unified-88", false},
	} {
		got, err := cloudMintSeedCookie(tc.raw, tc.gateway, now)
		if tc.valid && (err != nil || got != cookie) {
			t.Fatal("valid pair not normalized")
		}
		if !tc.valid && err == nil {
			t.Fatal("invalid pair accepted")
		}
	}
	if got, err := cloudMintSeedCookie("__cf_bm=private; session=secret", "unified-88", now); err != nil || got != "" {
		t.Fatal("unrelated cookies became a seed")
	}
	if _, err := cloudMintSeedCookie(cookie, "unified-88", now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired seed accepted")
	}
	a := cloudMintWork{cfg: defaultCloudMintConfig(), model: "gpt-6-sol", seedCookie: cookie}
	b := a
	b.seedCookie = strings.Replace(cookie, "pair-test", "other-route", 1)
	if a.cacheKey() == b.cacheKey() {
		t.Fatal("seed change reused cache key")
	}
}
