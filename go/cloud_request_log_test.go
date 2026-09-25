package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func resetCloudRequestLogTest(t *testing.T) {
	t.Helper()
	reset := func() {
		cloudRequestLogs.Lock()
		clear(cloudRequestLogs.items)
		cloudRequestLogs.Unlock()
		cloudDashboardLogs.Lock()
		cloudDashboardLogs.items = nil
		cloudDashboardLogs.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func requestLogSnapshot() []cloudDashboardLog {
	cloudDashboardLogs.Lock()
	defer cloudDashboardLogs.Unlock()
	return append([]cloudDashboardLog(nil), cloudDashboardLogs.items...)
}

func TestCloudRequestLogReusedTicketAndBufferingAreSeparate(t *testing.T) {
	resetCloudRequestLogTest(t)
	cfg := defaultConfig()
	cfg.CloudMint.Enabled = true
	ticket := cloudTestTicket(time.Now())
	req := pluginapi.RequestInterceptRequest{RequestID: "reuse", Model: "gpt-6-sol", Headers: http.Header{
		"X-Codex-Turn-State": {ticket}, "Cookie": {"__cflb=route; __oailb=unified-94; private_session=never-log"},
	}}
	result := interceptCloudMint(req, cfg)
	if len(result.Headers) != 0 || result.Terminate {
		t.Fatal("observation changed request")
	}
	cloudLogResponse(req.RequestID, http.Header{
		"Set-Cookie":                            {"__cf_bm=secret-bm; Secure; HttpOnly"},
		"X-Codex-Safety-Buffering-Faster-Model": {"gpt-6-luna"},
	}, "")
	cloudLogStreamChunk(req.RequestID, []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\",\"model\":\"gpt-6-sol\",\"service_tier\":\"premium\"}}\n\n"))
	logs := requestLogSnapshot()
	if len(logs) != 1 || logs[0].Kind != "沿用" {
		t.Fatalf("expected one reused request: %+v", logs)
	}
	for _, text := range []string{"cookie unified-94", "→ 未返回", "模型 gpt-6-sol → gpt-6-sol", "返回网关 未返回", "Set-Cookie 有 __cf_bm", "票长 未返回", "缓冲 gpt-6-luna", "premium"} {
		if !strings.Contains(logs[0].Message, text) {
			t.Errorf("missing %q: %s", text, logs[0].Message)
		}
	}
	for _, secret := range []string{ticket, "secret-bm", "never-log", "已接受", "满血"} {
		if strings.Contains(logs[0].Message, secret) {
			t.Errorf("sensitive or inferred text %q", secret)
		}
	}
}

func TestCloudRequestLogAggregatesHeadersAndCreated(t *testing.T) {
	resetCloudRequestLogTest(t)
	cloudRememberInjection("aggregate", cloudMintEntry{Ticket: "secret-ticket", Model: "gpt-6-sol", Gateway: "unified-94"})
	cloudLogResponse("aggregate", http.Header{}, "")
	first := requestLogSnapshot()
	event := []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\",\"model\":\"gpt-6-sol\"}}\n\n")
	cloudLogStreamChunk("aggregate", event[:30])
	cloudLogStreamChunk("aggregate", event[30:])
	cloudLogStreamChunk("aggregate", event)
	logs := requestLogSnapshot()
	if len(logs) != 1 || !logs[0].At.Equal(first[0].At) || logs[0].Kind != "注入" {
		t.Fatalf("headers/model must update one row: %+v", logs)
	}
	if !strings.Contains(logs[0].Message, "模型 gpt-6-sol → gpt-6-sol") {
		t.Fatal("response model not merged")
	}
}

func TestCloudRequestLogUnknownCorrelationNeverClaimsInjection(t *testing.T) {
	resetCloudRequestLogTest(t)
	cloudLogResponse("unknown", http.Header{}, "gpt-6-sol")
	logs := requestLogSnapshot()
	if len(logs) != 1 || logs[0].Kind != "关联未知" || !strings.Contains(logs[0].Message, "模型 - → gpt-6-sol") {
		t.Fatalf("missing request context must stay unknown: %+v", logs)
	}
}

func TestCloudRequestLogKeepsNewestEighty(t *testing.T) {
	resetCloudRequestLogTest(t)
	for i := 0; i < 85; i++ {
		cloudRecordLog("本地测试", "row-%02d", i)
	}
	logs := requestLogSnapshot()
	if len(logs) != 80 || logs[0].Message != "row-05" || logs[79].Message != "row-84" {
		t.Fatal("log retention must be exactly 80 newest entries")
	}
}

func TestCloudRequestLogNonStreamingReadsResponseNotRequestModel(t *testing.T) {
	resetCloudRequestLogTest(t)
	cloudRememberInjection("nonstream", cloudMintEntry{Ticket: "test-ticket", Model: "gpt-6-sol"})
	payload, _ := json.Marshal(pluginapi.ResponseInterceptRequest{RequestID: "nonstream", Model: "gpt-6-sol",
		ResponseHeaders: http.Header{}, Body: []byte(`{"object":"response","id":"r2","model":"gpt-6-luna","service_tier":"premium"}`)})
	if _, err := interceptResponse(payload); err != nil {
		t.Fatal(err)
	}
	logs := requestLogSnapshot()
	if len(logs) != 1 || !strings.Contains(logs[0].Message, "模型 gpt-6-sol → gpt-6-luna") || !strings.Contains(logs[0].Message, "premium") {
		t.Fatalf("response declaration not recorded: %s", fmt.Sprint(logs))
	}
}
