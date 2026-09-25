package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCloudWSChainPreservesPreviousIDAndAggregatesCompleted(t *testing.T) {
	resetCloudRequestLogTest(t)
	cfg := defaultConfig()
	cfg.CloudMint.Enabled = true
	req := pluginapi.RequestInterceptRequest{RequestID: "chain-request", Model: "gpt-6-sol",
		Body:     []byte(`{"model":"gpt-6-sol","previous_response_id":"resp_private_parent","input":"new turn only"}`),
		Headers:  http.Header{turnStateHeader: {"private-ticket"}, "Cookie": {"__cflb=a; __oailb=unified-15"}},
		Metadata: map[string]any{selectedAuthMetadataKey: "private-account"}}
	out := interceptCloudMint(req, cfg)
	if out.Terminate || len(out.Body) != 0 || len(out.Headers) != 0 {
		t.Fatal("chain request modified")
	}
	for _, kind := range []string{"response.created", "response.completed", "response.completed"} {
		payload, _ := json.Marshal(map[string]any{"type": kind, "response": map[string]any{
			"id": "resp_private_child", "model": "gpt-6-sol", "status": "completed",
			"output": []any{map[string]any{"private": "never-log-user-content"}},
		}})
		raw, _ := json.Marshal(pluginapi.WebSocketResponseEvent{RequestID: req.RequestID, AuthID: "private-account", EventType: kind, Payload: payload})
		if _, err := observeWebSocketEvent(raw); err != nil {
			t.Fatal(err)
		}
	}
	logs := requestLogSnapshot()
	if len(logs) != 1 {
		t.Fatalf("expected one merged request, got %d", len(logs))
	}
	for _, expected := range []string{"previous #" + cloudFingerprint("resp_private_parent"), "response #" + cloudFingerprint("resp_private_child"), "WS completed"} {
		if !strings.Contains(logs[0].Message, expected) {
			t.Errorf("missing %s: %s", expected, logs[0].Message)
		}
	}
	for _, secret := range []string{"resp_private", "private-account", "private-ticket", "never-log-user-content"} {
		if strings.Contains(logs[0].Message, secret) {
			t.Errorf("secret leaked: %s", secret)
		}
	}
}

func TestCloudWSChainDoesNotTreatCreatedOrIncompleteAsCompleted(t *testing.T) {
	resetCloudRequestLogTest(t)
	cloudRememberRequest(pluginapi.RequestInterceptRequest{RequestID: "not-completed", Model: "gpt-6-sol"}, pluginapi.RequestInterceptResponse{})
	for _, kind := range []string{"response.created", "response.incomplete"} {
		payload, _ := json.Marshal(map[string]any{"type": kind, "response": map[string]any{"id": "response-private", "model": "gpt-6-sol", "status": "incomplete"}})
		raw, _ := json.Marshal(pluginapi.WebSocketResponseEvent{RequestID: "not-completed", EventType: kind, Payload: payload})
		observeWebSocketEvent(raw)
		for _, row := range requestLogSnapshot() {
			if strings.Contains(row.Message, "WS completed") {
				t.Fatal("false completion")
			}
		}
	}
	logs := requestLogSnapshot()
	if len(logs) != 1 || !strings.Contains(logs[0].Message, "WS incomplete") {
		t.Fatalf("missing terminal state: %+v", logs)
	}
}

func TestCloudWSChainDoesNotMergeOtherAccountOrMismatchedResponse(t *testing.T) {
	resetCloudRequestLogTest(t)
	cloudRememberRequest(pluginapi.RequestInterceptRequest{RequestID: "shared-request", Model: "gpt-6-sol",
		Metadata: map[string]any{selectedAuthMetadataKey: "account-A"}}, pluginapi.RequestInterceptResponse{})
	emit := func(account, kind, responseID string) {
		body, _ := json.Marshal(map[string]any{"type": kind, "response": map[string]any{
			"id": responseID, "model": "gpt-6-sol", "status": "completed"}})
		raw, _ := json.Marshal(pluginapi.WebSocketResponseEvent{RequestID: "shared-request", AuthID: account, EventType: kind, Payload: body})
		observeWebSocketEvent(raw)
	}
	emit("account-A", "response.created", "response-A")
	emit("account-B", "response.completed", "response-B")
	logs := requestLogSnapshot()
	if len(logs) != 2 || logs[1].Kind != "关联未知" || strings.Contains(logs[0].Message, "WS completed") {
		t.Fatal("cross-account event merged")
	}
	emit("account-A", "response.completed", "wrong-response")
	if !strings.Contains(requestLogSnapshot()[0].Message, "WS id_mismatch") {
		t.Fatal("mismatched completion was trusted")
	}
}
