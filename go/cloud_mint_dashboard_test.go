package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCloudDashboardEmbedsProductionPage(t *testing.T) {
	body := string(handleDashboard().Body)
	for _, want := range []string{cloudDashboardBuild, "encodeURIComponent(PLUGIN_ID)", `name="cpa-plugin-id"`, "云端打票"} {
		if !strings.Contains(body, want) {
			t.Fatalf("embedded dashboard missing %q", want)
		}
	}
	for _, forbidden := range []string{"const records=[", "INTERACTIVE EXAMPLE", "保存示例设置", "探测范围", "代理池"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("embedded old/example UI %q", forbidden)
		}
	}
}

func TestCloudDashboardStatusContainsOnlySafeSummaries(t *testing.T) {
	service := newCloudMintService()
	defer service.close()
	now := time.Now()
	work := cloudMintWork{cfg: defaultCloudMintConfig(), creds: cloudMintCredentials{AuthID: "private-email@example.com", AccessToken: "secret-token"}, model: "gpt-6-sol"}
	row := cloudWorkRow(work)
	service.cache["id"] = cloudMintCached{entry: cloudMintEntry{Ticket: "secret-ticket", Cookies: map[string]string{"__oailb": "secret-cookie"}}, until: now.Add(time.Minute), row: row}
	service.jobs["busy"] = &cloudMintJob{row: row}
	raw, _ := json.Marshal(service.dashboardRows())
	for _, secret := range []string{"private-email", "secret-token", "secret-ticket", "secret-cookie"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("status leaked secret")
		}
	}
	if !bytes.Contains(raw, []byte("ready")) || !bytes.Contains(raw, []byte("minting")) {
		t.Fatal("missing real states")
	}
}

func TestCloudDashboardRejectsAnonymousAlias(t *testing.T) {
	req, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/codex-turn-state/cloud-status"})
	raw, err := managementHandle(req)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Result pluginapi.ManagementResponse `json:"result"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Result.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected response %s", raw)
	}
}

func TestCloudWebsocketObserverDoesNotSpamOrLeakIdentity(t *testing.T) {
	var output bytes.Buffer
	writer := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(writer)
	for _, eventType := range []string{"response.reasoning_summary_text.delta", "response.output_item.added", "response.completed"} {
		raw, _ := json.Marshal(pluginapi.WebSocketResponseEvent{AuthID: "private@example.com", Model: "requested", EventType: eventType})
		if _, err := observeWebSocketEvent(raw); err != nil {
			t.Fatal(err)
		}
	}
	if output.Len() != 0 {
		t.Fatalf("per-frame logging remains: %s", output.String())
	}
	raw, _ := json.Marshal(pluginapi.WebSocketResponseEvent{AuthID: "private@example.com", EventType: "response.created", Payload: []byte(`{"type":"response.created","response":{"id":"r1","model":"gpt-6-luna"}}`)})
	observeWebSocketEvent(raw)
	if !strings.Contains(output.String(), "→ gpt-6-luna") || strings.Contains(output.String(), "private@example.com") {
		t.Fatal("model not parsed or identity leaked")
	}
}
