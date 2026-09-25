package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCloudDashboardUsesFilenamePluginID(t *testing.T) {
	// CPA 实际发送的 ResourceBasePath 来自 .so 文件名，而不是 Metadata.Name。
	for _, id := range []string{"codex-turn-state", "codex-turn-state-cloud-mint"} {
		t.Run(id, func(t *testing.T) {
			raw, _ := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/" + id})
			response, err := managementRegister(raw)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { managementRegister(nil) })
			var env struct {
				Result pluginapi.ManagementRegistrationResponse `json:"result"`
			}
			if err := json.Unmarshal(response, &env); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, route := range env.Result.Routes {
				if route.Path == "/"+id+"/cloud-status" {
					found = true
				}
			}
			if !found {
				t.Fatal("status route uses wrong plugin ID")
			}
			for _, resource := range env.Result.Resources {
				if resource.Menu != "" && resource.Menu != "云端打票" {
					t.Fatal("old menu title")
				}
			}
			if !strings.Contains(string(handleDashboard().Body), `name="cpa-plugin-id" content="`+id+`"`) {
				t.Fatal("embedded UI uses wrong config ID")
			}
			req, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/management/" + id + "/cloud-status"})
			status, err := managementHandle(req)
			if err != nil {
				t.Fatal(err)
			}
			var reply struct {
				Result pluginapi.ManagementResponse `json:"result"`
			}
			json.Unmarshal(status, &reply)
			if reply.Result.StatusCode != 200 {
				t.Fatalf("status route not dispatched: %d", reply.Result.StatusCode)
			}
			req, _ = json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/" + id + "/cloud-status"})
			status, _ = managementHandle(req)
			json.Unmarshal(status, &reply)
			if reply.Result.StatusCode != 403 {
				t.Fatal("anonymous status alias not blocked")
			}
		})
	}
}
