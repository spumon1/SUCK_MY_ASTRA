package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// 续链归客户端和同一业务连接管；插件只记指纹，不擅自补 previous_response_id，旁观者别续台词。
type cloudChainObservation struct {
	previous string
	response string
	stage    string
}

type cloudWSChainEvent struct {
	Type     string `json:"type"`
	Response struct {
		ID     string `json:"id"`
		Model  string `json:"model"`
		Status string `json:"status"`
		Tier   string `json:"service_tier"`
	} `json:"response"`
}

func cloudResponseIDFingerprint(id string) string {
	if id == "" || len(id) > 512 || strings.TrimSpace(id) != id {
		return ""
	}
	return cloudFingerprint(id)
}

func cloudRequestChain(body []byte) cloudChainObservation {
	var request struct {
		Previous string `json:"previous_response_id"`
	}
	if json.Unmarshal(body, &request) != nil {
		return cloudChainObservation{}
	}
	return cloudChainObservation{previous: cloudResponseIDFingerprint(request.Previous)}
}

func cloudWSFallbackKey(authID, responseID string) string {
	if responseID == "" {
		return ""
	}
	// 跨账号即便响应 ID 同名也不合并；索引认完整摘要，不拿展示短指纹当户口本。
	value := sha256.Sum256([]byte(authID + "\x00" + responseID))
	return "ws-observation:" + hex.EncodeToString(value[:])
}

func cloudAuthObservationKey(authID string) string {
	if authID == "" {
		return ""
	}
	value := sha256.Sum256([]byte(authID))
	return hex.EncodeToString(value[:])
}

func cloudObserveWSChain(event pluginapi.WebSocketResponseEvent) bool {
	switch event.EventType {
	case "response.created", "response.completed", "response.failed", "response.incomplete":
	default:
		return false
	}
	var payload cloudWSChainEvent
	if json.Unmarshal(event.Payload, &payload) != nil || payload.Type != event.EventType {
		return event.EventType != "response.failed"
	}
	response := payload.Response
	fingerprint := cloudResponseIDFingerprint(response.ID)
	if fingerprint == "" {
		return event.EventType != "response.failed"
	}
	id := event.RequestID
	if id == "" {
		id = cloudWSFallbackKey(event.AuthID, response.ID)
	}
	cloudRequestLogs.Lock()
	defer cloudRequestLogs.Unlock()
	record := cloudGetRequestLog(id)
	if record == nil {
		return true
	}
	if record.authKey != "" && event.AuthID != "" && record.authKey != cloudAuthObservationKey(event.AuthID) {
		record = cloudGetRequestLog(cloudWSFallbackKey(event.AuthID, response.ID))
		if record == nil {
			return true
		}
	}
	cloudApplyWSChain(record, payload)
	return true
}

func cloudApplyWSChain(record *cloudPendingLog, event cloudWSChainEvent) {
	fingerprint := cloudResponseIDFingerprint(event.Response.ID)
	if record.chain.response != "" && record.chain.response != fingerprint {
		record.chain.stage = "id_mismatch"
		cloudPublishRequestLog(record, "WS 续链观测")
		return
	}
	record.chain.response = fingerprint
	stage := strings.TrimPrefix(event.Type, "response.")
	if stage == "completed" && event.Response.Status != "completed" {
		stage = "terminal_unconfirmed"
	}
	// 同请求迟到的 created 不能把已见终态倒拨回开场，散场铃响了不准再报幕。
	if record.chain.stage == "" || stage != "created" {
		record.chain.stage = stage
	}
	if model := cloudLogLabel(event.Response.Model); model != "" {
		record.response.Model = model
	}
	if tier := cloudResponseTier(event.Response.Tier); tier != "" {
		record.tier = tier
	}
	cloudPublishRequestLog(record, "WS 续链观测")
}

func formatCloudChainLog(chain cloudChainObservation) string {
	if chain.previous == "" && chain.response == "" {
		return ""
	}
	previous, response := "未带", "未观测"
	if chain.previous != "" {
		previous = "#" + chain.previous
	}
	if chain.response != "" {
		response = "#" + chain.response
	}
	message := "\nprevious " + previous + " · response " + response
	if chain.stage != "" {
		message += " · WS " + chain.stage
	}
	return message
}
