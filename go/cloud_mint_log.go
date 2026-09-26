package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 日志只记摘要与观测事实；原始票、Cookie、访问令牌、用户文本都不准上展台。
type cloudLogView struct {
	TicketLen         int
	Fingerprint       string
	Gateway           string
	Model             string
	AgeSeconds        int64
	HasAge            bool
	CookieFingerprint string
}

type cloudAttemptLog struct {
	SentGateway       string `json:"sent_gateway"`
	SentFingerprint   string `json:"sent_cookie_fingerprint"`
	Gateway           string `json:"received_gateway"`
	TicketLength      int    `json:"ticket_length"`
	TicketFingerprint string `json:"ticket_fingerprint"`
	TicketAge         *int64 `json:"ticket_age_s"`
	ServedModel       string `json:"served_model"`
}

func cloudFingerprint(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])[:8]
}
func cloudSafeLabel(value string) string {
	if cloudNamePattern.MatchString(value) {
		return value
	}
	return "未知"
}
func cloudDisplayGateway(value string) string {
	if cloudGatewayPattern.MatchString(value) {
		return value
	}
	return "网关未知"
}
func cloudDisplayFingerprint(value string) string {
	if len(value) == 8 && strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
	}) < 0 {
		return "#" + value
	}
	return "#未知"
}

func formatCloudMintLog(sent, got cloudLogView) string {
	before := "裸打/未注入票"
	if sent.TicketLen > 0 {
		before = fmt.Sprintf("cookie %s · 票长 %d · %s · %s", cloudDisplayFingerprint(sent.CookieFingerprint), sent.TicketLen, cloudDisplayFingerprint(sent.Fingerprint), cloudDisplayGateway(sent.Gateway))
	}
	after := fmt.Sprintf("得到 %s · 票长 %d · %s", cloudDisplayGateway(got.Gateway), got.TicketLen, cloudDisplayFingerprint(got.Fingerprint))
	age := "票龄未知"
	if got.HasAge && got.AgeSeconds >= 0 {
		age = fmt.Sprintf("这张票龄 %ds", got.AgeSeconds)
	}
	model := "未见模型"
	if got.Model != "" && cloudSafeLabel(got.Model) != "未知" {
		model = "模型 " + got.Model
	}
	change := "网关变化未知"
	if cloudGatewayPattern.MatchString(sent.Gateway) && cloudGatewayPattern.MatchString(got.Gateway) {
		change = "网关未变"
		if sent.Gateway != got.Gateway {
			change = "网关变化"
		}
	}
	return strings.Join([]string{before, after, age, model, change}, " · ")
}

func cloudEntryView(entry cloudMintEntry) cloudLogView {
	return cloudLogView{TicketLen: len(entry.Ticket), Fingerprint: cloudFingerprint(entry.Ticket), Gateway: entry.Gateway, Model: entry.Model,
		AgeSeconds: int64(time.Since(entry.IssuedAt).Seconds()), HasAge: !entry.IssuedAt.IsZero()}
}

// 云端 trace 当陌生来客，只取白名单字段；自由文本错误不打印，不能让客人自己往日志墙写字。
func logCloudAttempts(entries []cloudAttemptLog) {
	if len(entries) > 40 {
		entries = entries[len(entries)-40:]
	}
	for _, entry := range entries {
		got := cloudLogView{Gateway: entry.Gateway, TicketLen: entry.TicketLength, Fingerprint: entry.TicketFingerprint, Model: entry.ServedModel}
		if got.TicketLen < 0 || got.TicketLen > 4096 {
			got.TicketLen = 0
		}
		if entry.TicketAge != nil {
			got.AgeSeconds = *entry.TicketAge
			got.HasAge = true
		}
		prefix := "裸打"
		if entry.SentFingerprint != "" {
			prefix = "定向 Cookie " + cloudDisplayFingerprint(entry.SentFingerprint) + " · " + cloudDisplayGateway(entry.SentGateway)
		}
		line := strings.TrimPrefix(formatCloudMintLog(cloudLogView{Gateway: entry.SentGateway}, got), "裸打/未注入票 · ")
		cloudRecordLog("云端打票", "%s · %s", prefix, line)
	}
}

// 只看声明层字段，不翻任意嵌套 model，也不把 buffering 头错认成模型的身份证。
type cloudDeclaredResponse struct {
	ID     string `json:"id"`
	Model  string `json:"model"`
	Tier   string `json:"service_tier"`
	Object string `json:"object"`
}

func cloudResponseDeclaration(data []byte, stream bool) (string, string) {
	var event struct {
		Type string `json:"type"`
		cloudDeclaredResponse
		Response cloudDeclaredResponse `json:"response"`
	}
	if json.Unmarshal(data, &event) != nil {
		return "", ""
	}
	response := event.cloudDeclaredResponse
	if event.Type == "response.created" {
		response = event.Response
	} else if stream || event.Object != "response" {
		return "", ""
	}
	if strings.TrimSpace(response.ID) == "" {
		return "", ""
	}
	return cloudLogLabel(response.Model), cloudResponseTier(response.Tier)
}

func cloudResponseTier(value string) string {
	switch value {
	case "premium", "default", "priority", "flex", "scale", "auto":
		return value
	}
	return ""
}

func cloudCreatedModel(data []byte) string {
	model, _ := cloudResponseDeclaration(data, true)
	return model
}

func cloudSSEDeclaration(data []byte) (string, string) {
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	var fields []string
	eventName := ""
	for _, line := range lines[:len(lines)-1] {
		if line == "" {
			if eventName == "" || eventName == "response.created" {
				if model, tier := cloudResponseDeclaration([]byte(strings.Join(fields, "\n")), true); model != "" {
					return model, tier
				}
			}
			fields = nil
			eventName = ""
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		if name == "event" {
			eventName = value
		}
		if name == "data" {
			fields = append(fields, value)
		}
	}
	return "", ""
}

func cloudSSEModel(data []byte) string {
	model, _ := cloudSSEDeclaration(data)
	return model
}

func formatCloudRequestLog(record *cloudPendingLog) string {
	value := func(s, missing string) string {
		if s != "" {
			return s
		}
		return missing
	}
	sent, got := record.view, record.response
	sentTicket, gotTicket, length := "未带票", "未返回", "未返回"
	if record.action == "关联未知" {
		sentTicket = "未知"
	}
	if sent.TicketLen > 0 {
		sentTicket = cloudDisplayFingerprint(sent.Fingerprint)
	}
	if got.TicketLen > 0 {
		gotTicket, length = cloudDisplayFingerprint(got.Fingerprint), fmt.Sprint(got.TicketLen)
	}
	cookies := "未观测"
	if record.headersSeen {
		cookies = "无"
	}
	if len(record.cookieNames) > 0 {
		cookies = "有 " + strings.Join(record.cookieNames, ", ")
	}
	if !record.headersSeen {
		gotTicket, length = "未观测", "未观测"
	}
	first := fmt.Sprintf("cookie %s · 票 %s → %s · 模型 %s → %s", value(sent.Gateway, "-"), sentTicket,
		gotTicket, value(sent.Model, "-"), value(got.Model, "未返回"))
	second := fmt.Sprintf("返回网关 %s · Set-Cookie %s · 票长 %s", value(got.Gateway, "未返回"), cookies, length)
	if record.buffering != "" {
		second += " · 缓冲 " + record.buffering
	}
	if record.tier != "" {
		second += " · tier " + record.tier
	}
	return first + "\n" + second + formatCloudChainLog(record.chain)
}
