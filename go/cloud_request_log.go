package main

import (
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	cloudPendingRequestMax = 256
	cloudRequestScanMax    = 16 * 1024
	cloudRequestTTL        = 15 * time.Minute
)

// 待关联记录只保存摘要；SSE 临时缓冲有界，确认声明后立即释放。
type cloudPendingLog struct {
	view, response cloudLogView
	action         string
	at             time.Time
	sequence       uint64
	buffer         []byte
	headersSeen    bool
	scanned        bool
	published      bool
	cookieNames    []string
	buffering      string
	tier           string
	chain          cloudChainObservation
	authKey        string
}

var cloudRequestLogs = struct {
	sync.Mutex
	items    map[string]*cloudPendingLog
	sequence uint64
}{items: map[string]*cloudPendingLog{}}

func cloudRequestView(headers http.Header, model string) cloudLogView {
	pairs := map[string]string{}
	for _, part := range strings.Split(headerValue(headers, "Cookie"), ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && routeCookieWanted(name) {
			pairs["__"+strings.ToLower(strings.TrimLeft(name, "_"))] = value
		}
	}
	ticket := headerValue(headers, turnStateHeader)
	cookieHash := ""
	if len(pairs) > 0 {
		cookieHash = cloudFingerprint(pairs["__cflb"] + "\x00" + pairs["__oailb"])
	}
	return cloudLogView{TicketLen: len(ticket), Fingerprint: cloudFingerprint(ticket), CookieFingerprint: cookieHash,
		Gateway: cloudCookieGateway(pairs), Model: cloudLogLabel(model)}
}

func cloudLogLabel(value string) string {
	if cloudNamePattern.MatchString(value) {
		return value
	}
	return ""
}

func cloudHasRequestLog(id string) bool {
	cloudRequestLogs.Lock()
	defer cloudRequestLogs.Unlock()
	_, exists := cloudRequestLogs.items[id]
	return exists
}

// 合并的只是钩子的观测副本，绝不改动请求本身或增加模型请求。
func cloudRememberRequest(req pluginapi.RequestInterceptRequest, out pluginapi.RequestInterceptResponse) {
	if req.RequestID == "" {
		return
	}
	if out.Terminate {
		cloudRecordLog("已拦截", "请求模型 %s · 本地 HTTP %d · 未发送上游", cloudSafeLabel(req.Model), out.StatusCode)
		cloudRequestLogs.Lock()
		delete(cloudRequestLogs.items, req.RequestID)
		cloudRequestLogs.Unlock()
		return
	}
	headers := req.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	for _, key := range out.ClearHeaders {
		for name := range headers {
			if strings.EqualFold(name, key) {
				delete(headers, name)
			}
		}
	}
	for name, values := range out.Headers {
		for previous := range headers {
			if strings.EqualFold(previous, name) {
				delete(headers, previous)
			}
		}
		headers[name] = append([]string(nil), values...)
	}
	model := pickModel(req.Model, req.RequestedModel)
	before, after := cloudRequestView(req.Headers, model), cloudRequestView(headers, model)
	action := "未改写"
	if after.TicketLen > 0 || after.CookieFingerprint != "" {
		action = "沿用"
	}
	if (after.TicketLen > 0 && after.Fingerprint != before.Fingerprint) ||
		(after.CookieFingerprint != "" && after.CookieFingerprint != before.CookieFingerprint) {
		action = "注入"
	}
	body := req.Body
	if len(out.Body) > 0 {
		body = out.Body
	}
	cloudStartRequestLog(req.RequestID, &cloudPendingLog{view: after, action: action, chain: cloudRequestChain(body),
		authKey: cloudAuthObservationKey(metadataString(req.Metadata, selectedAuthMetadataKey))})
}

func cloudStartRequestLog(id string, record *cloudPendingLog) {
	if id == "" {
		return
	}
	cloudRequestLogs.Lock()
	defer cloudRequestLogs.Unlock()
	if len(cloudRequestLogs.items) >= cloudPendingRequestMax {
		oldest := ""
		for key, item := range cloudRequestLogs.items {
			if oldest == "" || item.at.Before(cloudRequestLogs.items[oldest].at) {
				oldest = key
			}
		}
		delete(cloudRequestLogs.items, oldest)
	}
	cloudRequestLogs.sequence++
	record.sequence, record.at = cloudRequestLogs.sequence, time.Now()
	cloudRequestLogs.items[id] = record
}

// 兼容已确认的注入观测；正常业务入口同时记录沿用/未改写路径。
func cloudRememberInjection(id string, entry cloudMintEntry) {
	cloudStartRequestLog(id, &cloudPendingLog{view: cloudEntryView(entry), action: "注入"})
}

func cloudGetRequestLog(id string) *cloudPendingLog {
	record := cloudRequestLogs.items[id]
	if record != nil && time.Since(record.at) > cloudRequestTTL {
		delete(cloudRequestLogs.items, id)
		return nil
	}
	if record == nil {
		if len(cloudRequestLogs.items) >= cloudPendingRequestMax {
			return nil
		}
		cloudRequestLogs.sequence++
		record = &cloudPendingLog{action: "关联未知", at: time.Now(), sequence: cloudRequestLogs.sequence}
		cloudRequestLogs.items[id] = record
	}
	return record
}

func cloudLogResponse(id string, headers http.Header, model string) {
	if id == "" {
		return
	}
	cloudRequestLogs.Lock()
	defer cloudRequestLogs.Unlock()
	record := cloudGetRequestLog(id)
	if record == nil {
		return
	}
	if headers != nil {
		ticket := headerValue(headers, turnStateHeader)
		pair := routeCookiesFromResponseHeaders(headers, time.Now())
		record.response.TicketLen, record.response.Fingerprint = len(ticket), cloudFingerprint(ticket)
		record.response.Gateway = cloudCookieGateway(pair.pairs)
		record.headersSeen, record.cookieNames = true, cloudSetCookieNames(headers)
		record.buffering = cloudLogLabel(headerValue(headers, "X-Codex-Safety-Buffering-Faster-Model"))
	}
	if model = cloudLogLabel(model); model != "" {
		record.response.Model = model
	}
	cloudPublishRequestLog(record, "业务回源观测")
}

func cloudSetCookieNames(headers http.Header) []string {
	seen := map[string]bool{}
	for key, values := range headers {
		if !strings.EqualFold(key, "Set-Cookie") {
			continue
		}
		for _, value := range values {
			name, _, ok := strings.Cut(value, "=")
			name = strings.TrimSpace(name)
			// 名称也不可信；不展示任意会话标识或利用 cookie 名携带的内容。
			if !ok || (name != "__cf_bm" && name != "__cflb" && name != "__oailb") {
				name = "其他"
			}
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloudLogStreamChunk(id string, chunk []byte) {
	cloudRequestLogs.Lock()
	defer cloudRequestLogs.Unlock()
	record := cloudRequestLogs.items[id]
	if record == nil || record.scanned {
		return
	}
	if time.Since(record.at) > cloudRequestTTL {
		delete(cloudRequestLogs.items, id)
		return
	}
	remaining := cloudRequestScanMax - len(record.buffer)
	record.buffer = append(record.buffer, chunk[:min(len(chunk), remaining)]...)
	model, tier := cloudSSEDeclaration(record.buffer)
	if model != "" {
		record.response.Model, record.tier = model, tier
		record.buffer, record.scanned = nil, true
		cloudPublishRequestLog(record, "业务模型确认")
	} else if len(record.buffer) == cloudRequestScanMax {
		record.buffer, record.scanned = nil, true
	}
}

func cloudLogResponseBody(id string, body []byte) {
	if id == "" {
		return
	}
	model, tier := cloudResponseDeclaration(body, false)
	if model == "" {
		return
	}
	cloudRequestLogs.Lock()
	defer cloudRequestLogs.Unlock()
	record := cloudGetRequestLog(id)
	if record == nil {
		return
	}
	record.response.Model, record.tier = model, tier
	cloudPublishRequestLog(record, "业务模型确认")
}

func cloudPublishRequestLog(record *cloudPendingLog, phase string) {
	message := formatCloudRequestLog(record)
	if cloudUpsertRequestLog(record.sequence, record.at, record.action, message, record.published) {
		log.Printf(logPrefix+"%s · %s · %s", phase, record.action, message)
	}
	record.published = true
}
