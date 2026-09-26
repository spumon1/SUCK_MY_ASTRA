package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 插件 → FC 走 WS(而非 HTTP POST):插件对 FC 的透明 WS 中继开一条 WS,FC 透传到
// chatgpt,插件在这条隧道上自己完成 codex 铸票——发 response.create ping,从 101 响应头
// 取 __cflb/__oailb,从 codex.response.metadata 帧取 x-codex-turn-state。全程 WS,FC 只当
// 隧道(零改动)。出口 = FC 部署地域的出口(现"原始模式"下即阿里云直连)。
//
// 与 HTTP 打票等价的验收(票长、Fernet 签发时刻、网关、pair、有效期)复用
// validateCloudMint 的同款判定,保证隧道票和 HTTP 票质量一致。
func mintViaFCTunnel(ctx context.Context, work cloudMintWork) (cloudMintEntry, error) {
	cfg, creds, model, key := work.cfg, work.creds, work.model, work.key
	if strings.TrimSpace(work.proxyURL) != "" {
		return cloudMintEntry{}, errors.New("fc_ws_tunnel 不支持前置代理(plugin→FC 直连);清空该源 proxy_url")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return cloudMintEntry{}, errors.New("invalid cloud endpoint")
	}
	host := u.Hostname()
	secure := u.Scheme == "https"
	port := u.Port()
	if port == "" {
		if secure {
			port = "443"
		} else {
			port = "80"
		}
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, 20*time.Second)
	defer cancelDial()
	raw, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return cloudMintEntry{}, fmt.Errorf("dial FC: %w", err)
	}
	var conn net.Conn = raw
	if secure {
		tconn := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
		if err := tconn.HandshakeContext(dialCtx); err != nil {
			raw.Close()
			return cloudMintEntry{}, fmt.Errorf("tls FC: %w", err)
		}
		conn = tconn
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// WS 升级到 codex 业务端点。X-Relay-Key 给 FC 鉴权;Authorization/账号头/codex 头
	// 由 FC 透传给 chatgpt。带 seedCookie 则是定向打(钉在该 pair 的网关)。
	wsKeyRaw := make([]byte, 16)
	_, _ = rand.Read(wsKeyRaw)
	wsKey := base64.StdEncoding.EncodeToString(wsKeyRaw)
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", "/backend-api/codex/responses")
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", wsKey)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("OpenAI-Beta: responses_websockets=2026-02-06\r\n")
	req.WriteString("Originator: codex-tui\r\n")
	fmt.Fprintf(&req, "Session-Id: %s\r\n", newUUIDish())
	fmt.Fprintf(&req, "User-Agent: %s\r\n", probeUserAgent)
	fmt.Fprintf(&req, "X-Relay-Key: %s\r\n", key)
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", creds.AccessToken)
	if creds.AccountID != "" {
		fmt.Fprintf(&req, "Chatgpt-Account-Id: %s\r\n", creds.AccountID)
	}
	if work.seedCookie != "" {
		fmt.Fprintf(&req, "Cookie: %s\r\n", work.seedCookie)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return cloudMintEntry{}, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return cloudMintEntry{}, fmt.Errorf("read upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return cloudMintEntry{}, fmt.Errorf("FC/上游拒绝 WS 升级: HTTP %d", resp.StatusCode)
	}
	sum := sha1.Sum([]byte(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return cloudMintEntry{}, errors.New("bad ws accept")
	}
	// 路由 pair 在 101 的 Set-Cookie 上(FC 原样透传上游的 101)。
	cookies := parseRoutePair(resp.Header["Set-Cookie"])
	if cookies["__cflb"] == "" || cookies["__oailb"] == "" {
		return cloudMintEntry{}, errors.New("101 未带 __cflb/__oailb 路由 pair")
	}

	// 发 response.create ping(不带 stream,与 FC 的 WS 打票一致),触发上游下发 turn-state。
	ping, _ := json.Marshal(map[string]any{
		"type":                "response.create",
		"model":               model,
		"instructions":        "",
		"store":               false,
		"input":               []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "ping"}}}},
		"reasoning":           map[string]any{"effort": "low"},
		"tool_choice":         "auto",
		"parallel_tool_calls": false,
	})
	if err := wsWriteMasked(conn, 0x1, ping); err != nil {
		return cloudMintEntry{}, fmt.Errorf("write ping: %w", err)
	}

	// 读帧:从 codex.response.metadata 的 headers 取 x-codex-turn-state。
	ticket := ""
	var frag []byte
	for ticket == "" {
		fin, opcode, payload, rerr := wsReadServerFrame(br)
		if rerr != nil {
			return cloudMintEntry{}, fmt.Errorf("read frame: %w", rerr)
		}
		switch opcode {
		case 0x8:
			return cloudMintEntry{}, errors.New("上游在下发票前关闭了 WS")
		case 0x9:
			_ = wsWriteMasked(conn, 0xA, payload)
			continue
		case 0xA:
			continue
		}
		if opcode != 0x0 && opcode != 0x1 {
			continue
		}
		frag = append(frag, payload...)
		if !fin {
			continue
		}
		text := frag
		frag = nil
		if t := ticketFromMetadataFrame(text); t != "" {
			ticket = t
		}
	}

	if len(ticket) != cfg.TicketLength {
		return cloudMintEntry{}, fmt.Errorf("票长不符:得到 %d,要求 %d", len(ticket), cfg.TicketLength)
	}
	// 用与 HTTP 打票同款的合成结果跑 validateCloudMint,复用其网关/pair/有效期判定。
	now := time.Now()
	synthetic := cloudMintResult{
		Transport: cfg.Transport,
		Gateway:   cloudCookieGateway(cookies),
		Cookies:   cookies,
		Tickets: map[string]cloudMintTicket{model: {
			TurnState: ticket, TicketLen: len(ticket), ServedModel: model,
			IssuedAt: cloudIssuedAt(ticket), ExpiresAt: now.Add(time.Duration(cfg.TTLSeconds) * time.Second),
		}},
	}
	synthetic.ExpiresAt = now.Add(time.Duration(cfg.TTLSeconds) * time.Second)
	return validateCloudMint(synthetic, cfg, model, now)
}

// parseRoutePair 从多条 Set-Cookie 里取 __cflb / __oailb 的值。
func parseRoutePair(setCookie []string) map[string]string {
	out := map[string]string{}
	for _, line := range setCookie {
		semi := line
		if i := strings.IndexByte(line, ';'); i >= 0 {
			semi = line[:i]
		}
		eq := strings.IndexByte(semi, '=')
		if eq <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(semi[:eq]))
		val := strings.TrimSpace(semi[eq+1:])
		if name == "__cflb" || name == "__oailb" {
			out[name] = val
		}
	}
	return out
}

// ticketFromMetadataFrame 从 codex.response.metadata 帧的 headers 取 x-codex-turn-state。
func ticketFromMetadataFrame(text []byte) string {
	if !strings.Contains(string(text), "codex.response.metadata") {
		return ""
	}
	var msg struct {
		Headers map[string]any `json:"headers"`
	}
	if json.Unmarshal(text, &msg) != nil {
		return ""
	}
	if v, ok := msg.Headers["x-codex-turn-state"].(string); ok {
		return v
	}
	return ""
}

// newUUIDish 生成一个用作 Session-Id 的随机十六进制串(无需严格 UUID 格式)。
func newUUIDish() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
