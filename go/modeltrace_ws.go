package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Test B 的 WS 客户端只连本机 CPA 业务端点，不直连上游；发 codex 挑战，收 output_text。
// CPA 按真实业务链路处理：插件注入池票、CPA 出口联网。这里是坐席上的客人，不兼任厨师，
// 票的回放交给 CPA 注入链路，不在客户端私自加菜。
const wsClientReadCap = 8 << 20

// clientTurnWS 向 CPA 或 FC 桥接发一轮 WS 挑战，带回声明模型和输出文本。
// accountID 不空就加 Chatgpt-Account-Id，FC 桥接铸票要验这个身份证。
func clientTurnWS(ctx context.Context, endpoint, apiKey, accountID, model, prompt string) (served, output string, err error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return "", "", errors.New("invalid ws endpoint")
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	var conn net.Conn
	raw, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", "", fmt.Errorf("dial: %w", err)
	}
	if u.Scheme == "wss" {
		tconn := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
		if err := tconn.HandshakeContext(dialCtx); err != nil {
			raw.Close()
			return "", "", fmt.Errorf("tls: %w", err)
		}
		conn = tconn
	} else {
		conn = raw
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	wsKey := base64.StdEncoding.EncodeToString(keyRaw)
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", wsKey)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("OpenAI-Beta: responses_websockets=2026-02-06\r\n")
	req.WriteString("Originator: codex-tui\r\n")
	fmt.Fprintf(&req, "User-Agent: %s\r\n", probeUserAgent)
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", apiKey)
	if accountID != "" {
		fmt.Fprintf(&req, "Chatgpt-Account-Id: %s\r\n", accountID)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return "", "", fmt.Errorf("write handshake: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", "", fmt.Errorf("read handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return "", "", fmt.Errorf("CPA ws upgrade 拒绝: HTTP %d", resp.StatusCode)
	}
	sum := sha1.Sum([]byte(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return "", "", errors.New("bad ws accept")
	}

	// 发 response.create 挑战帧但不夹票；票由 CPA 注入链路上菜，客户端别抢厨师的勺。
	frame, _ := json.Marshal(map[string]any{
		"type":  "response.create",
		"model": model,
		"input": []any{map[string]any{"type": "message", "role": "user",
			"content": []any{map[string]any{"type": "input_text", "text": prompt}}}},
		"reasoning":           map[string]any{"effort": "low"},
		"store":               false,
		"stream":              true,
		"tool_choice":         "auto",
		"parallel_tool_calls": false,
	})
	if err := wsWriteMasked(conn, 0x1, frame); err != nil {
		return "", "", fmt.Errorf("write frame: %w", err)
	}
	return wsCollectOutput(conn, br)
}

func wsWriteMasked(conn net.Conn, opcode byte, payload []byte) error {
	var header []byte
	n := len(payload)
	switch {
	case n < 126:
		header = []byte{0x80 | opcode, byte(0x80 | n)}
	case n <= 0xffff:
		header = []byte{0x80 | opcode, 0x80 | 126, byte(n >> 8), byte(n)}
	default:
		header = make([]byte, 10)
		header[0] = 0x80 | opcode
		header[1] = 0x80 | 127
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	buf := append(append(append([]byte{}, header...), mask[:]...), masked...)
	_, err := conn.Write(buf)
	return err
}

// wsCollectOutput 逐勺累积 response.output_text.delta，见终态才收碗返回。
func wsCollectOutput(conn net.Conn, br *bufio.Reader) (served, output string, err error) {
	var out strings.Builder
	var frag []byte
	total := 0
	for {
		fin, opcode, payload, rerr := wsReadServerFrame(br)
		if rerr != nil {
			if out.Len() > 0 {
				return served, out.String(), nil
			}
			return served, out.String(), rerr
		}
		total += len(payload)
		if total > wsClientReadCap {
			return served, out.String(), errors.New("output exceeded cap")
		}
		switch opcode {
		case 0x8:
			return served, out.String(), nil
		case 0x9:
			_ = wsWriteMasked(conn, 0xA, payload)
			continue
		case 0xA:
			continue
		}
		if opcode == 0x0 || opcode == 0x1 {
			frag = append(frag, payload...)
			if !fin {
				continue
			}
			text := frag
			frag = nil
			var ev struct {
				Type     string `json:"type"`
				Delta    string `json:"delta"`
				Response struct {
					Model string `json:"model"`
				} `json:"response"`
			}
			if json.Unmarshal(text, &ev) != nil {
				continue
			}
			switch ev.Type {
			case "response.output_text.delta":
				out.WriteString(ev.Delta)
			case "response.created", "response.in_progress":
				if ev.Response.Model != "" {
					served = ev.Response.Model
				}
			case "response.completed", "response.incomplete":
				if ev.Response.Model != "" {
					served = ev.Response.Model
				}
				return served, out.String(), nil
			case "response.failed", "error":
				return served, out.String(), fmt.Errorf("upstream %s", ev.Type)
			}
		}
	}
}

func wsReadServerFrame(br *bufio.Reader) (bool, byte, []byte, error) {
	h0, err := br.ReadByte()
	if err != nil {
		return false, 0, nil, err
	}
	h1, err := br.ReadByte()
	if err != nil {
		return false, 0, nil, err
	}
	fin := h0&0x80 != 0
	opcode := h0 & 0x0f
	if h1&0x80 != 0 {
		return false, 0, nil, errors.New("server frame must not be masked")
	}
	length := uint64(h1 & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := readFullWS(br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := readFullWS(br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsClientReadCap {
		return false, 0, nil, errors.New("server frame too large")
	}
	payload := make([]byte, length)
	if _, err := readFullWS(br, payload); err != nil {
		return false, 0, nil, err
	}
	return fin, opcode, payload, nil
}

func readFullWS(br *bufio.Reader, p []byte) (int, error) {
	got := 0
	for got < len(p) {
		n, err := br.Read(p[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
