package main

import (
	"errors"
	"strings"
	"time"
)

type cloudMintRoute struct {
	Model  string
	Cookie string
}

// 只拿请求明确带来的 LB pair；无关 Cookie 留在业务链路，不向其他账号池借盘子。
func cloudMintSeedCookie(raw, gateway string, now time.Time) (string, error) {
	pairs := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if name != "__cflb" && name != "__oailb" {
			continue
		}
		if !ok || value == "" || !cookieValueSafe(value) || pairs[name] != "" ||
			strings.IndexFunc(value, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
			return "", errors.New("invalid route cookie pair")
		}
		pairs[name] = value
	}
	if len(pairs) == 0 {
		return "", nil
	}
	if pairs["__cflb"] == "" || pairs["__oailb"] == "" {
		return "", errors.New("incomplete route cookie pair")
	}
	if cloudCookieGateway(pairs) != gateway || !jwtExpiresAt(pairs["__oailb"]).After(now) {
		return "", errors.New("expired or off-target route cookie pair")
	}
	return "__cflb=" + pairs["__cflb"] + "; __oailb=" + pairs["__oailb"], nil
}
