#!/usr/bin/env bash
# 手动打一发云端打票，用于诊断 503。与插件 cloud_mint_client.go 发同一组头。
#
#   CPA_RELAY_KEY=xxx ./scripts/mint_once.sh <fc_url> [model]
#
# 环境变量:
#   CPA_RELAY_KEY   必填,与 FC 的 RELAY_KEY 同值(不进命令行参数,不落盘)
#   AUTH_FILE       Codex 凭据 JSON,默认取仓库根目录 codex-*.json 第一个
#   CPA_MINT_PROXY  可选,插件到 FC 的前置代理(http/https/socks5/socks5h)
#   MINT_GATEWAY    目标网关,默认 unified-88(对齐 cloud_mint.gateway)
#   MINT_TRANSPORT  sse|websocket,默认 sse(对齐 cloud_mint.transport)
#
# 输出只含状态码、错误码与脱敏摘要;票/Cookie/token 一律只打长度。
set -euo pipefail

FC_URL="${1:?usage: mint_once.sh <fc_url> [model]}"
MODEL="${2:-gpt-6-sol}"
: "${CPA_RELAY_KEY:?export CPA_RELAY_KEY first}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUTH_FILE="${AUTH_FILE:-$(ls "$ROOT"/codex-*.json 2>/dev/null | head -1)}"
[ -n "$AUTH_FILE" ] || { echo "no codex-*.json auth file found; set AUTH_FILE" >&2; exit 1; }

TOKEN="$(jq -r '.access_token // empty' "$AUTH_FILE")"
ACCOUNT="$(jq -r '.account_id // empty' "$AUTH_FILE")"
[ -n "$TOKEN" ] || { echo "auth file has no access_token: $AUTH_FILE" >&2; exit 1; }

echo "== target: $FC_URL  model: $MODEL  auth: $(basename "$AUTH_FILE") (token len ${#TOKEN})"

CURL=(curl -sS -o /tmp/mint_once_body.json -D /tmp/mint_once_headers.txt -w "%{http_code}")
[ -n "${CPA_MINT_PROXY:-}" ] && CURL+=(--proxy "$CPA_MINT_PROXY")

CODE="$("${CURL[@]}" -X POST "$FC_URL" \
  -H "X-Relay-Key: $CPA_RELAY_KEY" \
  -H "X-Relay-Mint: ${MINT_GATEWAY:-unified-88}" \
  -H "X-Mint-Model: $MODEL" \
  -H "X-Mint-Transport: ${MINT_TRANSPORT:-sse}" \
  -H "X-Mint-Len: 780" \
  -H "X-Mint-TTL: 240" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Chatgpt-Account-Id: $ACCOUNT" \
  --max-time 120)" || true

echo "== HTTP $CODE"
grep -iE "^(x-relay-error|x-fc-request-id|x-relay-edge-ip|x-fc-error)" /tmp/mint_once_headers.txt || true

jq 'def mask(s): if (s|type)=="string" then "<len=\(s|length)>" else s end;
  {
    transport, gateway, edge_ip, attempts, expires_at,
    cookies:      (.cookies      // {} | with_entries(.value = mask(.value))),
    cookie_header: (.cookie_header | mask(. // empty)),
    turn_state:   (.turn_state   | mask(. // empty)),
    tickets:      (.tickets      // {} | with_entries(.value |= {ticket_len, served_model, issued_at, expires_at, age_s, cached})),
    errors, attempt_log,
    error: (.error // empty | if type=="object" then . + {upstream_body: ((.upstream_body // "") | tostring | .[0:200])} else . end)
  }' /tmp/mint_once_body.json 2>/dev/null || head -c 500 /tmp/mint_once_body.json
