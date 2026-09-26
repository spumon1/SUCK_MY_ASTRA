#!/usr/bin/env bash
# 给云端打票端点递一次诊断单，专查 503；头部照抄插件 cloud_mint_client.go 的工牌，不临场加戏。
#
#   CPA_RELAY_KEY=xxx ./scripts/mint_once.sh <fc_url> [model]
#
# 环境变量负责报菜名：
#   CPA_RELAY_KEY   必填，与 FC 的 RELAY_KEY 对口令；不进命令行参数、不落盘，钥匙不登台
#   AUTH_FILE       Codex 凭据 JSON；未点名时请仓库根目录第一个 codex-*.json 出列
#   CPA_MINT_PROXY  可选，插件到 FC 的带路人（http/https/socks5/socks5h）
#   MINT_GATEWAY    目标网关门牌，默认 unified-88（与 cloud_mint.gateway 对齐）
#   MINT_TRANSPORT  sse|websocket 两条走廊，默认 sse（与 cloud_mint.transport 对齐）
#
# 报告只让状态码、错误码与脱敏摘要上台；票/Cookie/token 只报身高（长度），不露脸。
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
