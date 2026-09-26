#!/usr/bin/env bash
# 多个 FC（或本地 relay）排队验出票能力；每个目标各领一个账号，别让一个替身包办所有挨打戏。
#   CPA_RELAY_KEY=xxx AUTH_DIR=/path/to/codex-jsons ./scripts/probe_fcs.sh <url1> <url2> ...
# 开场道具由环境提供：
#   CPA_RELAY_KEY  必填，与各 FC 的 RELAY_KEY 对上口令才能开场
#   AUTH_DIR       codex-*.json 的住处；轮流点名，一个 URL 请一个账号上台
#   MODEL          未点名就请 gpt-6-astra 出场
set -uo pipefail
: "${CPA_RELAY_KEY:?export CPA_RELAY_KEY first}"
MODEL="${MODEL:-gpt-6-astra}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUTH_DIR="${AUTH_DIR:-$ROOT}"
mapfile -t AUTHS < <(ls "$AUTH_DIR"/codex-*.json 2>/dev/null)
[ "${#AUTHS[@]}" -gt 0 ] || { echo "no codex-*.json in $AUTH_DIR" >&2; exit 1; }
i=0
printf '%-46s | %-4s | %-6s | %-13s | %-12s | %s\n' URL HTTP TKTLEN SERVED GATEWAY REASON
printf '%.0s-' {1..110}; echo
for URL in "$@"; do
  AF="${AUTHS[$((i % ${#AUTHS[@]}))]}"; i=$((i+1))
  TOKEN="$(jq -r '.access_token // empty' "$AF")"; ACCT="$(jq -r '.account_id // empty' "$AF")"
  BODY=/tmp/probe_body_$i.json; HDR=/tmp/probe_hdr_$i.txt
  CODE="$(curl -sS -o "$BODY" -D "$HDR" -w '%{http_code}' -X POST "$URL" \
     -H "X-Relay-Key: $CPA_RELAY_KEY" -H "X-Relay-Mint: any" -H "X-Mint-Model: $MODEL" \
     -H "X-Mint-Transport: sse" -H "X-Mint-Len: 780" -H "X-Mint-TTL: 240" \
     -H "Authorization: Bearer $TOKEN" -H "Chatgpt-Account-Id: $ACCT" --max-time 120 2>/dev/null)" || CODE=ERR
  read -r TKT SERVED GW REASON < <(python3 - "$BODY" <<'PY'
import sys,json
try: d=json.load(open(sys.argv[1]))
except Exception: print("- - - parse_err"); raise SystemExit
if isinstance(d,dict) and 'error' not in d:
    t=(d.get('tickets') or {}); v=next(iter(t.values()),{}) if t else {}
    print(v.get('ticket_len','-'), v.get('served_model','-') or '-', d.get('gateway','-') or '-', 'OK')
else:
    e=d.get('error',{}) if isinstance(d,dict) else {}
    last=e.get('last',{}) or {}
    print(last.get('len','-'), '-', last.get('gateway','-') or '-', e.get('code') or last.get('why','?'))
PY
)
  printf '%-46s | %-4s | %-6s | %-13s | %-12s | %s\n' "${URL:0:46}" "$CODE" "$TKT" "$SERVED" "$GW" "$REASON"
done
