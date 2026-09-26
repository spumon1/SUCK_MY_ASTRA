"""从一轮对话抓取路由 pair，再在新 WS 上进行两轮续链验证。"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml

from ws_chain_probe import ProbeError, completed_response, conversation_payload, fingerprint, parse_route_cookie, probe_connection, run_chain


class RouteCapture:
    def __init__(self):
        self.cookies = {}
        self.names = set()
        self.events = {}

    def headers(self, headers):
        values = headers.get_all("set-cookie") if hasattr(headers, "get_all") else next(
            (value for key, value in headers.items() if key.lower() == "set-cookie"), [])
        for line in values if isinstance(values, list) else [values]:
            name, equals, value = str(line).split(";", 1)[0].partition("=")
            if equals and name in {"__cflb", "__oailb", "__cf_bm"}:
                self.names.add(name)
            if equals and name in {"__cflb", "__oailb"}:
                self.cookies[name] = value

    def event(self, event):
        kind = event.get("type")
        allowed = {"response.created", "response.completed", "response.failed", "response.incomplete",
                   "response.output_text.delta", "error", "codex.response.metadata"}
        key = kind if kind in allowed else "other"
        self.events[key] = self.events.get(key, 0) + 1
        if kind == "codex.response.metadata" and isinstance(event.get("headers"), dict):
            self.headers(event["headers"])

    def summary(self):
        return {"cookie_names": sorted(self.names), "complete_pair": set(self.cookies) == {"__cflb", "__oailb"},
                "event_counts": dict(self.events)}


def capture_dialogue(url, headers, model, *, proxy=None, timeout=45):
    capture = RouteCapture()
    report = {"dialogue_completed": False, "connection_attempts": 1}
    deadline = time.monotonic() + timeout
    try:
        with probe_connection(url, headers, proxy) as ws:
            report["handshake_status"] = ws.response.status_code
            capture.headers(ws.response.headers)
            payload = conversation_payload(model, "Reply only OK.")
            ws.send(json.dumps(payload))
            response = completed_response(ws, deadline, model, observer=capture.event)
            report.update(dialogue_completed=True, response_id_fingerprint=fingerprint(response["id"]))
        cookie = parse_route_cookie(json.dumps(capture.cookies))
        encoded = capture.cookies["__oailb"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        gateway = "unified-" + re.search(r"unified[-_.]?(\d+)", json.dumps(claims), re.I)[1]
        report.update(capture.summary(), gateway=gateway, cookie_fingerprint=fingerprint(cookie))
        return cookie, report
    except Exception as error:
        report.update(capture.summary())
        if hasattr(error, "diagnostic"):
            report["upstream_error"] = error.diagnostic
        response = getattr(error, "response", None)
        if response is not None:
            report["handshake_status"] = getattr(response, "status_code", None)
        error.capture_report = report
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-dir", type=Path, required=True)
    parser.add_argument("--auth-file", type=Path, required=True)
    parser.add_argument("--model", default="gpt-6-sol")
    parser.add_argument("--confirm-live", action="store_true")
    args = parser.parse_args()
    if not args.confirm_live:
        parser.error("最多 3 轮、2 条连接并消耗额度；确认后添加 --confirm-live")
    root = args.instance_dir
    cfg_bytes = (root / "config.yaml").read_bytes()
    auth_bytes = args.auth_file.read_bytes()
    config = yaml.safe_load(cfg_bytes)["plugins"]["configs"]["codex-turn-state-cloud-mint"]["cloud_mint"]
    env = json.loads((root / "cloud-mint.env.json").read_text())
    auth = json.loads(auth_bytes)
    report = {"model": args.model, "max_connections": 2, "max_turns": 3, "completed": False,
              "credential_source_sha256": hashlib.sha256(auth_bytes).hexdigest(),
              "account_fingerprint": fingerprint(auth["account_id"])}
    tag = secrets.token_hex(4)
    try:
        endpoint = urlsplit(config["url"])
        if endpoint.scheme != "https" or endpoint.username or endpoint.query or endpoint.fragment:
            raise ProbeError("invalid_fc_endpoint")
        url = urlunsplit(("wss", endpoint.netloc, "/backend-api/codex/responses", "", ""))
        headers = {"Authorization": "Bearer " + auth["access_token"], "Chatgpt-Account-Id": auth["account_id"],
                   "X-Relay-Key": env[config["key_env"]], "OpenAI-Beta": "responses_websockets=2026-02-06", "originator": "codex-tui"}
        proxy = config.get("proxy_url") or env.get(config.get("proxy_env", ""))
        if config.get("proxy_env") and not proxy:
            raise ProbeError("configured_proxy_missing")
        cookie, report["capture"] = capture_dialogue(url, headers, args.model, proxy=proxy)
        private = root / ("captured-route-" + tag + ".json")
        # 新文件穿 0600 防护衣，旧 Cookie 不动；报告只按指纹点名，不让秘密上台。
        with os.fdopen(os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump({"cookies": dict(part.split("=", 1) for part in cookie.split("; ")),
                       "gateway": report["capture"]["gateway"]}, file)
        report["cookie_file"] = private.name
        report["chain"] = run_chain(url, {**headers, "Cookie": cookie}, args.model, proxy=proxy)
        report["completed"] = report["chain"]["completed"]
    except Exception as error:
        report["error"] = str(error) if isinstance(error, ProbeError) else type(error).__name__
        if hasattr(error, "capture_report"):
            report["capture"] = error.capture_report
        if hasattr(error, "probe_report"):
            report["chain"] = error.probe_report
    report["source_unchanged"] = args.auth_file.read_bytes() == auth_bytes
    report["config_unchanged"] = (root / "config.yaml").read_bytes() == cfg_bytes
    output = root / "results" / ("ws-capture-chain-" + tag + ".json")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    print("report:", output.name)
    return 0 if report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
