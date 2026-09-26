"""带路由 Cookie 的双轮 WebSocket 续链诊断；默认不执行线上请求。"""
import argparse
import base64
import hashlib
import json
import re
import secrets
import socket
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from websockets.sync.client import connect


class ProbeError(Exception):
    """只携带受控错误码，避免把原始异常中的凭据写进报告。"""


def fingerprint(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode()[:8]


def route_cookie(path, gateway):
    raw = Path(path).read_text().strip()
    return parse_route_cookie(raw, gateway)


def parse_route_cookie(raw, gateway=None):
    if raw.startswith("{"):
        data = json.loads(raw)
        data = data.get("cookies", data)
        raw = "; ".join(key + "=" + data[key] for key in ["__cflb", "__oailb"] if key in data)
    raw = raw.removeprefix("Cookie:").strip()
    pairs = {}
    for part in raw.split(";"):
        name, found, value = part.strip().partition("=")
        if name not in {"__cflb", "__oailb"}:
            continue
        if not found or name in pairs or not value or len(value) > 4096 or any(ord(c) < 33 or ord(c) > 126 or c in ",;" for c in value):
            raise ProbeError("invalid_route_cookie")
        pairs[name] = value
    if set(pairs) != {"__cflb", "__oailb"}:
        raise ProbeError("incomplete_route_pair")
    part = pairs["__oailb"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    import re
    label = re.search(r"unified[-_.]?(\d+)", json.dumps(claims), re.I)
    if not label or (gateway and "unified-" + label[1] != gateway):
        raise ProbeError("route_gateway_mismatch")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time():
        raise ProbeError("route_pair_expired")
    return "__cflb=" + pairs["__cflb"] + "; __oailb=" + pairs["__oailb"]


def receive_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ProbeError("proxy_closed")
        chunks.extend(chunk)
    return bytes(chunks)


def error_diagnostic(event):
    error = event.get("error") or event.get("response", {}).get("error") or event
    if not isinstance(error, dict):
        return {"code": "response_not_completed"}
    known = {"previous_response_not_found", "invalid_request_error", "invalid_request", "invalid_api_key",
             "rate_limit_exceeded", "unsupported_parameter", "unknown_parameter", "invalid_value",
             "model_not_found", "server_error", "authentication_error", "permission_denied"}
    parameters = {"max_output_tokens", "max_completion_tokens", "previous_response_id", "model", "input",
                  "instructions", "store", "stream", "type", "reasoning", "reasoning.effort"}
    details = {"code": error.get("code") if error.get("code") in known else "response_not_completed"}
    if error.get("type") in known:
        details["type"] = error["type"]
    if error.get("param") in parameters:
        details["param"] = error["param"]
    message = str(error.get("message", ""))[:512]
    if message.lower().startswith(("unsupported parameter", "unknown parameter")):
        details["code"] = "unsupported_parameter"
        for name in sorted(parameters, key=len, reverse=True):
            if name in message:
                details["param"] = name
                break
    return details


def conversation_payload(model, prompt, previous=None):
    # 跟 CPA 的 Codex 转换器排同一支队：私有端点不收 max_output_tokens，WS 也别把 stream 带来凑热闹。
    payload = {"type": "response.create", "model": model,
               "instructions": "Follow the user's short output instruction.", "store": False,
               "reasoning": {"effort": "low"}, "parallel_tool_calls": True,
               "include": ["reasoning.encrypted_content"],
               "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": prompt}]}]}
    if previous:
        payload["previous_response_id"] = previous
    return payload


def socks_tunnel(proxy, target):
    """SOCKS5 域名远端解析；无明文凭据命令参数、无代理失败直连回退。"""
    address, destination = urlsplit(proxy), urlsplit(target)
    if not address.hostname or not address.port:
        raise ProbeError("proxy_port_missing")
    sock = socket.create_connection((address.hostname, address.port), timeout=10)
    try:
        method = 2 if address.username is not None else 0
        sock.sendall(bytes([5, 1, method]))
        if receive_exact(sock, 2) != bytes([5, method]):
            raise ProbeError("proxy_auth_method_rejected")
        if method == 2:
            username = unquote(address.username).encode()
            password = unquote(address.password or "").encode()
            if not 0 < len(username) <= 255 or len(password) > 255:
                raise ProbeError("invalid_proxy_credentials")
            sock.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
            if receive_exact(sock, 2) != b"\x01\x00":
                raise ProbeError("proxy_auth_rejected")
        host = destination.hostname.encode("idna")
        if len(host) > 255:
            raise ProbeError("invalid_target_host")
        port = destination.port or (443 if destination.scheme == "wss" else 80)
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + port.to_bytes(2, "big"))
        version, status, reserved, kind = receive_exact(sock, 4)
        if (version, status, reserved) != (5, 0, 0):
            raise ProbeError("proxy_connect_rejected")
        sizes = {1: 4, 4: 16}
        size = receive_exact(sock, 1)[0] if kind == 3 else sizes.get(kind)
        if size is None:
            raise ProbeError("proxy_invalid_reply")
        receive_exact(sock, size + 2)
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def completed_response(ws, deadline, model, *, observer=None):
    created_id, declared_model = None, None
    streamed_text = ""
    for _ in range(256):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("chain_deadline")
        try:
            event = json.loads(ws.recv(timeout=remaining))
        except TimeoutError:
            raise ProbeError("chain_deadline") from None
        kind = event.get("type")
        if observer:
            observer(event)
        response = event.get("response", {})
        if kind == "response.output_text.delta" and isinstance(event.get("delta"), str):
            streamed_text = (streamed_text + event["delta"])[:4096]
        if kind in {"error", "response.failed", "response.incomplete"}:
            diagnostic = error_diagnostic(event)
            error = ProbeError(diagnostic["code"])
            error.diagnostic = diagnostic
            raise error
        if kind == "response.created":
            created_id, declared_model = response.get("id"), response.get("model")
        if kind != "response.completed":
            continue
        response_id = response.get("id")
        if not isinstance(response_id, str) or not response_id or response.get("status") != "completed":
            raise ProbeError("invalid_completed_response")
        if created_id and created_id != response_id:
            raise ProbeError("response_id_mismatch")
        if response.get("model", declared_model) != model or (declared_model and declared_model != model):
            raise ProbeError("declared_model_mismatch")
        return {**response, "_probe_stream_text": streamed_text}
    raise ProbeError("event_limit")


@contextmanager
def probe_connection(url, headers, proxy=None):
    sock = socks_tunnel(proxy, url) if proxy and urlsplit(proxy).scheme in {"socks5", "socks5h"} else None
    try:
        with connect(url, additional_headers=headers, sock=sock, proxy=None if sock else proxy,
                     compression=None, open_timeout=10, close_timeout=2, max_size=1024 * 1024) as ws:
            yield ws
    finally:
        if sock:
            sock.close()


def run_chain(url, headers, model, timeout=60, proxy=None):
    """同一 socket 两轮；首轮完成前不续链，错误时不重连、不补历史、不重试。"""
    marker = "CHAIN_" + secrets.token_hex(6)
    deadline = time.monotonic() + timeout
    report = {"connection_attempts": 1, "connections": 0, "turn_limit": 2, "turns": []}
    try:
        with probe_connection(url, headers, proxy) as ws:
            report["connections"] = 1
            previous = None
            prompts = [f"Remember this marker: {marker}. Reply only OK.", "What marker did I ask you to remember? Reply only the marker."]
            for index, prompt in enumerate(prompts):
                parent = previous
                payload = conversation_payload(model, prompt, previous)
                ws.send(json.dumps(payload))
                response = completed_response(ws, deadline, model)
                report["turns"].append({"turn": index + 1, "completed": True,
                                        "response_id_fingerprint": fingerprint(response["id"]),
                                        "previous_id_fingerprint": fingerprint(previous) if previous else None})
                previous = response["id"]
                if index == 1:
                    text = "".join(part.get("text", "") for item in response.get("output", [])
                                   for part in item.get("content", []) if part.get("type") == "output_text")
                    report["text_source"] = "completed_output" if text else "stream_delta"
                    text = text or response.get("_probe_stream_text", "")
                    report["output_text_length"] = len(text)
                    report["exact_output"] = text.strip() == marker
                    report["context_marker_recalled"] = re.search(r"(?<![A-Za-z0-9_])" + re.escape(marker) + r"(?![A-Za-z0-9_])", text) is not None
                    report["previous_id_echoed"] = response.get("previous_response_id") == parent if response.get("previous_response_id") else None
                    if not report["context_marker_recalled"]:
                        raise ProbeError("context_not_confirmed")
            report["completed"] = True
            return report
    except Exception as error:
        if hasattr(error, "diagnostic"):
            report["upstream_error"] = error.diagnostic
        error.probe_report = report
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-dir", type=Path, required=True)
    parser.add_argument("--cookie-file", type=Path, required=True)
    parser.add_argument("--auth-file", type=Path)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--model", default="gpt-6-sol")
    parser.add_argument("--confirm-live", action="store_true")
    args = parser.parse_args()
    if not args.confirm_live:
        parser.error("真实测试最多生成两轮并消耗额度；确认后添加 --confirm-live")
    import yaml
    root = args.instance_dir
    config = yaml.safe_load((root / "config.yaml").read_text())["plugins"]["configs"]["codex-turn-state-cloud-mint"]["cloud_mint"]
    env = json.loads((root / "cloud-mint.env.json").read_text())
    auth_path = args.auth_file or root / "auth/codex-local-smoke-test.json"
    auth_bytes = auth_path.read_bytes()
    auth = json.loads(auth_bytes)
    report = {"gateway": args.gateway, "model": args.model, "completed": False,
              "credential_source_sha256": hashlib.sha256(auth_bytes).hexdigest(),
              "account_fingerprint": fingerprint(auth["account_id"])}
    try:
        cookie = route_cookie(args.cookie_file, args.gateway)
        endpoint = urlsplit(config["url"])
        if endpoint.scheme != "https" or endpoint.username or endpoint.query or endpoint.fragment:
            raise ProbeError("invalid_fc_endpoint")
        url = urlunsplit(("wss", endpoint.netloc, "/backend-api/codex/responses", "", ""))
        headers = {"Cookie": cookie, "Authorization": "Bearer " + auth["access_token"],
                   "Chatgpt-Account-Id": auth["account_id"], "X-Relay-Key": env[config["key_env"]],
                   "OpenAI-Beta": "responses_websockets=2026-02-06", "originator": "codex-tui"}
        proxy = config.get("proxy_url") or env.get(config.get("proxy_env", ""))
        if config.get("proxy_env") and not proxy:
            raise ProbeError("configured_proxy_missing")
        report.update(run_chain(url, headers, args.model, proxy=proxy))
    except ProbeError as error:
        report.update(getattr(error, "probe_report", {}))
        report["error"] = str(error)
    except Exception as error:
        report.update(getattr(error, "probe_report", {}))
        report["error"] = type(error).__name__
    output = root / "results" / ("ws-chain-" + secrets.token_hex(4) + ".json")
    report["source_unchanged"] = auth_path.read_bytes() == auth_bytes
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("report:", output)
    return 0 if report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
