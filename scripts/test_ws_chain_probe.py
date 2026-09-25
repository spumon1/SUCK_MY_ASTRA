"""WebSocket 续链诊断测试：合成 Cookie、本地服务器、无真实账号或额度。"""
import base64
import json
import os
import re
import select
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

from websockets.sync.server import serve

from ws_chain_probe import ProbeError, route_cookie, run_chain
from ws_chain_probe import error_diagnostic
from ws_capture_route import capture_dialogue


@contextmanager
def local_server(mode="ok", set_route_cookie=False, *, on_request=None, on_event=None):
    seen = {"connections": 0, "payloads": [], "cookie": None}

    def handler(ws):
        seen["connections"] += 1
        seen["cookie"] = ws.request.headers.get("Cookie")
        marker = ""
        try:
            for index in range(2):
                payload = json.loads(ws.recv())
                seen["payloads"].append(payload)
                if on_request:
                    on_request(payload, ws.request.headers, index)
                if index == 0:
                    match = re.search(r"CHAIN_[a-f0-9]+", payload["input"][0]["content"][0]["text"])
                    marker = match[0] if match else ""
                if mode == "missing_previous" and index == 1:
                    ws.send(json.dumps({"type": "error", "error": {"code": "previous_response_not_found"}}))
                    return
                if mode == "silent":
                    ws.recv()
                    return
                rid = "resp_fixture_" + str(index)
                created = {"type": "response.created", "response": {"id": rid, "model": payload["model"]}}
                if on_event:
                    on_event(created, index)
                ws.send(json.dumps(created))
                text = "OK" if index == 0 else ("wrong" if mode == "wrong_context" else marker)
                if mode == "quoted_context" and index == 1:
                    text = "`" + marker + "`"
                ws.send(json.dumps({"type": "response.output_text.delta", "delta": text}))
                response = {"id": rid, "model": payload["model"], "status": "completed",
                            "output": [{"content": [{"type": "output_text", "text": text}]}]}
                if mode == "delta_only":
                    response["output"] = []
                completed = {"type": "response.completed", "response": response}
                if on_event:
                    on_event(completed, index)
                ws.send(json.dumps(completed))
        except Exception:
            return

    def handshake(connection, request, response):
        if set_route_cookie:
            payload = json.dumps({"exp": int(time.time()) + 300, "aud": "chat.gateway.unified-15.api.openai.com"}).encode()
            token = "e30." + base64.urlsafe_b64encode(payload).decode().rstrip("=") + ".sig"
            response.headers["Set-Cookie"] = "__cflb=route; Path=/"
            response.headers["Set-Cookie"] = "__oailb=" + token + "; Path=/"
            response.headers["Set-Cookie"] = "__cf_bm=private; Path=/"
        return response

    with serve(handler, "127.0.0.1", 0, compression=None, process_response=handshake) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.socket.getsockname()[1], seen
        finally:
            server.shutdown()
            thread.join(timeout=2)


@contextmanager
def local_relay(upstream_port):
    env = {**os.environ, "FC_SERVER_PORT": "0", "RELAY_KEY": "local-relay-key",
           "RELAY_UPSTREAM": f"http://127.0.0.1:{upstream_port}"}
    command = ["node", str(Path(__file__).resolve().parents[1] / "relay" / "index.js")]
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([process.stdout], [], [], 5)[0]:
            raise RuntimeError("local relay startup timeout")
        first = json.loads(process.stdout.readline())
        port = int(first["msg"].rsplit(":", 1)[1])
        yield port
    finally:
        process.terminate()
        process.communicate(timeout=5)


class WebSocketChainTests(unittest.TestCase):
    def test_diagnostics_whitelist_fields_and_never_echo_free_text(self):
        event = {"type": "error", "error": {"code": "unsupported_parameter", "param": "max_output_tokens",
                                               "message": "Access Token private-secret is not allowed"}}
        diagnostic = error_diagnostic(event)
        self.assertEqual("unsupported_parameter", diagnostic["code"])
        self.assertEqual("max_output_tokens", diagnostic["param"])
        self.assertNotIn("private-secret", json.dumps(diagnostic))

    def test_capture_from_dialogue_then_chain_with_cookie_via_fc(self):
        with local_server(set_route_cookie=True) as (upstream, seen), local_relay(upstream) as port:
            url = f"ws://127.0.0.1:{port}/backend-api/codex/responses"
            headers = {"X-Relay-Key": "local-relay-key"}
            cookie, capture = capture_dialogue(url, headers, "gpt-6-sol", timeout=3)
            result = run_chain(url, {**headers, "Cookie": cookie}, "gpt-6-sol", timeout=3)
        self.assertTrue(capture["dialogue_completed"])
        self.assertEqual("unified-15", capture["gateway"])
        self.assertTrue(result["completed"])
        self.assertEqual(2, seen["connections"])
        self.assertEqual(3, len(seen["payloads"]))
        self.assertTrue(all("max_output_tokens" not in payload for payload in seen["payloads"]))
        self.assertTrue(all("stream" not in payload for payload in seen["payloads"]))
        self.assertEqual(cookie, seen["cookie"])
        self.assertNotIn("__cf_bm", cookie)
        self.assertNotIn(cookie, json.dumps(capture))

    def test_two_turns_use_same_socket_and_completed_response_id(self):
        with local_server() as (port, seen):
            report = run_chain(f"ws://127.0.0.1:{port}", {"Cookie": "__cflb=fake; __oailb=fake"}, "gpt-6-sol", timeout=3)
        self.assertTrue(report["completed"])
        self.assertTrue(report["context_marker_recalled"])
        self.assertEqual(1, seen["connections"])
        self.assertEqual("resp_fixture_0", seen["payloads"][1]["previous_response_id"])
        self.assertNotIn("previous_response_id", seen["payloads"][0])
        self.assertNotIn("CHAIN_", json.dumps(seen["payloads"][1]))
        self.assertNotIn("resp_fixture", json.dumps(report))

    def test_real_relay_tunnel_preserves_cookie_and_continuation(self):
        with local_server() as (upstream, seen), local_relay(upstream) as port:
            report = run_chain(f"ws://127.0.0.1:{port}/backend-api/codex/responses",
                               {"X-Relay-Key": "local-relay-key", "Cookie": "__cflb=fake; __oailb=fake"}, "gpt-6-sol", timeout=3)
        self.assertTrue(report["completed"])
        self.assertEqual(1, seen["connections"])
        self.assertEqual("__cflb=fake; __oailb=fake", seen["cookie"])
        self.assertEqual("resp_fixture_0", seen["payloads"][1]["previous_response_id"])

    def test_missing_previous_never_reconnects_or_replays_history(self):
        with local_server("missing_previous") as (port, seen):
            with self.assertRaisesRegex(ProbeError, "previous_response_not_found") as error:
                run_chain(f"ws://127.0.0.1:{port}", {}, "gpt-6-sol", timeout=3)
        self.assertEqual(1, seen["connections"])
        self.assertEqual(2, len(seen["payloads"]))
        self.assertEqual(1, len(error.exception.probe_report["turns"]))

    def test_wrong_answer_does_not_claim_context_continuation(self):
        with local_server("wrong_context") as (port, _):
            with self.assertRaisesRegex(ProbeError, "context_not_confirmed"):
                run_chain(f"ws://127.0.0.1:{port}", {}, "gpt-6-sol", timeout=3)

    def test_quoted_marker_confirms_context_but_not_exact_output(self):
        with local_server("quoted_context") as (port, _):
            result = run_chain(f"ws://127.0.0.1:{port}", {}, "gpt-6-sol", timeout=3)
        self.assertTrue(result["context_marker_recalled"])
        self.assertFalse(result["exact_output"])

    def test_streamed_text_used_when_completed_output_is_absent(self):
        with local_server("delta_only") as (port, _):
            result = run_chain(f"ws://127.0.0.1:{port}", {}, "gpt-6-sol", timeout=3)
        self.assertTrue(result["completed"])
        self.assertEqual("stream_delta", result["text_source"])

    def test_no_event_has_bounded_deadline(self):
        with local_server("silent") as (port, seen):
            with self.assertRaisesRegex(ProbeError, "chain_deadline"):
                run_chain(f"ws://127.0.0.1:{port}", {}, "gpt-6-sol", timeout=0.15)
        self.assertEqual(1, len(seen["payloads"]))

    def test_cookie_file_allowlist_gateway_and_expiry(self):
        def pair(exp):
            claims = {"aud": "chat.gateway.unified-15.api.openai.com", "exp": exp}
            jwt = "e30." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".sig"
            return {"__cflb": "route", "__oailb": jwt, "session": "must-not-forward", "__cf_bm": "private"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cookie.json"
            path.write_text(json.dumps(pair(time.time() + 300)))
            value = route_cookie(path, "unified-15")
            self.assertNotIn("must-not-forward", value)
            self.assertNotIn("__cf_bm", value)
            with self.assertRaisesRegex(ProbeError, "route_gateway_mismatch"):
                route_cookie(path, "unified-94")
            path.write_text(json.dumps(pair(1)))
            with self.assertRaisesRegex(ProbeError, "route_pair_expired"):
                route_cookie(path, "unified-15")


if __name__ == "__main__":
    unittest.main()
