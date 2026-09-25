"""通过真实原生 ABI 验证冷启动 503 恢复；宿主和云函数均使用本地虚构数据。"""

import base64
import ctypes
import json
import os
import struct
import subprocess
import sys
import threading
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from test_native_ws_chain import Buffer, Plugin


MODEL = "gpt-6-sol"
GATEWAY = "unified-88"
KEY_ENV = "CPA_NATIVE_RECOVERY_KEY"
RELAY_KEY = "synthetic-relay-key"
ACCESS_TOKEN = "synthetic-access-token"
WAIT_SECONDS = 5
POLL_SECONDS = 0.01
FIXTURE_ENV = "CPA_NATIVE_RECOVERY_CHILD"

HostCall = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(Buffer),
)
HostFree = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)


class HostAPI(ctypes.Structure):
    _fields_ = [("abi_version", ctypes.c_uint32), ("host_ctx", ctypes.c_void_p),
                ("call", HostCall), ("free_buffer", HostFree)]


class PluginAPI(ctypes.Structure):
    _fields_ = [("abi_version", ctypes.c_uint32), ("call", ctypes.c_void_p),
                ("free_buffer", ctypes.c_void_p), ("shutdown", ctypes.c_void_p)]


class NativeHost:
    def __init__(self, plugin):
        self.runtime = {"id": "native-recovery", "name": "native-recovery.json", "provider": "codex"}
        self.buffers = {}
        self.methods = []
        self.call = HostCall(self.handle)
        self.free = HostFree(lambda ptr, _length: self.buffers.pop(ptr, None))
        self.api = HostAPI(1, None, self.call, self.free)
        self.plugin_api = PluginAPI()
        init = plugin.library.cliproxy_plugin_init
        init.argtypes = [ctypes.POINTER(HostAPI), ctypes.POINTER(PluginAPI)]
        init.restype = ctypes.c_int
        if init(ctypes.byref(self.api), ctypes.byref(self.plugin_api)) != 0:
            raise RuntimeError("native host initialization failed")

    def handle(self, _ctx, method, raw, length, output):
        try:
            name = method.decode()
            self.methods.append(name)
            if json.loads(ctypes.string_at(raw, length)) != {"auth_index": "native-index"}:
                raise ValueError("unexpected credential lookup")
            if name == "host.auth.get_runtime":
                result = {"auth": self.runtime}
            elif name == "host.auth.get":
                result = {"auth_index": "native-index", "name": "native-recovery.json",
                          "json": {"type": "codex", "access_token": ACCESS_TOKEN}}
            else:
                raise ValueError("unexpected host method")
            response = {"ok": True, "result": result}
        except Exception:
            response = {"ok": False, "error": {"code": "fixture_error", "message": "invalid fixture call"}}
        encoded = json.dumps(response).encode()
        buffer = ctypes.create_string_buffer(encoded)
        address = ctypes.addressof(buffer)
        self.buffers[address] = buffer  # 持有宿主缓冲区，直到 Go 调用 free_buffer。
        output.contents.ptr, output.contents.length = address, len(encoded)
        return 0


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def cloud_result():
    issued = int(time.time())
    timestamp = lambda seconds: datetime.fromtimestamp(seconds, timezone.utc).isoformat()
    ticket = encoded(b"\x80" + struct.pack(">Q", issued) + bytes(576))
    claims = {"aud": f"chat.gateway.{GATEWAY}.api.openai.com", "exp": issued + 3600}
    cookies = {"__cflb": "synthetic-pair", "__oailb": "e30." + encoded(json.dumps(claims).encode()) + ".fixture"}
    return {"transport": "sse", "gateway": GATEWAY, "cookies": cookies,
            "expires_at": timestamp(issued + 3600), "tickets": {MODEL: {
                "turn_state": ticket, "ticket_len": len(ticket), "served_model": MODEL,
                "issued_at": timestamp(issued), "expires_at": timestamp(issued + 240)}}}


@contextmanager
def local_mint():
    release = threading.Event()
    observed = {"calls": 0, "authorized": False}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            observed["calls"] += 1
            observed["authorized"] = (self.headers.get("X-Relay-Key") == RELAY_KEY
                                      and self.headers.get("Authorization") == "Bearer " + ACCESS_TOKEN)
            if not release.wait(WAIT_SECONDS):
                self.send_error(504)
                return
            body = json.dumps(cloud_result()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", release, observed
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(WAIT_SECONDS)


def wait_ready(plugin):
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        response = plugin.call("management.handle", {"Method": "GET",
            "Path": "/v0/management/codex-turn-state-cloud-mint/cloud-status"})
        body = json.loads(base64.b64decode(response["Body"]))
        if any(row["state"] == "ready" for row in body["rows"]):
            return body
        time.sleep(POLL_SECONDS)
    raise AssertionError("background mint did not become ready")


@unittest.skipUnless(os.environ.get("NATIVE_PLUGIN_PATH"), "set NATIVE_PLUGIN_PATH to a freshly built plugin")
class NativeRecoveryTest(unittest.TestCase):
    def test_cold_503_recovers_and_disabled_account_stays_blocked(self):
        if os.environ.get(FIXTURE_ENV) != "1":
            # Go 原生库使用启动时的环境快照，不能依赖加载后 Python 的 putenv。
            env = {**os.environ, KEY_ENV: RELAY_KEY, FIXTURE_ENV: "1"}
            run = subprocess.run([sys.executable, str(Path(__file__).resolve())],
                                 env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, run.returncode, run.stdout + run.stderr)
            return
        with local_mint() as (url, release, observed):
            plugin = Plugin(os.environ["NATIVE_PLUGIN_PATH"])
            host = NativeHost(plugin)
            try:
                self.check_recovery(plugin, host, url=url, release=release, observed=observed)
            finally:
                plugin.library.cliproxyPluginShutdown()
            self.assertFalse(host.buffers, "host response buffers must be released")

    def check_recovery(self, plugin, host, *, url, release, observed):
        config = {"role": "business", "dry_run": False, "cloud_mint": {
            "enabled": True, "url": url, "key_env": KEY_ENV, "wait_ms": 20, "gateway": GATEWAY}}
        plugin.call("plugin.register", {"schema_version": 6,
            "config_yaml": base64.b64encode(json.dumps(config).encode()).decode()})
        plugin.call("management.register", {"ResourceBasePath": "/v0/resource/plugins/codex-turn-state-cloud-mint"})
        request = {"RequestID": "native-recovery-request", "Model": MODEL,
                   "Metadata": {"selected_auth_id": "native-recovery", "selected_auth_index": "native-index"}}
        cold = plugin.call("request.intercept_after", request)
        self.assertTrue(cold["Terminate"])
        self.assertEqual(503, cold["StatusCode"])
        self.assertEqual(["host.auth.get_runtime", "host.auth.get"], host.methods)
        host.runtime.update(unavailable=True, status="error", next_retry_after="2000-01-01T00:00:00Z")
        release.set()
        status = wait_ready(plugin)
        recovered = plugin.call("request.intercept_after", request)
        self.assertFalse(recovered["Terminate"])
        headers = {key.lower(): value for key, value in recovered["Headers"].items()}
        self.assertEqual(780, len(headers["x-codex-turn-state"][0]))
        self.assertIn("__oailb=", headers["cookie"][0])
        self.assertEqual(1, observed["calls"], "ready ticket must be reused, not reminted")
        self.assertTrue(observed["authorized"])
        reads = host.methods.count("host.auth.get")
        host.runtime.update(disabled=True)
        blocked = plugin.call("request.intercept_after", request)
        self.assertTrue(blocked["Terminate"])
        self.assertEqual(503, blocked["StatusCode"])
        self.assertEqual(reads, host.methods.count("host.auth.get"))
        for secret in [RELAY_KEY, ACCESS_TOKEN]:
            self.assertNotIn(secret, json.dumps(status))


if __name__ == "__main__":
    unittest.main()
