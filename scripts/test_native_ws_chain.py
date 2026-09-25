"""加载真实插件 .so，将两轮实际本地 WS 数据喂入 ABI 钩子；无真实凭据。"""
import base64
import ctypes
import json
import os
import unittest
from pathlib import Path

import yaml

from test_ws_chain_probe import local_relay, local_server
from ws_chain_probe import fingerprint, run_chain


class Buffer(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class Plugin:
    def __init__(self, path):
        self.library = ctypes.CDLL(str(Path(path).resolve()))
        self.library.cliproxyPluginCall.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Buffer)]
        self.library.cliproxyPluginCall.restype = ctypes.c_int
        self.library.cliproxyPluginFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

    def call(self, method, value):
        raw = json.dumps(value).encode()
        output = Buffer()
        code = self.library.cliproxyPluginCall(method.encode(), raw, len(raw), ctypes.byref(output))
        try:
            response = json.loads(ctypes.string_at(output.ptr, output.length))
        finally:
            self.library.cliproxyPluginFree(output.ptr, output.length)
        if code != 0 or not response["ok"]:
            raise RuntimeError("native plugin ABI call failed")
        return response["result"]


@unittest.skipUnless(os.environ.get("NATIVE_PLUGIN_PATH"), "set NATIVE_PLUGIN_PATH to the newly built local .so")
class NativeChainTest(unittest.TestCase):
    def test_real_relay_websocket_and_plugin_preserve_chain(self):
        plugin = Plugin(os.environ["NATIVE_PLUGIN_PATH"])
        config = {"role": "business", "dry_run": False, "cloud_mint": {
            "enabled": True, "url": "http://127.0.0.1:1/", "gateway": "unified-15", "transport": "websocket"}}
        plugin.call("plugin.register", {"schema_version": 6, "config_yaml": base64.b64encode(yaml.safe_dump(config).encode()).decode()})
        plugin.call("management.register", {"ResourceBasePath": "/v0/resource/plugins/codex-turn-state-cloud-mint"})
        requests = []

        def request(payload, headers, index):
            request_id = "native-turn-" + str(index)
            result = plugin.call("request.intercept_after", {"RequestID": request_id, "Model": "gpt-6-sol",
                "Body": base64.b64encode(json.dumps(payload).encode()).decode(),
                "Headers": {name: [value] for name, value in headers.raw_items()},
                "Metadata": {"selected_auth_id": "codex-local-fixture.json"}})
            self.assertFalse(result.get("Terminate", result.get("terminate", False)))
            self.assertFalse(result.get("Body", result.get("body")))
            self.assertFalse(result.get("Headers", result.get("headers")))
            requests.append(payload)

        def event(payload, index):
            plugin.call("websocket.response_event", {"RequestID": "native-turn-" + str(index),
                "AuthID": "codex-local-fixture.json", "Provider": "codex", "EventType": payload["type"],
                "Payload": base64.b64encode(json.dumps(payload).encode()).decode()})

        with local_server(on_request=request, on_event=event) as (upstream, seen), local_relay(upstream) as relay:
            result = run_chain(f"ws://127.0.0.1:{relay}/backend-api/codex/responses",
                {"X-Relay-Key": "local-relay-key", "Cookie": "__cflb=route; __oailb=unified-15", "X-Codex-Turn-State": "private-native-ticket"},
                "gpt-6-sol", timeout=4)
        self.assertTrue(result["completed"])
        self.assertEqual(1, seen["connections"])
        self.assertEqual("resp_fixture_0", requests[1]["previous_response_id"])
        status = plugin.call("management.handle", {"Method": "GET", "Path": "/v0/management/codex-turn-state-cloud-mint/cloud-status"})
        body = json.loads(base64.b64decode(status.get("Body", status.get("body"))))
        logs = body["logs"]
        self.assertEqual(2, len(logs))
        self.assertTrue(all(row["kind"] == "沿用" and "WS completed" in row["message"] for row in logs))
        self.assertIn("previous #" + fingerprint("resp_fixture_0"), logs[1]["message"])
        for private in ["private-native-ticket", "codex-local-fixture.json", "resp_fixture_0", "resp_fixture_1"]:
            self.assertNotIn(private, json.dumps(body))


if __name__ == "__main__":
    unittest.main()
