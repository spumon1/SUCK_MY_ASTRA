"""Directly verify a native plugin's management ABI and embedded dashboard.

Run with a .so matching the current machine architecture. This loads trusted
local native code; it does not contact CPA or upstream services.
"""
import argparse
import base64
import ctypes
import json
from pathlib import Path


class Buffer(ctypes.Structure):
    _fields_ = [('ptr', ctypes.c_void_p), ('length', ctypes.c_size_t)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('--plugin-id', default='codex-turn-state-cloud-mint')
    parser.add_argument('--html-out', type=Path)
    args = parser.parse_args()
    library = ctypes.CDLL(str(args.library.resolve()))
    call = library.cliproxyPluginCall
    call.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Buffer)]
    call.restype = ctypes.c_int
    library.cliproxyPluginFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

    def invoke(method, request):
        payload = json.dumps(request).encode()
        output = Buffer()
        code = call(method.encode(), payload, len(payload), ctypes.byref(output))
        try:
            response = json.loads(ctypes.string_at(output.ptr, output.length))
        finally:
            library.cliproxyPluginFree(output.ptr, output.length)
        assert code == 0 and response['ok'], response
        return response['result']

    prefix = '/v0/resource/plugins/' + args.plugin_id
    routes = invoke('management.register', {'ResourceBasePath': prefix})
    paths = [r.get('Path', r.get('path')) for r in routes.get('Routes', routes.get('routes'))]
    assert '/' + args.plugin_id + '/cloud-status' in paths, paths
    result = invoke('management.handle', {'Method': 'GET', 'Path': prefix + '/dashboard'})
    html = base64.b64decode(result.get('Body', result.get('body')))
    expected = f'name="cpa-plugin-id" content="{args.plugin_id}"'.encode()
    assert expected in html, 'configuration uses wrong plugin ID'
    assert b'cloud-mint-ui-20260924-ws-chain' in html, 'old dashboard'
    assert b'const records=[' not in html and b'INTERACTIVE EXAMPLE' not in html
    status = invoke('management.handle', {
        'Method': 'GET', 'Path': '/v0/management/' + args.plugin_id + '/cloud-status',
    })
    assert status.get('StatusCode', status.get('status_code')) == 200
    if args.html_out:
        args.html_out.write_bytes(html)
    print(f'PASS actual ABI: ID={args.plugin_id}; dashboard={len(html)} bytes; authenticated status route=200')


if __name__ == '__main__':
    main()
