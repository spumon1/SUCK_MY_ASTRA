"""Serve the embedded dashboard locally with isolated, synthetic API responses.

Usage: python scripts/ui_preview.py --port 8765
The server binds only to loopback and never connects to CPA or an upstream API.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


class PreviewHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/fixture.js':
            payload = (ROOT / 'tests/ui/fixture.js').read_bytes()
            content_type = 'text/javascript; charset=utf-8'
        elif path in ('/', '/baseline'):
            if path == '/baseline':
                html = subprocess.check_output(
                    ['git', 'show', '762df1b:go/ui.html'], cwd=ROOT
                ).decode('utf-8')
            else:
                html = (ROOT / 'go/ui.html').read_text(encoding='utf-8')
            html = html.replace('<head>', '<head><script src="/fixture.js"></script>', 1)
            html = html.replace('<body>', '<body><div style="padding:8px 12px;border:1px solid #aab9a4;border-radius:6px;margin-bottom:20px;font:12px sans-serif;color:#526548;background:#f4f8f1">本地验收 · 全部为虚构数据，操作不会发送到 CPA</div>', 1)
            payload = html.encode('utf-8')
            content_type = 'text/html; charset=utf-8'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'none'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(payload)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), PreviewHandler)
    print(f'Local preview: http://127.0.0.1:{args.port}', flush=True)
    server.serve_forever()
