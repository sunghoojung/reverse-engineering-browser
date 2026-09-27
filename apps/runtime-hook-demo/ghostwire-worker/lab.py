"""Serve the worker signer fixture."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, mime):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        routes = {
            '/': (HERE / 'parcel.html', 'text/html; charset=utf-8'),
            '/signer-worker.js': (HERE / 'signer-worker.js', 'text/javascript'),
        }
        path, mime = routes.get(self.path.split('?', 1)[0], (None, None))
        if not path or not path.exists():
            self.reply(404, b'Not found', 'text/plain')
            return
        self.reply(200, path.read_bytes(), mime)

    def do_POST(self):
        if self.path != '/api/submit':
            self.reply(404, b'Not found', 'text/plain')
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                raise ValueError('invalid body')
            payload = json.loads(self.rfile.read(size))['payload']
            if not isinstance(payload, str):
                raise ValueError('invalid payload')
            result = {'accepted': True, 'receipt': hashlib.sha256(payload.encode()).hexdigest()[:12]}
            self.reply(200, json.dumps(result).encode(), 'application/json')
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self.reply(400, json.dumps({'error': str(exc)}).encode(), 'application/json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8766)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'http://127.0.0.1:{server.server_port}/', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
