#!/usr/bin/env python3

import argparse
import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class ResearchHandler(SimpleHTTPRequestHandler):
    ui_directory: Path
    event_store: Path

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.ui_directory), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self.send_json(
                {
                    "status": "ok",
                    "store": str(self.event_store),
                    "store_exists": self.event_store.exists(),
                }
            )
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["500"])[0]), 5000))
                events = self.load_events()[-limit:]
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self.send_json({"count": len(events), "events": events})
            return
        super().do_GET()

    def load_events(self) -> list[dict]:
        if not self.event_store.exists():
            return []
        events = []
        with self.event_store.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("The evidence store contains a malformed event")
                    events.append(event)
        return events

    def send_json(self, value: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local REB research UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7319)
    parser.add_argument("--store", type=Path, default=Path("build/sessions/demo.jsonl"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ResearchHandler.ui_directory = Path(__file__).resolve().parent
    ResearchHandler.event_store = args.store.resolve()
    server = ThreadingHTTPServer((args.host, args.port), ResearchHandler)
    print(f"Research UI: http://{args.host}:{args.port}")
    print(f"Event store: {ResearchHandler.event_store}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
