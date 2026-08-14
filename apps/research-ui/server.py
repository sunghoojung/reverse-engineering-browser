#!/usr/bin/env python3

import argparse
import json
import re
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


CANONICAL_UINT64 = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT_KINDS = {"javascript", "wasm", "source_map", "response_body"}
MAX_ARTIFACT_RESPONSE_BYTES = 2 * 1024 * 1024
PUBLIC_ARTIFACT_FIELDS = (
    "protocol_version",
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "parent_artifact_id",
    "creator_event_id",
    "kind",
    "url",
    "mime_type",
    "byte_size",
    "sha256",
    "sensitive",
)


class ResearchHandler(SimpleHTTPRequestHandler):
    ui_directory: Path
    event_store: Path
    artifact_store: Path

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
                    "artifact_store": str(self.artifact_store),
                    "artifact_store_exists": self.artifact_store.exists(),
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
        if parsed.path == "/api/artifacts":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["500"])[0]), 5000))
                artifacts = self.load_artifacts()[-limit:]
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            public_artifacts = [
                {field: artifact[field] for field in PUBLIC_ARTIFACT_FIELDS}
                for artifact in artifacts
            ]
            self.send_json({"count": len(public_artifacts), "artifacts": public_artifacts})
            return
        artifact_match = re.fullmatch(r"/api/artifacts/([^/]+)/content", parsed.path)
        if artifact_match is not None:
            try:
                artifact_id = artifact_match.group(1)
                query = parse_qs(parsed.query)
                offset = max(0, int(query.get("offset", ["0"])[0]))
                limit = max(
                    1,
                    min(
                        int(query.get("limit", [str(MAX_ARTIFACT_RESPONSE_BYTES)])[0]),
                        MAX_ARTIFACT_RESPONSE_BYTES,
                    ),
                )
                artifact, content_path = self.find_artifact(artifact_id)
                total_size = artifact["byte_size"]
                if offset > total_size:
                    raise ValueError("Artifact content offset exceeds byte size")
                with content_path.open("rb") as stream:
                    stream.seek(offset)
                    body = stream.read(limit)
            except FileNotFoundError:
                self.send_json({"error": "Artifact not found"}, HTTPStatus.NOT_FOUND)
                return
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            self.send_artifact_bytes(body, total_size, offset)
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

    def load_artifacts(self) -> list[dict]:
        manifest = self.artifact_store / "manifest.jsonl"
        if not manifest.exists():
            return []
        artifacts = []
        seen_ids = set()
        with manifest.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                artifact = json.loads(line)
                if not self.is_artifact(artifact):
                    raise ValueError("The artifact manifest contains a malformed record")
                if artifact["artifact_id"] in seen_ids:
                    raise ValueError("The artifact manifest contains a duplicate artifact ID")
                seen_ids.add(artifact["artifact_id"])
                artifacts.append(artifact)
        return artifacts

    def is_artifact(self, artifact: object) -> bool:
        if (
            not isinstance(artifact, dict)
            or type(artifact.get("protocol_version")) is not int
            or artifact["protocol_version"] != 1
        ):
            return False
        identifier_fields = (
            "artifact_id",
            "session_id",
            "navigation_id",
            "frame_id",
            "parent_artifact_id",
            "creator_event_id",
        )
        if not all(
            isinstance(artifact.get(field), str)
            and CANONICAL_UINT64.fullmatch(artifact[field])
            and int(artifact[field]) < 2**64
            for field in identifier_fields
        ):
            return False
        if artifact.get("kind") not in ARTIFACT_KINDS:
            return False
        if not isinstance(artifact.get("url"), str) or not artifact["url"]:
            return False
        if not isinstance(artifact.get("mime_type"), str) or not artifact["mime_type"]:
            return False
        if (
            type(artifact.get("byte_size")) is not int
            or artifact["byte_size"] < 0
            or artifact["byte_size"] >= 2**64
        ):
            return False
        if not isinstance(artifact.get("sha256"), str) or not SHA256.fullmatch(artifact["sha256"]):
            return False
        if not isinstance(artifact.get("sensitive"), bool):
            return False
        if artifact.get("content_path") != f"blobs/{artifact['sha256']}.bin":
            return False
        return artifact["sensitive"] == (artifact["kind"] == "response_body")

    def find_artifact(self, artifact_id: str) -> tuple[dict, Path]:
        if not CANONICAL_UINT64.fullmatch(artifact_id) or int(artifact_id) >= 2**64:
            raise FileNotFoundError(artifact_id)
        artifact = next(
            (item for item in self.load_artifacts() if item["artifact_id"] == artifact_id),
            None,
        )
        if artifact is None:
            raise FileNotFoundError(artifact_id)
        store_root = self.artifact_store.resolve()
        content_path = (store_root / artifact["content_path"]).resolve()
        if not content_path.is_relative_to(store_root):
            raise ValueError("Artifact content path escapes the artifact store")
        if not content_path.is_file() or content_path.stat().st_size != artifact["byte_size"]:
            raise ValueError("Artifact content does not match its manifest")
        return artifact, content_path

    def send_json(self, value: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_artifact_bytes(self, body: bytes, total_size: int, offset: int) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "sandbox")
        self.send_header("Content-Disposition", 'attachment; filename="artifact.bin"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Artifact-Total-Bytes", str(total_size))
        self.send_header("X-Artifact-Offset", str(offset))
        self.send_header("X-Artifact-Truncated", "1" if offset + len(body) < total_size else "0")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local REB research UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7319)
    parser.add_argument("--store", type=Path, default=Path("build/sessions/demo.jsonl"))
    parser.add_argument("--artifacts", type=Path, default=Path("build/sessions/artifacts"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ResearchHandler.ui_directory = Path(__file__).resolve().parent
    ResearchHandler.event_store = args.store.resolve()
    ResearchHandler.artifact_store = args.artifacts.resolve()
    server = ThreadingHTTPServer((args.host, args.port), ResearchHandler)
    print(f"Research UI: http://{args.host}:{args.port}")
    print(f"Event store: {ResearchHandler.event_store}")
    print(f"Artifact store: {ResearchHandler.artifact_store}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
