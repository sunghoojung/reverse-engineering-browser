"""Bounded, ephemeral selection of one outgoing request value."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from urllib.parse import parse_qsl, urlencode, urlsplit

from deobfuscation_worker import worker_path

MAX_BODY_BYTES = 128 * 1024
MAX_POINTER_BYTES = 256
MAX_PREVIEW_BYTES = 256
FIELD_STATUSES = {
    "available", "missing", "invalid_json", "invalid_pointer", "body_too_large",
    "value_too_large", "unavailable", "error", "uncaptured", "truncated", "ambiguous",
}
SELECTOR_KINDS = {"json", "form", "query", "header", "body"}


def query_context_digest(url: str, kind: str, selector: str, key: bytes) -> str | None:
    """Keyed digest of unselected query input; never disclose its raw value."""
    try:
        query = urlsplit(url).query
        if len(query.encode("utf-8")) > 8 * 1024:
            return None
        if kind == "query":
            pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=1024)
            query = urlencode([(name, value) for name, value in pairs if name != selector])
        return hmac.new(key, query.encode("utf-8"), hashlib.sha256).hexdigest()
    except ValueError:
        return None


def _selected_text(value: str) -> dict:
    encoded = value.encode("utf-8")
    if len(encoded) > 4 * 1024:
        return {"status": "value_too_large", "sha256": None, "preview": "", "bytes": 0}
    return {"status": "available", "sha256": hashlib.sha256(encoded).hexdigest(),
            "preview": encoded[:MAX_PREVIEW_BYTES].decode("utf-8", "ignore"), "bytes": len(encoded)}


def extract_request_value(kind: str, selector: str, *, body: str | None = None,
                          url: str = "", headers: dict | None = None) -> dict:
    """Select one value without retaining unrelated request material."""
    if kind == "json":
        return extract_field(body, selector) if body is not None else _empty("uncaptured")
    if kind == "body":
        if body is None:
            return _empty("uncaptured")
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            return _empty("truncated")
        return _selected_text(body)
    if kind == "header":
        if not isinstance(headers, dict):
            return _empty("uncaptured")
        matches = [value for name, value in headers.items()
                   if isinstance(name, str) and name.lower() == selector.lower()]
        if not matches:
            return _empty("missing")
        if len(matches) != 1 or not isinstance(matches[0], str):
            return _empty("ambiguous")
        return _selected_text(json.dumps(matches[0], ensure_ascii=False))
    try:
        source = body if kind == "form" else urlsplit(url).query if kind == "query" else None
    except ValueError:
        return _empty("unavailable")
    if source is None:
        return _empty("uncaptured")
    if len(source.encode("utf-8")) > MAX_BODY_BYTES:
        return _empty("truncated")
    try:
        matches = [value for name, value in parse_qsl(source, keep_blank_values=True,
                                                       max_num_fields=1024) if name == selector]
    except ValueError:
        return _empty("unavailable")
    if not matches:
        return _empty("missing")
    if len(matches) != 1:
        return _empty("ambiguous")
    return _selected_text(json.dumps(matches[0], ensure_ascii=False))


def _empty(status: str) -> dict:
    return {"status": status, "sha256": None, "preview": "", "bytes": 0}


def extract_field(body: str, pointer: str) -> dict:
    """Never retain the full body or selected value after this call returns."""
    if len(body.encode("utf-8")) > MAX_BODY_BYTES or len(pointer.encode("utf-8")) > MAX_POINTER_BYTES:
        return {"status": "truncated", "sha256": None, "preview": "", "bytes": 0}
    try:
        binary = worker_path()
        if binary is None:
            raise OSError("worker unavailable")
        encoded = json.dumps({"operation": "request_field", "body": body, "pointer": pointer}).encode() + b"\n"
        result = subprocess.run(
            [str(binary)], input=encoded, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=1, check=False, env={"LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode or len(result.stdout) > 8 * 1024:
            raise ValueError("worker result")
        document = json.loads(result.stdout)
        status = document.get("status")
        if document.get("schema") != "reb-request-field-v1" or status not in FIELD_STATUSES:
            raise ValueError("worker response")
        value = document.get("value")
        if status == "available":
            if not isinstance(value, str) or len(value.encode("utf-8")) > 4 * 1024:
                raise ValueError("worker value")
            encoded_value = value.encode("utf-8")
            preview = encoded_value[:MAX_PREVIEW_BYTES].decode("utf-8", "ignore")
            return {"status": status, "sha256": hashlib.sha256(encoded_value).hexdigest(),
                    "preview": preview, "bytes": len(encoded_value)}
        if value is not None:
            raise ValueError("unexpected worker value")
        return {"status": status, "sha256": None, "preview": "", "bytes": 0}
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "sha256": None, "preview": "", "bytes": 0}
