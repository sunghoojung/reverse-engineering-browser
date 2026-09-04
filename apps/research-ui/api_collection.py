#!/usr/bin/env python3

import json
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

API_COLLECTION_CONTRACT_VERSION = 1
API_COLLECTION_DOCUMENT_KIND = "api-collection"
API_COLLECTION_ROOT_ID = 1
MAX_API_COLLECTION_BYTES = 2 * 1024 * 1024
MAX_API_COLLECTION_FOLDERS = 32
MAX_API_COLLECTION_REQUESTS = 128
MAX_API_COLLECTION_FOLDER_DEPTH = 4
MAX_API_COLLECTION_NAME_BYTES = 128
MAX_API_COLLECTION_VARIABLES = 32
MAX_API_COLLECTION_VARIABLE_NAME_BYTES = 64
MAX_API_COLLECTION_VARIABLE_VALUE_BYTES = 4 * 1024
MAX_API_COLLECTION_VARIABLE_BYTES = 32 * 1024
MAX_API_COLLECTION_URL_BYTES = 8 * 1024
MAX_API_COLLECTION_METHOD_BYTES = 256
MAX_API_COLLECTION_HEADERS = 64
MAX_API_COLLECTION_HEADER_NAME_BYTES = 128
MAX_API_COLLECTION_HEADER_VALUE_BYTES = 2 * 1024
MAX_API_COLLECTION_HEADER_BYTES = 16 * 1024
MAX_API_COLLECTION_BODY_BYTES = 64 * 1024
MIN_API_COLLECTION_TIMEOUT_MS = 100
MAX_API_COLLECTION_TIMEOUT_MS = 30_000
MAX_SAFE_INTEGER = 2**53 - 1

VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
HEADER_TOKEN = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
FORBIDDEN_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "set-cookie",
    "transfer-encoding",
}


class ApiCollectionError(ValueError):
    pass


class ApiCollectionConflict(ApiCollectionError):
    pass


def api_collection_limits() -> dict[str, int]:
    return {
        "folders": MAX_API_COLLECTION_FOLDERS,
        "requests": MAX_API_COLLECTION_REQUESTS,
        "folder_depth": MAX_API_COLLECTION_FOLDER_DEPTH,
        "variables_per_scope": MAX_API_COLLECTION_VARIABLES,
        "variable_bytes_per_scope": MAX_API_COLLECTION_VARIABLE_BYTES,
        "request_body_bytes": MAX_API_COLLECTION_BODY_BYTES,
        "document_bytes": MAX_API_COLLECTION_BYTES,
    }


def empty_api_collection() -> dict[str, Any]:
    return {
        "contract_version": API_COLLECTION_CONTRACT_VERSION,
        "document_kind": API_COLLECTION_DOCUMENT_KIND,
        "generation": 0,
        "updated_at_ms": 0,
        "folders": [
            {
                "id": API_COLLECTION_ROOT_ID,
                "name": "API Collection",
                "parent_id": None,
                "variables": [],
            }
        ],
        "requests": [],
        "limits": api_collection_limits(),
    }


def _safe_integer(value: Any, label: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise ApiCollectionError(f"{label} is invalid")
    return value


def _bounded_text(
    value: Any,
    label: str,
    max_bytes: int,
    *,
    allow_empty: bool = False,
    trim: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ApiCollectionError(f"{label} must be text")
    normalized = value.strip() if trim else value
    if (
        (not allow_empty and not normalized)
        or len(normalized.encode("utf-8")) > max_bytes
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
    ):
        raise ApiCollectionError(f"{label} is empty, oversized, or contains controls")
    return normalized


def normalize_api_collection_variables(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_API_COLLECTION_VARIABLES:
        raise ApiCollectionError("API Collection variables are invalid or oversized")
    variables: list[dict[str, str]] = []
    names: set[str] = set()
    total_bytes = 0
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"name", "value"}:
            raise ApiCollectionError("API Collection variable shape is invalid")
        name = _bounded_text(
            raw.get("name"),
            "API Collection variable name",
            MAX_API_COLLECTION_VARIABLE_NAME_BYTES,
        )
        variable_value = _bounded_text(
            raw.get("value"),
            "API Collection variable value",
            MAX_API_COLLECTION_VARIABLE_VALUE_BYTES,
            allow_empty=True,
        )
        if not VARIABLE_NAME.fullmatch(name) or name in names:
            raise ApiCollectionError("API Collection variable name is invalid or duplicated")
        names.add(name)
        total_bytes += len(name.encode("utf-8")) + len(variable_value.encode("utf-8"))
        if total_bytes > MAX_API_COLLECTION_VARIABLE_BYTES:
            raise ApiCollectionError("API Collection variable scope exceeds 32 KiB")
        variables.append({"name": name, "value": variable_value})
    return sorted(variables, key=lambda variable: variable["name"])


def _normalize_headers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_API_COLLECTION_HEADERS:
        raise ApiCollectionError("API Collection request headers are invalid")
    headers: list[dict[str, str]] = []
    names: set[str] = set()
    total_bytes = 0
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"name", "value"}:
            raise ApiCollectionError("API Collection request header shape is invalid")
        name = _bounded_text(
            raw.get("name"),
            "API Collection request header name",
            MAX_API_COLLECTION_HEADER_NAME_BYTES,
        )
        header_value = _bounded_text(
            raw.get("value"),
            "API Collection request header value",
            MAX_API_COLLECTION_HEADER_VALUE_BYTES,
            allow_empty=True,
        )
        lower_name = name.lower()
        if (
            any(character not in HEADER_TOKEN for character in name)
            or lower_name in FORBIDDEN_HEADERS
            or lower_name in names
        ):
            raise ApiCollectionError(
                "API Collection request header is forbidden, invalid, or duplicated"
            )
        names.add(lower_name)
        total_bytes += len(name.encode("utf-8")) + len(header_value.encode("utf-8"))
        if total_bytes > MAX_API_COLLECTION_HEADER_BYTES:
            raise ApiCollectionError("API Collection request headers exceed 16 KiB")
        headers.append({"name": name, "value": header_value})
    return headers


def _normalize_folder(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "id",
        "name",
        "parent_id",
        "variables",
    }:
        raise ApiCollectionError("API Collection folder shape is invalid")
    folder_id = _safe_integer(value.get("id"), "API Collection folder ID", 1)
    parent_id = value.get("parent_id")
    if parent_id is not None:
        parent_id = _safe_integer(parent_id, "API Collection parent folder ID", 1)
    name = _bounded_text(
        value.get("name"),
        "API Collection folder name",
        MAX_API_COLLECTION_NAME_BYTES,
        trim=True,
    )
    if "/" in name:
        raise ApiCollectionError("API Collection folder names cannot contain slashes")
    return {
        "id": folder_id,
        "name": name,
        "parent_id": parent_id,
        "variables": normalize_api_collection_variables(value.get("variables")),
    }


REQUEST_CONTENT_FIELDS = (
    "id",
    "folder_id",
    "name",
    "url",
    "method",
    "headers",
    "body",
    "timeout_ms",
    "variables",
)
REQUEST_FIELDS = frozenset((*REQUEST_CONTENT_FIELDS, "created_at_ms", "updated_at_ms"))


def _normalize_request(value: Any, *, require_metadata: bool) -> dict[str, Any]:
    expected = REQUEST_FIELDS if require_metadata else frozenset(REQUEST_CONTENT_FIELDS)
    if not isinstance(value, dict) or set(value) != expected:
        raise ApiCollectionError("API Collection request shape is invalid")
    request_id = _safe_integer(value.get("id"), "API Collection request ID", 1)
    folder_id = _safe_integer(value.get("folder_id"), "API Collection request folder ID", 1)
    name = _bounded_text(
        value.get("name"),
        "API Collection request name",
        MAX_API_COLLECTION_NAME_BYTES,
        trim=True,
    )
    if "/" in name:
        raise ApiCollectionError("API Collection request names cannot contain slashes")
    url = _bounded_text(
        value.get("url"),
        "API Collection request URL template",
        MAX_API_COLLECTION_URL_BYTES,
        trim=True,
    )
    method = _bounded_text(
        value.get("method"),
        "API Collection request method template",
        MAX_API_COLLECTION_METHOD_BYTES,
        trim=True,
    )
    body = value.get("body")
    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_API_COLLECTION_BODY_BYTES:
        raise ApiCollectionError("API Collection request body exceeds 64 KiB")
    timeout_ms = _safe_integer(
        value.get("timeout_ms"), "API Collection request timeout", MIN_API_COLLECTION_TIMEOUT_MS
    )
    if timeout_ms > MAX_API_COLLECTION_TIMEOUT_MS:
        raise ApiCollectionError("API Collection request timeout exceeds 30 seconds")
    request = {
        "id": request_id,
        "folder_id": folder_id,
        "name": name,
        "url": url,
        "method": method,
        "headers": _normalize_headers(value.get("headers")),
        "body": body,
        "timeout_ms": timeout_ms,
        "variables": normalize_api_collection_variables(value.get("variables")),
    }
    if require_metadata:
        created_at_ms = _safe_integer(
            value.get("created_at_ms"), "API Collection request creation time"
        )
        updated_at_ms = _safe_integer(
            value.get("updated_at_ms"), "API Collection request update time"
        )
        if updated_at_ms < created_at_ms:
            raise ApiCollectionError("API Collection request timestamps are invalid")
        request.update(
            {"created_at_ms": created_at_ms, "updated_at_ms": updated_at_ms}
        )
    return request


def normalize_api_collection(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "contract_version",
        "document_kind",
        "generation",
        "updated_at_ms",
        "folders",
        "requests",
        "limits",
    }:
        raise ApiCollectionError("API Collection document shape is invalid")
    if (
        value.get("contract_version") != API_COLLECTION_CONTRACT_VERSION
        or value.get("document_kind") != API_COLLECTION_DOCUMENT_KIND
        or value.get("limits") != api_collection_limits()
    ):
        raise ApiCollectionError("API Collection document contract is unsupported")
    generation = _safe_integer(value.get("generation"), "API Collection generation")
    updated_at_ms = _safe_integer(
        value.get("updated_at_ms"), "API Collection update time"
    )
    raw_folders = value.get("folders")
    raw_requests = value.get("requests")
    if not isinstance(raw_folders, list) or not 1 <= len(raw_folders) <= MAX_API_COLLECTION_FOLDERS:
        raise ApiCollectionError("API Collection folder count is invalid")
    if not isinstance(raw_requests, list) or len(raw_requests) > MAX_API_COLLECTION_REQUESTS:
        raise ApiCollectionError("API Collection request count is invalid")
    folders = [_normalize_folder(folder) for folder in raw_folders]
    requests = [_normalize_request(request, require_metadata=True) for request in raw_requests]
    folder_by_id = {folder["id"]: folder for folder in folders}
    if len(folder_by_id) != len(folders):
        raise ApiCollectionError("API Collection folder IDs are duplicated")
    root = folder_by_id.get(API_COLLECTION_ROOT_ID)
    if root is None or root["parent_id"] is not None or root["name"] != "API Collection":
        raise ApiCollectionError("API Collection root folder is invalid")
    if any(folder["id"] != API_COLLECTION_ROOT_ID and folder["parent_id"] is None for folder in folders):
        raise ApiCollectionError("API Collection has multiple root folders")

    for folder in folders:
        seen = {folder["id"]}
        current = folder
        depth = 0
        while current["parent_id"] is not None:
            parent_id = current["parent_id"]
            if parent_id in seen or parent_id not in folder_by_id:
                raise ApiCollectionError("API Collection folder hierarchy is invalid")
            seen.add(parent_id)
            current = folder_by_id[parent_id]
            depth += 1
            if depth > MAX_API_COLLECTION_FOLDER_DEPTH:
                raise ApiCollectionError("API Collection folder depth exceeds four levels")

    sibling_names: set[tuple[int | None, str]] = set()
    for folder in folders:
        key = (folder["parent_id"], folder["name"].casefold())
        if key in sibling_names:
            raise ApiCollectionError("API Collection folder name is duplicated")
        sibling_names.add(key)

    request_ids: set[int] = set()
    request_names: set[tuple[int, str]] = set()
    for request in requests:
        if request["id"] in request_ids or request["folder_id"] not in folder_by_id:
            raise ApiCollectionError("API Collection request ID or folder is invalid")
        request_ids.add(request["id"])
        key = (request["folder_id"], request["name"].casefold())
        if key in request_names:
            raise ApiCollectionError("API Collection request name is duplicated")
        request_names.add(key)

    document = {
        "contract_version": API_COLLECTION_CONTRACT_VERSION,
        "document_kind": API_COLLECTION_DOCUMENT_KIND,
        "generation": generation,
        "updated_at_ms": updated_at_ms,
        "folders": sorted(folders, key=lambda folder: folder["id"]),
        "requests": sorted(requests, key=lambda request: request["id"]),
        "limits": api_collection_limits(),
    }
    encoded = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_API_COLLECTION_BYTES:
        raise ApiCollectionError("API Collection document exceeds 2 MiB")
    if generation == 0 and (
        updated_at_ms != 0
        or document["folders"] != empty_api_collection()["folders"]
        or document["requests"]
    ):
        raise ApiCollectionError("API Collection generation zero must be empty")
    return document


class ApiCollectionStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def load(self) -> dict[str, Any]:
        with self._lock:
            return self._load_locked()

    def replace(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict) or set(request) != {
            "action",
            "expected_generation",
            "folders",
            "requests",
        } or request.get("action") != "replace_api_collection":
            raise ApiCollectionError("API Collection action is invalid")
        expected_generation = _safe_integer(
            request.get("expected_generation"), "Expected API Collection generation"
        )
        raw_folders = request.get("folders")
        raw_requests = request.get("requests")
        if not isinstance(raw_folders, list) or not isinstance(raw_requests, list):
            raise ApiCollectionError("API Collection replacement is invalid")
        with self._lock:
            current = self._load_locked()
            if current["generation"] != expected_generation:
                raise ApiCollectionConflict(
                    "API Collection changed in another window; refresh before saving"
                )
            folders = [_normalize_folder(folder) for folder in raw_folders]
            request_contents = [
                _normalize_request(value, require_metadata=False) for value in raw_requests
            ]
            now_ms = int(time.time() * 1_000)
            existing = {value["id"]: value for value in current["requests"]}
            requests = []
            for content in request_contents:
                previous = existing.get(content["id"])
                if previous is None:
                    created_at_ms = now_ms
                    updated_at_ms = now_ms
                else:
                    created_at_ms = previous["created_at_ms"]
                    unchanged = all(previous[field] == content[field] for field in REQUEST_CONTENT_FIELDS)
                    updated_at_ms = previous["updated_at_ms"] if unchanged else now_ms
                requests.append(
                    {
                        **content,
                        "created_at_ms": created_at_ms,
                        "updated_at_ms": updated_at_ms,
                    }
                )
            candidate = normalize_api_collection(
                {
                    "contract_version": API_COLLECTION_CONTRACT_VERSION,
                    "document_kind": API_COLLECTION_DOCUMENT_KIND,
                    "generation": current["generation"] + 1,
                    "updated_at_ms": now_ms,
                    "folders": folders,
                    "requests": requests,
                    "limits": api_collection_limits(),
                }
            )
            if (
                candidate["folders"] == current["folders"]
                and candidate["requests"] == current["requests"]
            ):
                return current
            self._write_locked(candidate)
            return candidate

    def _load_locked(self) -> dict[str, Any]:
        try:
            descriptor = os.open(
                self.path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return empty_api_collection()
        except OSError as exception:
            raise ApiCollectionError(
                "API Collection store must be a regular file"
            ) from exception
        try:
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ApiCollectionError(
                        "API Collection store must be a regular file"
                    )
                if metadata.st_size > MAX_API_COLLECTION_BYTES:
                    raise ApiCollectionError("API Collection store exceeds 2 MiB")
                encoded = stream.read(MAX_API_COLLECTION_BYTES + 1)
            if len(encoded) > MAX_API_COLLECTION_BYTES:
                raise ApiCollectionError("API Collection store exceeds 2 MiB")
            value = json.loads(encoded.decode("utf-8"))
        except ApiCollectionError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise ApiCollectionError("API Collection store is malformed") from exception
        return normalize_api_collection(value)

    def _write_locked(self, document: dict[str, Any]) -> None:
        encoded = (
            json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_API_COLLECTION_BYTES:
            raise ApiCollectionError("API Collection store exceeds 2 MiB")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            dir=self.path.parent, prefix=f".{self.path.name}."
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
