#!/usr/bin/env python3

import json
import math
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

ANALYST_CONTRACT_VERSION = 1
ANALYST_DOCUMENT_KIND = "local-analyst-workspace"
ANALYST_ROOT_ID = 1
MAX_ANALYST_DOCUMENT_BYTES = 1024 * 1024
MAX_ANALYST_FOLDERS = 32
MAX_ANALYST_FILES = 64
MAX_ANALYST_FOLDER_DEPTH = 4
MAX_ANALYST_NAME_BYTES = 128
MAX_ANALYST_FILE_BYTES = 32 * 1024
MAX_ANALYST_TOTAL_FILE_BYTES = 512 * 1024
MAX_ANALYST_VARIABLES = 32
MAX_ANALYST_VARIABLE_NAME_BYTES = 128
MAX_ANALYST_VARIABLE_VALUE_BYTES = 4 * 1024
MAX_ANALYST_VARIABLE_BYTES = 16 * 1024
MAX_ANALYST_EVIDENCE_BYTES = 768 * 1024
MAX_ANALYST_INPUT_BYTES = 800 * 1024
MAX_ANALYST_RESPONSE_BYTES = 128 * 1024
MAX_ANALYST_EVENTS = 500
MAX_ANALYST_ARTIFACTS = 500
MAX_ANALYST_TRACE_EDGES = 1000
MAX_ANALYST_SIGNAL_PROFILES = 256
MAX_ANALYST_SELECTED_ARTIFACT_BYTES = 64 * 1024
MAX_ANALYST_LOGS = 64
MAX_ANALYST_LOG_BYTES = 1024
MAX_ANALYST_RESULT_BYTES = 32 * 1024
ANALYST_TIMEOUT_SECONDS = 2.5
MAX_SAFE_INTEGER = 2**53 - 1

ANALYST_FILE_KINDS = {"analyst-script", "scratchpad"}
ANALYST_FILE_LANGUAGES = {"javascript", "json", "markdown", "text"}
VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")


class LocalAnalystError(ValueError):
    pass


class LocalAnalystConflict(LocalAnalystError):
    pass


class LocalAnalystBusy(LocalAnalystError):
    pass


class LocalAnalystProtocolError(LocalAnalystError):
    pass


def local_analyst_limits() -> dict[str, int]:
    return {
        "folders": MAX_ANALYST_FOLDERS,
        "files": MAX_ANALYST_FILES,
        "folder_depth": MAX_ANALYST_FOLDER_DEPTH,
        "file_bytes": MAX_ANALYST_FILE_BYTES,
        "total_file_bytes": MAX_ANALYST_TOTAL_FILE_BYTES,
        "document_bytes": MAX_ANALYST_DOCUMENT_BYTES,
        "variables": MAX_ANALYST_VARIABLES,
        "variable_value_bytes": MAX_ANALYST_VARIABLE_VALUE_BYTES,
        "variable_bytes": MAX_ANALYST_VARIABLE_BYTES,
        "evidence_bytes": MAX_ANALYST_EVIDENCE_BYTES,
        "selected_artifact_bytes": MAX_ANALYST_SELECTED_ARTIFACT_BYTES,
        "execution_timeout_ms": 2000,
        "logs": MAX_ANALYST_LOGS,
        "log_bytes": MAX_ANALYST_LOG_BYTES,
        "result_bytes": MAX_ANALYST_RESULT_BYTES,
    }


def empty_local_analyst_workspace() -> dict[str, Any]:
    return {
        "contract_version": ANALYST_CONTRACT_VERSION,
        "document_kind": ANALYST_DOCUMENT_KIND,
        "generation": 0,
        "updated_at_ms": 0,
        "folders": [
            {
                "id": ANALYST_ROOT_ID,
                "name": "Analyst Workspace",
                "parent_id": None,
            }
        ],
        "files": [],
        "limits": local_analyst_limits(),
    }


def _safe_integer(value: Any, label: str, minimum: int = 0) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise LocalAnalystError(f"{label} is invalid")
    return value


def _bounded_name(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise LocalAnalystError(f"{label} must be text")
    name = value.strip()
    if (
        not name
        or len(name.encode("utf-8")) > MAX_ANALYST_NAME_BYTES
        or "/" in name
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        raise LocalAnalystError(f"{label} is empty, oversized, or invalid")
    return name


def _bounded_content(value: Any) -> tuple[str, int]:
    if not isinstance(value, str):
        raise LocalAnalystError("Analyst file content must be text")
    content_bytes = len(value.encode("utf-8"))
    if content_bytes > MAX_ANALYST_FILE_BYTES or any(
        ord(character) < 0x20 and character not in "\t\n\r" for character in value
    ):
        raise LocalAnalystError("Analyst file content is oversized or contains controls")
    return value, content_bytes


def _normalize_folder(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"id", "name", "parent_id"}:
        raise LocalAnalystError("Analyst folder shape is invalid")
    folder_id = _safe_integer(value.get("id"), "Analyst folder ID", 1)
    parent_id = value.get("parent_id")
    if parent_id is not None:
        parent_id = _safe_integer(parent_id, "Analyst parent folder ID", 1)
    return {
        "id": folder_id,
        "name": _bounded_name(value.get("name"), "Analyst folder name"),
        "parent_id": parent_id,
    }


FILE_CONTENT_FIELDS = (
    "id",
    "folder_id",
    "name",
    "kind",
    "language",
    "content",
)
FILE_FIELDS = frozenset((*FILE_CONTENT_FIELDS, "content_bytes", "created_at_ms", "updated_at_ms"))


def _normalize_file(value: Any, *, require_metadata: bool) -> dict[str, Any]:
    expected = FILE_FIELDS if require_metadata else frozenset(FILE_CONTENT_FIELDS)
    if not isinstance(value, dict) or set(value) != expected:
        raise LocalAnalystError("Analyst file shape is invalid")
    file_id = _safe_integer(value.get("id"), "Analyst file ID", 1)
    folder_id = _safe_integer(value.get("folder_id"), "Analyst file folder ID", 1)
    kind = value.get("kind")
    language = value.get("language")
    if kind not in ANALYST_FILE_KINDS or language not in ANALYST_FILE_LANGUAGES:
        raise LocalAnalystError("Analyst file kind or language is invalid")
    if kind == "analyst-script" and language != "javascript":
        raise LocalAnalystError("Analyst scripts must use JavaScript")
    content, content_bytes = _bounded_content(value.get("content"))
    result = {
        "id": file_id,
        "folder_id": folder_id,
        "name": _bounded_name(value.get("name"), "Analyst file name"),
        "kind": kind,
        "language": language,
        "content": content,
        "content_bytes": content_bytes,
    }
    if require_metadata:
        if value.get("content_bytes") != content_bytes:
            raise LocalAnalystError("Analyst file byte count is invalid")
        created_at_ms = _safe_integer(value.get("created_at_ms"), "Analyst file creation time")
        updated_at_ms = _safe_integer(value.get("updated_at_ms"), "Analyst file update time")
        if updated_at_ms < created_at_ms:
            raise LocalAnalystError("Analyst file timestamps are invalid")
        result.update({"created_at_ms": created_at_ms, "updated_at_ms": updated_at_ms})
    return result


def normalize_local_analyst_workspace(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "contract_version",
        "document_kind",
        "generation",
        "updated_at_ms",
        "folders",
        "files",
        "limits",
    }:
        raise LocalAnalystError("Analyst workspace document shape is invalid")
    if (
        value.get("contract_version") != ANALYST_CONTRACT_VERSION
        or value.get("document_kind") != ANALYST_DOCUMENT_KIND
        or value.get("limits") != local_analyst_limits()
    ):
        raise LocalAnalystError("Analyst workspace document contract is unsupported")
    generation = _safe_integer(value.get("generation"), "Analyst workspace generation")
    updated_at_ms = _safe_integer(value.get("updated_at_ms"), "Analyst workspace update time")
    raw_folders = value.get("folders")
    raw_files = value.get("files")
    if not isinstance(raw_folders, list) or not 1 <= len(raw_folders) <= MAX_ANALYST_FOLDERS:
        raise LocalAnalystError("Analyst folder count is invalid")
    if not isinstance(raw_files, list) or len(raw_files) > MAX_ANALYST_FILES:
        raise LocalAnalystError("Analyst file count is invalid")
    folders = [_normalize_folder(folder) for folder in raw_folders]
    files = [_normalize_file(file, require_metadata=True) for file in raw_files]
    folder_by_id = {folder["id"]: folder for folder in folders}
    if len(folder_by_id) != len(folders):
        raise LocalAnalystError("Analyst folder IDs are duplicated")
    root = folder_by_id.get(ANALYST_ROOT_ID)
    if root is None or root["parent_id"] is not None or root["name"] != "Analyst Workspace":
        raise LocalAnalystError("Analyst root folder is invalid")
    if any(folder["id"] != ANALYST_ROOT_ID and folder["parent_id"] is None for folder in folders):
        raise LocalAnalystError("Analyst workspace has multiple root folders")
    for folder in folders:
        seen = {folder["id"]}
        current = folder
        depth = 0
        while current["parent_id"] is not None:
            parent_id = current["parent_id"]
            if parent_id in seen or parent_id not in folder_by_id:
                raise LocalAnalystError("Analyst folder hierarchy is invalid")
            seen.add(parent_id)
            current = folder_by_id[parent_id]
            depth += 1
            if depth > MAX_ANALYST_FOLDER_DEPTH:
                raise LocalAnalystError("Analyst folder depth exceeds four levels")
    sibling_names: set[tuple[int | None, str]] = set()
    for folder in folders:
        key = (folder["parent_id"], folder["name"].casefold())
        if key in sibling_names:
            raise LocalAnalystError("Analyst sibling name is duplicated")
        sibling_names.add(key)
    file_ids: set[int] = set()
    total_content_bytes = 0
    for file in files:
        if file["id"] in file_ids or file["folder_id"] not in folder_by_id:
            raise LocalAnalystError("Analyst file ID or folder is invalid")
        file_ids.add(file["id"])
        key = (file["folder_id"], file["name"].casefold())
        if key in sibling_names:
            raise LocalAnalystError("Analyst sibling name is duplicated")
        sibling_names.add(key)
        total_content_bytes += file["content_bytes"]
    if total_content_bytes > MAX_ANALYST_TOTAL_FILE_BYTES:
        raise LocalAnalystError("Analyst file content exceeds 512 KiB")
    document = {
        "contract_version": ANALYST_CONTRACT_VERSION,
        "document_kind": ANALYST_DOCUMENT_KIND,
        "generation": generation,
        "updated_at_ms": updated_at_ms,
        "folders": sorted(folders, key=lambda folder: folder["id"]),
        "files": sorted(files, key=lambda file: file["id"]),
        "limits": local_analyst_limits(),
    }
    encoded = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_ANALYST_DOCUMENT_BYTES:
        raise LocalAnalystError("Analyst workspace document exceeds 1 MiB")
    if generation == 0 and (
        updated_at_ms != 0
        or document["folders"] != empty_local_analyst_workspace()["folders"]
        or document["files"]
    ):
        raise LocalAnalystError("Analyst workspace generation zero must be empty")
    return document


class LocalAnalystStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def load(self) -> dict[str, Any]:
        with self._lock:
            return self._load_locked()

    def replace(self, request: Any) -> dict[str, Any]:
        if (
            not isinstance(request, dict)
            or set(request) != {"action", "expected_generation", "folders", "files"}
            or request.get("action") != "replace_local_analyst_workspace"
        ):
            raise LocalAnalystError("Analyst workspace action is invalid")
        expected_generation = _safe_integer(
            request.get("expected_generation"), "Expected analyst workspace generation"
        )
        raw_folders = request.get("folders")
        raw_files = request.get("files")
        if not isinstance(raw_folders, list) or not isinstance(raw_files, list):
            raise LocalAnalystError("Analyst workspace replacement is invalid")
        with self._lock:
            current = self._load_locked()
            if current["generation"] != expected_generation:
                raise LocalAnalystConflict(
                    "Analyst workspace changed in another window; refresh before saving"
                )
            folders = [_normalize_folder(folder) for folder in raw_folders]
            contents = [_normalize_file(file, require_metadata=False) for file in raw_files]
            now_ms = int(time.time() * 1000)
            existing = {file["id"]: file for file in current["files"]}
            files = []
            for content in contents:
                previous = existing.get(content["id"])
                if previous is None:
                    created_at_ms = now_ms
                    updated_at_ms = now_ms
                else:
                    created_at_ms = previous["created_at_ms"]
                    unchanged = all(previous[field] == content[field] for field in FILE_CONTENT_FIELDS)
                    updated_at_ms = previous["updated_at_ms"] if unchanged else now_ms
                files.append(
                    {
                        **content,
                        "created_at_ms": created_at_ms,
                        "updated_at_ms": updated_at_ms,
                    }
                )
            candidate = normalize_local_analyst_workspace(
                {
                    "contract_version": ANALYST_CONTRACT_VERSION,
                    "document_kind": ANALYST_DOCUMENT_KIND,
                    "generation": current["generation"] + 1,
                    "updated_at_ms": now_ms,
                    "folders": folders,
                    "files": files,
                    "limits": local_analyst_limits(),
                }
            )
            if candidate["folders"] == current["folders"] and candidate["files"] == current["files"]:
                return current
            self._write_locked(candidate)
            return candidate

    def _load_locked(self) -> dict[str, Any]:
        try:
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return empty_local_analyst_workspace()
        except OSError as exception:
            raise LocalAnalystError("Analyst workspace store must be a regular file") from exception
        try:
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise LocalAnalystError("Analyst workspace store must be a regular file")
                if metadata.st_size > MAX_ANALYST_DOCUMENT_BYTES:
                    raise LocalAnalystError("Analyst workspace store exceeds 1 MiB")
                encoded = stream.read(MAX_ANALYST_DOCUMENT_BYTES + 1)
            if len(encoded) > MAX_ANALYST_DOCUMENT_BYTES:
                raise LocalAnalystError("Analyst workspace store exceeds 1 MiB")
            value = json.loads(encoded.decode("utf-8"))
        except LocalAnalystError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise LocalAnalystError("Analyst workspace store is malformed") from exception
        return normalize_local_analyst_workspace(value)

    def _write_locked(self, document: dict[str, Any]) -> None:
        encoded = (json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_ANALYST_DOCUMENT_BYTES:
            raise LocalAnalystError("Analyst workspace store exceeds 1 MiB")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.")
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


def _validate_json_value(value: Any, depth: int = 0, entries: Optional[list[int]] = None) -> None:
    if entries is None:
        entries = [0]
    if depth > 16:
        raise LocalAnalystError("Analyst evidence exceeds the nesting limit")
    entries[0] += 1
    if entries[0] > 50_000:
        raise LocalAnalystError("Analyst evidence exceeds the entry limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LocalAnalystError("Analyst evidence contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth + 1, entries)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                raise LocalAnalystError("Analyst evidence contains an invalid key")
            _validate_json_value(item, depth + 1, entries)
        return
    raise LocalAnalystError("Analyst evidence contains an unsupported value")


def normalize_analyst_run_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "action",
        "protocol_version",
        "run_id",
        "script_id",
        "library_generation",
        "source",
        "variables",
        "evidence",
        "confirmed",
        "confirmed_sensitive",
    } or value.get("action") != "run_local_analyst_script":
        raise LocalAnalystError("Analyst run action is invalid")
    if value.get("protocol_version") != 1 or value.get("confirmed") is not True:
        raise LocalAnalystError("Confirm local analyst script execution before running")
    run_id = _safe_integer(value.get("run_id"), "Analyst run ID", 1)
    script_id = _safe_integer(value.get("script_id"), "Analyst script ID", 1)
    library_generation = _safe_integer(value.get("library_generation"), "Analyst library generation")
    source, source_bytes = _bounded_content(value.get("source"))
    if not source.strip():
        raise LocalAnalystError("Analyst script source is required")
    variables_value = value.get("variables")
    if not isinstance(variables_value, dict) or len(variables_value) > MAX_ANALYST_VARIABLES:
        raise LocalAnalystError("Analyst variables are invalid or oversized")
    variables: dict[str, str] = {}
    variable_bytes = 0
    for raw_name, raw_value in variables_value.items():
        if (
            not isinstance(raw_name, str)
            or not VARIABLE_NAME.fullmatch(raw_name)
            or len(raw_name.encode("utf-8")) > MAX_ANALYST_VARIABLE_NAME_BYTES
            or not isinstance(raw_value, str)
            or len(raw_value.encode("utf-8")) > MAX_ANALYST_VARIABLE_VALUE_BYTES
        ):
            raise LocalAnalystError("Analyst variable name or value is invalid")
        variable_bytes += len(raw_name.encode("utf-8")) + len(raw_value.encode("utf-8"))
        if variable_bytes > MAX_ANALYST_VARIABLE_BYTES:
            raise LocalAnalystError("Analyst variables exceed 16 KiB")
        variables[raw_name] = raw_value
    evidence = value.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {
        "events",
        "artifacts",
        "trace_edges",
        "signal_profiles",
        "vm_analysis",
        "selected_artifact",
        "summary",
    }:
        raise LocalAnalystError("Analyst evidence snapshot shape is invalid")
    bounded_arrays = (
        ("events", MAX_ANALYST_EVENTS),
        ("artifacts", MAX_ANALYST_ARTIFACTS),
        ("trace_edges", MAX_ANALYST_TRACE_EDGES),
        ("signal_profiles", MAX_ANALYST_SIGNAL_PROFILES),
    )
    for name, limit in bounded_arrays:
        if not isinstance(evidence[name], list) or len(evidence[name]) > limit:
            raise LocalAnalystError(f"Analyst {name.replace('_', ' ')} are invalid or oversized")
    if evidence["vm_analysis"] is not None and not isinstance(evidence["vm_analysis"], dict):
        raise LocalAnalystError("Analyst VM analysis snapshot is invalid")
    selected = evidence["selected_artifact"]
    if selected is not None:
        if not isinstance(selected, dict) or not isinstance(selected.get("content"), str):
            raise LocalAnalystError("Analyst selected artifact snapshot is invalid")
        if len(selected["content"].encode("utf-8")) > MAX_ANALYST_SELECTED_ARTIFACT_BYTES:
            raise LocalAnalystError("Analyst selected artifact exceeds 64 KiB")
        if selected.get("sensitive") is True and value.get("confirmed_sensitive") is not True:
            raise LocalAnalystError(
                "Confirm inclusion of sensitive selected artifact bytes before running"
            )
    if not isinstance(evidence["summary"], dict):
        raise LocalAnalystError("Analyst evidence summary is invalid")
    _validate_json_value(evidence)
    evidence_bytes = len(
        json.dumps(evidence, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )
    if evidence_bytes > MAX_ANALYST_EVIDENCE_BYTES:
        raise LocalAnalystError("Analyst evidence snapshot exceeds 768 KiB")
    normalized = {
        "protocol_version": 1,
        "run_id": run_id,
        "script_id": script_id,
        "library_generation": library_generation,
        "source": source,
        "variables": variables,
        "evidence": evidence,
    }
    input_bytes = len(
        json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )
    if input_bytes > MAX_ANALYST_INPUT_BYTES or source_bytes > MAX_ANALYST_FILE_BYTES:
        raise LocalAnalystError("Analyst runner input is oversized")
    return normalized


def validate_saved_analyst_run(value: Any, workspace_value: Any) -> dict[str, Any]:
    request = normalize_analyst_run_request(value)
    workspace = normalize_local_analyst_workspace(workspace_value)
    if request["library_generation"] != workspace["generation"]:
        raise LocalAnalystConflict(
            "Analyst workspace changed; refresh before running the saved script"
        )
    script = next(
        (file for file in workspace["files"] if file["id"] == request["script_id"]),
        None,
    )
    if (
        script is None
        or script["kind"] != "analyst-script"
        or script["language"] != "javascript"
        or script["content"] != request["source"]
    ):
        raise LocalAnalystConflict(
            "Only the current saved JavaScript analyst script can execute"
        )
    return request


def _bounded_result_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        raise LocalAnalystProtocolError(f"{label} is malformed or oversized")
    return value


def normalize_analyst_result(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "protocol_version",
        "run_id",
        "script_id",
        "library_generation",
        "ok",
        "outcome",
        "result_type",
        "result_text",
        "result_truncated",
        "logs",
        "logs_truncated",
        "duration_ms",
        "error",
    }
    if not isinstance(value, dict) or set(value) != expected_keys or value.get("protocol_version") != 1:
        raise LocalAnalystProtocolError("Analyst runner returned a malformed result")
    if any(value.get(key) != expected[key] for key in ("run_id", "script_id", "library_generation")):
        raise LocalAnalystProtocolError(
            "Analyst runner returned mismatched correlation identifiers"
        )
    if (
        not isinstance(value.get("ok"), bool)
        or value.get("outcome") not in {"completed", "failed", "cancelled", "timed_out"}
        or value["ok"] != (value["outcome"] == "completed")
        or not isinstance(value.get("result_truncated"), bool)
        or not isinstance(value.get("logs_truncated"), bool)
        or not isinstance(value.get("duration_ms"), int)
        or isinstance(value.get("duration_ms"), bool)
        or not 0 <= value["duration_ms"] <= 7000
    ):
        raise LocalAnalystProtocolError("Analyst runner returned invalid result state")
    result_type = _bounded_result_text(value.get("result_type"), "Analyst result type", 64)
    result_text = _bounded_result_text(value.get("result_text"), "Analyst result text", MAX_ANALYST_RESULT_BYTES)
    error = _bounded_result_text(value.get("error"), "Analyst error", 512)
    if (value["ok"] and error) or (not value["ok"] and not error):
        raise LocalAnalystProtocolError("Analyst runner returned inconsistent error state")
    raw_logs = value.get("logs")
    if not isinstance(raw_logs, list) or len(raw_logs) > MAX_ANALYST_LOGS:
        raise LocalAnalystProtocolError("Analyst runner returned too many logs")
    logs = []
    for raw_log in raw_logs:
        if not isinstance(raw_log, dict) or set(raw_log) != {"level", "text"}:
            raise LocalAnalystProtocolError("Analyst runner returned a malformed log")
        if raw_log.get("level") not in {"log", "info", "warn", "error"}:
            raise LocalAnalystProtocolError("Analyst runner returned an invalid log level")
        logs.append(
            {
                "level": raw_log["level"],
                "text": _bounded_result_text(raw_log.get("text"), "Analyst log", MAX_ANALYST_LOG_BYTES),
            }
        )
    return {
        **value,
        "result_type": result_type,
        "result_text": result_text,
        "error": error,
        "logs": logs,
    }


class LocalAnalystRunner:
    def __init__(self, directory: Path):
        self._directory = directory.resolve()
        self._node = shutil.which("node")
        self._unavailable_reason = "Local analyst execution requires Node.js 22 or newer"
        if self._node is not None:
            try:
                completed = subprocess.run(
                    [self._node, "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                major = int(completed.stdout.strip().lstrip("v").split(".", 1)[0])
                if major < 22:
                    self._node = None
            except (OSError, ValueError, subprocess.SubprocessError):
                self._node = None
        self._lock = threading.Lock()
        self._active: Optional[subprocess.Popen[bytes]] = None
        self._active_run_id: Optional[int] = None
        self._cancel_requested = False

    def available(self) -> bool:
        return self._node is not None

    def active_run_id(self) -> Optional[int]:
        with self._lock:
            return self._active_run_id

    @staticmethod
    def _child_limits() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        descriptor_limit = min(32, resource.getrlimit(resource.RLIMIT_NOFILE)[1])
        resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, descriptor_limit))

    @staticmethod
    def _failure(request: dict[str, Any], outcome: str, message: str, duration_ms: int) -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "run_id": request["run_id"],
            "script_id": request["script_id"],
            "library_generation": request["library_generation"],
            "ok": False,
            "outcome": outcome,
            "result_type": "error",
            "result_text": "",
            "result_truncated": False,
            "logs": [],
            "logs_truncated": False,
            "duration_ms": max(0, min(duration_ms, 7000)),
            "error": message.encode("utf-8")[:512].decode("utf-8", errors="ignore"),
        }

    def run(self, value: Any, workspace: Any) -> dict[str, Any]:
        request = validate_saved_analyst_run(value, workspace)
        if self._node is None:
            raise LocalAnalystError(self._unavailable_reason)
        node_runner = self._directory / "analyst_runner_node.js"
        core_runner = self._directory / "analyst_runner_core.js"
        encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        command = [
            self._node,
            "--permission",
            f"--allow-fs-read={self._directory}",
            "--max-old-space-size=64",
            "--disable-proto=throw",
            "--no-addons",
            str(node_runner),
            str(core_runner),
        ]
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tempfile.gettempdir(),
                env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                start_new_session=True,
                preexec_fn=self._child_limits,
            )
        except OSError as exception:
            raise LocalAnalystError(f"Could not start the local analyst runner: {exception}") from exception
        with self._lock:
            if self._active is not None:
                process.kill()
                process.wait(timeout=1)
                raise LocalAnalystBusy("Another local analyst script is already running")
            self._active = process
            self._active_run_id = request["run_id"]
            self._cancel_requested = False
        timed_out = False
        try:
            stdout, stderr = process.communicate(encoded, timeout=ANALYST_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        finally:
            with self._lock:
                cancelled = self._cancel_requested and self._active is process
                if self._active is process:
                    self._active = None
                    self._active_run_id = None
                    self._cancel_requested = False
        duration_ms = int((time.monotonic() - started) * 1000)
        if cancelled:
            return self._failure(request, "cancelled", "Analyst script cancelled", duration_ms)
        if timed_out:
            return self._failure(request, "timed_out", "Analyst script exceeded the 2 second execution limit", duration_ms)
        if len(stdout) > MAX_ANALYST_RESPONSE_BYTES:
            raise LocalAnalystProtocolError(
                "Analyst runner returned more than 128 KiB"
            )
        try:
            document = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            detail = stderr.decode("utf-8", errors="replace")[:512].strip()
            raise LocalAnalystProtocolError(
                detail or "Analyst runner returned malformed output"
            ) from exception
        return normalize_analyst_result(document, request)

    def cancel(self, run_id: Any) -> bool:
        normalized_id = _safe_integer(run_id, "Analyst run ID", 1)
        with self._lock:
            process = self._active
            if process is None or self._active_run_id != normalized_id:
                raise LocalAnalystError("The selected analyst run is no longer active")
            self._cancel_requested = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        return True

    def stop(self) -> None:
        with self._lock:
            process = self._active
            if process is None:
                return
            self._cancel_requested = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
