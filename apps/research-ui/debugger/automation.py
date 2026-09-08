from __future__ import annotations

import json
import math
from typing import Any
from urllib.parse import urlparse, urlunparse

from debugger.errors import (
    DebuggerBridgeError,
    ProtocolError,
)
from debugger.limits import (
    AUTOMATION_EXECUTION_TIMEOUT_MS,
    MAX_AUTOMATION_LABEL_BYTES,
    MAX_AUTOMATION_LOG_BYTES,
    MAX_AUTOMATION_LOGS,
    MAX_AUTOMATION_RECIPE_SOURCE_BYTES,
    MAX_AUTOMATION_RESULT_BYTES,
    MAX_AUTOMATION_VARIABLE_BYTES,
    MAX_AUTOMATION_VARIABLE_NAME_BYTES,
    MAX_AUTOMATION_VARIABLE_VALUE_BYTES,
    MAX_AUTOMATION_VARIABLES,
    MAX_INTERCEPTION_URL_BYTES,
    MAX_OBJECT_EXPERIMENT_VALUE_DEPTH,
    MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES,
    MAX_RUNTIME_HOOK_RETURN_BYTES,
    REPEATER_VARIABLE_NAME,
)
from debugger.requests import (
    redacted_request_url,
)
from debugger.validation import (
    required_text,
    truncate_text,
)


def runtime_hook_text(
    request: dict[str, Any], field: str, limit: int
) -> str:
    value = request.get(field, "")
    if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
        raise DebuggerBridgeError(
            f"Runtime Hooks {field.replace('_', ' ')} is invalid or oversized"
        )
    return value


def runtime_hook_source_label(url: str) -> str:
    if not url:
        return "(anonymous script)"
    try:
        parsed = urlparse(url)
    except ValueError:
        return "(anonymous script)"
    if parsed.scheme in {"http", "https"}:
        return redacted_request_url(url) or "(anonymous script)"
    if parsed.scheme == "data":
        return "data:(inline script)"
    return truncate_text(
        urlunparse(parsed._replace(query="", fragment="")),
        MAX_INTERCEPTION_URL_BYTES,
    )


def normalize_runtime_hook_json(value: Any) -> tuple[Any, bytes]:
    entries = 0

    def validate(candidate: Any, depth: int) -> None:
        nonlocal entries
        if depth > MAX_OBJECT_EXPERIMENT_VALUE_DEPTH:
            raise DebuggerBridgeError("Runtime Hooks JSON exceeds depth 8")
        if candidate is None or isinstance(candidate, bool):
            return
        if isinstance(candidate, int):
            if abs(candidate) > 2**53 - 1:
                raise DebuggerBridgeError(
                    "Runtime Hooks integer exceeds JavaScript's exact range"
                )
            return
        if isinstance(candidate, float):
            if not math.isfinite(candidate):
                raise DebuggerBridgeError("Runtime Hooks number must be finite")
            return
        if isinstance(candidate, str):
            if len(candidate.encode("utf-8")) > MAX_RUNTIME_HOOK_RETURN_BYTES:
                raise DebuggerBridgeError("Runtime Hooks JSON string exceeds 8 KiB")
            return
        if isinstance(candidate, list):
            entries += len(candidate)
            if entries > MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES:
                raise DebuggerBridgeError("Runtime Hooks JSON exceeds 256 entries")
            for item in candidate:
                validate(item, depth + 1)
            return
        if isinstance(candidate, dict):
            entries += len(candidate)
            if entries > MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES:
                raise DebuggerBridgeError("Runtime Hooks JSON exceeds 256 entries")
            for key, item in candidate.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 4096:
                    raise DebuggerBridgeError("Runtime Hooks JSON key is invalid")
                validate(item, depth + 1)
            return
        raise DebuggerBridgeError("Runtime Hooks replacement must be JSON data")

    validate(value, 0)
    try:
        canonical = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exception:
        raise DebuggerBridgeError(
            "Runtime Hooks replacement must be valid JSON"
        ) from exception
    if len(canonical) > MAX_RUNTIME_HOOK_RETURN_BYTES:
        raise DebuggerBridgeError("Runtime Hooks replacement exceeds 8 KiB")
    return value, canonical


def normalize_automation_recipe(
    request: dict[str, Any]
) -> dict[str, Any]:
    label = required_text(
        request, "label", MAX_AUTOMATION_LABEL_BYTES
    ).strip()
    if not label:
        raise DebuggerBridgeError("Automation recipe label is required")
    source = required_text(
        request, "source", MAX_AUTOMATION_RECIPE_SOURCE_BYTES
    )
    if not source.strip():
        raise DebuggerBridgeError("Automation recipe source is required")
    trigger = request.get("trigger", "manual")
    if trigger not in {"manual", "created", "before-load", "after-load"}:
        raise DebuggerBridgeError("Automation recipe trigger is invalid")
    enabled = request.get("enabled", True)
    if not isinstance(enabled, bool):
        raise DebuggerBridgeError("Automation recipe enabled state must be boolean")
    return {
        "label": label,
        "trigger": trigger,
        "enabled": enabled,
        "source": source,
        "source_bytes": len(source.encode("utf-8")),
    }


def automation_recipe_id(request: dict[str, Any]) -> int:
    recipe_id = request.get("recipe_id")
    if (
        not isinstance(recipe_id, int)
        or isinstance(recipe_id, bool)
        or recipe_id <= 0
        or recipe_id > 2**53 - 1
    ):
        raise DebuggerBridgeError("Automation recipe identifier is invalid")
    return recipe_id


def normalize_automation_variables(
    request: dict[str, Any]
) -> tuple[dict[str, str], int]:
    raw_variables = request.get("variables", {})
    if not isinstance(raw_variables, dict):
        raise DebuggerBridgeError("Automation variables must be a JSON object")
    if len(raw_variables) > MAX_AUTOMATION_VARIABLES:
        raise DebuggerBridgeError("Automation variable limit reached")
    variables: dict[str, str] = {}
    total_bytes = 0
    for raw_name, raw_value in raw_variables.items():
        if (
            not isinstance(raw_name, str)
            or REPEATER_VARIABLE_NAME.fullmatch(raw_name) is None
            or not raw_name
            or len(raw_name.encode("utf-8"))
            > MAX_AUTOMATION_VARIABLE_NAME_BYTES
        ):
            raise DebuggerBridgeError("Automation variable name is invalid")
        if (
            not isinstance(raw_value, str)
            or len(raw_value.encode("utf-8"))
            > MAX_AUTOMATION_VARIABLE_VALUE_BYTES
        ):
            raise DebuggerBridgeError(
                "Automation variable values must be strings no larger than 4 KiB"
            )
        total_bytes += len(raw_name.encode("utf-8")) + len(
            raw_value.encode("utf-8")
        )
        if total_bytes > MAX_AUTOMATION_VARIABLE_BYTES:
            raise DebuggerBridgeError(
                "Automation variables exceed the 16 KiB session limit"
            )
        variables[raw_name] = raw_value
    return variables, total_bytes


def automation_runner_config(
    recipe: dict[str, Any], variables: dict[str, str], binding: bool = False
) -> dict[str, Any]:
    return {
        "source": recipe["source"],
        "variables": variables,
        "resultLimit": 4 * 1024 if binding else MAX_AUTOMATION_RESULT_BYTES,
        "logLimit": 4 if binding else MAX_AUTOMATION_LOGS,
        "logBytes": 512 if binding else MAX_AUTOMATION_LOG_BYTES,
        "timeoutMs": AUTOMATION_EXECUTION_TIMEOUT_MS,
    }


def normalize_automation_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("protocolVersion") != 1:
        raise ProtocolError("Debugger returned a malformed automation result")
    ok = value.get("ok")
    result_type = value.get("resultType")
    result_text = value.get("resultText")
    result_truncated = value.get("resultTruncated")
    logs_truncated = value.get("logsTruncated")
    elapsed_ms = value.get("elapsedMs")
    timed_out = value.get("timedOut")
    raw_logs = value.get("logs")
    if (
        not isinstance(ok, bool)
        or not isinstance(result_type, str)
        or len(result_type.encode("utf-8")) > 64
        or not isinstance(result_text, str)
        or len(result_text.encode("utf-8")) > MAX_AUTOMATION_RESULT_BYTES
        or not isinstance(result_truncated, bool)
        or not isinstance(logs_truncated, bool)
        or not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or elapsed_ms < 0
        or elapsed_ms > AUTOMATION_EXECUTION_TIMEOUT_MS + 5_000
        or not isinstance(timed_out, bool)
        or not isinstance(raw_logs, list)
        or len(raw_logs) > MAX_AUTOMATION_LOGS
    ):
        raise ProtocolError("Debugger returned a malformed automation result")
    logs = []
    for raw_log in raw_logs:
        if not isinstance(raw_log, dict):
            raise ProtocolError("Debugger returned a malformed automation log")
        level = raw_log.get("level")
        text = raw_log.get("text")
        if (
            level not in {"log", "info", "warn", "error"}
            or not isinstance(text, str)
            or len(text.encode("utf-8")) > MAX_AUTOMATION_LOG_BYTES
        ):
            raise ProtocolError("Debugger returned a malformed automation log")
        logs.append({"level": level, "text": text})
    error = value.get("error", "")
    if (
        not isinstance(error, str)
        or len(error.encode("utf-8")) > 512
        or (not ok and not error)
    ):
        raise ProtocolError("Debugger returned a malformed automation result")
    return {
        "ok": ok,
        "result_type": result_type,
        "result_text": result_text,
        "result_truncated": result_truncated,
        "logs": logs,
        "logs_truncated": logs_truncated,
        "elapsed_ms": elapsed_ms,
        "timed_out": timed_out,
        "error": error,
    }


def automation_failure_result(message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "result_type": "error",
        "result_text": "",
        "result_truncated": False,
        "logs": [],
        "logs_truncated": False,
        "elapsed_ms": 0,
        "timed_out": False,
        "error": truncate_text(message, 512),
    }
