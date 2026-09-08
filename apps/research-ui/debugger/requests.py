from __future__ import annotations

import hashlib
import re
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from debugger.errors import (
    DebuggerBridgeError,
    ProtocolError,
)
from debugger.limits import (
    MAX_INTERCEPTION_BODY_BYTES,
    MAX_INTERCEPTION_HEADER_BYTES,
    MAX_INTERCEPTION_HEADER_NAME_BYTES,
    MAX_INTERCEPTION_HEADER_VALUE_BYTES,
    MAX_INTERCEPTION_HEADERS,
    MAX_INTERCEPTION_METHOD_BYTES,
    MAX_INTERCEPTION_PATTERN_BYTES,
    MAX_INTERCEPTION_RESPONSE_BYTES,
    MAX_INTERCEPTION_URL_BYTES,
    MAX_REPEATER_TEMPLATE_METHOD_BYTES,
    MAX_REPEATER_TIMEOUT_MS,
    MAX_REPEATER_VARIABLE_BYTES,
    MAX_REPEATER_VARIABLE_NAME_BYTES,
    MAX_REPEATER_VARIABLE_VALUE_BYTES,
    MAX_REPEATER_VARIABLES,
    MIN_REPEATER_TIMEOUT_MS,
    REPEATER_VARIABLE_NAME,
    REPEATER_VARIABLE_TOKEN,
    SENSITIVE_INTERCEPTION_HEADERS,
)
from debugger.validation import (
    required_text,
    truncate_text,
)


def default_request_interception_rule() -> dict[str, Any]:
    return {
        "mode": "continue",
        "url_pattern": "*",
        "method_filter": "",
        "rewrite_url": "",
        "rewrite_method": "",
        "rewrite_headers": [],
        "rewrite_body": "",
        "response_code": 200,
        "response_headers": [],
        "response_body": "",
    }


def normalize_repeater_variables(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, dict) or len(value) > MAX_REPEATER_VARIABLES:
        raise DebuggerBridgeError("Repeater variables must be a bounded object")
    total_bytes = 0
    variables = []
    for name, variable_value in sorted(value.items()):
        if not isinstance(name, str) or not isinstance(variable_value, str):
            raise DebuggerBridgeError("Repeater variable names and values must be text")
        name_bytes = len(name.encode("utf-8"))
        value_bytes = len(variable_value.encode("utf-8"))
        if (
            not REPEATER_VARIABLE_NAME.fullmatch(name)
            or name_bytes > MAX_REPEATER_VARIABLE_NAME_BYTES
            or value_bytes > MAX_REPEATER_VARIABLE_VALUE_BYTES
        ):
            raise DebuggerBridgeError("Repeater variable is invalid or oversized")
        total_bytes += name_bytes + value_bytes
        if total_bytes > MAX_REPEATER_VARIABLE_BYTES:
            raise DebuggerBridgeError("Repeater variables exceed 32 KiB")
        variables.append({"name": name, "value": variable_value})
    return variables


def resolve_repeater_text(
    value: str, variables: dict[str, str]
) -> tuple[str, set[str]]:
    used: set[str] = set()
    missing: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        escaped = match.group(1) == "="
        name = match.group(2)
        if (
            not REPEATER_VARIABLE_NAME.fullmatch(name)
            or len(name.encode("utf-8")) > MAX_REPEATER_VARIABLE_NAME_BYTES
        ):
            raise DebuggerBridgeError("Repeater request contains an invalid variable")
        if escaped:
            return "{{" + name + "}}"
        used.add(name)
        if name not in variables:
            missing.add(name)
            return match.group(0)
        return variables[name]

    resolved = REPEATER_VARIABLE_TOKEN.sub(replace, value)
    if missing:
        names = ", ".join(sorted(missing)[:8])
        raise DebuggerBridgeError(f"Unresolved Repeater variables: {names}")
    return resolved, used


def normalize_repeater_template(request: dict[str, Any]) -> dict[str, Any]:
    url = required_text(request, "url", MAX_INTERCEPTION_URL_BYTES).strip()
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise DebuggerBridgeError("Repeater request URL is invalid")
    method = request.get("method", "GET")
    if (
        not isinstance(method, str)
        or not method.strip()
        or len(method.strip().encode("utf-8")) > MAX_REPEATER_TEMPLATE_METHOD_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in method)
    ):
        raise DebuggerBridgeError("Repeater request method template is invalid")
    headers = normalize_request_interception_headers(
        request.get("headers", {}), "Repeater request"
    )
    body = request.get("body", "")
    if (
        not isinstance(body, str)
        or len(body.encode("utf-8")) > MAX_INTERCEPTION_BODY_BYTES
    ):
        raise DebuggerBridgeError("Repeater request body exceeds 64 KiB")
    timeout_ms = request.get("timeout_ms", MAX_REPEATER_TIMEOUT_MS)
    if (
        not isinstance(timeout_ms, int)
        or isinstance(timeout_ms, bool)
        or timeout_ms < MIN_REPEATER_TIMEOUT_MS
        or timeout_ms > MAX_REPEATER_TIMEOUT_MS
    ):
        raise DebuggerBridgeError("Repeater timeout must be between 100 and 30000 ms")
    collection_request_id = request.get("collection_request_id")
    if collection_request_id is not None and (
        not isinstance(collection_request_id, int)
        or isinstance(collection_request_id, bool)
        or collection_request_id <= 0
        or collection_request_id > 2**53 - 1
    ):
        raise DebuggerBridgeError("Repeater collection request ID is invalid")
    return {
        "url": url,
        "method": method.strip(),
        "headers": headers,
        "body": body,
        "timeout_ms": timeout_ms,
        "collection_request_id": collection_request_id,
    }


def resolve_repeater_request(
    template: dict[str, Any], variables: list[dict[str, str]]
) -> tuple[dict[str, Any], list[str]]:
    variable_map = {entry["name"]: entry["value"] for entry in variables}
    url, used = resolve_repeater_text(template["url"], variable_map)
    method, method_used = resolve_repeater_text(
        template["method"], variable_map
    )
    used.update(method_used)
    body, body_used = resolve_repeater_text(template["body"], variable_map)
    used.update(body_used)
    resolved_headers: dict[str, str] = {}
    for header in template["headers"]:
        header_value, header_used = resolve_repeater_text(
            header["value"], variable_map
        )
        used.update(header_used)
        resolved_headers[header["name"]] = header_value
    resolved = normalize_request_interception_request(
        {
            "url": url,
            "method": method,
            "headers": resolved_headers,
            "body": body,
        }
    )
    resolved["timeout_ms"] = template["timeout_ms"]
    return resolved, sorted(used)


def normalize_repeater_result(value: Any) -> dict[str, Any]:
    result = normalize_request_interception_result(value)
    duration_ms = value.get("durationMs") if isinstance(value, dict) else None
    cancelled = value.get("cancelled") if isinstance(value, dict) else None
    timed_out = value.get("timedOut") if isinstance(value, dict) else None
    if (
        not isinstance(duration_ms, int)
        or isinstance(duration_ms, bool)
        or duration_ms < 0
        or duration_ms > MAX_REPEATER_TIMEOUT_MS + 5_000
        or not isinstance(cancelled, bool)
        or not isinstance(timed_out, bool)
        or (cancelled and timed_out)
        or (result["ok"] and (cancelled or timed_out))
    ):
        raise ProtocolError("Debugger returned a malformed Repeater result")
    result.update(
        {
            "duration_ms": duration_ms,
            "cancelled": cancelled,
            "timed_out": timed_out,
            "body_sha256": hashlib.sha256(
                result["body"].encode("utf-8")
            ).hexdigest(),
        }
    )
    return result


def compare_repeater_entries(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    baseline_response = baseline["response"]
    current_response = current["response"]

    def header_map(response: dict[str, Any]) -> dict[str, str]:
        return {
            header["name"].lower(): header["value"]
            for header in response["headers"]
        }

    before_headers = header_map(baseline_response)
    after_headers = header_map(current_response)
    before_names = set(before_headers)
    after_names = set(after_headers)
    changed = sorted(
        name
        for name in before_names & after_names
        if before_headers[name] != after_headers[name]
    )
    baseline_body_bytes = len(baseline_response["body"].encode("utf-8"))
    current_body_bytes = len(current_response["body"].encode("utf-8"))
    return {
        "protocol_version": 1,
        "baseline_id": baseline["id"],
        "current_id": current["id"],
        "baseline_status": baseline_response["status"],
        "current_status": current_response["status"],
        "status_changed": baseline_response["status"]
        != current_response["status"],
        "duration_delta_ms": current_response["duration_ms"]
        - baseline_response["duration_ms"],
        "baseline_body_bytes": baseline_body_bytes,
        "current_body_bytes": current_body_bytes,
        "body_bytes_delta": current_body_bytes - baseline_body_bytes,
        "baseline_body_sha256": baseline_response["body_sha256"],
        "current_body_sha256": current_response["body_sha256"],
        "body_changed": baseline_response["body_sha256"]
        != current_response["body_sha256"],
        "headers_added": sorted(after_names - before_names),
        "headers_removed": sorted(before_names - after_names),
        "headers_changed": changed,
        "partial": any(
            (
                baseline_response["headers_truncated"],
                baseline_response["body_truncated"],
                current_response["headers_truncated"],
                current_response["body_truncated"],
            )
        ),
    }


def normalize_request_interception_rule(
    request: dict[str, Any]
) -> dict[str, Any]:
    mode = request.get("mode")
    if mode not in {"continue", "block", "drop", "rewrite", "fulfill"}:
        raise DebuggerBridgeError("Request interception mode is invalid")
    pattern = required_text(
        request, "url_pattern", MAX_INTERCEPTION_PATTERN_BYTES
    )
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in pattern):
        raise DebuggerBridgeError("Request interception URL pattern is invalid")
    if pattern != "*" and not pattern.startswith(("http://", "https://")):
        raise DebuggerBridgeError(
            "Request interception URL pattern must use HTTP, HTTPS, or *"
        )
    method_filter = request.get("method_filter", "")
    if not isinstance(method_filter, str):
        raise DebuggerBridgeError("Request interception method filter is invalid")
    method_filter = method_filter.strip().upper()
    if method_filter:
        validate_request_interception_method(method_filter)

    rule = default_request_interception_rule()
    rule.update(
        {"mode": mode, "url_pattern": pattern, "method_filter": method_filter}
    )
    if mode == "rewrite":
        rewrite_url = request.get("rewrite_url", "")
        if not isinstance(rewrite_url, str):
            raise DebuggerBridgeError("Request rewrite URL is invalid")
        rewrite_url = rewrite_url.strip()
        if rewrite_url:
            validate_request_interception_url(rewrite_url)
        rewrite_method = request.get("rewrite_method", "")
        if not isinstance(rewrite_method, str):
            raise DebuggerBridgeError("Request rewrite method is invalid")
        rewrite_method = rewrite_method.strip().upper()
        if rewrite_method:
            validate_request_interception_method(rewrite_method)
        rewrite_headers = normalize_request_interception_headers(
            request.get("rewrite_headers", {}), "rewrite"
        )
        rewrite_body = request.get("rewrite_body", "")
        if (
            not isinstance(rewrite_body, str)
            or len(rewrite_body.encode("utf-8")) > MAX_INTERCEPTION_BODY_BYTES
        ):
            raise DebuggerBridgeError("Request rewrite body exceeds 64 KiB")
        if not any((rewrite_url, rewrite_method, rewrite_headers, rewrite_body)):
            raise DebuggerBridgeError(
                "Request rewrite requires at least one bounded override"
            )
        rule.update(
            {
                "rewrite_url": rewrite_url,
                "rewrite_method": rewrite_method,
                "rewrite_headers": rewrite_headers,
                "rewrite_body": rewrite_body,
            }
        )
    elif mode == "fulfill":
        response_code = request.get("response_code", 200)
        if (
            not isinstance(response_code, int)
            or isinstance(response_code, bool)
            or response_code < 100
            or response_code > 599
        ):
            raise DebuggerBridgeError("Synthetic response status is invalid")
        response_headers = normalize_request_interception_headers(
            request.get("response_headers", {}), "response"
        )
        response_body = request.get("response_body", "")
        if (
            not isinstance(response_body, str)
            or len(response_body.encode("utf-8")) > MAX_INTERCEPTION_RESPONSE_BYTES
        ):
            raise DebuggerBridgeError("Synthetic response body exceeds 64 KiB")
        if not response_headers:
            response_headers = [
                {"name": "content-type", "value": "text/plain; charset=utf-8"},
            ]
        if not any(
            header["name"].lower() == "access-control-allow-origin"
            for header in response_headers
        ):
            if len(response_headers) >= MAX_INTERCEPTION_HEADERS:
                raise DebuggerBridgeError(
                    "Synthetic response headers must include access-control-allow-origin at the 64-header limit"
                )
            response_headers.append(
                {"name": "access-control-allow-origin", "value": "*"}
            )
        rule.update(
            {
                "response_code": response_code,
                "response_headers": response_headers,
                "response_body": response_body,
            }
        )
    return rule


def normalize_request_interception_request(
    request: dict[str, Any]
) -> dict[str, Any]:
    url = required_text(request, "url", MAX_INTERCEPTION_URL_BYTES).strip()
    validate_request_interception_url(url)
    method = request.get("method", "GET")
    if not isinstance(method, str):
        raise DebuggerBridgeError("Experiment request method is invalid")
    method = method.strip().upper()
    validate_request_interception_method(method)
    headers = normalize_request_interception_headers(
        request.get("headers", {}), "request"
    )
    body = request.get("body", "")
    if (
        not isinstance(body, str)
        or len(body.encode("utf-8")) > MAX_INTERCEPTION_BODY_BYTES
    ):
        raise DebuggerBridgeError("Experiment request body exceeds 64 KiB")
    if method in {"GET", "HEAD"} and body:
        raise DebuggerBridgeError(
            "GET and HEAD experiment requests cannot include a body"
        )
    return {"url": url, "method": method, "headers": headers, "body": body}


def validate_request_interception_url(url: str) -> None:
    try:
        parsed = urlparse(url)
        _ = parsed.port
    except ValueError as exception:
        raise DebuggerBridgeError(
            "Experiment request URL is invalid"
        ) from exception
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise DebuggerBridgeError(
            "Experiment request URL must be credential-free HTTP or HTTPS"
        )


def validate_request_interception_method(method: str) -> None:
    allowed = frozenset(
        "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )
    if (
        not method
        or len(method.encode("ascii", errors="ignore"))
        != len(method.encode("utf-8"))
        or len(method) > MAX_INTERCEPTION_METHOD_BYTES
        or method[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        or any(character not in allowed for character in method)
    ):
        raise DebuggerBridgeError("Experiment request method is invalid")


def normalize_request_interception_headers(
    value: Any, label: str
) -> list[dict[str, str]]:
    if not isinstance(value, dict) or len(value) > MAX_INTERCEPTION_HEADERS:
        raise DebuggerBridgeError(
            f"Request interception {label} headers are invalid"
        )
    token_characters = frozenset(
        "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    )
    forbidden = SENSITIVE_INTERCEPTION_HEADERS | {
        "connection",
        "content-length",
        "host",
        "transfer-encoding",
    }
    total_bytes = 0
    headers = []
    for name, header_value in value.items():
        if not isinstance(name, str) or not isinstance(header_value, str):
            raise DebuggerBridgeError(
                f"Request interception {label} headers must be text"
            )
        name_bytes = len(name.encode("utf-8"))
        value_bytes = len(header_value.encode("utf-8"))
        if (
            not name
            or name_bytes > MAX_INTERCEPTION_HEADER_NAME_BYTES
            or value_bytes > MAX_INTERCEPTION_HEADER_VALUE_BYTES
            or any(character not in token_characters for character in name)
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in header_value
            )
            or name.lower() in forbidden
        ):
            raise DebuggerBridgeError(
                f"Request interception {label} header is forbidden or invalid"
            )
        total_bytes += name_bytes + value_bytes
        if total_bytes > MAX_INTERCEPTION_HEADER_BYTES:
            raise DebuggerBridgeError(
                f"Request interception {label} headers exceed 16 KiB"
            )
        headers.append({"name": name, "value": header_value})
    return headers


def normalize_request_interception_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("protocolVersion") != 1:
        raise ProtocolError("Debugger returned a malformed experiment result")
    ok = value.get("ok")
    if not isinstance(ok, bool):
        raise ProtocolError("Debugger returned a malformed experiment result")
    if not ok:
        error = value.get("error")
        if not isinstance(error, str):
            raise ProtocolError("Debugger returned a malformed experiment error")
        return {
            "protocol_version": 1,
            "ok": False,
            "status": 0,
            "status_text": "",
            "url": "",
            "headers": [],
            "headers_truncated": False,
            "body": "",
            "body_truncated": False,
            "error": truncate_text(error, 512),
        }
    status = value.get("status")
    status_text = value.get("statusText")
    response_url = value.get("url")
    raw_headers = value.get("headers")
    headers_truncated = value.get("headersTruncated")
    body = value.get("body")
    body_truncated = value.get("bodyTruncated")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or status < 0
        or status > 599
        or not isinstance(status_text, str)
        or not isinstance(response_url, str)
        or not isinstance(raw_headers, list)
        or len(raw_headers) > MAX_INTERCEPTION_HEADERS
        or not isinstance(headers_truncated, bool)
        or not isinstance(body, str)
        or not isinstance(body_truncated, bool)
    ):
        raise ProtocolError("Debugger returned a malformed experiment result")
    headers = []
    header_bytes = 0
    for header in raw_headers:
        if (
            not isinstance(header, dict)
            or not isinstance(header.get("name"), str)
            or not isinstance(header.get("value"), str)
            or header["name"].lower() in SENSITIVE_INTERCEPTION_HEADERS
        ):
            raise ProtocolError("Debugger returned malformed experiment headers")
        headers_truncated = headers_truncated or (
            len(header["name"].encode("utf-8"))
            > MAX_INTERCEPTION_HEADER_NAME_BYTES
            or len(header["value"].encode("utf-8"))
            > MAX_INTERCEPTION_HEADER_VALUE_BYTES
        )
        name = truncate_text(
            header["name"], MAX_INTERCEPTION_HEADER_NAME_BYTES
        )
        header_value = truncate_text(
            header["value"], MAX_INTERCEPTION_HEADER_VALUE_BYTES
        )
        header_bytes += len(name.encode("utf-8")) + len(
            header_value.encode("utf-8")
        )
        if header_bytes > MAX_INTERCEPTION_HEADER_BYTES:
            raise ProtocolError("Debugger returned oversized experiment headers")
        headers.append({"name": name, "value": header_value})
    encoded_body = body.encode("utf-8")
    truncated_by_bridge = len(encoded_body) > MAX_INTERCEPTION_RESPONSE_BYTES
    return {
        "protocol_version": 1,
        "ok": True,
        "status": status,
        "status_text": truncate_text(status_text, 256),
        "url": redacted_request_url(response_url),
        "headers": headers,
        "headers_truncated": headers_truncated,
        "body": truncate_text(body, MAX_INTERCEPTION_RESPONSE_BYTES),
        "body_truncated": body_truncated or truncated_by_bridge,
        "error": None,
    }


def redacted_request_url(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        _ = parsed.port
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
    path = parsed.path or "/"
    return truncate_text(
        urlunparse((parsed.scheme, netloc, path, "", "", "")),
        MAX_INTERCEPTION_URL_BYTES,
    )


def request_interception_preflight_headers(
    request: dict[str, Any], rule: dict[str, Any]
) -> Optional[list[dict[str, str]]]:
    if rule["mode"] != "fulfill" or request.get("method") != "OPTIONS":
        return None
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return None
    requested_method = headers.get("Access-Control-Request-Method")
    if not isinstance(requested_method, str):
        requested_method = headers.get("access-control-request-method")
    if not isinstance(requested_method, str):
        return None
    requested_method = requested_method.strip().upper()
    try:
        validate_request_interception_method(requested_method)
    except DebuggerBridgeError:
        return None
    if rule["method_filter"] and requested_method != rule["method_filter"]:
        return None

    requested_headers = headers.get("Access-Control-Request-Headers")
    if not isinstance(requested_headers, str):
        requested_headers = headers.get("access-control-request-headers", "")
    if not isinstance(requested_headers, str) or len(
        requested_headers.encode("utf-8")
    ) > MAX_INTERCEPTION_HEADER_VALUE_BYTES:
        return None
    token_characters = frozenset(
        "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    )
    header_names = (
        [name.strip().lower() for name in requested_headers.split(",")]
        if requested_headers.strip()
        else []
    )
    if any(
        not name
        or any(character not in token_characters for character in name)
        or name in SENSITIVE_INTERCEPTION_HEADERS
        for name in header_names
    ) or len(header_names) > MAX_INTERCEPTION_HEADERS:
        return None
    response_headers = [
        {"name": "access-control-allow-origin", "value": "*"},
        {
            "name": "access-control-allow-methods",
            "value": requested_method,
        },
    ]
    if requested_headers:
        response_headers.append(
            {
                "name": "access-control-allow-headers",
                "value": ", ".join(header_names),
            }
        )
    return response_headers
