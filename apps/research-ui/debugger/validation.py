from __future__ import annotations

import math
from typing import Any

from debugger.errors import (
    DebuggerBridgeError,
    ProtocolError,
)
from debugger.limits import (
    MAX_REMOTE_TEXT_BYTES,
    MAX_TARGET_ID_BYTES,
)


def runtime_result_object_id(
    result: dict[str, Any], label: str, *, field: str = "result"
) -> str:
    remote = result.get(field)
    object_id = remote.get("objectId") if isinstance(remote, dict) else None
    if not isinstance(object_id, str) or not object_id:
        raise ProtocolError(f"Debugger returned a malformed {label}")
    return object_id


def required_protocol_identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_TARGET_ID_BYTES
    ):
        raise ProtocolError(f"Browser returned an invalid {label} identifier")
    return value


def bounded_integer(value: Any) -> int:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value < 2**53
    ):
        return value
    return 0


def is_finite_protocol_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) <= 2**53
    return isinstance(value, float) and math.isfinite(value)


def truncate_text(value: str, max_bytes: int = MAX_REMOTE_TEXT_BYTES) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def required_text(
    request: dict[str, Any], field: str, max_bytes: int, allow_empty: bool = False
) -> str:
    value = request.get(field)
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value.encode("utf-8")) > max_bytes
    ):
        raise DebuggerBridgeError(f"Debugger {field.replace('_', ' ')} is invalid")
    return value
