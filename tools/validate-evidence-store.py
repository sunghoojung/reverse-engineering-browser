#!/usr/bin/env python3

import argparse
import fcntl
import hashlib
import json
import os
import select
import subprocess
import tempfile
from pathlib import Path


EXPECTED_FIELDS = {
    "artifact_id",
    "browser_context_id_high",
    "browser_context_id_low",
    "category",
    "decoded_body_length",
    "encoded_data_length",
    "error_code",
    "flags",
    "frame_id",
    "initiator_process_id",
    "initiator_request_id",
    "monotonic_time_ns",
    "navigation_id",
    "parent_event_id",
    "payload",
    "payload_encoding",
    "payload_size",
    "payload_truncated",
    "process_id",
    "protocol_version",
    "request_id",
    "resource_type",
    "sequence_number",
    "session_id",
    "status_code",
    "thread_id",
    "type",
}
UNSIGNED_STRING_INTEGER_FIELDS = {
    "artifact_id",
    "browser_context_id_high",
    "browser_context_id_low",
    "frame_id",
    "monotonic_time_ns",
    "navigation_id",
    "parent_event_id",
    "request_id",
    "sequence_number",
    "session_id",
}
SIGNED_STRING_INTEGER_FIELDS = {
    "decoded_body_length",
    "encoded_data_length",
}
INTEGER_FIELDS = {
    "error_code",
    "flags",
    "initiator_process_id",
    "initiator_request_id",
    "payload_size",
    "process_id",
    "protocol_version",
    "resource_type",
    "status_code",
    "thread_id",
}
SENSITIVE_PAYLOAD_MARKERS = (
    b"authorization:",
    b"cookie:",
    b"proxy-authorization:",
    b"set-cookie:",
)
EVENT_CATEGORIES = {
    "artifact",
    "canvas",
    "navigator",
    "network",
    "permissions",
    "runtime",
    "storage",
    "vm",
    "wasm",
    "web_audio",
    "webgl",
    "webrtc",
}
EVENT_TYPES = {
    "api_call",
    "artifact_capture_failed",
    "artifact_captured",
    "gap",
    "js_dispatch_observation",
    "js_invocation_request",
    "js_invocation_settle",
    "js_invocation_start",
    "module_compiled",
    "module_instantiated",
    "property_read",
    "request_body",
    "request_completed",
    "request_failed",
    "request_initiated",
    "request_initiator_stack",
    "request_watch_match",
    "listener_dispatch",
    "timer_observation",
    "csp_violation",
    "exception_observation",
    "dom_mutation",
    "request_redirected",
    "request_started",
    "request_target",
    "response_completed",
    "response_started",
    "script_identity",
    "vm_finding",
    "vm_dispatch_sample",
    "wasm_dispatch_observation",
    "wasm_guest_dispatch",
    "wasm_guest_invocation",
    "wasm_execution_outcome",
    "wasm_indirect_observation",
    "wasm_dispatch_overflow",
    "wasm_indirect_overflow",
}
UINT64_MAX = (1 << 64) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def parse_canonical_integer(value: object, field: str, line_number: int) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError(f"line {line_number}: {field} is not a canonical integer string")
    if value[0] == "-":
        digits = value[1:]
        if not digits or not digits.isdigit() or value.startswith("-0"):
            raise ValueError(f"line {line_number}: {field} is not canonical")
    elif not value.isdigit() or (value.startswith("0") and value != "0"):
        raise ValueError(f"line {line_number}: {field} is not canonical")
    return int(value)


def valid_js_dispatch(event: dict, payload: bytes) -> bool:
    """Rules of protocol/native-js-dispatch-v1.md, shared with C++, Rust and JS."""
    if (event["protocol_version"] != 3 or event["category"] != "vm" or event["flags"] != 0
            or event["payload_truncated"] or len(payload) != 128
            or any(event[key] == "0" for key in (
                "session_id", "sequence_number", "monotonic_time_ns", "frame_id"))
            or any(event[key] != "0" for key in (
                "artifact_id", "parent_event_id", "navigation_id", "request_id"))
            or not 1 <= event["process_id"] <= 0xFFFFFFFF
            or not 1 <= event["thread_id"] <= 0xFFFFFFFF):
        return False

    def at(offset: int, size: int) -> int:
        return int.from_bytes(payload[offset:offset + size], "little")

    shape, kind, slot, flags = payload[4], payload[5], payload[6], payload[7]
    selector, activation, parent = at(20, 4), at(36, 4), at(40, 4)
    handler = (at(24, 4), at(28, 4), at(32, 4))
    if (at(0, 2) != 1 or at(2, 2) != 128 or shape not in (1, 2) or not 1 <= kind <= 9
            or slot >= 8 or flags & ~0x0F or at(8, 4) == 0 or at(16, 4) == 0
            or at(12, 4) >= at(16, 4) or activation == 0 or at(44, 2) >= 64
            or at(46, 2) >= 256 or any(payload[80:])):
        return False
    if (kind == 7 and selector > 1) or (kind not in (1, 7) and selector != 0):
        return False
    if flags & 0x08:
        if shape != 2 or handler[0] == 0 or handler[1] >= handler[2]:
            return False
    elif any(handler):
        return False
    return parent == 0 or (parent < activation and not flags & 0x06)


TOKEN_CHARACTERS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")
REQUEST_DIGEST_LIMIT = 4 * 1024 * 1024


def valid_request_child(event: dict, payload: bytes) -> bool:
    """Envelope shared by request_body and request_target (native-network-v2.md)."""
    return (event["protocol_version"] == 3 and event["category"] == "network"
            and event["flags"] == 0 and not event["payload_truncated"] and len(payload) == 128
            and payload[:4] == bytes((1, 0, 128, 0))
            and all(event[key] != "0" for key in ("session_id", "sequence_number",
                                                  "parent_event_id"))
            and int(event["parent_event_id"]) < int(event["sequence_number"])
            and 1 <= event["process_id"] <= 0xFFFFFFFF and event["navigation_id"] == "0"
            and event["status_code"] == 0 and event["error_code"] == 0
            and event["encoded_data_length"] == "0" and event["decoded_body_length"] == "0"
            and event["resource_type"] == 0)


def valid_request_target(event: dict, payload: bytes) -> bool:
    length = int.from_bytes(payload[4:8], "little")
    prefix = min(length, 116)
    return (valid_request_child(event, payload) and event["artifact_id"] == "0"
            and payload[8] <= 4 and payload[9] == 0 and 0 not in payload[12:12 + prefix]
            and not any(payload[12 + prefix:]))


def valid_stack_frame(frame: bytes, is_async: bool) -> bool:
    """One 16-byte request stack frame, mirrored from include/reb/request_stack.hpp."""
    kind, flags = frame[0], frame[1]
    combinator = int.from_bytes(frame[2:4], "little")
    script_id = int.from_bytes(frame[4:8], "little")
    detail = int.from_bytes(frame[12:16], "little")
    if kind == 1:
        return not is_async and script_id != 0 and combinator == 0 and flags & ~3 == 0
    if kind == 2:
        return not is_async and script_id != 0 and combinator == 0 and flags == 0
    if kind == 3:
        return is_async and script_id != 0 and combinator == 0 and flags & ~2 == 0
    if kind == 4:
        return is_async and script_id == 0 and 1 <= combinator <= 3 and flags == 0 and detail == 0
    return False


def valid_stack_child(event: dict, payload: bytes) -> bool:
    """Envelope of request_initiator_stack and script_identity (native-network-v3.md)."""
    return (valid_request_child(event, payload) and event["artifact_id"] == "0"
            and event["initiator_request_id"] == 0 and event["initiator_process_id"] == 0
            and payload[6:8] == b"\0\0")


def valid_request_stack(event: dict, payload: bytes) -> bool:
    if not valid_stack_child(event, payload) or event["request_id"] == "0" or any(payload[80:]):
        return False
    return valid_stack_summary(payload)


def ascii_name(field: bytes, length: int, required: bool) -> bool:
    if length > len(field) or (required and length == 0):
        return False
    return (all(0x20 < c < 0x7F for c in field[:length]) and not any(field[length:]))


def optional_js_frame(frame: bytes) -> bool:
    return not any(frame) or (frame[0] == 1 and valid_stack_frame(frame, False))


OBSERVATION_TYPES = frozenset((
    "request_watch_match", "listener_dispatch", "timer_observation",
    "csp_violation", "exception_observation", "dom_mutation"))


def valid_observation(event: dict, payload: bytes) -> bool:
    """Types 40-45, protocol/native-debugger-observation-v1.md."""
    kind = event["type"]
    request = kind == "request_watch_match"
    if (event["category"] != ("network" if request else "runtime") or len(payload) != 128
            or payload[:4] != b"\x01\x00\x80\x00" or payload[6:8] != b"\0\0"
            or event["artifact_id"] != "0" or (event["request_id"] == "0") == request
            or (request and event["parent_event_id"] == "0")
            or not valid_stack_summary(payload)):
        return False
    t = payload[80:]
    if request:
        return t[0] < 8 and t[1] & ~1 == 0 and not any(t[2:])
    if kind == "listener_dispatch":
        return (t[0] < 16 and 1 <= t[1] <= 5 and optional_js_frame(t[4:20])
                and ascii_name(t[21:48], t[20], True))
    if kind == "timer_observation":
        return (t[0] in (1, 2) and t[1] in (1, 2) and t[2] & ~1 == 0 and t[3] == 0
                and optional_js_frame(t[12:28]) and not any(t[28:]))
    if kind == "csp_violation":
        return t[1] in (1, 2) and ascii_name(t[3:48], t[2], False)
    if kind == "exception_observation":
        return t[0] in (1, 2, 3) and not any(t[1:4]) and optional_js_frame(t[4:20]) and not any(t[20:])
    return (t[0] in (1, 2, 3) and t[1] < 4 and ascii_name(t[5:37], t[4], t[0] == 1)
            and (t[0] == 1 or t[4] == 0) and not any(t[37:]))


def valid_stack_summary(payload: bytes) -> bool:
    """Bytes 0-79 shared by request_initiator_stack and debugger observations."""
    state, flags = payload[4], payload[5]
    total, recorded, omitted = (int.from_bytes(payload[i:i + 4], "little") for i in (8, 12, 16))
    async_frames = int.from_bytes(payload[20:22], "little")
    segments = int.from_bytes(payload[22:24], "little")
    wasm, scripts = (int.from_bytes(payload[i:i + 4], "little") for i in (24, 28))
    digest, innermost = payload[32:64], payload[64:80]
    if flags & ~0x0F:
        return False
    if state in (2, 3):
        return flags & ~0x08 == 0 and not any(payload[8:80])
    if state not in (1, 4, 5):
        return False
    return (1 <= recorded <= 1024 and recorded + omitted == total
            and (omitted != 0) == bool(flags & 0x02) and (omitted == 0 or recorded == 1024)
            and async_frames <= 32 and segments <= async_frames
            and (not flags & 0x04 or async_frames == 32) and (not flags & 0x01 or state == 1)
            and wasm <= recorded + async_frames and scripts <= recorded + async_frames
            and any(digest) and valid_stack_frame(innermost, False))


def valid_script_identity(event: dict, payload: bytes) -> bool:
    if not valid_stack_child(event, payload) or event["request_id"] != "0" or any(payload[72:]):
        return False
    kind, flags = payload[4], payload[5]
    script_id = int.from_bytes(payload[8:12], "little")
    context = int.from_bytes(payload[24:32], "little")
    length = int.from_bytes(payload[32:40], "little")
    digest = payload[40:72]
    retention = flags & 0x1E
    if (any(payload[20:24]) or script_id == 0 or context == 0 or flags & ~0x1F
            or retention & (retention - 1) or kind not in (1, 2)
            or (kind == 2 and flags & ~0x0C) or (kind == 1 and retention == 0)):
        return False
    if retention == 0x08:
        return length == 0 and not any(digest)
    if retention == 0x04:
        return length > 16 * 1024 * 1024 and not any(digest)
    return 0 < length <= 16 * 1024 * 1024 and any(digest)


def valid_request_body(event: dict, payload: bytes) -> bool:
    """Every state rule of the request_body payload, mirrored from the C++ core."""
    if not valid_request_child(event, payload):
        return False
    kind, state, flags, type_length = payload[4], payload[5], payload[6], payload[7]
    body_length = int.from_bytes(payload[8:16], "little")
    captured = int.from_bytes(payload[16:24], "little")
    elements = int.from_bytes(payload[24:28], "little")
    digest, content_type = payload[32:64], payload[64:128]
    content, has_digest, size_limit = bool(flags & 1), bool(flags & 2), bool(flags & 4)
    partial, type_present, type_omitted = bool(flags & 8), bool(flags & 16), bool(flags & 32)
    media = content_type[:type_length]
    if (kind > 6 or not 1 <= state <= 11 or flags & ~0x3F or any(payload[28:32])
            or type_length > 64 or (type_present and type_omitted)
            or type_present != (type_length != 0) or any(content_type[type_length:])
            or (type_present and (media.count(b"/") != 1 or media.startswith(b"/")
                                  or media.endswith(b"/")
                                  or any(b not in TOKEN_CHARACTERS and b != 0x2F for b in media)))
            or captured > body_length):
        return False
    is_bytes, is_none = kind == 1, kind == 0
    if ((has_digest and (not is_bytes or size_limit or body_length > REQUEST_DIGEST_LIMIT))
            or (not has_digest and any(digest))
            or (size_limit and (not is_bytes or body_length <= REQUEST_DIGEST_LIMIT))
            or (is_bytes and state != 11 and has_digest == size_limit)
            or (state == 11 and (has_digest or size_limit))
            or partial != (not is_none and not is_bytes) or is_none != (state == 1)
            or (is_none and (elements or body_length)) or (not is_none and not elements)
            or (kind == 5 and elements < 2)):
        return False
    retained = state in (4, 5)
    if (event["artifact_id"] != "0") != retained or (not retained and captured):
        return False
    return {
        1: True,
        2: is_bytes and body_length == 0,
        3: not content and (not is_bytes or body_length != 0),
        4: content and is_bytes and body_length != 0 and captured == body_length,
        5: content and is_bytes and 0 < captured < body_length,
        6: content and not is_none and not is_bytes,
        7: content and is_bytes and body_length != 0,
        8: content and is_bytes and body_length != 0,
        9: content and is_bytes and body_length != 0,
        10: content and is_bytes and body_length != 0,
        11: True,
    }[state]


def valid_invocation_context(state: int, invocation_id: int) -> bool:
    """A consumer record's JavaScript invocation context: protocol/native-js-invocation-v1.md."""
    return state <= 3 and (state == 2) == (invocation_id != 0)


def invocation_envelope(event: dict, payload: bytes) -> bool:
    return not (event["protocol_version"] != 3 or event["category"] != "vm" or event["flags"] != 0
                or event["payload_truncated"] or len(payload) != 128
                or any(event[key] == "0" for key in (
                    "session_id", "sequence_number", "monotonic_time_ns"))
                or any(event[key] != "0" for key in (
                    "artifact_id", "parent_event_id", "navigation_id"))
                or not 1 <= event["process_id"] <= 0xFFFFFFFF
                or not 1 <= event["thread_id"] <= 0xFFFFFFFF)


def valid_value_kind(kind: int, low32: int) -> bool:
    return 1 <= kind <= 14 and (kind == 1 or (low32 <= 1 if kind == 7 else low32 == 0))


def valid_js_invocation(event: dict, payload: bytes) -> bool:
    """Rules of protocol/native-js-invocation-v1.md, shared with C++, Rust and JS."""
    if not invocation_envelope(event, payload):
        return False

    def at(offset: int, size: int) -> int:
        return int.from_bytes(payload[offset:offset + size], "little")

    if at(0, 2) != 1 or at(2, 2) != 128:
        return False
    kind = event["type"]
    if kind == "js_invocation_request":
        state = payload[4]
        return (event["request_id"] != "0" and int(event["request_id"]) <= 0xFFFFFFFF
                and state in (2, 3) and valid_invocation_context(state, at(8, 4))
                and at(12, 2) < 256 and not any(payload[5:8]) and at(14, 2) == 0
                and not any(payload[16:]))
    if event["frame_id"] == "0" or event["request_id"] != "0":
        return False
    if kind == "js_invocation_start":
        slot, flags, argc = payload[4], payload[5], at(6, 2)
        invocation, parent = at(20, 4), at(24, 4)
        if (slot >= 8 or flags & ~0x03 or at(8, 4) == 0 or at(16, 4) == 0
                or at(12, 4) >= at(16, 4) or invocation == 0 or at(28, 2) >= 64
                or at(30, 2) >= 256 or at(104, 8) == 0 or any(payload[112:])):
            return False
        if parent != 0 and (parent >= invocation or flags & 0x01):
            return False
        if bool(flags & 0x02) != (argc > 8):
            return False
        for index in range(8):
            arg_kind, low32 = payload[32 + index], at(40 + 4 * index, 4)
            if index < argc:
                if not valid_value_kind(arg_kind, low32):
                    return False
            elif arg_kind or low32:
                return False
        return True
    # js_invocation_settle
    slot, outcome, via, value_kind = payload[4], payload[5], payload[6], payload[7]
    length, state, encoding, flags = at(12, 4), payload[16], payload[17], payload[18]
    byte_length, rolling = at(20, 4), at(24, 8)
    fulfilled, rejected = outcome == 1, outcome == 2
    if (slot >= 8 or not (fulfilled or rejected) or not 1 <= value_kind <= 14
            or at(8, 4) == 0 or at(64, 8) == 0 or payload[19] != 0 or flags & ~0x01
            or any(payload[72:])):
        return False
    if not ((via == 1 and fulfilled) or (via == 2 and rejected) or via == 3):
        return False
    is_string, is_bytes = value_kind == 3, value_kind in (12, 13)
    if length and not (is_string or is_bytes or value_kind == 11):
        return False
    if state == 1:
        return (fulfilled and byte_length <= 1 << 20
                and ((is_string and encoding == 1) or (is_bytes and encoding == 2))
                and (is_string or not flags & 0x01)
                and (not is_string or byte_length >= length)
                and (not is_bytes or byte_length == length)
                and (byte_length != 0 or rolling == 0))
    if encoding or byte_length or rolling or flags or any(payload[32:64]):
        return False
    if state == 0:
        return True
    if state == 2:
        return not (fulfilled and (is_string or is_bytes))
    if state == 3:
        return fulfilled and (is_string or is_bytes)
    if state == 4:
        return fulfilled and is_bytes
    return False


def wasm_direct_caller_invalid(payload: bytes) -> bool:
    """Version 3 stores the direct caller at bytes 32..40. Older versions reserve them."""
    if payload[0] < 3:
        return any(payload[32:])
    kind = payload[32]
    index = int.from_bytes(payload[36:40], "little")
    if any(payload[33:36]) or any(payload[40:]):
        return True
    if kind == 0:
        return index != 0
    if kind == 1:
        return index >= 16 * 1024 * 1024
    return True


def wasm_context_invalid(payload: bytes, version: int, new_version: int, offset: int) -> bool:
    """Version new_version stores the invocation context at offset; older ones reserve it."""
    state = payload[offset]
    invocation = int.from_bytes(payload[offset + 4:offset + 8], "little")
    return (any(payload[offset + 1:offset + 4])
            or (version < new_version and (state or invocation))
            or not valid_invocation_context(state, invocation))


def valid_wasm_overflow(event: dict, payload: bytes, indirect: bool) -> bool:
    size = 40 if indirect else 32
    if (
        event["protocol_version"] != 3
        or event["category"] != "vm"
        or event["flags"] != 0
        or event["payload_truncated"]
        or event["artifact_id"] != "0"
        or event["parent_event_id"] != "0"
        or any(event[key] == "0" for key in (
            "session_id", "sequence_number", "monotonic_time_ns", "frame_id"
        ))
        or not 1 <= event["process_id"] <= 0xFFFFFFFF
        or not 1 <= event["thread_id"] <= 0xFFFFFFFF
        or len(payload) != size
        or int.from_bytes(payload[0:2], "little") != 1
        or int.from_bytes(payload[2:4], "little") != size
        or payload[5] != 0
    ):
        return False
    if indirect:
        if int.from_bytes(payload[32:40], "little") != 0:
            return False
    elif int.from_bytes(payload[28:32], "little") != 0:
        return False
    kind = payload[4]
    ring = int.from_bytes(payload[6:8], "little")
    omitted_at = 28 if indirect else 24
    omitted = int.from_bytes(payload[omitted_at:omitted_at + 4], "little")
    limit = 16 * 1024 * 1024
    if kind == 2:
        return ring == 0 and omitted >= 1 and not any(payload[8:omitted_at])
    if kind != 1 or omitted != 0 or ring >= 32:
        return False
    function_index = int.from_bytes(payload[8:12], "little")
    offset = int.from_bytes(payload[12:16], "little")
    if function_index >= limit or not 8 <= offset < limit:
        return False
    if not indirect:
        return int.from_bytes(payload[20:24], "little") < limit
    return (
        int.from_bytes(payload[16:20], "little") < limit
        and int.from_bytes(payload[24:28], "little") < 5
    )


def validate_event(event: object, line_number: int) -> None:
    if not isinstance(event, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")

    protocol_version = event.get("protocol_version")
    expected_fields = EXPECTED_FIELDS | ({"tab_id"} if protocol_version == 3 else set())
    fields = set(event)
    if fields != expected_fields:
        missing = sorted(expected_fields - fields)
        unexpected = sorted(fields - expected_fields)
        raise ValueError(
            f"line {line_number}: evidence schema mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )

    for field in UNSIGNED_STRING_INTEGER_FIELDS:
        value = parse_canonical_integer(event[field], field, line_number)
        if not 0 <= value <= UINT64_MAX:
            raise ValueError(f"line {line_number}: {field} is outside uint64 range")

    for field in SIGNED_STRING_INTEGER_FIELDS:
        value = parse_canonical_integer(event[field], field, line_number)
        if not INT64_MIN <= value <= INT64_MAX:
            raise ValueError(f"line {line_number}: {field} is outside int64 range")

    for field in INTEGER_FIELDS:
        if not isinstance(event[field], int) or isinstance(event[field], bool):
            raise ValueError(f"line {line_number}: {field} is not an integer")

    if protocol_version == 3 and (
        not isinstance(event["tab_id"], int)
        or isinstance(event["tab_id"], bool)
        or not 0 <= event["tab_id"] < 2**32
    ):
        raise ValueError(f"line {line_number}: tab_id is outside uint32 range")

    if not isinstance(event["payload_truncated"], bool):
        raise ValueError(f"line {line_number}: payload_truncated is not a boolean")
    if protocol_version not in {2, 3}:
        raise ValueError(f"line {line_number}: unsupported protocol version")
    if event["category"] not in EVENT_CATEGORIES or event["type"] not in EVENT_TYPES:
        raise ValueError(f"line {line_number}: unknown category or event type")
    if not 0 <= event["flags"] <= 7:
        raise ValueError(f"line {line_number}: unsupported event flags")
    if not 0 <= event["payload_size"] <= 128:
        raise ValueError(f"line {line_number}: payload size exceeds the inline limit")
    if event["payload_encoding"] != "hex":
        raise ValueError(f"line {line_number}: unsupported payload encoding")
    try:
        payload = bytes.fromhex(event["payload"])
    except (TypeError, ValueError) as exception:
        raise ValueError(f"line {line_number}: payload is not valid hex") from exception
    if len(payload) != event["payload_size"]:
        raise ValueError(f"line {line_number}: payload size does not match encoded data")
    if event["type"] == "vm_dispatch_sample" and (
        event["category"] != "vm"
        or len(payload) != 128
        or int.from_bytes(payload[0:2], "little") != 1
        or int.from_bytes(payload[2:4], "little") != 128
        or int.from_bytes(payload[20:24], "little") != 0
        or int.from_bytes(payload[24:32], "little") == 0
        or int.from_bytes(payload[32:40], "little") == 0
        or payload[56] != 0
        or int.from_bytes(payload[58:60], "little") != 0
        or int.from_bytes(payload[60:64], "little") != 0
        or int.from_bytes(payload[64:72], "little") != 0
        or any(payload[72:])
    ):
        raise ValueError(f"line {line_number}: VM dispatch sample payload is invalid")
    if event["type"] == "wasm_dispatch_observation" and (
        protocol_version != 3
        or event["category"] != "vm"
        or event["flags"] != 0
        or event["payload_truncated"]
        or event["parent_event_id"] != "0"
        or any(event[key] == "0" for key in (
            "session_id", "sequence_number", "monotonic_time_ns", "frame_id", "artifact_id"
        ))
        or not 1 <= event["process_id"] <= 0xFFFFFFFF
        or not 1 <= event["thread_id"] <= 0xFFFFFFFF
        or len(payload) != 128
        or payload[0] not in (1, 2, 3)
        or payload[1:4] != bytes((0, 128, 0))
        or int.from_bytes(payload[4:8], "little") >= 16777216
        or not 8 <= int.from_bytes(payload[8:12], "little") < 16777216
        or int.from_bytes(payload[16:20], "little") >= 16777216
        or int.from_bytes(payload[20:24], "little") >= 16
        or wasm_context_invalid(payload, payload[0], 2, 24)
        or wasm_direct_caller_invalid(payload)
    ):
        raise ValueError(f"line {line_number}: native Wasm dispatch observation is invalid")
    if event["type"] == "wasm_indirect_observation" and (
        protocol_version != 3
        or event["category"] != "vm"
        or event["flags"] != 0
        or event["payload_truncated"]
        or event["parent_event_id"] != "0"
        or any(event[key] == "0" for key in (
            "session_id", "sequence_number", "monotonic_time_ns", "frame_id", "artifact_id"
        ))
        or not 1 <= event["process_id"] <= 0xFFFFFFFF
        or not 1 <= event["thread_id"] <= 0xFFFFFFFF
        or len(payload) != 128
        or payload[0] not in (1, 2)
        or payload[1:4] != bytes((0, 128, 0))
        or int.from_bytes(payload[4:8], "little") >= 16777216
        or not 8 <= int.from_bytes(payload[8:12], "little") < 16777216
        or int.from_bytes(payload[12:16], "little") >= 16777216
        or int.from_bytes(payload[20:24], "little") >= 16777216
        or int.from_bytes(payload[24:28], "little") >= 5
        or (int.from_bytes(payload[24:28], "little") != 0 and any(payload[20:24]))
        or int.from_bytes(payload[28:32], "little") >= 16
        or wasm_context_invalid(payload, payload[0], 2, 32)
        or any(payload[40:])
    ):
        raise ValueError(f"line {line_number}: native Wasm call_indirect observation is invalid")
    if event["type"] == "wasm_execution_outcome":
        version = payload[0] if len(payload) > 0 else 0
        kind = payload[4] if len(payload) > 4 else 0
        reason = payload[5] if len(payload) > 5 else 0
        bounds = payload[6] if len(payload) > 6 else 0
        known = payload[7] if len(payload) > 7 else 0
        function_index = int.from_bytes(payload[8:12], "little") if len(payload) >= 12 else 0
        module_offset = int.from_bytes(payload[12:16], "little") if len(payload) >= 16 else 0
        invocation = int.from_bytes(payload[16:20], "little") if len(payload) >= 20 else 0
        sample = int.from_bytes(payload[20:24], "little") if len(payload) >= 24 else 0
        stream = payload[24] if len(payload) > 24 else 0
        if (
            protocol_version != 3
            or event["category"] != "vm"
            or event["flags"] != 0
            or event["payload_truncated"]
            or event["parent_event_id"] != "0"
            or any(event[key] == "0" for key in (
                "session_id", "sequence_number", "monotonic_time_ns", "frame_id", "artifact_id"
            ))
            or not 1 <= event["process_id"] <= 0xFFFFFFFF
            or not 1 <= event["thread_id"] <= 0xFFFFFFFF
            or len(payload) != 128
            or version != 1
            or payload[1:4] != bytes((0, 128, 0))
            or (known & ~3) != 0
            or kind > 1
            or stream > 2
            or invocation == 0
            or (function_index >= 16777216 if known & 1 else function_index != 0)
            or (module_offset < 8 or module_offset >= 16777216 if known & 2 else module_offset != 0)
            or (reason != 0 or bounds != 0 if kind == 1 else reason >= 6)
            or (bounds >= 7 if reason == 3 else bounds != 0)
            or (sample != 0xFFFFFFFF if stream == 0 else sample >= 16)
            or any(payload[25:28])
            or wasm_context_invalid(payload, version, 1, 28)
            or any(payload[36:])
        ):
            raise ValueError(f"line {line_number}: native Wasm execution outcome is invalid")
    if event["type"] in ("wasm_dispatch_overflow", "wasm_indirect_overflow") and not valid_wasm_overflow(
        event, payload, event["type"] == "wasm_indirect_overflow"
    ):
        raise ValueError(f"line {line_number}: native Wasm overflow identity is invalid")
    if event["type"] == "js_dispatch_observation" and not valid_js_dispatch(event, payload):
        raise ValueError(f"line {line_number}: native JavaScript dispatch observation is invalid")
    if event["type"] == "request_body" and not valid_request_body(event, payload):
        raise ValueError(f"line {line_number}: native request body record is invalid")
    if event["type"] == "request_target" and not valid_request_target(event, payload):
        raise ValueError(f"line {line_number}: native request target record is invalid")
    if event["type"] == "request_initiator_stack" and not valid_request_stack(event, payload):
        raise ValueError(f"line {line_number}: native request initiator stack record is invalid")
    if event["type"] == "script_identity" and not valid_script_identity(event, payload):
        raise ValueError(f"line {line_number}: native script identity record is invalid")
    if event["type"] in OBSERVATION_TYPES and not valid_observation(event, payload):
        raise ValueError(f"line {line_number}: native debugger observation record is invalid")
    if event["type"].startswith("js_invocation_") and not valid_js_invocation(event, payload):
        raise ValueError(f"line {line_number}: native JavaScript invocation record is invalid")
    if event["type"] in ("wasm_guest_dispatch", "wasm_guest_invocation"):
        # Invocation version 2 adds the exact parent dispatch at bytes 72..80,
        # version 3 the adapter site (at most 8) at bytes 80..84 and version 4
        # the JavaScript invocation context at bytes 84..92.
        versions = (1, 2, 3, 4) if event["type"] == "wasm_guest_invocation" else (1,)
        if (protocol_version != 3 or event["category"] != "vm" or event["flags"] != 0
                or event["payload_truncated"] or len(payload) != 128
                or payload[0] not in versions or payload[1:4] != bytes((0, 128, 0))
                or any(event[k] == "0" for k in ("session_id", "sequence_number", "monotonic_time_ns", "frame_id", "artifact_id"))
                or not 1 <= event["process_id"] <= 0xFFFFFFFF
                or not 1 <= event["thread_id"] <= 0xFFFFFFFF):
            raise ValueError(f"line {line_number}: native guest envelope invalid")

        def at(offset: int, size: int) -> int:
            return int.from_bytes(payload[offset:offset + size], "little")

        invalid = at(4, 4) >= 16777216
        if event["type"] == "wasm_guest_invocation":
            parent_dispatch = at(72, 8)
            invalid |= (event["parent_event_id"] != "0" or at(8, 8) == 0 or at(16, 8) == 0
                        or at(24, 8) == 0 or at(24, 8) == int(event["artifact_id"])
                        or at(64, 8) == at(16, 8) or not any(payload[32:64]) or any(payload[92:])
                        or wasm_context_invalid(payload, payload[0], 4, 84)
                        or (payload[0] < 3 and at(80, 4) != 0) or at(80, 4) >= 8
                        or (parent_dispatch != 0
                            and (payload[0] == 1 or at(64, 8) == 0
                                 or parent_dispatch >= int(event["sequence_number"]))))
        else:
            invalid |= (not 0 < int(event["parent_event_id"]) < int(event["sequence_number"])
                        or not 8 <= at(8, 4) < 16777216 or at(16, 4) >= 16777216
                        or at(20, 4) >= 256 or at(24, 8) == 0 or at(32, 8) == 0
                        or at(56, 8) == 0 or at(56, 8) == int(event["artifact_id"])
                        or not 0 < at(72, 4) <= 65536 or at(40, 8) >= at(72, 4)
                        or at(64, 8) + at(72, 4) > 0xFFFFFFFFFFFFFFFF or not any(payload[96:]))
        if invalid:
            raise ValueError(f"line {line_number}: native guest payload invalid")
    lowered_payload = payload.lower()
    if any(marker in lowered_payload for marker in SENSITIVE_PAYLOAD_MARKERS):
        raise ValueError(f"line {line_number}: payload contains sensitive HTTP metadata")


def validate_store(path: Path) -> int:
    event_count = 0
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            validate_event(json.loads(line), line_number)
            event_count += 1
    if event_count == 0:
        raise ValueError("evidence store is empty")
    return event_count



def validate_writer_guards(broker: Path, receiver: Path, producer: Path) -> None:
    """Real writer lifetime barriers; no sleeps, browser, sockets or network."""
    marker = b"REB_EVIDENCE_GUARD_V1\n"
    with tempfile.TemporaryDirectory(prefix="reb-guard-check-") as temporary:
        root = Path(temporary)
        for binary, store, guard, ready in [
            (broker, root / "events.jsonl", root / "events.jsonl.reb-lock-v1", b"Event store ready\n"),
            (receiver, root / "artifacts", root / "artifacts/evidence.reb-lock-v1", b"Artifact store ready\n"),
        ]:
            command = [str(binary.resolve()), "--store", str(store)]
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                assert child.stderr is not None and child.stdin is not None
                assert select.select([child.stderr], [], [], 10)[0], "Writer readiness deadline"
                assert child.stderr.readline() == ready, "Writer failed before acquiring its guard"
                assert guard.read_bytes() == marker
                assert guard.stat().st_mode & 0o777 == 0o600
                inode = guard.stat().st_ino
                with guard.open("rb") as held:
                    try:
                        fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        raise AssertionError("A live writer did not retain its exclusive guard")
                before = hashlib.sha256(store.read_bytes()).digest() if store.is_file() else None
                competing = subprocess.run(command, input=b"", capture_output=True, timeout=10, check=False)
                assert competing.returncode != 0, "A second writer acquired the same store"
                if before is not None:
                    assert hashlib.sha256(store.read_bytes()).digest() == before, "Competing writer truncated evidence"
                # Broker output is deliberately buffered until EOF. Its lifetime
                # guard covers the final delayed stream flush and stream close.
                if binary == broker:
                    events = subprocess.run([str(producer.resolve())], capture_output=True, timeout=10, check=True).stdout
                    child.stdin.write(events)
                    child.stdin.flush()
                    with guard.open("rb") as held:
                        try:
                            fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        except BlockingIOError:
                            pass
                        else:
                            raise AssertionError("Buffered broker released its writer guard early")
                child.stdin.close()
                assert child.wait(timeout=10) == 0
                assert guard.stat().st_ino == inode and guard.read_bytes() == marker
                with guard.open("rb") as held:
                    fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    before = hashlib.sha256(store.read_bytes()).digest() if store.is_file() else None
                    blocked = subprocess.run(command, input=b"", capture_output=True, timeout=10, check=False)
                    assert blocked.returncode != 0, "Writer bypassed an export lease"
                    if before is not None:
                        assert hashlib.sha256(store.read_bytes()).digest() == before
                if binary == broker:
                    assert validate_store(store) == 14
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
            # Process death releases the lease without deleting/replacing the
            # immutable inode. It does not certify complete captured evidence.
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                assert child.stderr is not None
                assert select.select([child.stderr], [], [], 10)[0]
                assert child.stderr.readline() == ready
                child.kill()
                child.wait(timeout=10)
                with guard.open("rb") as held:
                    fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                assert guard.stat().st_ino == inode
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        # Every alias and output role must participate before first mutation.
        event = root / "held.jsonl"
        command = [str(broker.resolve()), "--store", str(event)]
        subprocess.run(command, input=b"", capture_output=True, timeout=10, check=True)
        event.write_bytes(b"original retained bytes\n")
        event_guard = root / "held.jsonl.reb-lock-v1"
        with event_guard.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
            for alias_kind in ("symlink", "hardlink"):
                alias = root / f"{alias_kind}.jsonl"
                if alias_kind == "symlink":
                    alias.symlink_to(event)
                else:
                    os.link(event, alias)
                failed = subprocess.run([str(broker.resolve()), "--store", str(alias)], input=b"", capture_output=True, timeout=10, check=False)
                assert failed.returncode != 0
                assert event.read_bytes() == b"original retained bytes\n"
                alias.unlink()
            fresh = root / "new-main.jsonl"
            failed = subprocess.run([str(broker.resolve()), "--store", str(fresh), "--trace-store", str(event)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0 and not fresh.exists()
            failed = subprocess.run([str(broker.resolve()), "--store", str(event_guard)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0 and event_guard.read_bytes() == marker
        artifacts = root / "aliased-artifacts"
        artifacts.mkdir()
        manifest = artifacts / "manifest.jsonl"
        for alias_kind in ("symlink", "hardlink"):
            if alias_kind == "symlink":
                manifest.symlink_to(event)
            else:
                os.link(event, manifest)
            failed = subprocess.run([str(receiver.resolve()), "--store", str(artifacts)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0
            assert event.read_bytes() == b"original retained bytes\n"
            manifest.unlink()
        external_blobs = root / "external-blobs"
        external_blobs.mkdir()
        (artifacts / "blobs").rmdir()
        (artifacts / "blobs").symlink_to(external_blobs, target_is_directory=True)
        failed = subprocess.run([str(receiver.resolve()), "--store", str(artifacts)], input=b"", capture_output=True, timeout=10, check=False)
        assert failed.returncode != 0 and not list(external_blobs.iterdir())
        (artifacts / "blobs").unlink()
        (artifacts / "blobs").mkdir()
        for forbidden in (artifacts / "manifest.jsonl", artifacts / "artifact-1.part", artifacts / "blobs" / ("0" * 64 + ".bin")):
            failed = subprocess.run([str(broker.resolve()), "--store", str(forbidden)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0 and not forbidden.exists()

    print("Evidence writer guard check passed (lifetime, buffered flush, competing owners, shared export and process death)")

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate normalized broker evidence")
    parser.add_argument("store", type=Path)
    parser.add_argument("--broker", type=Path)
    parser.add_argument("--receiver", type=Path)
    parser.add_argument("--producer", type=Path)
    args = parser.parse_args()
    if any((args.broker, args.receiver, args.producer)) and not all((args.broker, args.receiver, args.producer)):
        parser.error("--broker, --receiver and --producer must be supplied together")
    try:
        event_count = validate_store(args.store)
    except (OSError, ValueError, json.JSONDecodeError) as exception:
        parser.error(str(exception))
    print(f"Evidence contract check passed ({event_count} events)")
    if args.broker:
        validate_writer_guards(args.broker, args.receiver, args.producer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
