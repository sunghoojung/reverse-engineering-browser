#!/usr/bin/env python3

import argparse
import json
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
    "canvas",
    "navigator",
    "network",
    "permissions",
    "storage",
    "wasm",
    "web_audio",
    "webgl",
    "webrtc",
}
EVENT_TYPES = {
    "api_call",
    "gap",
    "module_compiled",
    "module_instantiated",
    "property_read",
    "request_completed",
    "request_failed",
    "request_initiated",
    "request_redirected",
    "request_started",
    "response_completed",
    "response_started",
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


def validate_event(event: object, line_number: int) -> None:
    if not isinstance(event, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")

    fields = set(event)
    if fields != EXPECTED_FIELDS:
        missing = sorted(EXPECTED_FIELDS - fields)
        unexpected = sorted(fields - EXPECTED_FIELDS)
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

    if not isinstance(event["payload_truncated"], bool):
        raise ValueError(f"line {line_number}: payload_truncated is not a boolean")
    if event["protocol_version"] != 2:
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate normalized broker evidence")
    parser.add_argument("store", type=Path)
    args = parser.parse_args()
    try:
        event_count = validate_store(args.store)
    except (OSError, ValueError, json.JSONDecodeError) as exception:
        parser.error(str(exception))
    print(f"Evidence contract check passed ({event_count} events)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
