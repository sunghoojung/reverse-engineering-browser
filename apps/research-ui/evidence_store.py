"""Bounded evidence-file reads and validation, independent of HTTP handling."""

import json
import re
from pathlib import Path

CANONICAL_UINT64 = re.compile(r"(?:0|[1-9][0-9]*)\Z")

SHA256 = re.compile(r"[0-9a-f]{64}\Z")

ARTIFACT_KINDS = {"javascript", "wasm", "source_map", "response_body"}

JSONL_TAIL_CHUNK_BYTES = 64 * 1024

MAX_EVENT_JSON_BYTES = 4 * 1024

SIGNAL_CATEGORIES = {
    "canvas",
    "webgl",
    "web_audio",
    "navigator",
    "permissions",
    "storage",
    "webrtc",
}

ARTIFACT_CAPTURE_ORIGINS = {
    "unknown",
    "network_response",
    "dynamic_javascript",
    "webassembly_compile",
    "webassembly_module",
    "webassembly_instantiate",
}

def read_recent_json_lines(
    path: Path, limit: int, max_record_bytes: int, record_name: str
) -> list[str]:
    if limit <= 0:
        return []
    if not path.exists():
        return []

    lines = []
    suffix = b""
    with path.open("rb") as stream:
        position = stream.seek(0, 2)
        while position > 0 and len(lines) < limit:
            chunk_size = min(position, JSONL_TAIL_CHUNK_BYTES)
            position -= chunk_size
            stream.seek(position)
            parts = stream.read(chunk_size).split(b"\n")
            parts[-1] += suffix
            for encoded_line in reversed(parts[1:]):
                if encoded_line.strip():
                    lines.append(
                        decode_json_line(
                            encoded_line, max_record_bytes, record_name
                        )
                    )
                    if len(lines) == limit:
                        break
            suffix = parts[0]
            if len(suffix) > max_record_bytes:
                raise ValueError(
                    f"The evidence store contains an oversized {record_name}"
                )

        if position == 0 and len(lines) < limit and suffix.strip():
            lines.append(
                decode_json_line(
                    suffix, max_record_bytes, record_name
                )
            )

    lines.reverse()
    return lines


def parse_event(line: str) -> dict:
    event = json.loads(line)
    if not isinstance(event, dict):
        raise ValueError("The evidence store contains a malformed event")
    return event


def decode_event_line(encoded_line: bytes) -> str:
    return decode_json_line(
        encoded_line, MAX_EVENT_JSON_BYTES, "event"
    )


def decode_json_line(
    encoded_line: bytes, max_record_bytes: int, record_name: str
) -> str:
    if len(encoded_line) > max_record_bytes:
        raise ValueError(f"The evidence store contains an oversized {record_name}")
    return encoded_line.decode("utf-8")


def is_canonical_uint(value: object, bits: int, nonzero: bool = False) -> bool:
    if not isinstance(value, str) or CANONICAL_UINT64.fullmatch(value) is None:
        return False
    number = int(value)
    return (not nonzero or number != 0) and number < 2**bits


def is_signal_event_reference(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"process_id", "sequence_number"}
        and isinstance(value["process_id"], int)
        and not isinstance(value["process_id"], bool)
        and 0 <= value["process_id"] < 2**32
        and is_canonical_uint(value["sequence_number"], 64, nonzero=True)
    )


def is_request_signal_profile(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "protocol_version",
        "document_kind",
        "session_id",
        "request_id",
        "root_event",
        "initiator_event",
        "navigation_id",
        "frame_id",
        "signals",
        "coverage",
    }:
        return False
    if (
        not isinstance(value["protocol_version"], int)
        or isinstance(value["protocol_version"], bool)
        or value["protocol_version"] != 1
        or value["document_kind"] != "request-signal-profile"
        or not is_canonical_uint(value["session_id"], 64, nonzero=True)
        or not is_canonical_uint(value["request_id"], 64, nonzero=True)
        or not is_canonical_uint(value["navigation_id"], 64)
        or not is_canonical_uint(value["frame_id"], 64)
        or not is_signal_event_reference(value["root_event"])
        or (
            value["initiator_event"] is not None
            and not is_signal_event_reference(value["initiator_event"])
        )
        or not isinstance(value["signals"], list)
        or len(value["signals"]) > len(SIGNAL_CATEGORIES)
    ):
        return False
    categories = set()
    expected_process_id = (value["initiator_event"] or value["root_event"])[
        "process_id"
    ]
    has_saturated_count = False
    for signal in value["signals"]:
        if not isinstance(signal, dict) or set(signal) != {
            "category",
            "relation",
            "confidence",
            "event_count",
            "first_event",
            "last_event",
        }:
            return False
        category = signal["category"]
        relation = signal["relation"]
        if (
            category not in SIGNAL_CATEGORIES
            or category in categories
            or relation not in {"parent_chain", "same_context"}
            or signal["confidence"]
            != ("observed" if relation == "parent_chain" else "correlated")
            or not is_canonical_uint(signal["event_count"], 64, nonzero=True)
            or not is_signal_event_reference(signal["first_event"])
            or not is_signal_event_reference(signal["last_event"])
            or signal["first_event"]["process_id"] != expected_process_id
            or signal["last_event"]["process_id"] != expected_process_id
        ):
            return False
        categories.add(category)
        has_saturated_count = has_saturated_count or signal["event_count"] == str(
            2**64 - 1
        )
    coverage = value["coverage"]
    return (
        isinstance(coverage, dict)
        and set(coverage)
        == {
            "parent_depth",
            "parent_depth_limit",
            "copied_from_initiator",
            "retention_truncated",
            "parent_depth_limited",
            "count_saturated",
        }
        and isinstance(coverage["parent_depth"], int)
        and not isinstance(coverage["parent_depth"], bool)
        and 0 <= coverage["parent_depth"] <= 32
        and coverage["parent_depth_limit"] == 32
        and all(
            isinstance(coverage[field], bool)
            for field in (
                "copied_from_initiator",
                "retention_truncated",
                "parent_depth_limited",
                "count_saturated",
            )
        )
        and (value["initiator_event"] is not None)
        == coverage["copied_from_initiator"]
        and (not coverage["count_saturated"] or has_saturated_count)
        and (not coverage["parent_depth_limited"] or coverage["parent_depth"] == 32)
    )


def is_artifact(artifact: object) -> bool:
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
    runtime_fields = ("execution_context_id", "capture_origin")
    if any(field in artifact for field in runtime_fields):
        if not all(field in artifact for field in runtime_fields):
            return False
        if (
            not isinstance(artifact["execution_context_id"], str)
            or not CANONICAL_UINT64.fullmatch(artifact["execution_context_id"])
            or int(artifact["execution_context_id"]) >= 2**64
            or artifact["capture_origin"] not in ARTIFACT_CAPTURE_ORIGINS
        ):
            return False
        origin = artifact["capture_origin"]
        if origin == "dynamic_javascript" and (
            artifact.get("kind") != "javascript"
            or artifact["execution_context_id"] == "0"
        ):
            return False
        if origin.startswith("webassembly_") and (
            artifact.get("kind") != "wasm"
            or artifact["execution_context_id"] == "0"
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
    if not isinstance(artifact.get("sha256"), str) or not SHA256.fullmatch(
        artifact["sha256"]
    ):
        return False
    if not isinstance(artifact.get("sensitive"), bool):
        return False
    if artifact.get("content_path") != f"blobs/{artifact['sha256']}.bin":
        return False
    return artifact["sensitive"] == (artifact["kind"] == "response_body")
