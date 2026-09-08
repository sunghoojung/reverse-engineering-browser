from __future__ import annotations

import json
import math
from typing import Any, Optional

from debugger.errors import (
    DebuggerBridgeError,
    ProtocolError,
)
from debugger.limits import (
    LIVE_OBJECT_SEARCH_TIMEOUT_MS,
    MAX_HEAP_SNAPSHOT_BYTES,
    MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
    MAX_LIVE_OBJECT_QUERY_BYTES,
    MAX_LIVE_OBJECT_RESULTS,
    MAX_LIVE_OBJECT_SCAN,
    MAX_LIVE_OBJECT_SEARCH_PROPERTIES,
    MAX_LIVE_OBJECT_SHAPE_BYTES,
    MAX_OBJECT_EXPERIMENT_STRING_BYTES,
    MAX_OBJECT_EXPERIMENT_VALUE_BYTES,
    MAX_OBJECT_EXPERIMENT_VALUE_DEPTH,
    MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES,
)
from debugger.validation import (
    is_finite_protocol_number,
    truncate_text,
)


def live_object_search_criteria(
    request: dict[str, Any]
) -> dict[str, Any]:
    property_query = optional_search_text(request, "property_query")
    value_query = optional_search_text(request, "value_query")
    class_query = optional_search_text(request, "class_query")
    regex = request.get("regex", False)
    case_sensitive = request.get("case_sensitive", False)
    include_shape_values = request.get("include_shape_values", False)
    if not all(
        isinstance(value, bool)
        for value in (regex, case_sensitive, include_shape_values)
    ):
        raise DebuggerBridgeError("Live object search options must be boolean")

    shape_text = request.get("shape", "")
    if not isinstance(shape_text, str):
        raise DebuggerBridgeError("Live object shape must be JSON text")
    if len(shape_text.encode("utf-8")) > MAX_LIVE_OBJECT_SHAPE_BYTES:
        raise DebuggerBridgeError("Live object shape exceeds the 4 KiB limit")
    shape: Optional[Any] = None
    if shape_text.strip():
        try:
            shape = json.loads(shape_text)
        except json.JSONDecodeError as exception:
            raise DebuggerBridgeError(
                "Live object shape must be valid JSON"
            ) from exception
        if not isinstance(shape, (dict, list)):
            raise DebuggerBridgeError("Live object shape must be an object or array")

    threshold = request.get("similarity_threshold", 0.75)
    if (
        not is_finite_protocol_number(threshold)
        or isinstance(threshold, bool)
        or threshold < 0
        or threshold > 1
    ):
        raise DebuggerBridgeError(
            "Live object similarity threshold must be between 0 and 1"
        )
    if not any((property_query, value_query, class_query, shape is not None)):
        raise DebuggerBridgeError("Live object search requires at least one criterion")

    return {
        "propertyQuery": property_query,
        "valueQuery": value_query,
        "classQuery": class_query,
        "regex": regex,
        "caseSensitive": case_sensitive,
        "shape": shape,
        "includeShapeValues": include_shape_values,
        "similarityThreshold": float(threshold),
        "resultLimit": MAX_LIVE_OBJECT_RESULTS,
        "scanLimit": MAX_LIVE_OBJECT_SCAN,
        "previewProperties": MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
        "propertyScanLimit": MAX_LIVE_OBJECT_SEARCH_PROPERTIES,
        "timeoutMs": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
    }


def optional_search_text(request: dict[str, Any], field: str) -> str:
    value = request.get(field, "")
    if not isinstance(value, str):
        raise DebuggerBridgeError("Live object search criteria must be text")
    if len(value.encode("utf-8")) > MAX_LIVE_OBJECT_QUERY_BYTES:
        raise DebuggerBridgeError("Live object search criterion exceeds 512 bytes")
    return value


def normalize_object_experiment_value(
    value: Any
) -> tuple[Any, bytes]:
    entries = 0

    def validate(candidate: Any, depth: int) -> None:
        nonlocal entries
        if depth > MAX_OBJECT_EXPERIMENT_VALUE_DEPTH:
            raise DebuggerBridgeError("Object Lab JSON value exceeds depth 8")
        if candidate is None or isinstance(candidate, bool):
            return
        if isinstance(candidate, int):
            if abs(candidate) > 2**53 - 1:
                raise DebuggerBridgeError(
                    "Object Lab integer exceeds JavaScript's exact range"
                )
            return
        if isinstance(candidate, float):
            if not math.isfinite(candidate):
                raise DebuggerBridgeError("Object Lab number must be finite")
            return
        if isinstance(candidate, str):
            if len(candidate.encode("utf-8")) > MAX_OBJECT_EXPERIMENT_STRING_BYTES:
                raise DebuggerBridgeError("Object Lab JSON string exceeds 4 KiB")
            return
        if isinstance(candidate, list):
            entries += len(candidate)
            if entries > MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES:
                raise DebuggerBridgeError("Object Lab JSON value exceeds 256 entries")
            for item in candidate:
                validate(item, depth + 1)
            return
        if isinstance(candidate, dict):
            entries += len(candidate)
            if entries > MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES:
                raise DebuggerBridgeError("Object Lab JSON value exceeds 256 entries")
            for key, item in candidate.items():
                if (
                    not isinstance(key, str)
                    or len(key.encode("utf-8"))
                    > MAX_OBJECT_EXPERIMENT_STRING_BYTES
                ):
                    raise DebuggerBridgeError(
                        "Object Lab JSON object key exceeds 4 KiB"
                    )
                validate(item, depth + 1)
            return
        raise DebuggerBridgeError("Object Lab set value must be JSON data")

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
        raise DebuggerBridgeError("Object Lab set value must be valid JSON") from exception
    if len(canonical) > MAX_OBJECT_EXPERIMENT_VALUE_BYTES:
        raise DebuggerBridgeError("Object Lab JSON value exceeds 16 KiB")
    return value, canonical


def empty_object_experiment_descriptor(value_type: str) -> dict[str, Any]:
    return {
        "exists": False,
        "type": value_type,
        "class_name": "",
        "writable": False,
        "configurable": False,
        "preview": None,
    }


def normalize_object_experiment_descriptor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError("Object Lab returned a malformed property descriptor")
    exists = value.get("exists")
    value_type = value.get("type")
    class_name = value.get("className", "")
    writable = value.get("writable")
    configurable = value.get("configurable")
    preview = value.get("preview")
    if (
        not isinstance(exists, bool)
        or not isinstance(value_type, str)
        or not value_type
        or len(value_type.encode("utf-8")) > 128
        or not isinstance(class_name, str)
        or len(class_name.encode("utf-8")) > 256
        or not isinstance(writable, bool)
        or not isinstance(configurable, bool)
        or (preview is not None and not isinstance(preview, str))
    ):
        raise ProtocolError("Object Lab returned an invalid property descriptor")
    return {
        "exists": exists,
        "type": value_type,
        "class_name": class_name,
        "writable": writable,
        "configurable": configurable,
        "preview": truncate_text(preview, 512)
        if isinstance(preview, str)
        else None,
    }


def normalize_heap_snapshot_probe(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("protocol_version") != 1:
        raise ProtocolError("Native heap snapshot probe returned malformed output")
    integer_fields = (
        "file_bytes",
        "total_nodes",
        "analyzed_nodes",
        "reachable_nodes",
        "total_edges",
        "indexed_edges",
        "total_strings",
        "duration_ms",
    )
    if any(
        not isinstance(value.get(field), int)
        or isinstance(value.get(field), bool)
        or value[field] < 0
        or value[field] > 2**53 - 1
        for field in integer_fields
    ):
        raise ProtocolError("Native heap snapshot probe returned invalid counts")
    boolean_fields = (
        "match_found",
        "reachability_indexed",
        "node_limit_reached",
        "edge_limit_reached",
        "string_limit_reached",
    )
    if any(not isinstance(value.get(field), bool) for field in boolean_fields):
        raise ProtocolError("Native heap snapshot probe returned invalid limits")
    scope = value.get("scope")
    if (
        scope not in {"all", "reachable", "unreachable"}
        or value["file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
        or value["analyzed_nodes"] > value["total_nodes"]
        or value["reachable_nodes"] > value["total_nodes"]
        or value["indexed_edges"] > value["total_edges"]
        or (value["match_found"] and value["analyzed_nodes"] == 0)
        or (
            not value["match_found"]
            and not value["node_limit_reached"]
            and value["analyzed_nodes"] != value["total_nodes"]
        )
        or (
            scope == "all"
            and (
                value["reachability_indexed"]
                or value["reachable_nodes"] != 0
                or value["indexed_edges"] != 0
            )
        )
        or (scope != "all" and not value["reachability_indexed"])
    ):
        raise ProtocolError("Native heap snapshot probe returned invalid coverage")
    raw_match = value.get("match")
    if value["match_found"] != isinstance(raw_match, dict):
        raise ProtocolError("Native heap snapshot probe returned a malformed match")
    match = None
    if isinstance(raw_match, dict):
        match_id = raw_match.get("id")
        self_size = raw_match.get("self_size")
        if (
            not isinstance(match_id, str)
            or not match_id.isascii()
            or not match_id.isdigit()
            or (len(match_id) > 1 and match_id.startswith("0"))
            or len(match_id) > 20
            or not isinstance(raw_match.get("type"), str)
            or not isinstance(raw_match.get("name"), str)
            or not isinstance(self_size, int)
            or isinstance(self_size, bool)
            or self_size < 0
            or self_size > 2**53 - 1
        ):
            raise ProtocolError("Native heap snapshot probe returned a malformed match")
        match = {
            "id": match_id,
            "type": truncate_text(raw_match["type"], 64),
            "name": truncate_text(raw_match["name"], 256),
            "self_size": self_size,
        }
    return {
        "protocol_version": 1,
        **{field: value[field] for field in integer_fields},
        **{field: value[field] for field in boolean_fields},
        "scope": scope,
        "match": match,
    }
