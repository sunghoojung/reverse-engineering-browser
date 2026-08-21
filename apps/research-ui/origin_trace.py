from __future__ import annotations

from collections import defaultdict
from typing import Optional


class OriginTraceError(ValueError):
    pass


TRACE_CONTRACT_VERSION = 1
MAX_TRACE_STEPS = 32
UINT64_MAX = 2**64 - 1
UINT32_MAX = 2**32 - 1
RELATION_PRIORITY = {
    "parent_event": 0,
    "request_initiator": 1,
    "request_lifecycle": 2,
    "artifact_request": 3,
}
SOURCE_BOUNDARY_CATEGORIES = {
    "canvas",
    "webgl",
    "web_audio",
    "navigator",
    "permissions",
    "storage",
    "webrtc",
}


def _canonical_unsigned(value: object, maximum: int, field: str) -> str:
    if not isinstance(value, str) or not value or (
        value != "0" and (value.startswith("0") or not value.isdecimal())
    ):
        raise OriginTraceError(f"{field} must be a canonical unsigned integer")
    parsed = int(value)
    if parsed > maximum:
        raise OriginTraceError(f"{field} exceeds its integer range")
    return value


def _uint32(value: object, field: str) -> int:
    if type(value) is not int or value < 0 or value > UINT32_MAX:
        raise OriginTraceError(f"{field} must be an unsigned 32-bit integer")
    return value


def _canonical_nonzero(value: object, maximum: int, field: str) -> str:
    result = _canonical_unsigned(value, maximum, field)
    if result == "0":
        raise OriginTraceError(f"{field} must be nonzero")
    return result


def event_reference(event: object) -> tuple[str, int, str]:
    if not isinstance(event, dict):
        raise OriginTraceError("Origin trace input contains a malformed event")
    return (
        _canonical_nonzero(event.get("session_id"), UINT64_MAX, "session_id"),
        _uint32(event.get("process_id"), "process_id"),
        _canonical_nonzero(
            event.get("sequence_number"), UINT64_MAX, "sequence_number"
        ),
    )


def is_origin_trace_edge(edge: object) -> bool:
    if not isinstance(edge, dict) or set(edge) != {
        "protocol_version",
        "session_id",
        "from_process_id",
        "from_sequence_number",
        "to_process_id",
        "to_sequence_number",
        "relation",
        "confidence",
        "request_id",
        "artifact_id",
    }:
        return False
    try:
        session_id = _canonical_nonzero(
            edge.get("session_id"), UINT64_MAX, "session_id"
        )
        from_process = _uint32(edge.get("from_process_id"), "from_process_id")
        from_sequence = _canonical_nonzero(
            edge.get("from_sequence_number"), UINT64_MAX, "from_sequence_number"
        )
        to_process = _uint32(edge.get("to_process_id"), "to_process_id")
        to_sequence = _canonical_nonzero(
            edge.get("to_sequence_number"), UINT64_MAX, "to_sequence_number"
        )
        _canonical_unsigned(edge.get("request_id"), UINT64_MAX, "request_id")
        _canonical_unsigned(edge.get("artifact_id"), UINT64_MAX, "artifact_id")
    except OriginTraceError:
        return False
    return (
        type(edge.get("protocol_version")) is int
        and edge["protocol_version"] == TRACE_CONTRACT_VERSION
        and edge.get("relation") in RELATION_PRIORITY
        and edge.get("confidence") in {"observed", "correlated"}
        and (session_id, from_process, from_sequence)
        != (session_id, to_process, to_sequence)
    )


def _edge_references(edge: dict) -> tuple[tuple[str, int, str], tuple[str, int, str]]:
    session_id = edge["session_id"]
    return (
        (session_id, edge["from_process_id"], edge["from_sequence_number"]),
        (session_id, edge["to_process_id"], edge["to_sequence_number"]),
    )


def _decode_payload(event: dict) -> str:
    payload = event.get("payload")
    if not isinstance(payload, str) or len(payload) % 2 != 0:
        return ""
    try:
        decoded = bytes.fromhex(payload).decode("utf-8", errors="replace")
    except ValueError:
        return ""
    return decoded[:256]


def _event_step(event: dict, relation: str, confidence: str) -> dict:
    session_id, process_id, sequence_number = event_reference(event)
    return {
        "event": {
            "session_id": session_id,
            "process_id": process_id,
            "sequence_number": sequence_number,
        },
        "monotonic_time_ns": _canonical_unsigned(
            event.get("monotonic_time_ns"), UINT64_MAX, "monotonic_time_ns"
        ),
        "category": str(event.get("category", "unknown")),
        "operation": str(event.get("type", "unknown")),
        "frame_id": _canonical_unsigned(
            event.get("frame_id"), UINT64_MAX, "frame_id"
        ),
        "artifact_id": _canonical_unsigned(
            event.get("artifact_id"), UINT64_MAX, "artifact_id"
        ),
        "request_id": _canonical_unsigned(
            event.get("request_id"), UINT64_MAX, "request_id"
        ),
        "relation": relation,
        "confidence": confidence,
        "value": _decode_payload(event),
    }


def _root_event(
    events: list[dict],
    request_id: str,
    root_process_id: Optional[int],
    root_sequence_number: Optional[str],
) -> tuple[Optional[dict], bool]:
    candidates = [
        event
        for event in events
        if event.get("category") == "network"
        and event.get("request_id") == request_id
    ]
    if root_process_id is not None and root_sequence_number is not None:
        exact = [
            event
            for event in candidates
            if event.get("process_id") == root_process_id
            and event.get("sequence_number") == root_sequence_number
        ]
        if len(exact) != 1:
            return None, False
        return exact[0], False

    preferred = [
        event for event in candidates if event.get("type") == "request_started"
    ]
    if not preferred:
        preferred = [
            event for event in candidates if event.get("type") == "request_initiated"
        ]
    if not preferred:
        preferred = candidates
    if not preferred:
        return None, False
    if len(preferred) > 1:
        return None, True
    return preferred[0], False


def _gap(reason: str, after_step: int, detail: str) -> dict:
    return {"reason": reason, "after_step": after_step, "detail": detail}


def build_origin_trace(
    events: list[dict],
    edges: list[dict],
    artifacts: list[dict],
    request_id: str,
    *,
    root_process_id: Optional[int] = None,
    root_sequence_number: Optional[str] = None,
    max_steps: int = MAX_TRACE_STEPS,
) -> dict:
    request_id = _canonical_unsigned(request_id, UINT64_MAX, "request_id")
    if (root_process_id is None) != (root_sequence_number is None):
        raise OriginTraceError(
            "root_process_id and root_sequence_number must be supplied together"
        )
    if root_process_id is not None:
        _uint32(root_process_id, "root_process_id")
        root_sequence_number = _canonical_unsigned(
            root_sequence_number, UINT64_MAX, "root_sequence_number"
        )
    if max_steps < 1 or max_steps > MAX_TRACE_STEPS:
        raise OriginTraceError("max_steps is outside the supported range")

    events_by_reference: dict[tuple[str, int, str], dict] = {}
    for event in events:
        reference = event_reference(event)
        if reference in events_by_reference:
            raise OriginTraceError("Origin trace input contains a duplicate event reference")
        events_by_reference[reference] = event

    edges_by_source: dict[tuple[str, int, str], list[dict]] = defaultdict(list)
    for edge in edges:
        if not is_origin_trace_edge(edge):
            raise OriginTraceError("Origin trace store contains a malformed edge")
        source, _ = _edge_references(edge)
        edges_by_source[source].append(edge)

    root, ambiguous = _root_event(
        events, request_id, root_process_id, root_sequence_number
    )
    if ambiguous:
        return {
            "contract_version": TRACE_CONTRACT_VERSION,
            "document_kind": "origin-trace",
            "request_id": request_id,
            "status": "ambiguous",
            "steps": [],
            "gaps": [
                _gap(
                    "ambiguous_request",
                    0,
                    "More than one request start uses this identifier. Select a concrete request row.",
                )
            ],
            "coverage": {
                "linked_steps": 0,
                "observed_links": 0,
                "correlated_links": 0,
                "gap_count": 1,
                "percent": 0,
            },
            "artifacts": [],
        }
    if root is None:
        return {
            "contract_version": TRACE_CONTRACT_VERSION,
            "document_kind": "origin-trace",
            "request_id": request_id,
            "status": "empty",
            "steps": [],
            "gaps": [],
            "coverage": {
                "linked_steps": 0,
                "observed_links": 0,
                "correlated_links": 0,
                "gap_count": 0,
                "percent": 0,
            },
            "artifacts": [],
        }

    steps = [_event_step(root, "trace_target", "observed")]
    gaps: list[dict] = []
    visited = {event_reference(root)}
    current = root
    observed_links = 0
    correlated_links = 0

    while len(steps) < max_steps:
        current_reference = event_reference(current)
        candidates = sorted(
            edges_by_source.get(current_reference, []),
            key=lambda edge: (
                RELATION_PRIORITY[edge["relation"]],
                -int(edge["to_sequence_number"]),
            ),
        )
        selected_edge = None
        selected_event = None
        missing_target = False
        for edge in candidates:
            _, target = _edge_references(edge)
            target_event = events_by_reference.get(target)
            if target_event is None:
                missing_target = True
                continue
            selected_edge = edge
            selected_event = target_event
            break

        if selected_edge is None or selected_event is None:
            if current.get("category") not in SOURCE_BOUNDARY_CATEGORIES:
                reason = "missing_event" if missing_target else "no_predecessor"
                detail = (
                    "A referenced predecessor is outside the retained evidence window."
                    if missing_target
                    else "No earlier observed relationship reaches this event."
                )
                gaps.append(_gap(reason, len(steps) - 1, detail))
            break

        target_reference = event_reference(selected_event)
        if target_reference in visited:
            gaps.append(
                _gap(
                    "cycle",
                    len(steps) - 1,
                    "The correlation index contains a cycle, so traversal stopped safely.",
                )
            )
            break
        visited.add(target_reference)
        steps.append(
            _event_step(
                selected_event,
                selected_edge["relation"],
                selected_edge["confidence"],
            )
        )
        if selected_edge["confidence"] == "observed":
            observed_links += 1
        else:
            correlated_links += 1
        current = selected_event
    else:
        gaps.append(
            _gap(
                "step_limit",
                len(steps) - 1,
                "The bounded trace step limit was reached.",
            )
        )

    linked_steps = max(0, len(steps) - 1)
    denominator = linked_steps + len(gaps)
    percent = round(linked_steps * 100 / denominator) if denominator else 0
    artifact_ids = {step["artifact_id"] for step in steps if step["artifact_id"] != "0"}
    public_artifacts = [
        {
            key: value
            for key, value in artifact.items()
            if key
            in {
                "artifact_id",
                "kind",
                "url",
                "sha256",
                "byte_size",
                "creator_event_id",
                "parent_artifact_id",
            }
        }
        for artifact in artifacts
        if artifact.get("artifact_id") in artifact_ids
    ]
    document = {
        "contract_version": TRACE_CONTRACT_VERSION,
        "document_kind": "origin-trace",
        "request_id": request_id,
        "status": "complete" if not gaps else "partial",
        "steps": steps,
        "gaps": gaps,
        "coverage": {
            "linked_steps": linked_steps,
            "observed_links": observed_links,
            "correlated_links": correlated_links,
            "gap_count": len(gaps),
            "percent": percent,
        },
        "artifacts": public_artifacts,
    }
    verify_origin_trace_document(document)
    return document


def verify_origin_trace_document(document: object) -> None:
    if not isinstance(document, dict) or set(document) != {
        "contract_version",
        "document_kind",
        "request_id",
        "status",
        "steps",
        "gaps",
        "coverage",
        "artifacts",
    }:
        raise OriginTraceError("Origin trace document has an invalid shape")
    if (
        type(document.get("contract_version")) is not int
        or document["contract_version"] != TRACE_CONTRACT_VERSION
        or document.get("document_kind") != "origin-trace"
        or document.get("status")
        not in {"complete", "partial", "empty", "ambiguous"}
    ):
        raise OriginTraceError("Origin trace document has invalid metadata")
    _canonical_unsigned(document.get("request_id"), UINT64_MAX, "request_id")
    if not isinstance(document.get("steps"), list) or len(document["steps"]) > MAX_TRACE_STEPS:
        raise OriginTraceError("Origin trace document has invalid steps")
    if not isinstance(document.get("gaps"), list) or not isinstance(
        document.get("artifacts"), list
    ):
        raise OriginTraceError("Origin trace document has invalid collections")
    coverage = document.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != {
        "linked_steps",
        "observed_links",
        "correlated_links",
        "gap_count",
        "percent",
    }:
        raise OriginTraceError("Origin trace document has invalid coverage")
    for field in coverage:
        value = coverage[field]
        maximum = 100 if field == "percent" else MAX_TRACE_STEPS
        if type(value) is not int or value < 0 or value > maximum:
            raise OriginTraceError("Origin trace coverage is outside its range")
    if coverage["linked_steps"] != max(0, len(document["steps"]) - 1):
        raise OriginTraceError("Origin trace linked-step coverage does not match its steps")
    if coverage["gap_count"] != len(document["gaps"]):
        raise OriginTraceError("Origin trace gap coverage does not match its gaps")
