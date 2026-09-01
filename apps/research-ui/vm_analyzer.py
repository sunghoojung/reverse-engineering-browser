#!/usr/bin/env python3

"""Bounded, deterministic cold-path VM detection for captured artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONTRACT_VERSION = 1
ANALYZER_ID = "origin-trace-vm-detector"
ANALYZER_VERSION = "1.0.0"
PROFILE_ID = "anti-bot-vm-detection-v1"
CANONICAL_UINT64 = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_JS_MATCHES_PER_RULE = 32
MAX_JS_FUNCTION_REGIONS = 4096
MAX_JS_REGION_WORK_BYTES = 64 * 1024 * 1024
MAX_WASM_SECTIONS = 128
MAX_WASM_SECTION_BYTES = 2 * 1024 * 1024
MAX_GRAPH_EDGES = 1024
MAX_BYTECODE_SNAPSHOT_BYTES = 256
MAX_MANIFEST_LINE_BYTES = 64 * 1024
MAX_EVENT_LINE_BYTES = 16 * 1024
MAX_ARTIFACT_RECORDS = 10_000
MAX_EVENT_RECORDS = 100_000
MAX_WASM_FUNCTIONS = 100_000
MAX_WASM_INSTRUCTIONS = 1_000_000
CANDIDATE_THRESHOLD = 20
LIKELY_VM_THRESHOLD = 60
LIKELY_VM_FAMILIES = 3

RULE_WEIGHTS = {
    "js.dispatch-loop": 20,
    "js.instruction-pointer": 20,
    "js.indexed-bytecode-read": 20,
    "js.state-effects": 15,
    "js.handler-selection": 15,
    "js.bounded-exit": 5,
    "wasm.dispatch-loop": 20,
    "wasm.instruction-pointer": 20,
    "wasm.linear-memory": 20,
    "wasm.handler-table": 15,
    "wasm.bytecode-region": 15,
    "wasm.bounded-exit": 5,
}

RULE_FAMILIES = {
    "js.dispatch-loop": "dispatch",
    "js.instruction-pointer": "instruction-pointer",
    "js.indexed-bytecode-read": "bytecode",
    "js.state-effects": "state",
    "js.handler-selection": "handlers",
    "js.bounded-exit": "exits",
    "wasm.dispatch-loop": "dispatch",
    "wasm.instruction-pointer": "instruction-pointer",
    "wasm.linear-memory": "state",
    "wasm.handler-table": "handlers",
    "wasm.bytecode-region": "bytecode",
    "wasm.bounded-exit": "exits",
}

ANTI_BOT_RULES = (
    (
        "antibot.canvas-webgl",
        25,
        re.compile(
            r"\b(?:canvas|getImageData|toDataURL|webgl|readPixels|getParameter)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "antibot.navigator-device",
        25,
        re.compile(
            r"\b(?:navigator|screen|hardwareConcurrency|deviceMemory|platform|timezone|language)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "antibot.automation",
        20,
        re.compile(
            r"\b(?:webdriver|automation|headless|permissions\.query)\b", re.IGNORECASE
        ),
    ),
    (
        "antibot.encoding-crypto",
        15,
        re.compile(
            r"\b(?:crypto|subtle|digest|base64|btoa|encode|hash)\b", re.IGNORECASE
        ),
    ),
    (
        "antibot.request",
        15,
        re.compile(r"\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket)\b", re.IGNORECASE),
    ),
)


class AnalysisError(ValueError):
    """An input could not be analyzed without violating the contract."""


@dataclass(frozen=True)
class Limits:
    max_artifact_bytes: int = MAX_ARTIFACT_BYTES
    max_js_matches_per_rule: int = MAX_JS_MATCHES_PER_RULE
    max_js_function_regions: int = MAX_JS_FUNCTION_REGIONS
    max_js_region_work_bytes: int = MAX_JS_REGION_WORK_BYTES
    max_wasm_sections: int = MAX_WASM_SECTIONS
    max_wasm_section_bytes: int = MAX_WASM_SECTION_BYTES
    max_graph_edges: int = MAX_GRAPH_EDGES
    max_bytecode_snapshot_bytes: int = MAX_BYTECODE_SNAPSHOT_BYTES
    max_manifest_line_bytes: int = MAX_MANIFEST_LINE_BYTES
    max_event_line_bytes: int = MAX_EVENT_LINE_BYTES
    max_artifact_records: int = MAX_ARTIFACT_RECORDS
    max_event_records: int = MAX_EVENT_RECORDS
    max_wasm_functions: int = MAX_WASM_FUNCTIONS
    max_wasm_instructions: int = MAX_WASM_INSTRUCTIONS

    def as_dict(self) -> dict[str, int]:
        return {
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_js_matches_per_rule": self.max_js_matches_per_rule,
            "max_js_function_regions": self.max_js_function_regions,
            "max_js_region_work_bytes": self.max_js_region_work_bytes,
            "max_wasm_sections": self.max_wasm_sections,
            "max_wasm_section_bytes": self.max_wasm_section_bytes,
            "max_graph_edges": self.max_graph_edges,
            "max_bytecode_snapshot_bytes": self.max_bytecode_snapshot_bytes,
            "max_manifest_line_bytes": self.max_manifest_line_bytes,
            "max_event_line_bytes": self.max_event_line_bytes,
            "max_artifact_records": self.max_artifact_records,
            "max_event_records": self.max_event_records,
            "max_wasm_functions": self.max_wasm_functions,
            "max_wasm_instructions": self.max_wasm_instructions,
        }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _finding_id(artifact_digest: str, rule_ids: Iterable[str]) -> str:
    identity = f"{PROFILE_ID}:{artifact_digest}:{','.join(sorted(rule_ids))}".encode()
    return hashlib.sha256(identity).hexdigest()[:24]


def _observation(rule_id: str, start: int, end: int, detail: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "family": RULE_FAMILIES[rule_id],
        "weight": RULE_WEIGHTS[rule_id],
        "coordinate": {"byte_offset": start, "byte_size": max(1, end - start)},
        "detail": detail,
    }


def _find_js_rule(
    source: str,
    rule_id: str,
    patterns: Iterable[re.Pattern[str]],
    detail: str,
    limits: Limits,
) -> dict[str, Any] | None:
    first_match = None
    match_count = 0
    matches_truncated = False
    for pattern in patterns:
        for match in pattern.finditer(source):
            if match_count >= limits.max_js_matches_per_rule:
                matches_truncated = True
                break
            match_count += 1
            if first_match is None or match.start() < first_match.start():
                first_match = match
        if matches_truncated:
            break
    if first_match is None:
        return None
    observation = _observation(rule_id, first_match.start(), first_match.end(), detail)
    observation["match_count"] = match_count
    observation["matches_truncated"] = matches_truncated
    return observation


def _js_region_observations(source: str, limits: Limits) -> list[dict[str, Any]]:
    loop = re.search(r"\b(?:while|for)\s*\(", source)
    dispatch = re.search(r"\bswitch\s*\(|\b[A-Za-z_$][\w$]*\s*\[[^\]]+\]\s*\(", source)
    observations: list[dict[str, Any]] = []
    if loop and dispatch:
        observations.append(
            _observation(
                "js.dispatch-loop",
                min(loop.start(), dispatch.start()),
                max(loop.end(), dispatch.end()),
                "A loop and switch or indexed callable dispatch occur in the same function region.",
            )
        )
    candidates = (
        _find_js_rule(
            source,
            "js.instruction-pointer",
            (
                re.compile(
                    r"\b(?:pc|ip|instructionPointer|offset|cursor)\b\s*(?:\+\+|--|[+\-]?=)"
                ),
            ),
            "A program-counter-like binding is advanced or assigned.",
            limits,
        ),
        _find_js_rule(
            source,
            "js.indexed-bytecode-read",
            (
                re.compile(
                    r"\b(?:program|bytecode|code|instructions|opcodes|bytes)\s*\[[^\]]+\]",
                    re.IGNORECASE,
                ),
                re.compile(r"\b(?:Uint8Array|DataView)\b"),
            ),
            "A byte-oriented candidate guest program is read by index.",
            limits,
        ),
        _find_js_rule(
            source,
            "js.state-effects",
            (
                re.compile(r"\.(?:push|pop|shift|unshift)\s*\("),
                re.compile(
                    r"\b(?:stack|registers?|accumulator|memory)\b\s*(?:\[|[+\-^|&]?=)",
                    re.IGNORECASE,
                ),
            ),
            "Stack, register, accumulator, or memory-like state is mutated.",
            limits,
        ),
        _find_js_rule(
            source,
            "js.handler-selection",
            (
                re.compile(
                    r"\bcase\s+(?:0x[0-9a-f]+|\d+|['\"][^'\"]+['\"])?\s*:",
                    re.IGNORECASE,
                ),
                re.compile(r"\b(?:handlers?|opcodes?)\s*\[[^\]]+\]", re.IGNORECASE),
            ),
            "Opcode cases or an indexed handler collection selects behavior.",
            limits,
        ),
        _find_js_rule(
            source,
            "js.bounded-exit",
            (re.compile(r"\b(?:return|break|throw)\b"),),
            "A dispatch candidate contains an explicit exit or unknown-opcode frontier.",
            limits,
        ),
    )
    observations.extend(item for item in candidates if item is not None)
    return observations


def _mask_js_literals(source: str) -> str:
    masked = list(source)
    index = 0
    quote = ""
    line_comment = False
    block_comment = False
    escaped = False
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
            else:
                masked[index] = " "
        elif block_comment:
            masked[index] = " "
            if character == "*" and following == "/":
                masked[index + 1] = " "
                block_comment = False
                index += 1
        elif quote:
            masked[index] = " "
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character == "/" and following == "/":
            masked[index] = masked[index + 1] = " "
            line_comment = True
            index += 1
        elif character == "/" and following == "*":
            masked[index] = masked[index + 1] = " "
            block_comment = True
            index += 1
        elif character in {'"', "'", "`"}:
            masked[index] = " "
            quote = character
        index += 1
    return "".join(masked)


def _js_function_regions(
    source: str, limits: Limits
) -> tuple[list[tuple[int, int]], list[dict[str, Any]]]:
    masked = _mask_js_literals(source)
    starts = []
    omissions = []
    for match in re.finditer(
        r"(?:\bfunction\b[^{}]*|\([^{}]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*\{",
        masked,
    ):
        if len(starts) >= limits.max_js_function_regions:
            omissions.append(
                {
                    "reason": "javascript-function-region-limit",
                    "observed_records": len(starts),
                }
            )
            break
        starts.append(match.end() - 1)

    openings = set(starts)
    brace_stack: list[int] = []
    regions_by_opening: dict[int, tuple[int, int]] = {}
    for index, character in enumerate(masked):
        if character == "{":
            brace_stack.append(index)
        elif character == "}" and brace_stack:
            opening = brace_stack.pop()
            if opening in openings:
                regions_by_opening[opening] = (opening + 1, index)
    if any(opening not in regions_by_opening for opening in openings):
        raise AnalysisError("unterminated JavaScript function body")
    regions = [regions_by_opening[opening] for opening in starts]
    if not regions:
        return [(0, len(source))], omissions
    return [(0, len(source)), *regions], omissions


def _js_observations(
    source: str, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    regions, omissions = _js_function_regions(source, limits)
    ordered_regions = sorted(regions, key=lambda item: (item[0], -item[1]))
    children: dict[tuple[int, int], list[tuple[int, int]]] = {
        region: [] for region in regions
    }
    region_stack: list[tuple[int, int]] = []
    for region in ordered_regions:
        start, end = region
        while region_stack and start >= region_stack[-1][1]:
            region_stack.pop()
        if region_stack and end <= region_stack[-1][1]:
            children[region_stack[-1]].append(region)
        region_stack.append(region)

    ranked = []
    work_bytes = 0
    evaluation_order = [
        regions[0],
        *sorted(regions[1:], key=lambda item: item[1] - item[0]),
    ]
    for start, end in evaluation_order:
        region_bytes = len(source[start:end].encode("utf-8"))
        if work_bytes + region_bytes > limits.max_js_region_work_bytes:
            omissions.append(
                {
                    "reason": "javascript-region-work-limit",
                    "observed_bytes": work_bytes,
                    "total_bytes": work_bytes + region_bytes,
                }
            )
            break
        work_bytes += region_bytes
        region_source = list(source[start:end])
        for nested_start, nested_end in children[(start, end)]:
            region_source[nested_start - start : nested_end - start] = " " * (
                nested_end - nested_start
            )
        observations = _js_region_observations("".join(region_source), limits)
        for observation in observations:
            observation["coordinate"]["byte_offset"] += start
            observation["function_region"] = {
                "byte_offset": start,
                "byte_size": end - start,
            }
        score = sum(item["weight"] for item in observations)
        family_count = len({item["family"] for item in observations})
        ranked.append((score, family_count, -start, observations))
    observations = max(ranked, default=(0, 0, 0, []))[3]
    for observation in observations:
        coordinate = observation["coordinate"]
        character_start = coordinate["byte_offset"]
        character_end = character_start + coordinate["byte_size"]
        coordinate["byte_offset"] = len(source[:character_start].encode("utf-8"))
        coordinate["byte_size"] = len(
            source[character_start:character_end].encode("utf-8")
        )
        function_region = observation["function_region"]
        function_start = function_region["byte_offset"]
        function_end = function_start + function_region["byte_size"]
        function_region["byte_offset"] = len(source[:function_start].encode("utf-8"))
        function_region["byte_size"] = len(
            source[function_start:function_end].encode("utf-8")
        )
    return observations, omissions


def _read_leb(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if offset >= end:
            raise AnalysisError("truncated unsigned LEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise AnalysisError("oversized unsigned LEB128 value")


def _wasm_sections(data: bytes, limits: Limits) -> list[tuple[int, int, int]]:
    if len(data) < 8 or data[:4] != b"\x00asm" or data[4:8] != b"\x01\x00\x00\x00":
        raise AnalysisError("invalid or unsupported WebAssembly header")
    sections = []
    offset = 8
    while offset < len(data):
        if len(sections) >= limits.max_wasm_sections:
            raise AnalysisError("WebAssembly section count limit reached")
        section_id = data[offset]
        offset += 1
        size, offset = _read_leb(data, offset, len(data))
        if size > limits.max_wasm_section_bytes:
            raise AnalysisError("WebAssembly section byte limit reached")
        end = offset + size
        if end > len(data):
            raise AnalysisError("truncated WebAssembly section")
        sections.append((section_id, offset, end))
        offset = end
    return sections


def _read_signed_leb(
    data: bytes, offset: int, end: int, max_bytes: int
) -> tuple[int, int]:
    value = 0
    shift = 0
    byte = 0
    for _ in range(max_bytes):
        if offset >= end:
            raise AnalysisError("truncated signed LEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            if shift < max_bytes * 7 and byte & 0x40:
                value |= -(1 << shift)
            return value, offset
    raise AnalysisError("oversized signed LEB128 value")


def _skip_wasm_immediate(
    data: bytes, offset: int, end: int, opcode: int
) -> tuple[int, list[int]]:
    operands = []
    if opcode in {0x02, 0x03, 0x04}:
        if offset >= end:
            raise AnalysisError("truncated WebAssembly block type")
        if data[offset] in {0x40, 0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F}:
            return offset + 1, operands
        _, offset = _read_signed_leb(data, offset, end, 5)
    elif opcode in {
        0x0C,
        0x0D,
        0x10,
        0x12,
        0x14,
        0x20,
        0x21,
        0x22,
        0x23,
        0x24,
        0x25,
        0x26,
    }:
        value, offset = _read_leb(data, offset, end)
        operands.append(value)
    elif opcode == 0x0E:
        count, offset = _read_leb(data, offset, end)
        if count > 1_000_000:
            raise AnalysisError("WebAssembly br_table target limit reached")
        for _ in range(count + 1):
            value, offset = _read_leb(data, offset, end)
            operands.append(value)
    elif opcode == 0x11:
        type_index, offset = _read_leb(data, offset, end)
        table_index, offset = _read_leb(data, offset, end)
        operands.extend((type_index, table_index))
    elif opcode == 0x1C:
        count, offset = _read_leb(data, offset, end)
        if count > 16 or offset + count > end:
            raise AnalysisError("invalid typed select immediate")
        offset += count
    elif 0x28 <= opcode <= 0x3E:
        alignment, offset = _read_leb(data, offset, end)
        memory_offset, offset = _read_leb(data, offset, end)
        operands.extend((alignment, memory_offset))
    elif opcode in {0x3F, 0x40}:
        memory_index, offset = _read_leb(data, offset, end)
        operands.append(memory_index)
    elif opcode == 0x41:
        value, offset = _read_signed_leb(data, offset, end, 5)
        operands.append(value)
    elif opcode == 0x42:
        value, offset = _read_signed_leb(data, offset, end, 10)
        operands.append(value)
    elif opcode == 0x43:
        offset += 4
    elif opcode == 0x44:
        offset += 8
    elif opcode == 0xD0:
        value, offset = _read_signed_leb(data, offset, end, 5)
        operands.append(value)
    elif opcode == 0xD2:
        value, offset = _read_leb(data, offset, end)
        operands.append(value)
    elif opcode == 0xFC:
        subopcode, offset = _read_leb(data, offset, end)
        operands.append(subopcode)
        extra_count = {
            8: 2,
            9: 1,
            10: 2,
            11: 1,
            12: 2,
            13: 1,
            14: 2,
            15: 1,
            16: 1,
            17: 1,
        }.get(subopcode, 0)
        if subopcode > 17:
            raise AnalysisError(f"unsupported WebAssembly 0xfc subopcode {subopcode}")
        for _ in range(extra_count):
            value, offset = _read_leb(data, offset, end)
            operands.append(value)
    elif opcode in {0xFB, 0xFD, 0xFE}:
        raise AnalysisError(f"unsupported WebAssembly prefixed opcode 0x{opcode:02x}")
    elif not (
        opcode in {0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B, 0xD1, 0xD3}
        or 0x45 <= opcode <= 0xC4
    ):
        raise AnalysisError(f"unsupported WebAssembly opcode 0x{opcode:02x}")
    if offset > end:
        raise AnalysisError("truncated WebAssembly instruction immediate")
    return offset, operands


def _decode_wasm_functions(
    data: bytes,
    code_range: tuple[int, int],
    limits: Limits,
    function_index_base: int,
    expected_function_count: int,
) -> list[dict[str, Any]]:
    offset, section_end = code_range
    function_count, offset = _read_leb(data, offset, section_end)
    if function_count != expected_function_count:
        raise AnalysisError("WebAssembly function and code section counts differ")
    if function_count > limits.max_wasm_functions:
        raise AnalysisError("WebAssembly function count limit reached")
    functions = []
    instruction_count = 0
    for function_index in range(function_count):
        body_size, offset = _read_leb(data, offset, section_end)
        body_start = offset
        body_end = body_start + body_size
        if body_end > section_end:
            raise AnalysisError("truncated WebAssembly function body")
        local_group_count, offset = _read_leb(data, offset, body_end)
        if local_group_count > 1_000_000:
            raise AnalysisError("WebAssembly local group limit reached")
        for _ in range(local_group_count):
            _, offset = _read_leb(data, offset, body_end)
            if offset >= body_end:
                raise AnalysisError("truncated WebAssembly local declaration")
            offset += 1
        control_stack: list[int] = []
        instructions = []
        function_ended = False
        while offset < body_end:
            instruction_count += 1
            if instruction_count > limits.max_wasm_instructions:
                raise AnalysisError("WebAssembly instruction count limit reached")
            instruction_offset = offset
            opcode = data[offset]
            offset += 1
            loop_depth = control_stack.count(0x03)
            offset, operands = _skip_wasm_immediate(data, offset, body_end, opcode)
            instructions.append(
                {
                    "opcode": opcode,
                    "offset": instruction_offset,
                    "end": offset,
                    "operands": operands,
                    "loop_depth": loop_depth,
                }
            )
            if opcode in {0x02, 0x03, 0x04}:
                control_stack.append(opcode)
            elif opcode == 0x05:
                if not control_stack or control_stack[-1] != 0x04:
                    raise AnalysisError("WebAssembly else without matching if")
            elif opcode == 0x0B:
                if control_stack:
                    control_stack.pop()
                else:
                    function_ended = True
                    break
        if not function_ended or offset != body_end:
            raise AnalysisError("WebAssembly function body has an invalid end")
        functions.append(
            {
                "function_index": function_index_base + function_index,
                "body_start": body_start,
                "body_end": body_end,
                "instructions": instructions,
            }
        )
    if offset != section_end:
        raise AnalysisError("WebAssembly code section has trailing bytes")
    return functions


def _skip_wasm_name(data: bytes, offset: int, end: int) -> int:
    size, offset = _read_leb(data, offset, end)
    if offset + size > end:
        raise AnalysisError("truncated WebAssembly import name")
    return offset + size


def _skip_wasm_limits(data: bytes, offset: int, end: int) -> int:
    flags, offset = _read_leb(data, offset, end)
    if flags & ~0x03:
        raise AnalysisError("unsupported WebAssembly limits flags")
    _, offset = _read_leb(data, offset, end)
    if flags & 0x01:
        _, offset = _read_leb(data, offset, end)
    return offset


def _wasm_imported_function_count(
    data: bytes, import_range: tuple[int, int] | None
) -> int:
    if import_range is None:
        return 0
    offset, end = import_range
    import_count, offset = _read_leb(data, offset, end)
    function_count = 0
    for _ in range(import_count):
        offset = _skip_wasm_name(data, offset, end)
        offset = _skip_wasm_name(data, offset, end)
        if offset >= end:
            raise AnalysisError("truncated WebAssembly import descriptor")
        kind = data[offset]
        offset += 1
        if kind == 0:
            _, offset = _read_leb(data, offset, end)
            function_count += 1
        elif kind == 1:
            if offset >= end:
                raise AnalysisError("truncated WebAssembly table import")
            offset = _skip_wasm_limits(data, offset + 1, end)
        elif kind == 2:
            offset = _skip_wasm_limits(data, offset, end)
        elif kind == 3:
            if offset + 2 > end:
                raise AnalysisError("truncated WebAssembly global import")
            offset += 2
        elif kind == 4:
            if offset >= end:
                raise AnalysisError("truncated WebAssembly tag import")
            _, offset = _read_leb(data, offset + 1, end)
        else:
            raise AnalysisError(f"unsupported WebAssembly import kind {kind}")
    if offset != end:
        raise AnalysisError("WebAssembly import section has trailing bytes")
    return function_count


def _wasm_defined_function_count(
    data: bytes, function_range: tuple[int, int] | None
) -> int:
    if function_range is None:
        return 0
    offset, end = function_range
    count, offset = _read_leb(data, offset, end)
    for _ in range(count):
        _, offset = _read_leb(data, offset, end)
    if offset != end:
        raise AnalysisError("WebAssembly function section has trailing bytes")
    return count


def _instruction(function: dict[str, Any], opcodes: set[int]) -> dict[str, Any] | None:
    return next(
        (item for item in function["instructions"] if item["opcode"] in opcodes), None
    )


def _wasm_function_observations(function: dict[str, Any]) -> list[dict[str, Any]]:
    instructions = function["instructions"]
    dispatch = next(
        (
            item
            for item in instructions
            if item["opcode"] in {0x0E, 0x11} and item["loop_depth"] > 0
        ),
        None,
    )
    observations = []
    if dispatch:
        loop = next(
            item
            for item in instructions
            if item["opcode"] == 0x03 and item["offset"] < dispatch["offset"]
        )
        observations.append(
            _observation(
                "wasm.dispatch-loop",
                loop["offset"],
                dispatch["end"],
                "Decoded br_table or call_indirect dispatch occurs inside a loop.",
            )
        )
    reads = {
        item["operands"][0]
        for item in instructions
        if item["opcode"] in {0x20, 0x23} and item["operands"]
    }
    writes = {
        item["operands"][0]
        for item in instructions
        if item["opcode"] in {0x21, 0x22, 0x24} and item["operands"]
    }
    arithmetic = _instruction(function, {0x6A, 0x6B, 0x7C, 0x7D})
    if reads & writes and arithmetic:
        variable = next(iter(reads & writes))
        first = next(
            item
            for item in instructions
            if item["opcode"] in {0x20, 0x23} and item["operands"][0] == variable
        )
        observations.append(
            _observation(
                "wasm.instruction-pointer",
                first["offset"],
                arithmetic["end"],
                "The same decoded local or global is read, advanced, and written.",
            )
        )
    memory = _instruction(function, set(range(0x28, 0x3F)))
    if memory:
        observations.append(
            _observation(
                "wasm.linear-memory",
                memory["offset"],
                memory["end"],
                "A decoded load or store accesses linear memory.",
            )
        )
    indirect = _instruction(function, {0x11})
    if indirect:
        observations.append(
            _observation(
                "wasm.handler-table",
                indirect["offset"],
                indirect["end"],
                "A decoded call_indirect selects a function-table entry.",
            )
        )
    exit_instruction = _instruction(function, {0x00, 0x0F})
    if exit_instruction:
        observations.append(
            _observation(
                "wasm.bounded-exit",
                exit_instruction["offset"],
                exit_instruction["end"],
                "A decoded return or trap bounds a candidate path.",
            )
        )
    for observation in observations:
        observation["coordinate"].update(
            {
                "function_index": function["function_index"],
                "function_body_offset": function["body_start"],
                "function_body_size": function["body_end"] - function["body_start"],
            }
        )
    return observations


def _wasm_observations(
    data: bytes, limits: Limits
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sections = _wasm_sections(data, limits)
    code_ranges = [
        (start, end) for section_id, start, end in sections if section_id == 10
    ]
    import_ranges = [
        (start, end) for section_id, start, end in sections if section_id == 2
    ]
    function_ranges = [
        (start, end) for section_id, start, end in sections if section_id == 3
    ]
    data_ranges = [
        (start, end) for section_id, start, end in sections if section_id == 11
    ]
    table_ranges = [
        (start, end) for section_id, start, end in sections if section_id in {4, 9}
    ]
    if len(code_ranges) > 1 or len(import_ranges) > 1 or len(function_ranges) > 1:
        raise AnalysisError("WebAssembly contains a duplicate structural section")
    imported_function_count = _wasm_imported_function_count(
        data, import_ranges[0] if import_ranges else None
    )
    defined_function_count = _wasm_defined_function_count(
        data, function_ranges[0] if function_ranges else None
    )
    functions = (
        _decode_wasm_functions(
            data,
            code_ranges[0],
            limits,
            imported_function_count,
            defined_function_count,
        )
        if code_ranges
        else []
    )
    ranked = []
    for function in functions:
        function_observations = _wasm_function_observations(function)
        ranked.append(
            (
                sum(item["weight"] for item in function_observations),
                len({item["family"] for item in function_observations}),
                -function["function_index"],
                function_observations,
            )
        )
    observations = max(ranked, default=(0, 0, 0, []))[3]
    if table_ranges and not any(
        item["rule_id"] == "wasm.handler-table" for item in observations
    ):
        start, _ = table_ranges[0]
        observations.append(
            _observation(
                "wasm.handler-table",
                start,
                start + 1,
                "A table or element section is present without decoded indirect dispatch.",
            )
        )
    if data_ranges:
        start, end = data_ranges[0]
        observations.append(
            _observation(
                "wasm.bytecode-region",
                start,
                min(end, start + 16),
                "A data section can supply candidate guest bytes.",
            )
        )
    return observations, {
        "section_count": len(sections),
        "code_section_count": len(code_ranges),
        "data_section_count": len(data_ranges),
        "decoded_function_count": len(functions),
        "imported_function_count": imported_function_count,
        "decoded_instruction_count": sum(
            len(item["instructions"]) for item in functions
        ),
    }


def _anti_bot_observations(source: str) -> list[dict[str, Any]]:
    observations = []
    for rule_id, weight, pattern in ANTI_BOT_RULES:
        match = pattern.search(source)
        if match:
            observations.append(
                {
                    "rule_id": rule_id,
                    "weight": weight,
                    "coordinate": {
                        "byte_offset": match.start(),
                        "byte_size": match.end() - match.start(),
                    },
                    "detail": "Static anti-bot relevance signal. It does not establish VM structure.",
                }
            )
    return observations


def _runtime_anti_bot_observations(
    artifact: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    families = {
        "canvas": ("antibot.runtime-canvas-webgl", 25),
        "webgl": ("antibot.runtime-canvas-webgl", 25),
        "navigator": ("antibot.runtime-navigator-device", 25),
    }
    observations = []
    seen = set()
    for event in events:
        rule = families.get(str(event.get("category")))
        if rule is None or rule[0] in seen:
            continue
        if (
            str(event.get("session_id")) != artifact["session_id"]
            or str(event.get("navigation_id")) != artifact["navigation_id"]
            or str(event.get("frame_id")) != artifact["frame_id"]
        ):
            continue
        seen.add(rule[0])
        observed = str(event.get("artifact_id", "0")) == artifact["artifact_id"]
        observations.append(
            {
                "rule_id": rule[0],
                "weight": rule[1],
                "coordinate": {"byte_offset": 0, "byte_size": 1},
                "event_sequence": str(event.get("sequence_number", "0")),
                "state": "observed" if observed else "correlated",
                "detail": (
                    "A captured browser-signal event is attributed to this artifact."
                    if observed
                    else "A captured browser-signal event shares this artifact's session and frame."
                ),
            }
        )
    return observations


def _bytecode_snapshot(
    source: str, artifact_id: str, limits: Limits
) -> dict[str, Any] | None:
    match = re.search(
        r"(?:Uint8Array\.of|new\s+Uint8Array)\s*\((?:\[)?\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+))*)",
        source,
        re.IGNORECASE,
    )
    if not match:
        return None
    values = [int(value, 0) for value in re.split(r"\s*,\s*", match.group(1))]
    if any(value < 0 or value > 255 for value in values):
        return None
    full = bytes(values)
    snapshot = full[: limits.max_bytecode_snapshot_bytes]
    return {
        "artifact_id": artifact_id,
        "producer": {"kind": "static-initializer", "byte_offset": match.start()},
        "consumer": {"kind": "indexed-read", "status": "inferred"},
        "sha256": hashlib.sha256(full).hexdigest(),
        "original_byte_count": len(full),
        "snapshot_byte_count": len(snapshot),
        "snapshot_hex": snapshot.hex(),
        "truncated": len(snapshot) < len(full),
        "unavailable_reason": None,
    }


def _event_graph(
    artifact: dict[str, Any],
    finding_id: str,
    events: list[dict[str, Any]],
    limits: Limits,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    nodes = [
        {
            "id": f"artifact:{artifact['artifact_id']}",
            "kind": "artifact",
            "label": artifact["url"],
        },
        {"id": f"finding:{finding_id}", "kind": "vm-candidate", "label": finding_id},
    ]
    edges = [
        {
            "from": f"artifact:{artifact['artifact_id']}",
            "to": f"finding:{finding_id}",
            "state": "inferred",
            "reason": "Deterministic static analysis produced this candidate.",
        }
    ]
    request_ids: list[str] = []
    fingerprint_categories = {"canvas", "webgl", "navigator"}
    relevant = [
        event
        for event in events
        if str(event.get("session_id")) == artifact["session_id"]
        and str(event.get("navigation_id")) == artifact["navigation_id"]
        and str(event.get("frame_id")) == artifact["frame_id"]
    ]
    for event in relevant:
        if len(edges) >= limits.max_graph_edges:
            break
        sequence = str(event.get("sequence_number", "0"))
        if event.get("category") in fingerprint_categories:
            node_id = f"event:{sequence}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "browser-signal",
                    "label": f"{event.get('category')} {event.get('type')}",
                    "event_sequence": sequence,
                }
            )
            state = (
                "observed"
                if str(event.get("artifact_id", "0")) == artifact["artifact_id"]
                else "correlated"
            )
            edges.append(
                {
                    "from": node_id,
                    "to": f"finding:{finding_id}",
                    "state": state,
                    "reason": "Captured artifact attribution."
                    if state == "observed"
                    else "Same session and frame.",
                }
            )
        if event.get("category") == "network" and event.get("type") in {
            "request_initiated",
            "request_started",
        }:
            request_id = str(event.get("request_id", "0"))
            if request_id == "0" or request_id in request_ids:
                continue
            request_ids.append(request_id)
            node_id = f"request:{request_id}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "request",
                    "label": f"request {request_id}",
                    "request_id": request_id,
                }
            )
            edges.append(
                {
                    "from": f"finding:{finding_id}",
                    "to": node_id,
                    "state": "correlated",
                    "reason": "Same session and frame. Exact value provenance is not claimed.",
                }
            )
    return nodes, edges, request_ids


def analyze_artifact(
    artifact: dict[str, Any],
    content: bytes,
    events: list[dict[str, Any]],
    limits: Limits,
) -> dict[str, Any]:
    omissions = []
    original_size = len(content)
    if original_size > limits.max_artifact_bytes:
        content = content[: limits.max_artifact_bytes]
        omissions.append(
            {
                "reason": "artifact-byte-limit",
                "observed_bytes": len(content),
                "total_bytes": original_size,
            }
        )
    runtime = "javascript" if artifact["kind"] == "javascript" else "webassembly"
    frontend = {}
    source = ""
    try:
        if runtime == "javascript":
            source = content.decode("utf-8", errors="strict")
            observations, javascript_omissions = _js_observations(source, limits)
            omissions.extend(javascript_omissions)
            frontend = {"replacement_character_count": 0}
        else:
            observations, frontend = _wasm_observations(content, limits)
    except (AnalysisError, UnicodeDecodeError) as exception:
        return {
            "artifact_id": artifact["artifact_id"],
            "artifact_sha256": artifact["sha256"],
            "runtime": runtime,
            "status": "failed",
            "error": {"code": "malformed-artifact", "message": str(exception)},
            "coverage": {"complete": False, "omissions": omissions},
        }
    rule_ids = [item["rule_id"] for item in observations]
    families = sorted({item["family"] for item in observations})
    score = sum(RULE_WEIGHTS[rule_id] for rule_id in rule_ids)
    dispatch_rule = (
        "js.dispatch-loop" if runtime == "javascript" else "wasm.dispatch-loop"
    )
    has_dispatch = dispatch_rule in rule_ids
    tier = (
        "likely-vm"
        if has_dispatch
        and score >= LIKELY_VM_THRESHOLD
        and len(families) >= LIKELY_VM_FAMILIES
        else "candidate"
        if score >= CANDIDATE_THRESHOLD
        else "none"
    )
    anti_bot = _anti_bot_observations(source) if runtime == "javascript" else []
    anti_bot.extend(_runtime_anti_bot_observations(artifact, events))
    anti_bot_score = min(100, sum(item["weight"] for item in anti_bot))
    finding_id = _finding_id(artifact["sha256"], rule_ids)
    nodes, edges, request_ids = _event_graph(artifact, finding_id, events, limits)
    result = {
        "artifact_id": artifact["artifact_id"],
        "artifact_sha256": artifact["sha256"],
        "runtime": runtime,
        "status": "complete" if not omissions else "partial",
        "finding_id": finding_id,
        "tier": tier,
        "vm_score": score,
        "vm_threshold": LIKELY_VM_THRESHOLD,
        "required_family_count": LIKELY_VM_FAMILIES,
        "evidence_families": families,
        "observations": observations,
        "anti_bot_score": anti_bot_score,
        "anti_bot_observations": anti_bot,
        "related_request_ids": request_ids,
        "graph": {"nodes": nodes, "edges": edges},
        "coverage": {
            "complete": not omissions,
            "observed_bytes": len(content),
            "total_bytes": original_size,
            "omissions": omissions,
            "residual_unknowns": [
                "Static evidence does not confirm guest dispatch at runtime.",
                "Request edges are correlation, not exact value provenance.",
            ],
        },
        "frontend": frontend,
    }
    if runtime == "javascript" and tier != "none":
        result["bytecode_snapshot"] = _bytecode_snapshot(
            source, artifact["artifact_id"], limits
        ) or {
            "artifact_id": artifact["artifact_id"],
            "snapshot_hex": None,
            "unavailable_reason": "No bounded static byte initializer was recognized.",
        }
    return result


def _read_bounded_jsonl(
    path: Path, line_limit: int, record_limit: int, source: str
) -> tuple[list[tuple[int, Any]], list[dict[str, Any]], str]:
    if not path.exists():
        return [], [], hashlib.sha256(b"").hexdigest()
    records = []
    omissions = []
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        line_number = 0
        while len(records) < record_limit:
            encoded = stream.readline(line_limit + 1)
            if not encoded:
                break
            line_number += 1
            digest.update(encoded)
            if len(encoded) > line_limit:
                omissions.append(
                    {"reason": f"{source}-line-byte-limit", "line": line_number}
                )
                break
            if not encoded.strip():
                continue
            try:
                records.append((line_number, json.loads(encoded.decode("utf-8"))))
            except (UnicodeDecodeError, json.JSONDecodeError):
                omissions.append({"reason": f"malformed-{source}", "line": line_number})
        if len(records) >= record_limit and stream.read(1):
            omissions.append(
                {"reason": f"{source}-record-limit", "observed_records": len(records)}
            )
    return records, omissions, digest.hexdigest()


def _canonical_uint64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and CANONICAL_UINT64.fullmatch(value) is not None
        and int(value) < 2**64
    )


def _load_events(
    event_store: Path | None, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    if event_store is None:
        return [], [], None
    records, omissions, digest = _read_bounded_jsonl(
        event_store, limits.max_event_line_bytes, limits.max_event_records, "event"
    )
    events = []
    for line_number, event in records:
        if not isinstance(event, dict) or not all(
            _canonical_uint64(event.get(field))
            for field in (
                "session_id",
                "sequence_number",
                "navigation_id",
                "frame_id",
            )
        ):
            omissions.append({"reason": "invalid-event-contract", "line": line_number})
            continue
        if not isinstance(event.get("category"), str) or not isinstance(
            event.get("type"), str
        ):
            omissions.append({"reason": "invalid-event-contract", "line": line_number})
            continue
        optional_ids = ("artifact_id", "request_id")
        if any(
            field in event and not _canonical_uint64(event[field])
            for field in optional_ids
        ):
            omissions.append({"reason": "invalid-event-contract", "line": line_number})
            continue
        events.append(event)
    return events, omissions, digest


def _manifest_failure(artifact: Any, line: int, reason: str) -> dict[str, Any]:
    value = artifact if isinstance(artifact, dict) else {}
    artifact_id = value.get("artifact_id")
    digest = value.get("sha256")
    kind = value.get("kind")
    return {
        "artifact_id": artifact_id if _canonical_uint64(artifact_id) else "0",
        "artifact_sha256": digest
        if isinstance(digest, str) and SHA256_HEX.fullmatch(digest)
        else "0" * 64,
        "runtime": "javascript"
        if kind == "javascript"
        else "webassembly"
        if kind == "wasm"
        else "unknown",
        "status": "failed",
        "error": {
            "code": "invalid-artifact-manifest",
            "message": f"Artifact manifest line {line}: {reason}",
        },
        "coverage": {
            "complete": False,
            "omissions": [{"reason": "invalid-artifact-manifest", "line": line}],
        },
    }


def _validate_artifact(artifact: Any) -> str | None:
    if not isinstance(artifact, dict):
        return "record is not an object"
    if (
        type(artifact.get("protocol_version")) is not int
        or artifact["protocol_version"] != 1
    ):
        return "unsupported protocol version"
    for field in (
        "artifact_id",
        "session_id",
        "navigation_id",
        "frame_id",
        "parent_artifact_id",
        "creator_event_id",
    ):
        if not _canonical_uint64(artifact.get(field)):
            return f"{field} is not a canonical uint64"
    runtime_fields = ("execution_context_id", "capture_origin")
    if any(field in artifact for field in runtime_fields):
        if not all(field in artifact for field in runtime_fields):
            return "runtime provenance fields are incomplete"
        if not _canonical_uint64(artifact["execution_context_id"]):
            return "execution_context_id is not a canonical uint64"
        origin = artifact["capture_origin"]
        if origin not in {
            "unknown",
            "network_response",
            "dynamic_javascript",
            "webassembly_compile",
            "webassembly_module",
            "webassembly_instantiate",
        }:
            return "capture_origin is unsupported"
        if origin == "dynamic_javascript" and (
            artifact.get("kind") != "javascript"
            or artifact["execution_context_id"] == "0"
        ):
            return "dynamic JavaScript provenance is inconsistent"
        if origin.startswith("webassembly_") and (
            artifact.get("kind") != "wasm"
            or artifact["execution_context_id"] == "0"
        ):
            return "WebAssembly provenance is inconsistent"
    if artifact.get("kind") not in {
        "javascript",
        "wasm",
        "source_map",
        "response_body",
    }:
        return "unsupported artifact kind"
    if not isinstance(artifact.get("url"), str) or not artifact["url"]:
        return "url is missing"
    if not isinstance(artifact.get("mime_type"), str) or not artifact["mime_type"]:
        return "MIME type is missing"
    if (
        type(artifact.get("byte_size")) is not int
        or artifact["byte_size"] < 0
        or artifact["byte_size"] >= 2**64
    ):
        return "byte_size is invalid"
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or SHA256_HEX.fullmatch(digest) is None:
        return "sha256 is invalid"
    if not isinstance(artifact.get("sensitive"), bool):
        return "sensitive is not a boolean"
    content_path = artifact.get("content_path")
    if not isinstance(content_path, str) or content_path != f"blobs/{digest}.bin":
        return "content_path is noncanonical"
    path = Path(content_path)
    if path.is_absolute() or ".." in path.parts:
        return "content_path escapes the artifact store"
    return None


def _load_artifacts(
    artifact_store: Path, limits: Limits
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], str]:
    manifest = artifact_store / "manifest.jsonl"
    records, omissions, digest = _read_bounded_jsonl(
        manifest,
        limits.max_manifest_line_bytes,
        limits.max_artifact_records,
        "artifact-manifest",
    )
    artifacts = []
    failures = []
    seen_ids = set()
    for line_number, artifact in records:
        error = _validate_artifact(artifact)
        if error is None and artifact["artifact_id"] in seen_ids:
            error = "duplicate artifact ID"
        if error is not None:
            failures.append(_manifest_failure(artifact, line_number, error))
            continue
        seen_ids.add(artifact["artifact_id"])
        artifacts.append(artifact)
    return artifacts, failures, omissions, digest


def analyze_store(
    artifact_store: Path,
    event_store: Path | None = None,
    limits: Limits | None = None,
) -> dict[str, Any]:
    if limits is None:
        limits = Limits()
    events, event_omissions, event_digest = _load_events(event_store, limits)
    artifacts, manifest_failures, manifest_omissions, manifest_digest = _load_artifacts(
        artifact_store, limits
    )
    input_omissions = [*manifest_omissions, *event_omissions]
    input_omissions.extend(
        failure["coverage"]["omissions"][0] for failure in manifest_failures
    )
    profile = {
        "profile_id": PROFILE_ID,
        "candidate_threshold": CANDIDATE_THRESHOLD,
        "likely_vm_threshold": LIKELY_VM_THRESHOLD,
        "likely_vm_required_families": LIKELY_VM_FAMILIES,
        "rule_weights": RULE_WEIGHTS,
        "limits": limits.as_dict(),
    }
    profile_digest = digest_value(profile)
    results = list(manifest_failures)
    store_root = artifact_store.resolve()
    for artifact in artifacts:
        if artifact.get("kind") not in {"javascript", "wasm"}:
            continue
        blob = (store_root / artifact["content_path"]).resolve()
        if not blob.is_relative_to(store_root):
            results.append(
                _manifest_failure(
                    artifact, 0, "content_path resolves outside the artifact store"
                )
            )
            continue
        try:
            actual_size = blob.stat().st_size
            if actual_size > limits.max_artifact_bytes:
                results.append(
                    {
                        "artifact_id": artifact["artifact_id"],
                        "artifact_sha256": artifact["sha256"],
                        "runtime": "javascript"
                        if artifact["kind"] == "javascript"
                        else "webassembly",
                        "status": "failed",
                        "error": {
                            "code": "artifact-byte-limit",
                            "message": "Artifact exceeds the configured analysis byte limit.",
                        },
                        "coverage": {
                            "complete": False,
                            "omissions": [
                                {
                                    "reason": "artifact-byte-limit",
                                    "observed_bytes": 0,
                                    "total_bytes": actual_size,
                                }
                            ],
                        },
                    }
                )
                continue
            with blob.open("rb") as stream:
                content = stream.read(limits.max_artifact_bytes + 1)
        except OSError as exception:
            results.append(
                {
                    "artifact_id": str(artifact.get("artifact_id", "0")),
                    "artifact_sha256": str(artifact.get("sha256", "")),
                    "runtime": "javascript"
                    if artifact.get("kind") == "javascript"
                    else "webassembly",
                    "status": "failed",
                    "error": {
                        "code": "unavailable-artifact",
                        "message": str(exception),
                    },
                    "coverage": {
                        "complete": False,
                        "omissions": [{"reason": "unavailable-artifact"}],
                    },
                }
            )
            continue
        if actual_size != artifact.get("byte_size"):
            results.append(
                {
                    "artifact_id": str(artifact.get("artifact_id", "0")),
                    "artifact_sha256": str(artifact.get("sha256", "")),
                    "runtime": "javascript"
                    if artifact.get("kind") == "javascript"
                    else "webassembly",
                    "status": "failed",
                    "error": {
                        "code": "artifact-integrity",
                        "message": "Artifact bytes do not match the manifest.",
                    },
                    "coverage": {
                        "complete": False,
                        "omissions": [{"reason": "artifact-integrity"}],
                    },
                }
            )
            continue
        if hashlib.sha256(content).hexdigest() != artifact.get("sha256"):
            results.append(
                {
                    "artifact_id": str(artifact.get("artifact_id", "0")),
                    "artifact_sha256": str(artifact.get("sha256", "")),
                    "runtime": "javascript"
                    if artifact.get("kind") == "javascript"
                    else "webassembly",
                    "status": "failed",
                    "error": {
                        "code": "artifact-integrity",
                        "message": "Artifact bytes do not match the manifest.",
                    },
                    "coverage": {
                        "complete": False,
                        "omissions": [{"reason": "artifact-integrity"}],
                    },
                }
            )
            continue
        result = analyze_artifact(artifact, content, events, limits)
        if result["status"] != "failed" and input_omissions:
            result["status"] = "partial"
            result["coverage"]["complete"] = False
            result["coverage"]["omissions"].extend(input_omissions)
        results.append(result)

    java_script = {
        item["artifact_id"]: item for item in results if item["runtime"] == "javascript"
    }
    wasm = {
        item["artifact_id"]: item
        for item in results
        if item["runtime"] == "webassembly"
    }
    mixed = []
    by_id = {str(item.get("artifact_id")): item for item in artifacts}
    for wasm_id, wasm_result in wasm.items():
        parent_id = str(by_id.get(wasm_id, {}).get("parent_artifact_id", "0"))
        js_result = java_script.get(parent_id)
        js_tier = js_result.get("tier") if js_result else None
        wasm_tier = wasm_result.get("tier")
        if js_tier not in {"candidate", "likely-vm"} or wasm_tier not in {
            "candidate",
            "likely-vm",
        }:
            continue
        rules = [item["rule_id"] for item in js_result.get("observations", [])]
        rules.extend(item["rule_id"] for item in wasm_result.get("observations", []))
        mixed.append(
            {
                "finding_id": _finding_id(
                    f"{js_result['artifact_sha256']}:{wasm_result['artifact_sha256']}",
                    rules,
                ),
                "runtime": "mixed",
                "tier": "likely-vm"
                if "likely-vm" in {js_tier, wasm_tier}
                else "candidate",
                "artifact_ids": [parent_id, wasm_id],
                "vm_score": js_result.get("vm_score", 0)
                + wasm_result.get("vm_score", 0),
                "anti_bot_score": js_result.get("anti_bot_score", 0),
                "evidence_families": sorted(
                    set(js_result.get("evidence_families", []))
                    | set(wasm_result.get("evidence_families", []))
                ),
                "boundary": {
                    "state": "observed",
                    "reason": "The WASM artifact manifest names the JavaScript artifact as its creator.",
                },
            }
        )

    document = {
        "contract_version": CONTRACT_VERSION,
        "document_kind": "vm-analysis",
        "producer": {"id": ANALYZER_ID, "version": ANALYZER_VERSION},
        "profile": profile,
        "profile_digest": profile_digest,
        "inputs": {
            "artifact_manifest_digest": manifest_digest,
            "event_store_digest": event_digest,
        },
        "input_coverage": {
            "complete": not input_omissions,
            "omissions": input_omissions,
        },
        "results": results,
        "mixed_findings": mixed,
        "summary": {
            "analyzed_artifacts": len(results),
            "candidate_count": sum(item.get("tier") == "candidate" for item in results),
            "likely_vm_count": sum(item.get("tier") == "likely-vm" for item in results),
            "failed_count": sum(item.get("status") == "failed" for item in results),
            "mixed_count": len(mixed),
        },
    }
    document["document_digest"] = digest_value(document)
    return document


def write_analysis(document: dict[str, Any], artifact_store: Path) -> Path:
    verify_analysis_document(document)
    analysis_directory = artifact_store / "analysis"
    analysis_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = analysis_directory / "vm-analysis-v1.json"
    temporary = analysis_directory / ".vm-analysis-v1.json.tmp"
    temporary.write_bytes(canonical_json(document) + b"\n")
    temporary.replace(path)
    return path


def verify_analysis_document(document: Any) -> None:
    if (
        not isinstance(document, dict)
        or document.get("contract_version") != CONTRACT_VERSION
    ):
        raise AnalysisError("VM analysis document has an invalid contract version")
    profile = document.get("profile")
    if not isinstance(profile, dict) or document.get("profile_digest") != digest_value(
        profile
    ):
        raise AnalysisError("VM analysis profile digest mismatch")
    expected = document.get("document_digest")
    if not isinstance(expected, str) or SHA256_HEX.fullmatch(expected) is None:
        raise AnalysisError("VM analysis document digest is invalid")
    unsigned = dict(document)
    unsigned.pop("document_digest", None)
    if digest_value(unsigned) != expected:
        raise AnalysisError("VM analysis document digest mismatch")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze captured JS and WASM for VM candidates"
    )
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = analyze_store(
        args.artifacts.resolve(), args.events.resolve() if args.events else None
    )
    if args.output:
        args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(document) + b"\n")
    else:
        write_analysis(document, args.artifacts.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
