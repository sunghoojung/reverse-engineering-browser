"""Resolve a live source cursor to the enclosing JavaScript function.

The Rust worker parses the original script without executing it. CDP columns are
UTF-16 code units, while its syntax tree spans use UTF-8 bytes.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from deobfuscation_worker import WorkerError, worker_path
from debugger.errors import DebuggerBridgeError


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _source_byte_at(source: str, script: dict[str, Any], line: int, column: int) -> int:
    relative_line = line - script["start_line"]
    lines = source.split("\n")
    if relative_line < 0 or relative_line >= len(lines):
        raise DebuggerBridgeError("Hook cursor is outside the live script")
    relative_column = column - (script["start_column"] if relative_line == 0 else 0)
    if relative_column < 0:
        raise DebuggerBridgeError("Hook cursor is outside the live script")
    current = lines[relative_line]
    units = 0
    characters = 0
    for character in current:
        if units == relative_column:
            break
        units += _utf16_units(character)
        characters += 1
        if units > relative_column:
            raise DebuggerBridgeError("Hook cursor splits a UTF-16 character")
    if units != relative_column or characters >= len(current):
        raise DebuggerBridgeError("Hook cursor must point inside a function")
    prefix = "\n".join(lines[:relative_line])
    if relative_line:
        prefix += "\n"
    return len((prefix + current[:characters]).encode("utf-8"))


def _script_location(source: str, script: dict[str, Any], byte_offset: int) -> dict[str, int]:
    encoded = source.encode("utf-8")
    if byte_offset < 0 or byte_offset > len(encoded):
        raise DebuggerBridgeError("Function locator returned an invalid source span")
    try:
        prefix = encoded[:byte_offset].decode("utf-8")
    except UnicodeDecodeError as error:
        raise DebuggerBridgeError("Function locator split a UTF-8 character") from error
    relative_line = prefix.count("\n")
    column = _utf16_units(prefix.rsplit("\n", 1)[-1])
    if relative_line == 0:
        column += script["start_column"]
    return {"line": script["start_line"] + relative_line, "column": column}


def locate_function(source: str, script: dict[str, Any], line: int, column: int) -> dict[str, Any]:
    try:
        path = worker_path()
    except WorkerError as error:
        raise DebuggerBridgeError("Function targeting worker is unavailable") from error
    if path is None:
        raise DebuggerBridgeError("Function targeting requires the bundled Rust worker")
    offset = _source_byte_at(source, script, line, column)
    request = json.dumps({"source": source, "function_at_byte": offset}).encode("utf-8") + b"\n"
    try:
        result = subprocess.run(
            [str(path)], input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=False, env={"LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DebuggerBridgeError("Function targeting worker is unavailable or timed out") from error
    if result.returncode or len(result.stdout) > 4096:
        raise DebuggerBridgeError("Function targeting worker failed")
    try:
        document = json.loads(result.stdout)
        if document["schema"] != "reb-deobfuscator-worker-v1" or document["ok"] is not True:
            raise ValueError("worker status")
        function = document["function_location"]
        if not isinstance(function, dict) or function.get("kind") not in {
            "function_declaration", "function_expression", "arrow_function",
            "method_definition", "generator_function_declaration", "generator_function",
        }:
            raise KeyError("function")
        start = function["start"]
        end = function["end"]
        body_start = function["body_start"]
        if any(type(value) is not int for value in (start, end, body_start)) or not (
            0 <= start <= offset < end <= len(source.encode("utf-8")) and start <= body_start < end
        ):
            raise ValueError("function range")
    except (KeyError, TypeError, ValueError) as error:
        raise DebuggerBridgeError("No enclosing JavaScript function was found at the cursor") from error
    return {
        "kind": function["kind"],
        "start": _script_location(source, script, start),
        "end": _script_location(source, script, end),
        "body_start": _script_location(source, script, body_start),
    }
