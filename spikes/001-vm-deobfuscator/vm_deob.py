#!/usr/bin/env python3
"""Static, bounded proof of concept for one JavaScript VM shape.

The input is treated as text. Only literals and handler statements matching an
explicit allowlist are interpreted; arbitrary JavaScript is never run.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path


class UnsupportedVM(ValueError):
    pass


MAX_SOURCE = 4 * 1024 * 1024
MAX_STEPS = 10_000
NUMBER = r"(?:0[xX][0-9a-fA-F]+|\d+)"


@dataclass(frozen=True)
class Handler:
    opcode: int
    operations: tuple[tuple[str, int | str | None], ...]


def number(text: str) -> int:
    return int(text, 0)


def find_bytecode(source: str) -> tuple[str, list[int]]:
    match = re.search(
        rf"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*([^\]]+)\]",
        source,
    )
    if not match:
        raise UnsupportedVM("no numeric bytecode array found")
    values = [number(item) for item in re.findall(NUMBER, match.group(2))]
    if not values or len(values) > 4096:
        raise UnsupportedVM("bytecode array is empty or exceeds the cap")
    return match.group(1), values


def find_decode(source: str, bytecode_name: str) -> int:
    pattern = rf"(?:const|let|var)\s+\w+\s*=\s*{re.escape(bytecode_name)}\s*\[\s*\w+\+\+\s*\]\s*\^\s*({NUMBER})"
    match = re.search(pattern, source)
    return number(match.group(1)) if match else 0


def handler_operations(body: str, bytecode_name: str) -> tuple[tuple[str, int | str | None], ...]:
    operations: list[tuple[str, int | str | None]] = []
    push_bytecode = rf"stack\.push\(\s*{re.escape(bytecode_name)}\s*\[\s*\w+\+\+\s*\]\s*\)"
    if re.search(push_bytecode, body):
        operations.append(("push-bytecode", None))
    else:
        push = re.search(rf"stack\.push\(\s*({NUMBER})\s*\)", body)
        if push:
            operations.append(("push", number(push.group(1))))

    binary = re.search(
        r"stack\.push\(\s*\w+\s*([+\-*/^&|])\s*\w+\s*\)", body
    )
    if binary:
        operations.append(("binary", binary.group(1)))

    if re.search(r"return\s+stack\.pop\(\s*\)", body):
        operations.append(("return", None))
    if not operations:
        raise UnsupportedVM("dispatcher contains an unsupported handler")
    return tuple(operations)


def find_handlers(source: str, bytecode_name: str) -> dict[int, Handler]:
    switch = re.search(r"switch\s*\(\s*\w+\s*\)\s*\{(?P<body>.*?)\n?\s*\}", source, re.S)
    if not switch:
        raise UnsupportedVM("no switch dispatcher found")
    # Case bodies may contain nested blocks.  Do not use the first closing
    # brace as the end of the switch, because that would truncate a handler
    # such as `case 0x20: { ... }` before later cases are seen.
    body = source[switch.start() :]
    matches = list(re.finditer(rf"case\s+({NUMBER})\s*:\s*(.*?)(?=\bcase\s+{NUMBER}\s*:|\bdefault\s*:|\Z)", body, re.S))
    if not matches:
        raise UnsupportedVM("dispatcher has no case handlers")
    handlers: dict[int, Handler] = {}
    for match in matches:
        opcode = number(match.group(1))
        handlers[opcode] = Handler(opcode, handler_operations(match.group(2), bytecode_name))
    return handlers


def apply_binary(operator: str, left: int, right: int) -> int:
    if operator == "+": return left + right
    if operator == "-": return left - right
    if operator == "*": return left * right
    if operator == "/":
        if right == 0: raise UnsupportedVM("division by zero in trace")
        return int(left / right)
    if operator == "^": return left ^ right
    if operator == "&": return left & right
    if operator == "|": return left | right
    raise UnsupportedVM(f"unsupported operator {operator}")


def analyze(source: str, max_steps: int = MAX_STEPS) -> dict[str, object]:
    if not isinstance(source, str) or not source or len(source.encode()) > MAX_SOURCE:
        raise UnsupportedVM("source is empty, invalid, or too large")
    bytecode_name, encoded = find_bytecode(source)
    key = find_decode(source, bytecode_name)
    handlers = find_handlers(source, bytecode_name)
    stack: list[int] = []
    pc = 0
    trace: list[dict[str, object]] = []
    result: int | None = None
    for step in range(max_steps):
        if pc >= len(encoded):
            break
        raw = encoded[pc]
        pc += 1
        opcode = raw ^ key
        handler = handlers.get(opcode)
        if handler is None:
            raise UnsupportedVM(f"trace reached unknown opcode {opcode}")
        before = list(stack)
        for operation, value in handler.operations:
            if operation == "push": stack.append(int(value))
            elif operation == "push-bytecode":
                if pc >= len(encoded): raise UnsupportedVM("push reads past bytecode")
                stack.append(encoded[pc]); pc += 1
            elif operation == "binary":
                if len(stack) < 2: raise UnsupportedVM("binary handler underflow")
                right, left = stack.pop(), stack.pop()
                stack.append(apply_binary(str(value), left, right))
            elif operation == "return":
                if not stack: raise UnsupportedVM("return handler underflow")
                result = stack.pop()
        trace.append({"step": step, "pc": pc, "raw_opcode": raw, "opcode": opcode, "stack_before": before, "stack_after": list(stack)})
        if result is not None:
            break
    else:
        raise UnsupportedVM("trace exceeded step limit")
    return {
        "schema": "vm-deobfuscation-poc-v1",
        "status": "recovered" if result is not None else "partial",
        "bytecode": {"name": bytecode_name, "length": len(encoded), "xor_key": key},
        "handlers": {str(opcode): [{"op": op, "value": value} for op, value in handler.operations] for opcode, handler in sorted(handlers.items())},
        "instructions": trace,
        "result": result,
        "pseudo_code": "\n".join(f"{item['step']:04}: op_{item['opcode']:02x}  // stack={item['stack_after']}" for item in trace),
        "limits": {"max_source_bytes": MAX_SOURCE, "max_steps": max_steps},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--max-steps", type=int, default=MAX_STEPS)
    args = parser.parse_args()
    try:
        print(json.dumps(analyze(args.source.read_text(encoding="utf-8"), args.max_steps), indent=2, sort_keys=True))
    except (OSError, ValueError) as error:
        print(json.dumps({"schema": "vm-deobfuscation-poc-v1", "status": "unsupported", "error": str(error)}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
