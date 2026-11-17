"""Small binary bodies the fixture serves: a PNG and two Wasm modules."""

from __future__ import annotations

import struct
import zlib

from live_acceptance.fixture import payload


def png(width: int, height: int, seed: str) -> bytes:
    rows = b"".join(b"\x00" + payload(f"{seed}:{y}", width * 3) for y in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows))
            + chunk(b"IEND", b""))


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _name(text: str) -> bytes:
    return _uleb(len(text)) + text.encode()


def _section(section_id: int, content: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(content)) + content


def _body(code: bytes) -> bytes:
    content = b"\x00" + code + b"\x0b"  # no locals; end
    return _uleb(len(content)) + content


def _function_names(names: dict[int, str]) -> bytes:
    entries = _vec([_uleb(index) + _name(name) for index, name in sorted(names.items())])
    subsection = b"\x01" + _uleb(len(entries)) + entries
    return _section(0, _name("name") + subsection)


MAGIC = b"\x00asm\x01\x00\x00\x00"
VOID = b"\x60\x00\x00"


def wasm_import_caller() -> bytes:
    """`run` calls `reb_inner`, which calls the JS import `env.f`.

    A `fetch` inside `env.f` then has two Wasm frames below its JS frame.
    """
    return b"".join([
        MAGIC,
        _section(1, _vec([VOID])),
        _section(2, _vec([_name("env") + _name("f") + b"\x00\x00"])),
        _section(3, _vec([b"\x00", b"\x00"])),
        _section(7, _vec([_name("run") + b"\x00\x02"])),
        _section(10, _vec([_body(b"\x10\x00"), _body(b"\x10\x01")])),
        _function_names({0: "reb_import_f", 1: "reb_inner", 2: "reb_run"}),
    ])


def wasm_dispatch() -> bytes:
    """`pick(i)` runs one `br_table` and one `call_indirect` through a table of two."""
    i32_to_i32 = b"\x60\x01\x7f\x01\x7f"
    to_i32 = b"\x60\x00\x01\x7f"
    pick = (
        b"\x02\x40\x02\x40"          # block, block
        b"\x20\x00\x0e\x01\x00\x01"  # local.get 0; br_table [0] default 1
        b"\x0b\x41\x01\x0f\x0b"      # end; i32.const 1; return; end
        b"\x20\x00\x41\x01\x71"      # local.get 0; i32.const 1; i32.and
        b"\x11\x01\x00"              # call_indirect (type 1) table 0
    )
    return b"".join([
        MAGIC,
        _section(1, _vec([i32_to_i32, to_i32])),
        _section(3, _vec([b"\x01", b"\x01", b"\x00"])),
        _section(4, _vec([b"\x70\x00\x02"])),
        _section(7, _vec([_name("pick") + b"\x00\x02"])),
        _section(9, _vec([b"\x00\x41\x00\x0b" + _vec([b"\x00", b"\x01"])])),
        _section(10, _vec([_body(b"\x41\x0a"), _body(b"\x41\x14"), _body(pick)])),
        _function_names({0: "reb_ten", 1: "reb_twenty", 2: "pick"}),
    ])
