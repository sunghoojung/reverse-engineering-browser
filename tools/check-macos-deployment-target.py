#!/usr/bin/env python3
"""Refuse an app bundle with a Mach-O that needs a newer macOS than it declares.

LaunchServices opens a bundle on any release its LSMinimumSystemVersion
admits, but dyld refuses an executable whose LC_BUILD_VERSION minimum is
newer than the running system. A compiler left at its default targets the
build host, so a bundle built on macOS 26 can declare 13.0 and still not start
on 13, 14 or 15. Every Mach-O slice in the bundle must record a macOS minimum,
and none may exceed the declared one. Run with --self-test to check the
checker on synthetic headers.
"""

import argparse
import plistlib
import struct
import sys
import tempfile
from pathlib import Path

THIN = {b"\xcf\xfa\xed\xfe": ("<", 32), b"\xce\xfa\xed\xfe": ("<", 28),
        b"\xfe\xed\xfa\xcf": (">", 32), b"\xfe\xed\xfa\xce": (">", 28)}
FAT = {b"\xca\xfe\xba\xbe": (">IIIII", 20), b"\xca\xfe\xba\xbf": (">IIQQII", 32)}
# A Java class file shares the 32-bit fat magic; its version word reads as an
# implausible slice count.
MAXIMUM_SLICES = 16
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1


def decode(version: int) -> tuple:
    return (version >> 16, (version >> 8) & 0xFF, version & 0xFF)


def parse(text: str) -> tuple:
    parts = text.split(".")
    if not 1 <= len(parts) <= 3 or not all(part.isdigit() for part in parts):
        raise ValueError(f"not a macOS version: {text!r}")
    return tuple(int(part) for part in parts) + (0,) * (3 - len(parts))


def show(version: tuple) -> str:
    major, minor, patch = version
    return f"{major}.{minor}.{patch}" if patch else f"{major}.{minor}"


def slice_minimum(handle, offset: int):
    """The macOS minimum one slice records, or why it has none."""
    handle.seek(offset)
    magic = handle.read(4)
    if magic not in THIN:
        return None, "a fat slice is not a Mach-O image"
    order, header_size = THIN[magic]
    header = magic + handle.read(header_size - 4)
    if len(header) < header_size:
        return None, "truncated Mach-O header"
    commands, size = struct.unpack_from(order + "II", header, 16)
    data = handle.read(size)
    if len(data) < size:
        return None, "truncated load commands"
    position, minimums, platforms = 0, [], set()
    for _ in range(commands):
        if position + 8 > size:
            return None, "truncated load commands"
        command, length = struct.unpack_from(order + "II", data, position)
        if length < 8 or position + length > size:
            return None, "malformed load command"
        if command == LC_BUILD_VERSION and length >= 24:
            platform, minimum = struct.unpack_from(order + "II", data, position + 8)
            platforms.add(platform)
            if platform == PLATFORM_MACOS:
                minimums.append(decode(minimum))
        elif command == LC_VERSION_MIN_MACOSX and length >= 16:
            minimums.append(decode(struct.unpack_from(order + "I", data, position + 8)[0]))
        position += length
    if not minimums:
        detail = f" (platforms {sorted(platforms)})" if platforms else ""
        return None, f"records no macOS minimum{detail}"
    return max(minimums), None


def file_minimums(path: Path):
    """[(slice offset, minimum or None, problem or None)], or None if not a Mach-O."""
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic in THIN:
            return [(0, *slice_minimum(handle, 0))]
        if magic not in FAT:
            return None
        count_bytes = handle.read(4)
        if len(count_bytes) < 4:
            return None
        count = struct.unpack(">I", count_bytes)[0]
        if not 0 < count <= MAXIMUM_SLICES:
            return None
        layout, entry_size = FAT[magic]
        entries = handle.read(entry_size * count)
        if len(entries) < entry_size * count:
            return [(0, None, "truncated fat header")]
        offsets = [struct.unpack_from(layout, entries, index * entry_size)[2] for index in range(count)]
        return [(offset, *slice_minimum(handle, offset)) for offset in offsets]


def problems(bundle: Path) -> tuple:
    """(problems, declared minimum, Mach-O file count, newest recorded minimum)."""
    with (bundle / "Contents/Info.plist").open("rb") as source:
        info = plistlib.load(source)
    declared = parse(str(info.get("LSMinimumSystemVersion", "")))
    executable = bundle / "Contents/MacOS" / str(info.get("CFBundleExecutable", ""))
    found, checked, newest = [], set(), None
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        slices = file_minimums(path)
        if slices is None:
            continue
        checked.add(path)
        name = path.relative_to(bundle)
        for offset, minimum, problem in slices:
            where = f"{name}" + (f" (slice at {offset})" if len(slices) > 1 else "")
            if problem:
                found.append(f"{where}: {problem}")
                continue
            newest = minimum if newest is None else max(newest, minimum)
            if minimum > declared:
                found.append(f"{where}: requires macOS {show(minimum)}, newer than the declared "
                             f"LSMinimumSystemVersion {show(declared)}")
    # A walk that finds nothing would otherwise pass any bundle.
    if executable not in checked:
        found.append(f"the bundle executable {executable.relative_to(bundle)} is not a Mach-O file")
    return found, declared, len(checked), newest


def self_test() -> None:
    def image(*commands, order="<"):
        body = b"".join(commands)
        return struct.pack(order + "IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2,
                           len(commands), len(body), 0, 0) + body

    def build(platform, minimum, order="<"):
        return struct.pack(order + "IIIIII", LC_BUILD_VERSION, 24, platform, minimum, minimum, 0)

    def legacy(minimum):
        return struct.pack("<IIII", LC_VERSION_MIN_MACOSX, 16, minimum, minimum)

    def fat(*images):
        header = struct.pack(">II", 0xCAFEBABE, len(images))
        offset, table, body = 4096, b"", b""
        for data in images:
            table += struct.pack(">IIIII", 0x0100000C, 0, offset + len(body), len(data), 12)
            body += data + b"\0" * (-len(data) % 4096)
        return header + table + b"\0" * (offset - len(header) - len(table)) + body

    v13, v11, v26 = 13 << 16, 11 << 16, 26 << 16
    cases = {
        "matching": ({"Main": image(build(PLATFORM_MACOS, v13))}, 0),
        "older": ({"Main": image(build(PLATFORM_MACOS, v11)), "Helper": image(legacy(10 << 16))}, 0),
        "big-endian": ({"Main": struct.pack(">IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
                        + build(PLATFORM_MACOS, v13, ">")}, 0),
        "fat": ({"Main": fat(image(build(PLATFORM_MACOS, v11)), image(build(PLATFORM_MACOS, v13)))}, 0),
        "newer": ({"Main": image(build(PLATFORM_MACOS, v13)), "Helper": image(build(PLATFORM_MACOS, v26))}, 1),
        "newer patch": ({"Main": image(build(PLATFORM_MACOS, v13 | 1))}, 1),
        "newer slice": ({"Main": fat(image(build(PLATFORM_MACOS, v11)), image(build(PLATFORM_MACOS, v26)))}, 1),
        "no minimum": ({"Main": image()}, 1),
        "other platform": ({"Main": image(build(2, v11))}, 1),
        "truncated": ({"Main": image(build(PLATFORM_MACOS, v13))[:40]}, 1),
        "not executable": ({"Main": b"#!/bin/sh\n"}, 1),
        "class file": ({"Main": image(build(PLATFORM_MACOS, v13)),
                        "Tool.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 32}, 0),
    }
    for name, (files, expected) in cases.items():
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory, "Synthetic.app")
            (bundle / "Contents/MacOS").mkdir(parents=True)
            with (bundle / "Contents/Info.plist").open("wb") as destination:
                plistlib.dump({"CFBundleExecutable": "Main", "LSMinimumSystemVersion": "13.0"}, destination)
            for relative, data in files.items():
                (bundle / "Contents/MacOS" / relative).write_bytes(data)
            found = problems(bundle)[0]
            assert len(found) == expected, (name, found)
    for text, expected in (("13", (13, 0, 0)), ("13.0", (13, 0, 0)), ("13.3.1", (13, 3, 1))):
        assert parse(text) == expected, text
    for text in ("", "13.x", "13.0.0.0"):
        try:
            parse(text)
        except ValueError:
            continue
        raise AssertionError(f"accepted {text!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", nargs="?", type=Path, help="path to the .app bundle")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test == (args.bundle is not None):
        parser.error("give either an app bundle or --self-test")
    self_test()
    if args.self_test:
        print("PASS macOS deployment target checker self-test")
        return 0
    found, declared, count, newest = problems(args.bundle)
    for problem in found:
        print(f"{args.bundle.name}: {problem}", file=sys.stderr)
    if found:
        print(f"Build each Mach-O for macOS {show(declared)} or earlier: Swift with -target, C and C++ "
              "with -mmacosx-version-min, Rust with MACOSX_DEPLOYMENT_TARGET.", file=sys.stderr)
        return 1
    print(f"PASS {count} Mach-O files in {args.bundle.name} require at most macOS {show(newest)}, "
          f"within LSMinimumSystemVersion {show(declared)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
