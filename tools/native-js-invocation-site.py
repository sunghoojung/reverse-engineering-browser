#!/usr/bin/env python3
"""Write a native-js-invocation-sites-v1 file from retained JavaScript artifacts.

Each site names one function by the key V8 computes at bytecode generation
(protocol/native-js-invocation-v1.md): SHA-256 of the script text as UTF-16LE,
its UTF-16 length, and the UTF-16 offset of the function's start position. The
text is the artifact decoded as strict UTF-8 with one leading U+FEFF removed.

A site is given as ARTIFACT_PATH:ARTIFACT_ID:BYTE_OFFSET, where BYTE_OFFSET is
the UTF-8 offset of the `(` that opens the function's parameter list. Any other
character is refused rather than guessed; an arrow function with a bare
parameter or an `async` head has another anchor and must be authored by hand.
The file is written to stdout as exact compact canonical JSON. Writing it arms
nothing until a new browser launch reads it through
REB_NATIVE_JS_INVOCATION_SITES.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

SITE_LIMIT = 8
FILE_LIMIT = 4096


def site(path: Path, artifact_id: str, byte_offset: int) -> dict:
    raw = path.read_bytes()
    if not artifact_id.isdigit() or (artifact_id.startswith("0") and artifact_id != "0"):
        raise ValueError(f"{path}: artifact ID must be a canonical unsigned decimal")
    text = raw.decode("utf-8", errors="strict")
    bom = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    if text.startswith("﻿"):
        text = text[1:]
    if not bom <= byte_offset < len(raw):
        raise ValueError(f"{path}: byte offset {byte_offset} is outside the script text")
    prefix = raw[bom:byte_offset].decode("utf-8", errors="strict")
    units = text.encode("utf-16-le")
    anchor = len(prefix.encode("utf-16-le")) // 2
    if text[len(prefix)] != "(":
        raise ValueError(f"{path}: byte offset {byte_offset} is not the `(` of a parameter list")
    return {
        "anchor_offset": anchor,
        "artifact_id": artifact_id,
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "byte_offset": byte_offset,
        "shape": "function-entry",
        "source_length": len(units) // 2,
        "source_sha256": hashlib.sha256(units).hexdigest(),
    }


def sites_file(specs: list[str]) -> str:
    if not 1 <= len(specs) <= SITE_LIMIT:
        raise ValueError(f"a site file names 1 to {SITE_LIMIT} sites")
    sites = []
    for spec in specs:
        path, artifact_id, offset = spec.rsplit(":", 2)
        sites.append(site(Path(path), artifact_id, int(offset)))
    keys = {(entry["source_sha256"], entry["anchor_offset"]) for entry in sites}
    if len(keys) != len(sites):
        raise ValueError("two sites name the same function")
    text = json.dumps({"sites": sites, "version": 1}, sort_keys=True, separators=(",", ":"))
    if len(text.encode()) > FILE_LIMIT:
        raise ValueError(f"the site file exceeds {FILE_LIMIT} bytes")
    return text


def self_test() -> None:
    import tempfile
    source = "﻿var a='é';window.hsw=function(aGh,jR,qN){return aGh};"
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "glue.js"
        path.write_bytes(source.encode("utf-8"))
        raw = path.read_bytes()
        offset = raw.index(b"function(") + len(b"function")
        parsed = json.loads(sites_file([f"{path}:12:{offset}"]))
        entry = parsed["sites"][0]
        text = source[1:]
        assert entry["anchor_offset"] == text.index("function(") + len("function")
        assert entry["source_length"] == len(text)
        assert entry["source_sha256"] == hashlib.sha256(text.encode("utf-16-le")).hexdigest()
        for bad in [f"{path}:12:{offset + 1}", f"{path}:012:{offset}", f"{path}:12:{len(raw)}"]:
            try:
                sites_file([bad])
            except ValueError:
                continue
            raise AssertionError(f"accepted {bad}")
        try:
            sites_file([f"{path}:12:{offset}", f"{path}:13:{offset}"])
        except ValueError:
            pass
        else:
            raise AssertionError("accepted a duplicate site")
    print("PASS native JS invocation site helper: BOM, UTF-16 anchor, canonical file, refusals")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("site", nargs="*", help="ARTIFACT_PATH:ARTIFACT_ID:BYTE_OFFSET")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        sys.stdout.write(sites_file(args.site))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(f"native-js-invocation-site: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
