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

Which tool to use: in the Origin Trace app, choose Track calls in Sources or
type a name such as window.hsw; the app saves the site and arms it in its next
capture, and `reb-api call resolve_js_invocation_site` gives the same site to an
agent or script. Use this tool for `make live`, for an artifact outside a
running Origin Trace backend, or to write a site file by hand from an exact `(`.
Both compute the same key and check
tools/fixtures/native-js-invocation/site-cases.json (--self-test).
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

SITE_LIMIT = 8
FILE_LIMIT = 4096
U64_MAX = 2**64 - 1
CASES = Path(__file__).resolve().parent / "fixtures/native-js-invocation/site-cases.json"


class SiteError(ValueError):
    """A refused site. `kind` names the rule, as the shared case fixture does."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def canonical_id(artifact_id: str) -> bool:
    # The browser reads artifact_id as an ASCII unsigned 64-bit decimal.
    return (artifact_id.isascii() and artifact_id.isdigit() and len(artifact_id) <= 20
            and (artifact_id == "0" or not artifact_id.startswith("0"))
            and int(artifact_id) <= U64_MAX)


def site_from_bytes(raw: bytes, artifact_id: str, byte_offset: int) -> dict:
    if not canonical_id(artifact_id):
        raise SiteError("artifact_id", "artifact ID must be a canonical unsigned 64-bit decimal")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SiteError("utf8", "the artifact is not strict UTF-8") from None
    bom = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    if text.startswith("\ufeff"):
        text = text[1:]
    if not bom <= byte_offset < len(raw):
        raise SiteError("outside", f"byte offset {byte_offset} is outside the script text")
    try:
        prefix = raw[bom:byte_offset].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SiteError("boundary", f"byte offset {byte_offset} is inside a character") from None
    units = text.encode("utf-16-le")
    anchor = len(prefix.encode("utf-16-le")) // 2
    if text[len(prefix)] != "(":
        raise SiteError("not_paren",
                        f"byte offset {byte_offset} is not the `(` of a parameter list")
    return {
        "anchor_offset": anchor,
        "artifact_id": artifact_id,
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "byte_offset": byte_offset,
        "shape": "function-entry",
        "source_length": len(units) // 2,
        "source_sha256": hashlib.sha256(units).hexdigest(),
    }


def site(path: Path, artifact_id: str, byte_offset: int) -> dict:
    try:
        return site_from_bytes(path.read_bytes(), artifact_id, byte_offset)
    except SiteError as error:
        raise SiteError(error.kind, f"{path}: {error}") from None


def sites_text(sites: list[dict]) -> str:
    if not 1 <= len(sites) <= SITE_LIMIT:
        raise SiteError("count", f"a site file names 1 to {SITE_LIMIT} sites")
    keys = {(entry["source_sha256"], entry["anchor_offset"]) for entry in sites}
    if len(keys) != len(sites):
        raise SiteError("duplicate", "two sites name the same function")
    text = json.dumps({"sites": sites, "version": 1}, sort_keys=True, separators=(",", ":"))
    if len(text.encode()) > FILE_LIMIT:
        raise SiteError("file_size", f"the site file exceeds {FILE_LIMIT} bytes")
    return text


def sites_file(specs: list[str]) -> str:
    if not 1 <= len(specs) <= SITE_LIMIT:
        raise ValueError(f"a site file names 1 to {SITE_LIMIT} sites")
    sites = []
    for spec in specs:
        path, artifact_id, offset = spec.rsplit(":", 2)
        sites.append(site(Path(path), artifact_id, int(offset)))
    return sites_text(sites)


def case_bytes(case: dict) -> bytes:
    return bytes.fromhex(case["source_hex"]) if "source_hex" in case else case["source"].encode()


def check_cases() -> int:
    """Run the cases the Rust backend also reads, so the two cannot drift."""
    fixture = json.loads(CASES.read_text(encoding="utf-8"))
    assert fixture["format"] == "reb-native-js-invocation-site-cases-v1"
    computed = {}
    for case in fixture["cases"]:
        try:
            result = site_from_bytes(case_bytes(case), case["artifact_id"], case["byte_offset"])
        except SiteError as error:
            assert error.kind == case.get("error"), (case["name"], error.kind)
            continue
        assert "error" not in case, (case["name"], "accepted")
        assert result == case["site"], case["name"]
        computed[case["name"]] = result
    for entry in fixture["files"]:
        sites = [computed[name] for name in entry["cases"]]
        try:
            text = sites_text(sites)
        except SiteError as error:
            assert error.kind == entry.get("error"), (entry["name"], error.kind)
            continue
        assert text == entry["file"], entry["name"]
    return len(fixture["cases"]) + len(fixture["files"])


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
    count = check_cases()
    print(f"PASS native JS invocation site helper: BOM, UTF-16 anchor, canonical file, refusals, {count} shared cases")


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
