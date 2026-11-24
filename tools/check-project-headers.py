#!/usr/bin/env python3
"""Require the project copyright header on project-written browser files.

Files this project writes for the Brave, Chromium and V8 trees sit beside
upstream code, and copying the neighbouring upstream header names upstream
authors who did not write the file. Chromium and V8 headers also point at their
BSD LICENSE file rather than this project's MPL 2.0 terms. Every overlay file,
every file a patch creates, and the tools/ stand-ins for upstream headers must
instead begin with the MPL 2.0 header for the authors listed in AUTHORS. Code
adapted from upstream keeps its upstream notice below that header. Upstream
files a patch edits keep their own notices, and vendored code is not checked.

Run with --fix to rewrite headers in place. A rewritten header changes the file
every later patch in the same stack edits, so the fix replays the stack's
created files in scratch repositories: it moves later hunks by the header's
line change, regenerates a later edit whose hunk reads the rewritten lines,
recomputes the blob ids in index lines, and writes a stack only when each
replayed step reproduces the rewritten file exactly. Run with --self-test to
check the checker on synthetic files and patch stacks.
"""

import argparse
import datetime
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOLDER = "The Reverse Engineering Browser Authors"
MPL = ("This Source Code Form is subject to the terms of the Mozilla Public",
       "License, v. 2.0. If a copy of the MPL was not distributed with this file,",
       "You can obtain one at https://mozilla.org/MPL/2.0/.")
BSD = ("Use of this source code is governed by a BSD-style license that can be",
       "found in the LICENSE file.")
PREFIXES = {".cc": "//", ".h": "//", ".js": "//", ".mm": "//", ".mojom": "//",
            ".gn": "#", ".gni": "#", ".py": "#"}
PROJECT = re.compile(r"(?://|#) Copyright (\d{4}) " + re.escape(HOLDER))
UPSTREAM = re.compile(r"(//|#) Copyright (?:\(c\) )?(\d{4}) "
                      r"(?:The Brave Authors|The Chromium Authors|the V8 project authors)"
                      r"(?:\. All rights reserved\.)?", re.IGNORECASE)
# A file without a known comment syntax, such as a V8 test expectation, has no
# header to require; an upstream notice in its first lines is still refused.
NOTICE_LINES = 8
OVERLAY = "browser/integration/brave/overlay"
PATCHES = "browser/integration/brave/patches"
STAND_INS = ("tools/native-debugger-pause", "tools/native-test-support")
NEW_FILE_HUNK = re.compile(r"@@ -0,0 \+1(?:,(\d+))? @@(.*)")
HUNK = re.compile(r"@@ -(\d+)(,\d+)? \+(\d+)(,\d+)? @@(.*)")
INDEX = re.compile(r"index ([0-9a-f]+)\.\.([0-9a-f]+)(.*)")
# Replays and regenerated hunks must not depend on the user's Git configuration.
GIT_ENVIRONMENT = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def header(prefix: str, year: str) -> list:
    return [f"{prefix} Copyright {year} {HOLDER}"] + [f"{prefix} {line}" for line in MPL]


def review(lines: list, suffix: str):
    """(problem or None, fixed lines or None) for one project-written file."""
    prefix = PREFIXES.get(suffix)
    if prefix is None:
        named = next((line for line in lines[:NOTICE_LINES] if UPSTREAM.fullmatch(line)), None)
        return (f"names upstream authors: {named}" if named else None), None
    start = 1 if lines and lines[0].startswith("#!") else 0
    first = lines[start] if len(lines) > start else ""
    project = PROJECT.fullmatch(first)
    if project and lines[start:start + 4] == header(prefix, project.group(1)):
        return None, None
    if project:
        return "has the project copyright line without the MPL 2.0 notice", None
    upstream = UPSTREAM.fullmatch(first)
    if upstream and upstream.group(1) == prefix:
        year, notice = upstream.group(2), lines[start + 1:]
        for terms in (MPL, BSD):
            if notice[:len(terms)] == [f"{prefix} {text}" for text in terms]:
                fixed = lines[:start] + header(prefix, year) + notice[len(terms):]
                return f"names upstream authors: {first}", fixed
        return f"names upstream authors under other terms: {first}", None
    if upstream:
        return f"names upstream authors: {first}", None
    blank = [""] if first else []
    fixed = lines[:start] + header(prefix, str(datetime.date.today().year)) + blank + lines[start:]
    return "lacks the project copyright header", fixed


def decode(data: bytes) -> list:
    return data.decode("utf-8", "surrogateescape").split("\n")


def encode(lines: list) -> bytes:
    return "\n".join(lines).encode("utf-8", "surrogateescape")


def rewritten(data, path: str):
    """A replayed file's content with its header fixed, as the fixed stack must produce it."""
    if data is None:
        return None
    fixed = review(decode(data), Path(path).suffix)[1]
    return data if fixed is None else encode(fixed)


def blob_id(data) -> str:
    if data is None:
        return "0" * 40
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def sections(lines: list):
    """Split a patch's lines into its preamble and one list per file section."""
    starts = [index for index, line in enumerate(lines) if line.startswith("diff --git ")]
    bounds = zip(starts, starts[1:] + [len(lines)])
    return lines[:starts[0]] if starts else lines, [lines[start:end] for start, end in bounds]


def section_path(section: list) -> str:
    return section[0].split(" b/", 1)[-1]


def created(section: list):
    """The index of the hunk line when a section creates a text file, else None."""
    hunk = next((position for position, line in enumerate(section) if NEW_FILE_HUNK.fullmatch(line)), None)
    if hunk is None or not any(line.startswith("new file mode") for line in section[1:hunk]):
        return None
    return hunk


def review_patch(text: str):
    """([(created path, problem)], fixed text or None, rewritten paths) for one patch.

    A fixed text carries new created-file content and hunk lengths only; the
    index lines and later patches are corrected by rebase_stack().
    """
    preamble, parts = sections(text.split("\n"))
    output, problems, paths = list(preamble), [], set()
    for section in parts:
        hunk = created(section)
        if hunk is None:
            output += section
            continue
        path = section_path(section)
        stop = hunk + 1
        while stop < len(section) and section[stop].startswith("+"):
            stop += 1
        problem, fixed = review([line[1:] for line in section[hunk + 1:stop]], Path(path).suffix)
        if problem:
            problems.append((path, problem))
        if fixed is None:
            output += section
            continue
        paths.add(path)
        length = "" if len(fixed) == 1 else f",{len(fixed)}"
        tail = NEW_FILE_HUNK.fullmatch(section[hunk]).group(2)
        output += section[:hunk] + [f"@@ -0,0 +1{length} @@{tail}"]
        output += ["+" + line for line in fixed] + section[stop:]
    return problems, ("\n".join(output) if paths else None), paths


class Scratch:
    """A throwaway repository that holds only the replayed files."""

    def __init__(self, directory: str):
        self.root = Path(directory)
        self.git("init", "-q")

    def git(self, *arguments, data=None) -> bytes:
        return subprocess.run(["git", *arguments], cwd=self.root, env=GIT_ENVIRONMENT, input=data,
                              check=True, capture_output=True).stdout

    def read(self, path: str):
        file = self.root / path
        return file.read_bytes() if file.is_file() else None

    def write(self, path: str, data: bytes) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)

    def apply(self, section: list, path: str) -> bool:
        payload = encode(section).rstrip(b"\n") + b"\n"
        return subprocess.run(["git", "apply", "--include", path, "-"], cwd=self.root, env=GIT_ENVIRONMENT,
                              input=payload, capture_output=True).returncode == 0

    def diff(self, path: str, before: bytes, after: bytes, abbreviation: int) -> list:
        self.write(path, before)
        self.git("add", "--", path)
        self.write(path, after)
        width = "--full-index" if abbreviation >= 40 else f"--abbrev={abbreviation}"
        lines = decode(self.git("diff", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
                                width, "--", path))
        self.git("rm", "-q", "--cached", "--force", "--", path)
        return lines[:-1] if lines and lines[-1] == "" else lines


def moved(section: list, delta: int, rewritten_lines: int):
    """The section with its hunks moved by delta, or None when one reads a rewritten line."""
    output = []
    for line in section:
        hunk = HUNK.fullmatch(line)
        if hunk:
            old, old_length, new, new_length, tail = hunk.groups()
            if int(old) <= rewritten_lines:
                return None
            line = f"@@ -{int(old) + delta}{old_length or ''} +{int(new) + delta}{new_length or ''} @@{tail}"
        output.append(line)
    return output


def with_ids(section: list, before, after) -> list:
    output = list(section)
    for position, line in enumerate(output[:4]):
        found = INDEX.fullmatch(line)
        if found:
            ids = (blob_id(before)[:len(found.group(1))], blob_id(after)[:len(found.group(2))])
            output[position] = f"index {ids[0]}..{ids[1]}{found.group(3)}"
    return output


def rebase_stack(stack: list, texts: dict, fixed_texts: dict, paths: set) -> dict:
    """The stack's patch texts with created-file headers fixed and every later edit rebased onto them."""
    with tempfile.TemporaryDirectory() as old_directory, tempfile.TemporaryDirectory() as new_directory, \
            tempfile.TemporaryDirectory() as diff_directory:
        old, new, diffs = Scratch(old_directory), Scratch(new_directory), Scratch(diff_directory)
        result = {}
        for patch in stack:
            preamble, parts = sections(fixed_texts.get(patch, texts[patch]).split("\n"))
            originals = sections(texts[patch].split("\n"))[1]
            output = list(preamble)
            for section, original in zip(parts, originals):
                path = section_path(section)
                if path not in paths:
                    output += section
                    continue
                old_before = old.read(path)
                if not old.apply(original, path):
                    raise ValueError(f"{patch.name}: {path} does not replay from the earlier patches")
                before, after = rewritten(old_before, path), rewritten(old.read(path), path)
                if new.read(path) != before:
                    raise ValueError(f"{patch.name}: {path} differs from the rewritten earlier patches")
                if created(section) is None:
                    if before is None or after is None:
                        raise ValueError(f"{patch.name}: regenerate its edit of {path} by hand")
                    old_lines, new_lines = decode(old_before), decode(before)
                    common = 0
                    while common < min(len(old_lines), len(new_lines)) and \
                            old_lines[-1 - common] == new_lines[-1 - common]:
                        common += 1
                    index = next((INDEX.fullmatch(line) for line in section[:4] if INDEX.fullmatch(line)), None)
                    abbreviation = len(index.group(2)) if index else 40
                    shifted = moved(section, len(new_lines) - len(old_lines), len(old_lines) - common)
                    if shifted is None:
                        # The last section of a patch carries the file's final newline.
                        shifted = diffs.diff(path, before, after, abbreviation) + section[-1:] * (section[-1] == "")
                    section = shifted
                if not new.apply(section, path) or new.read(path) != after:
                    raise ValueError(f"{patch.name}: replaying {path} does not reproduce the rewritten file")
                output += with_ids(section, before, after)
            result[patch] = "\n".join(output)
        return result


def tracked(root: Path, *paths: str) -> list:
    listing = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--", *paths])
    return [root / name for name in listing.decode("utf-8", "surrogateescape").split("\0") if name]


def check(fix: bool, root: Path = ROOT) -> list:
    found = []
    for path in tracked(root, OVERLAY, *STAND_INS):
        if path.suffix == ".md":
            continue
        problem, fixed = review(path.read_text("utf-8", "surrogateescape").split("\n"), path.suffix)
        if problem:
            found.append((path.relative_to(root), problem))
        if fix and fixed is not None:
            path.write_text("\n".join(fixed), "utf-8", "surrogateescape")
    # The sync script applies each directory's patches as one ordered stack.
    stacks = {}
    for path in tracked(root, PATCHES):
        if path.suffix == ".patch":
            stacks.setdefault(path.parent, []).append(path)
    for directory, stack in stacks.items():
        stack.sort(key=lambda path: path.name)
        texts = {path: path.read_text("utf-8", "surrogateescape") for path in stack}
        fixed_texts, paths = {}, set()
        for path in stack:
            problems, fixed, rewritten_paths = review_patch(texts[path])
            found += [(f"{path.relative_to(root)}: {name}", problem) for name, problem in problems]
            if fixed is not None:
                fixed_texts[path] = fixed
                paths |= rewritten_paths
        if not fix or not fixed_texts:
            continue
        try:
            result = rebase_stack(stack, texts, fixed_texts, paths)
        except ValueError as error:
            found.append((directory.relative_to(root), f"left unchanged: {error}"))
            continue
        for path, text in result.items():
            if text != texts[path]:
                path.write_text(text, "utf-8", "surrogateescape")
    return found


def self_test() -> None:
    v8 = ["// Copyright 2026 the V8 project authors. All rights reserved.", *("// " + line for line in BSD)]
    brave = ["# Copyright (c) 2026 The Brave Authors. All rights reserved.", *("# " + line for line in MPL)]
    chromium = "// Copyright 2026 The Chromium Authors"
    cases = {
        "project": (header("//", "2026") + ["", "int a;"], ".cc", False, None),
        "v8 bsd": (v8 + ["", "int a;"], ".h", True, header("//", "2026") + ["", "int a;"]),
        "brave mpl": (brave + ["", "x = 1"], ".gn", True, header("#", "2026") + ["", "x = 1"]),
        "shebang": (["#!/usr/bin/env python3"] + header("#", "2025"), ".py", False, None),
        "other terms": ([chromium, "// Licensed under the Apache License"], ".cc", True, None),
        "wrong syntax": (brave, ".cc", True, None),
        "adapted upstream code": (header("//", "2026") + ["", chromium, "// " + BSD[0]], ".cc", False, None),
        "notice only": (header("//", "2026")[:1] + ["int a;"], ".h", True, None),
        "expectation": (["Embedder pauses are reported."], ".txt", False, None),
        "noticed expectation": (["", chromium], ".txt", True, None),
    }
    for name, (lines, suffix, flagged, expected) in cases.items():
        problem, fixed = review(lines, suffix)
        assert bool(problem) == flagged and fixed == expected, (name, problem, fixed)
        if fixed is not None:
            assert review(fixed, suffix) == (None, None), (name, review(fixed, suffix))
    problem, fixed = review(["#pragma once", ""], ".h")
    assert problem and fixed[4:] == ["", "#pragma once", ""] and review(fixed, ".h") == (None, None), fixed

    # Patch 0001 edits an upstream file and creates two files; 0002 edits the
    # created header far below its notice and 0003 edits it beside the notice.
    # The fix must keep the upstream notice, move 0002, regenerate 0003, and
    # leave index lines that match an ordered replay.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)

        def git(*arguments, cwd=root):
            return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=t",
                                   "-c", "user.email=t@t", *arguments], cwd=cwd, env=GIT_ENVIRONMENT,
                                  check=True, capture_output=True, text=True).stdout

        upstream, stack = root / "upstream", root / PATCHES / "v8"
        upstream.mkdir()
        stack.mkdir(parents=True)
        body = [f"int line{number};" for number in range(12)]
        states = [
            {"kept.cc": v8 + ["int kept;", ""]},
            {"kept.cc": v8 + ["int kept = 1;", ""], "made.h": v8 + ["", *body, "int made;"],
             "made.txt": ["expected output", ""]},
            {"made.h": v8 + ["", *body, "int made;", "int more;", ""]},
            {"made.h": v8 + ["#include <cstdint>", "", *body, "int made;", "int more;", ""]},
        ]
        git("init", "-q", cwd=upstream)
        for number, state in enumerate(states):
            for name, lines in state.items():
                (upstream / name).write_text("\n".join(lines))
            git("add", "-A", cwd=upstream)
            git("commit", "-qm", f"state {number}", cwd=upstream)
            if number:
                width = "--full-index" if number == 1 else "--abbrev=7"
                (stack / f"000{number}-step.patch").write_text(git("diff", width, "HEAD~1", "HEAD", cwd=upstream))
        originals = {patch.name: patch.read_text() for patch in stack.iterdir()}
        git("init", "-q")
        git("add", "-A", PATCHES)
        problems = check(True, root)
        assert [str(path) for path, _ in problems] == [f"{PATCHES}/v8/0001-step.patch: made.h"], problems
        assert check(False, root) == [], check(False, root)
        fixed = {patch.name: patch.read_text() for patch in stack.iterdir()}
        assert originals["0001-step.patch"].count(v8[0]) == 2 and fixed["0001-step.patch"].count(v8[0]) == 1
        assert "@@ -15,4 +15,5 @@" in fixed["0002-step.patch"], fixed["0002-step.patch"]
        assert v8[0] not in fixed["0003-step.patch"] and header("//", "2026")[1] in fixed["0003-step.patch"]
        git("checkout", "-q", "HEAD~3", cwd=upstream)
        for name in sorted(fixed):
            before = (upstream / "made.h").read_bytes() if (upstream / "made.h").exists() else None
            git("apply", "--index", str(stack / name), cwd=upstream)
            after = (upstream / "made.h").read_bytes()
            for section in sections(fixed[name].split("\n"))[1]:
                if section_path(section) == "made.h":
                    ids = next(INDEX.fullmatch(line) for line in section if INDEX.fullmatch(line))
                    assert blob_id(before).startswith(ids.group(1)), (name, ids.group(0))
                    assert blob_id(after).startswith(ids.group(2)), (name, ids.group(0))
        expected = header("//", "2026") + ["#include <cstdint>", "", *body, "int made;", "int more;", ""]
        assert (upstream / "made.h").read_text() == "\n".join(expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fix", action="store_true", help="rewrite headers in place")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test()
    if args.self_test:
        print("PASS project header checker self-test")
        return 0
    found = check(args.fix)
    refused = [(path, problem) for path, problem in found if problem.startswith("left unchanged")]
    remaining = check(False) if args.fix else found
    for path, problem in refused + remaining:
        print(f"{path}: {problem}", file=sys.stderr)
    if args.fix:
        print(f"Rewrote {len(found) - len(refused) - len(remaining)} header(s)")
    if remaining:
        print(f"{len(remaining)} project-written file(s) need the project header"
              + ("" if args.fix else "; run python3 tools/check-project-headers.py --fix"), file=sys.stderr)
        return 1
    print("Project header check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
