#!/usr/bin/env python3
"""Decide which CI gates a diff can skip.

The default is the full gate. A narrower mode is returned only when every
changed path is in an allowlist that those skipped gates do not compile or
execute. Push, schedule, and manual runs do not call this; they always run
the full gate.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


DOCS_FILES = {
    "README.md",
    "AGENTS.md",
    "SAFETY.md",
    "CONTRIBUTING.md",
}
DOCS_PREFIXES = (
    "docs/",
    ".agents/",
    ".claude/",
)
RUST_PREFIXES = (
    "apps/origin-trace-backend/",
    "apps/deobfuscator-worker/",
)
# Edits to the skipper itself must not be able to classify a product change
# as documentation. The workflow also forces the full gate when these move.
FORCE_FULL_FILES = {
    "Makefile",
    "tools/ci-scope.py",
    "tools/ci-scope-test.py",
    "tools/ci-scope-decision.sh",
    "tools/ci-run-make.sh",
    "tools/ci-install-compiler-cache.sh",
    "tools/agent-preflight.sh",
}
FORCE_FULL_PREFIXES = (
    ".github/",
    ".githooks/",
    "mk/",
)


def classify_path(path: str) -> str:
    """Return docs, rust, or full for one repo-relative path."""
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized.startswith("../") or "/../" in f"/{normalized}":
        return "full"
    if normalized in FORCE_FULL_FILES or any(
        normalized.startswith(prefix) for prefix in FORCE_FULL_PREFIXES
    ):
        return "full"
    if normalized in DOCS_FILES or normalized.endswith("/README.md"):
        return "docs"
    if any(normalized.startswith(prefix) for prefix in DOCS_PREFIXES):
        return "docs"
    if any(normalized.startswith(prefix) for prefix in RUST_PREFIXES):
        return "rust"
    return "full"


def classify(paths: list[str]) -> str:
    """Return full, rust, or docs. Empty input stays on the full gate."""
    kinds = {classify_path(path) for path in paths if path.strip()}
    if not kinds or "full" in kinds:
        return "full"
    if "rust" in kinds:
        return "rust"
    if kinds == {"docs"}:
        return "docs"
    return "full"


def read_paths(from_file: str | None) -> list[str]:
    if from_file is None:
        return [line for line in sys.stdin.read().splitlines()]
    return Path(from_file).read_text(encoding="utf-8").splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-file",
        help="Read newline-separated paths from this file instead of stdin",
    )
    args = parser.parse_args()
    mode = classify(read_paths(args.from_file))
    if mode not in {"full", "rust", "docs"}:
        print(f"refusing unexpected CI scope {mode}", file=sys.stderr)
        return 1
    print(mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
