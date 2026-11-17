"""Fixture page text and the source positions cases compare frames with."""

from __future__ import annotations


def document(title: str, body: str, head: str = "") -> str:
    """A fixture page. Its first script is the beacon library, before any case."""
    return (f"<!doctype html>\n<meta charset=utf-8>\n<title>{title}</title>\n{head}"
            f"<script src=\"/__lib.js\"></script>\n{body}\n")


def locate(text: str, marker: str, occurrence: int = 1) -> tuple[int, int]:
    """One-based line and column of the start of marker, as stacks report them."""
    index = -1
    for _ in range(occurrence):
        index = text.index(marker, index + 1)
    line = text.count("\n", 0, index) + 1
    column = index - (text.rfind("\n", 0, index) + 1) + 1
    return line, column


def line_of(text: str, marker: str) -> int:
    return locate(text, marker)[0]
