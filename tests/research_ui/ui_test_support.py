"""Read the shipped interface for focused source-contract tests."""

# Keeps PEP 604 annotations unevaluated on the macOS system Python 3.9.
from __future__ import annotations

from pathlib import Path
from html.parser import HTMLParser

UI_DIRECTORY = Path(__file__).resolve().parents[2] / "apps" / "research-ui"


class _ShippedScripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            source = dict(attrs).get("src")
            if source and Path(source).name == source:
                self.names.append(source)


def read_ui_sources() -> str:
    parser = _ShippedScripts()
    parser.feed((UI_DIRECTORY / "index.html").read_text(encoding="utf-8"))
    return "\n".join(
        (UI_DIRECTORY / name).read_text(encoding="utf-8")
        for name in ("index.html", "app.css", *parser.names)
    )
