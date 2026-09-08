"""Read the shipped interface for source-contract and extracted-function tests."""

from pathlib import Path

UI_DIRECTORY = Path(__file__).resolve().parents[2] / "apps" / "research-ui"


def read_ui_sources() -> str:
    directory = UI_DIRECTORY
    return "\n".join(
        (directory / name).read_text(encoding="utf-8")
        for name in ("index.html", "app.css", "app_state.js", "evidence_models.js", "app.js")
    )
