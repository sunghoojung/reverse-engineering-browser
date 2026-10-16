"""Read the shipped interface for focused source-contract tests."""

from pathlib import Path

UI_DIRECTORY = Path(__file__).resolve().parents[2] / "apps" / "research-ui"


def read_ui_sources() -> str:
    return "\n".join(
        (UI_DIRECTORY / name).read_text(encoding="utf-8")
        for name in (
            "index.html",
            "app.css",
            "app_state.js",
            "evidence_models.js",
            "source_syntax.js",
            "traffic_view.js",
            "request_value_test.js",
            "field_provenance.js",
            "pane_layout.js",
            "app.js",
        )
    )
