"""One live session's run: its fixture, evidence reads and trusted input."""

from __future__ import annotations

from dataclasses import dataclass, field
import shutil
import subprocess
from typing import Callable

from live_acceptance.evidence import ApiError, Session, find_rows, request_records, row_tabs
from live_acceptance.fixture import Fixture
from live_acceptance.report import Report


def brotli_encoder() -> tuple[Callable[[bytes], bytes] | None, str]:
    """A brotli encoder: the Python module when installed, else the brotli CLI."""
    try:
        import brotli  # type: ignore[import-not-found]

        return brotli.compress, "the Python brotli module"
    except ImportError:
        pass
    tool = shutil.which("brotli")
    if tool:
        def encode(data: bytes) -> bytes:
            return subprocess.run([tool, "-c"], input=data, capture_output=True, check=True).stdout

        return encode, tool
    return None, "no brotli encoder: neither the Python brotli module nor a brotli executable on PATH"


@dataclass
class Options:
    brotli: Callable[[bytes], bytes] | None = None
    brotli_source: str = ""


@dataclass
class Run:
    kind: str
    fixture: Fixture
    report: Report
    session: Session
    options: Options
    _rows: list[dict] | None = None
    _records: tuple | None = None
    click_unavailable: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def api(self):
        return self.session.api

    def url(self, path: str) -> str:
        return self.fixture.origin + path

    def open(self, path: str) -> bool:
        try:
            self.api.open_url(self.url(path))
            return True
        except (ApiError, OSError) as error:
            self.report.failed("setup", f"open {path}", str(error))
            return False

    def wait(self, issue: str, names: list[str], timeout: float = 60) -> bool:
        """Wait for page beacons; one FAIL names any that never arrived."""
        missing = self.fixture.wait_beacons(names, timeout)
        if missing:
            self.report.failed(issue, "page", "beacon never arrived: " + ", ".join(sorted(missing)))
        return not missing

    def result(self, name: str) -> tuple[bool, object]:
        """A REB.run result: (ok, value or error text)."""
        value = self.fixture.beacon(name)
        if not isinstance(value, dict):
            return False, f"no result for {name}"
        return bool(value.get("ok")), value.get("value") if value.get("ok") else value.get("error")

    def rows(self, refresh: bool = False) -> list[dict]:
        if self._rows is None or refresh:
            self._rows = self.api.rows()
        return self._rows

    def records(self, refresh: bool = False):
        if self._records is None or refresh:
            self._records = request_records(self.api)
        return self._records

    def tab_of(self, target: str) -> str | None:
        """The tab of a document the fixture served: the tab its own row names."""
        for row in find_rows(self.rows(), target=target):
            tabs = row_tabs(row)
            if row.get("tab_id") not in (None, "0"):
                return row["tab_id"]
            if tabs:
                return sorted(tabs)[0]
        return None

    def click(self, issue: str, case: str, **target: object) -> bool:
        """A trusted click through `session_action`, which needs Accessibility."""
        if self.click_unavailable:
            return False
        try:
            self.api.action({"action": "click", **target})
            return True
        except ApiError as error:
            # No Accessibility permission for the app that runs reb-api, or not macOS.
            if error.code == "dependency_unavailable" or error.status == 501:
                self.click_unavailable = str(error)
            self.notes.append(f"{issue} {case}: trusted click failed: {error}")
            return False
        except OSError as error:
            self.notes.append(f"{issue} {case}: trusted click failed: {error}")
            return False
