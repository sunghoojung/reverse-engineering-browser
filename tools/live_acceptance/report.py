"""Result lines: PASS, FAIL, MANUAL and SKIP, never a pass for an unrun case."""

from __future__ import annotations

from dataclasses import dataclass
import sys

STATUSES = ("PASS", "FAIL", "MANUAL", "SKIP")


@dataclass(frozen=True)
class Line:
    status: str
    issue: str
    case: str
    detail: str

    def text(self) -> str:
        return f"{self.status} {self.issue} {self.case}: {self.detail}"


class Report:
    def __init__(self, session: str) -> None:
        self.session = session
        self.lines: list[Line] = []

    def add(self, status: str, issue: str, case: str, detail: str) -> None:
        if status not in STATUSES:
            raise ValueError(status)
        line = Line(status, issue, case, detail)
        self.lines.append(line)
        print(line.text(), file=sys.stderr if status == "FAIL" else sys.stdout, flush=True)

    def passed(self, issue: str, case: str, detail: str) -> None:
        self.add("PASS", issue, case, detail)

    def failed(self, issue: str, case: str, detail: str) -> None:
        self.add("FAIL", issue, case, detail)

    def manual(self, issue: str, case: str, steps: str) -> None:
        self.add("MANUAL", issue, case, steps)

    def skipped(self, issue: str, case: str, reason: str) -> None:
        self.add("SKIP", issue, case, reason)

    def check(self, issue: str, case: str, problems: list[str], detail: str) -> bool:
        """PASS with detail when there is no problem, else one FAIL naming them all."""
        if problems:
            shown = "; ".join(problems[:8])
            more = f" (+{len(problems) - 8} more)" if len(problems) > 8 else ""
            self.failed(issue, case, shown + more)
            return False
        self.passed(issue, case, detail)
        return True

    def count(self, status: str) -> int:
        return sum(1 for line in self.lines if line.status == status)

    def summary(self) -> str:
        counts = ", ".join(f"{self.count(s)} {s.lower()}" for s in STATUSES)
        return f"RESULT {self.session} session: {counts}"

    @property
    def exit_code(self) -> int:
        return 1 if self.count("FAIL") else 0
