"""Report assembly model (DOC-08 section 6/7)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from bletiner.models.entities import Finding, Severity
from bletiner.reporting.lifecycle import is_reportable
from bletiner.reporting.sanitizer import sanitize

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class ReportContext:
    title: str
    primary_target: str
    authorized_scope: tuple[str, ...]
    findings: tuple[Finding, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def reportable(self) -> list[Finding]:
        """Reportable findings, sorted by severity then priority (highest first)."""
        items = [f for f in self.findings if f.is_included_in_report and is_reportable(f.verification_status)]
        return sorted(items, key=lambda f: (_SEVERITY_ORDER[f.severity], -(f.affected_port or 0)))

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.reportable():
            counts[f.severity.value] += 1
        return counts

    def safe_summary(self, finding: Finding) -> str:
        return sanitize(finding.summary)
