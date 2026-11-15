"""Markdown report generator (DOC-08). Deterministic, air-gapped, no external references."""

from __future__ import annotations

from bletiner.reporting.model import ReportContext
from bletiner.reporting.sanitizer import sanitize


def _esc(text: str) -> str:
    # Neutralize Markdown control characters in untrusted strings.
    return sanitize(text).replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def build_markdown(ctx: ReportContext) -> str:
    counts = ctx.severity_counts()
    lines: list[str] = [
        f"# {_esc(ctx.title)}",
        "",
        f"- **Primary target:** `{_esc(ctx.primary_target)}`",
        f"- **Authorized scope:** {', '.join(f'`{_esc(s)}`' for s in ctx.authorized_scope) or 'n/a'}",
        f"- **Generated:** {ctx.generated_at.isoformat()}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines += [f"| {sev} | {counts[sev]} |" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    lines += ["", "## Findings", ""]

    reportable = ctx.reportable()
    if not reportable:
        lines.append("_No reportable findings._")
    for i, f in enumerate(reportable, 1):
        asset = f"{_esc(f.affected_asset)}" + (f":{f.affected_port}" if f.affected_port else "")
        lines += [
            f"### {i}. {_esc(f.title)}",
            "",
            f"- **Severity:** {f.severity.value} | **Confidence:** {f.confidence.value} | "
            f"**Status:** {f.verification_status.value}",
            f"- **Asset:** `{asset}`",
            f"- **Category:** {_esc(f.category)} | **Detection:** {_esc(f.detection_method)}",
            "",
            _esc(f.summary),
            "",
        ]
        if f.impact_statement:
            lines += [f"**Impact:** {_esc(f.impact_statement)}", ""]
        if f.remediation_guidance:
            lines += [f"**Remediation:** {_esc(f.remediation_guidance)}", ""]
    return "\n".join(lines).rstrip() + "\n"
