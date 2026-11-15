"""Gate-3 live-certification guard (DOC-14 rule 5 / section 10, mandatory instruction #6).

The autonomous agent must NOT run against a live sandbox until ``scripts/verify_gateway_poc.py`` has passed
all scenarios on real Docker. This module enforces that in code: the live investigation service calls
:func:`require_gate3_certified` before INITIALIZING; it raises unless a genuine passing report exists.

A report counts as passing only if it was produced in ``live`` mode with every test ``PASS`` and none
``NOT RUN``/``FAIL`` — a simulated or NOT-RUN report can never certify the gate (docs/16 R-05).
"""

from __future__ import annotations

import json
from pathlib import Path

from bletiner.models.errors import PoCVerificationFailedError

DEFAULT_EVIDENCE_DIR = Path("evidence/phase3")


def latest_report(evidence_dir: Path = DEFAULT_EVIDENCE_DIR) -> dict[str, object] | None:
    if not evidence_dir.is_dir():
        return None
    reports = sorted(evidence_dir.glob("gate3_*.json"))
    if not reports:
        return None
    try:
        return dict(json.loads(reports[-1].read_text()))
    except (OSError, json.JSONDecodeError):
        return None


def is_gate3_certified(evidence_dir: Path = DEFAULT_EVIDENCE_DIR) -> bool:
    report = latest_report(evidence_dir)
    if report is None:
        return False
    if report.get("mode") != "live":
        return False
    totals = report.get("totals")
    if not isinstance(totals, dict):
        return False
    return (
        bool(report.get("gate_passed"))
        and int(totals.get("fail", 1)) == 0
        and int(totals.get("not_run", 1)) == 0
        and int(totals.get("total", 0)) > 0
    )


def require_gate3_certified(evidence_dir: Path = DEFAULT_EVIDENCE_DIR) -> None:
    """Raise ``PoCVerificationFailedError`` unless a genuine passing live gate report exists."""
    if not is_gate3_certified(evidence_dir):
        raise PoCVerificationFailedError(
            "Gate 3 egress PoC has not passed live on Docker; the autonomous agent must not run against a "
            "live sandbox until `python scripts/verify_gateway_poc.py --build` passes all scenarios "
            "(DOC-14 rule 5 / section 10)."
        )
