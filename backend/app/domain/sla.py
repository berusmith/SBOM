"""
SLA (Service Level Agreement) tracking for vulnerability remediation.

Moved from backend/app/api/releases.py (_SLA_DAYS, _sla_info) and
backend/app/api/stats.py (duplicate _SLA_DAYS) in B.2 (2026-04-30).
Behavior bit-identical to the prior helpers.

Severity → SLA days mapping is the canonical source per code-principles.md §E2.
Both releases.py and stats.py now import from here (CODE-1.020 resolved).
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.domain.suppression import is_suppressed

# Severity → days-to-fix SLA per code-principles.md §E2.
SLA_DAYS: dict[str, int] = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def sla_info(vuln) -> dict:
    """Return {sla_days, sla_status} for a vulnerability.

    Short-circuits to {"sla_days": None, "sla_status": "n/a"} if any of:
      - vuln is suppressed (per is_suppressed)
      - vuln.status is in {"fixed", "not_affected"}
      - vuln.severity is not in SLA_DAYS (info / unknown / None)
      - vuln.scanned_at is None

    Otherwise returns:
      sla_days: int (negative if past due)
      sla_status: "overdue" if days < 0; "warning" if days ≤ 7; else "ok"
    """
    if is_suppressed(vuln) or vuln.status in ("fixed", "not_affected") or vuln.severity not in SLA_DAYS or not vuln.scanned_at:
        return {"sla_days": None, "sla_status": "n/a"}
    scanned = vuln.scanned_at
    if scanned.tzinfo is None:
        scanned = scanned.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - scanned).days
    remaining = SLA_DAYS[vuln.severity] - elapsed
    status = "overdue" if remaining < 0 else "warning" if remaining <= 7 else "ok"
    return {"sla_days": remaining, "sla_status": status}
