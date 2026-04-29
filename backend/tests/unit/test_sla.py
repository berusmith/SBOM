"""
Function-level characterization for `_sla_info` (currently in
backend/app/api/releases.py:75).

Locks the SLA invariants:
  - suppressed → "n/a"
  - status in {fixed, not_affected} → "n/a"
  - severity not in {critical, high, medium, low} → "n/a"
  - scanned_at is None → "n/a"
  - elapsed > sla_days → "overdue"
  - elapsed within 7d of sla_days → "warning"
  - else → "ok"

After B.2 the import path moves to backend/app/domain/sla.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

# IMPORT PIN — updated to backend/app/domain/sla.py in B.2
from app.api.releases import _sla_info


def _vuln(*, severity, status, scanned_days_ago=None, suppressed=False, suppressed_until=None):
    scanned_at = (datetime.now(timezone.utc) - timedelta(days=scanned_days_ago)) if scanned_days_ago is not None else None
    return SimpleNamespace(
        severity=severity,
        status=status,
        scanned_at=scanned_at,
        suppressed=suppressed,
        suppressed_until=suppressed_until,
    )


# ── Suppression short-circuits SLA ────────────────────────────────────────────

@pytest.mark.function_level
def test_suppressed_returns_na():
    info = _sla_info(_vuln(severity="critical", status="open", scanned_days_ago=100, suppressed=True))
    assert info == {"sla_days": None, "sla_status": "n/a"}


# ── Status short-circuits ─────────────────────────────────────────────────────

@pytest.mark.function_level
@pytest.mark.parametrize("status", ["fixed", "not_affected"])
def test_terminal_status_returns_na(status):
    info = _sla_info(_vuln(severity="critical", status=status, scanned_days_ago=100))
    assert info == {"sla_days": None, "sla_status": "n/a"}


# ── Unknown severity short-circuits ──────────────────────────────────────────

@pytest.mark.function_level
@pytest.mark.parametrize("severity", ["info", None, ""])
def test_unknown_severity_returns_na(severity):
    info = _sla_info(_vuln(severity=severity, status="open", scanned_days_ago=10))
    assert info == {"sla_days": None, "sla_status": "n/a"}


# ── Missing scanned_at → na ───────────────────────────────────────────────────

@pytest.mark.function_level
def test_missing_scanned_at_returns_na():
    info = _sla_info(_vuln(severity="critical", status="open", scanned_days_ago=None))
    assert info == {"sla_days": None, "sla_status": "n/a"}


# ── SLA windows per severity ─────────────────────────────────────────────────

@pytest.mark.function_level
@pytest.mark.parametrize(
    "severity, sla_days_total",
    [("critical", 7), ("high", 30), ("medium", 90), ("low", 180)],
)
def test_sla_status_overdue(severity, sla_days_total):
    """Scanned more days ago than the SLA permits → overdue, sla_days < 0."""
    info = _sla_info(_vuln(severity=severity, status="open", scanned_days_ago=sla_days_total + 5))
    assert info["sla_status"] == "overdue"
    assert info["sla_days"] < 0


@pytest.mark.function_level
@pytest.mark.parametrize(
    "severity, sla_days_total",
    [("critical", 7), ("high", 30), ("medium", 90), ("low", 180)],
)
def test_sla_status_warning_within_7_days(severity, sla_days_total):
    """Scanned (sla_days_total - 3) days ago → 3 days remaining → warning band."""
    info = _sla_info(_vuln(severity=severity, status="open", scanned_days_ago=sla_days_total - 3))
    assert info["sla_status"] == "warning"
    assert 0 <= info["sla_days"] <= 7


@pytest.mark.function_level
@pytest.mark.parametrize(
    "severity, sla_days_total",
    [("critical", 7), ("high", 30), ("medium", 90), ("low", 180)],
)
def test_sla_status_ok_well_before_warning_band(severity, sla_days_total):
    """For severities where the 7-day warning band still leaves an 'ok' window
    (high/medium/low), test that comfortably-early scan returns ok."""
    if sla_days_total <= 7:
        pytest.skip("critical's 7-day window has no 'ok' band — first day is already warning")
    info = _sla_info(_vuln(severity=severity, status="open", scanned_days_ago=1))
    assert info["sla_status"] == "ok"
    assert info["sla_days"] > 7


# ── Naive scanned_at coerced to UTC ──────────────────────────────────────────

@pytest.mark.function_level
def test_naive_scanned_at_coerced():
    """scanned_at without tzinfo treated as UTC (per code-principles.md §E1)."""
    naive_recent = datetime.utcnow() - timedelta(days=1)
    assert naive_recent.tzinfo is None
    info = _sla_info(SimpleNamespace(
        severity="medium", status="open", scanned_at=naive_recent,
        suppressed=False, suppressed_until=None,
    ))
    # 1 day in on a 90-day SLA → ok
    assert info["sla_status"] == "ok"
