"""
Function-level characterization for `_highest_severity` (currently in
backend/app/api/releases.py:2098).

Locks the reduce-by-severity-order behavior. SEVERITY_ORDER comes from
backend/app/core/constants.py (canonical: critical=4, high=3, medium=2,
low=1, info=0).

After B.3 both the constant and the helper move to
backend/app/domain/severity.py.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

# IMPORT PIN — updated to backend/app/domain/severity.py in B.3
from app.api.releases import _highest_severity


def _vulns(*severities):
    return [SimpleNamespace(severity=s) for s in severities]


# ── Empty / None ──────────────────────────────────────────────────────────────

@pytest.mark.function_level
def test_empty_list_returns_none():
    assert _highest_severity([]) is None


# ── Single element ────────────────────────────────────────────────────────────

@pytest.mark.function_level
@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low", "info"])
def test_single_element_returns_itself(sev):
    assert _highest_severity(_vulns(sev)) == sev


# ── Multi-element max behavior ────────────────────────────────────────────────

@pytest.mark.function_level
def test_multi_element_picks_highest():
    assert _highest_severity(_vulns("low", "medium", "high")) == "high"


@pytest.mark.function_level
def test_critical_wins_over_all():
    assert _highest_severity(_vulns("info", "low", "medium", "high", "critical")) == "critical"


@pytest.mark.function_level
def test_order_independence():
    """Result must not depend on input order."""
    assert _highest_severity(_vulns("critical", "low")) == _highest_severity(_vulns("low", "critical"))


# ── Unknown severity treated as info ──────────────────────────────────────────

@pytest.mark.function_level
def test_unknown_severity_treated_as_info():
    """SEVERITY_ORDER.get(unknown, 0) == info rank, so unknowns lose to anything ranked."""
    result = _highest_severity(_vulns("low", "totally-bogus"))
    # 'low' ranks 1; 'totally-bogus' falls back to 0 (info rank); low wins
    assert result == "low"


@pytest.mark.function_level
def test_only_unknown_severities_returns_first_max():
    """All unknown ⇒ max() picks the first by Python's stable max semantics
    when ranks tie (SEVERITY_ORDER.get returns 0 for both)."""
    result = _highest_severity(_vulns("foo", "bar"))
    assert result == "foo"  # stable: first item wins on tie


# ── None severity coerced to "info" rank ──────────────────────────────────────

@pytest.mark.function_level
def test_none_severity_treated_as_info():
    """The helper does (v.severity or "info") before SEVERITY_ORDER lookup."""
    result = _highest_severity(_vulns(None, "low"))
    assert result == "low"
