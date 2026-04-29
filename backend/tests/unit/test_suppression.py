"""
Function-level characterization for `_is_suppressed` (currently in
backend/app/api/releases.py:64).

Locks the boundary behavior in place before B.2 moves the helper to
backend/app/domain/suppression.py.  After B.2, only the import line
in this file changes; assertions stay identical.

Per AC-T1 (.refactor-audit/iteration-1/calibration.md §3.3): function_level
tests count toward the ≥ 1/3 requirement for Test quality dim to score 6.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

# IMPORT updated in B.2 (2026-04-30) — was: from app.api.releases import _is_suppressed
from app.domain.suppression import is_suppressed


def _vuln(suppressed: bool, until=None):
    """Duck-typed vuln.  _is_suppressed reads only .suppressed and .suppressed_until."""
    return SimpleNamespace(suppressed=suppressed, suppressed_until=until)


# ── Headline: not suppressed ──────────────────────────────────────────────────

@pytest.mark.function_level
def test_not_suppressed_returns_false():
    assert is_suppressed(_vuln(False)) is False


@pytest.mark.function_level
def test_not_suppressed_with_until_set_still_false():
    """suppressed=False trumps any suppressed_until value."""
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert is_suppressed(_vuln(False, future)) is False


# ── Headline: permanently suppressed (no expiry) ──────────────────────────────

@pytest.mark.function_level
def test_suppressed_no_until_is_permanent():
    assert is_suppressed(_vuln(True, None)) is True


# ── Headline: time-bounded suppression ────────────────────────────────────────

@pytest.mark.function_level
def test_suppressed_with_future_until_is_active():
    future = datetime.now(timezone.utc) + timedelta(days=7)
    assert is_suppressed(_vuln(True, future)) is True


@pytest.mark.function_level
def test_suppressed_with_past_until_is_expired():
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert is_suppressed(_vuln(True, past)) is False


@pytest.mark.function_level
def test_suppressed_with_now_boundary():
    """Edge: suppressed_until == now → strict < comparison means already expired."""
    now = datetime.now(timezone.utc)
    # The helper compares datetime.now(tz=UTC) < ts.  Since 'now' captured here
    # is slightly earlier than the helper's own datetime.now() call inside,
    # the helper's now will be > our captured now → returns False (expired).
    assert is_suppressed(_vuln(True, now)) is False


# ── Headline: timezone-naive datetime gets coerced to UTC ─────────────────────

@pytest.mark.function_level
def test_naive_datetime_is_coerced_to_utc():
    """Per code-principles.md §E1, naive timestamps are treated as UTC."""
    future_naive = datetime.utcnow() + timedelta(days=1)  # naive
    assert future_naive.tzinfo is None  # invariant of test setup
    assert is_suppressed(_vuln(True, future_naive)) is True


@pytest.mark.function_level
def test_naive_past_datetime_is_expired():
    past_naive = datetime.utcnow() - timedelta(days=1)
    assert past_naive.tzinfo is None
    assert is_suppressed(_vuln(True, past_naive)) is False
