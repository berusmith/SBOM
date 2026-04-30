"""
Function-level characterization for the Suppression value object
(backend/app/domain/suppression.py:Suppression).

Tests EXACTLY the 3 invariants from Constraint B (user iter-1 review
2026-04-30); does NOT test additional constraints (timezone enforcement,
reason length, etc.) — those are followup FU-1.NNN candidates.

Per AC-T1 (.refactor-audit/iteration-1/calibration.md §3.3): function_level
tests count toward the ≥ 1/3 requirement.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.domain.suppression import Suppression


# ── Happy paths ──────────────────────────────────────────────────────────────

@pytest.mark.function_level
def test_not_suppressed_no_until_no_reason_ok():
    """Most basic case: no suppression at all."""
    s = Suppression(suppressed=False)
    assert s.suppressed is False
    assert s.suppressed_until is None
    assert s.reason is None


@pytest.mark.function_level
def test_not_suppressed_with_reason_ok():
    """Reason without suppression is allowed (e.g. historical note)."""
    s = Suppression(suppressed=False, reason="historical note")
    assert s.reason == "historical note"


@pytest.mark.function_level
def test_permanent_suppression_with_reason_ok():
    s = Suppression(suppressed=True, reason="Fixing in v2.5 — see ticket #123")
    assert s.suppressed is True
    assert s.suppressed_until is None
    assert s.reason == "Fixing in v2.5 — see ticket #123"


@pytest.mark.function_level
def test_time_bound_suppression_future_ok():
    future = datetime.now(timezone.utc) + timedelta(days=30)
    s = Suppression(suppressed=True, suppressed_until=future, reason="awaiting upstream patch")
    assert s.suppressed_until == future


@pytest.mark.function_level
def test_naive_datetime_coerced_not_rejected():
    """Per Constraint B 'no timezone enforcement': naive datetime is accepted
    (and treated as UTC for the past/future comparison)."""
    future_naive = datetime.utcnow() + timedelta(days=7)  # naive
    assert future_naive.tzinfo is None  # invariant of test setup
    s = Suppression(suppressed=True, suppressed_until=future_naive, reason="...")
    assert s.suppressed_until == future_naive


# ── Invariant 1: past suppressed_until on active suppression ─────────────────

@pytest.mark.function_level
def test_invariant_1_past_until_rejected():
    past = datetime.now(timezone.utc) - timedelta(days=1)
    with pytest.raises(ValueError, match="already-expired"):
        Suppression(suppressed=True, suppressed_until=past, reason="reason")


@pytest.mark.function_level
def test_invariant_1_past_naive_until_rejected():
    """Naive past datetime: coerced to UTC for comparison, then rejected."""
    past_naive = datetime.utcnow() - timedelta(seconds=10)
    assert past_naive.tzinfo is None
    with pytest.raises(ValueError, match="already-expired"):
        Suppression(suppressed=True, suppressed_until=past_naive, reason="reason")


# ── Invariant 2: inconsistent state (not suppressed but has until) ───────────

@pytest.mark.function_level
def test_invariant_2_inconsistent_state_rejected():
    future = datetime.now(timezone.utc) + timedelta(days=1)
    with pytest.raises(ValueError, match="no meaning without an active suppression"):
        Suppression(suppressed=False, suppressed_until=future)


@pytest.mark.function_level
def test_invariant_2_inconsistent_state_with_past_also_rejected():
    """Same invariant — order of check shouldn't depend on the until value."""
    past = datetime.now(timezone.utc) - timedelta(days=1)
    with pytest.raises(ValueError, match="no meaning without an active suppression"):
        Suppression(suppressed=False, suppressed_until=past)


# ── Invariant 3: blank reason on active suppression ──────────────────────────

@pytest.mark.function_level
def test_invariant_3_no_reason_rejected():
    with pytest.raises(ValueError, match="non-blank reason"):
        Suppression(suppressed=True)


@pytest.mark.function_level
def test_invariant_3_none_reason_rejected():
    with pytest.raises(ValueError, match="non-blank reason"):
        Suppression(suppressed=True, reason=None)


@pytest.mark.function_level
def test_invariant_3_empty_reason_rejected():
    with pytest.raises(ValueError, match="non-blank reason"):
        Suppression(suppressed=True, reason="")


@pytest.mark.function_level
@pytest.mark.parametrize("reason", ["   ", "\t", "\n", "\t \n", "  \r\n  "])
def test_invariant_3_whitespace_only_reason_rejected(reason):
    with pytest.raises(ValueError, match="non-blank reason"):
        Suppression(suppressed=True, reason=reason)


# ── Frozen dataclass — immutability ──────────────────────────────────────────

@pytest.mark.function_level
def test_suppression_is_immutable():
    """Frozen dataclass — attempting to mutate raises FrozenInstanceError."""
    from dataclasses import FrozenInstanceError
    s = Suppression(suppressed=True, reason="x")
    with pytest.raises(FrozenInstanceError):
        s.suppressed = False  # type: ignore[misc]


# ── Out-of-scope invariants are NOT enforced (deferred to followups) ─────────

@pytest.mark.function_level
def test_no_reason_length_check():
    """Per Constraint B: reason length is NOT enforced.  Long reasons accepted."""
    long_reason = "x" * 10000
    s = Suppression(suppressed=True, reason=long_reason)
    assert s.reason == long_reason


@pytest.mark.function_level
def test_no_charset_check():
    """Per Constraint B: reason charset is NOT enforced.  Any chars accepted."""
    s = Suppression(suppressed=True, reason="🔥💥 \x00 emoji + null byte")
    assert s.reason == "🔥💥 \x00 emoji + null byte"


# ── Duck-type compatibility with is_suppressed ───────────────────────────────

@pytest.mark.function_level
def test_suppression_is_duck_type_compatible_with_is_suppressed():
    """The Suppression value object should be a drop-in argument to the
    is_suppressed(vuln) predicate — same attribute names."""
    from app.domain.suppression import is_suppressed
    permanent = Suppression(suppressed=True, reason="test")
    assert is_suppressed(permanent) is True

    not_supp = Suppression(suppressed=False)
    assert is_suppressed(not_supp) is False

    future = datetime.now(timezone.utc) + timedelta(days=1)
    time_bound = Suppression(suppressed=True, suppressed_until=future, reason="test")
    assert is_suppressed(time_bound) is True
