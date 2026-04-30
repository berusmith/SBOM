"""
Vulnerability suppression — state, predicates, and value object.

The is_suppressed predicate (moved from releases.py in B.2) operates on
ORM Vulnerability rows or any duck-typed object with .suppressed and
.suppressed_until attributes — used on read paths.

The Suppression value object (added in B.4 per AC-D3 from
.refactor-audit/iteration-1/calibration.md §3.3) is the canonical
construction interface for NEW suppressions — used on write paths.
Per code-principles.md §E1 + Constraint B (user iter-1 review 2026-04-30),
__post_init__ enforces EXACTLY 3 invariants — no more, no less:

  1. Suppression(suppressed=True, suppressed_until=<past>) raises ValueError
     "Already-expired suppression should not be constructed"
  2. Suppression(suppressed=False, suppressed_until=<not None>) raises ValueError
     "Expiry has no meaning without active suppression"
  3. Suppression(suppressed=True, reason=<None / empty / whitespace>)
     raises ValueError
     "Active suppression requires a non-blank reason for auditability"

Out of scope for B.4 — these belong in followups FU-1.NNN, not here:
  - timezone enforcement (naive datetimes coerced to UTC, not rejected)
  - reason length / charset constraints
  - suppressed_by user_id existence check (cross-table FK)
  - cross-validation against the Vulnerability row's other fields
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


def is_suppressed(vuln) -> bool:
    """Return True iff vuln.suppressed AND (suppressed_until is None OR future).

    The argument is duck-typed: anything with `.suppressed` (bool) and
    `.suppressed_until` (datetime | None) attributes is accepted.  ORM
    Vulnerability rows satisfy this; so does the Suppression value object
    below (whose attribute names match).

    Naive datetimes (no tzinfo) are coerced to UTC per code-principles.md §E1.
    """
    if not vuln.suppressed:
        return False
    if vuln.suppressed_until is None:
        return True
    ts = vuln.suppressed_until
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < ts


@dataclass(frozen=True)
class Suppression:
    """Immutable value object for constructing a suppression state.

    See module docstring for the 3 invariants enforced here.  The field
    names mirror the ORM Vulnerability columns so this object is duck-type
    compatible with `is_suppressed(suppression)` above.
    """
    suppressed: bool
    suppressed_until: datetime | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        # Invariant 2: inconsistent state — no expiry without active suppression
        if not self.suppressed and self.suppressed_until is not None:
            raise ValueError(
                "Suppression(suppressed=False, suppressed_until=...) is invalid: "
                "an expiry timestamp has no meaning without an active suppression"
            )

        if self.suppressed:
            # Invariant 1: a suppression that is already expired at construction
            # time should not be persisted.  Naive datetimes are coerced to UTC
            # (consistent with code-principles.md §E1, NOT rejection — per
            # Constraint B "no timezone enforcement").
            if self.suppressed_until is not None:
                ts = self.suppressed_until
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < datetime.now(timezone.utc):
                    raise ValueError(
                        "Suppression(suppressed=True, suppressed_until=<past>) "
                        "is invalid: an already-expired suppression should not "
                        "be constructed (caller should mark suppressed=False)"
                    )

            # Invariant 3: auditability — every active suppression must carry a
            # non-blank reason.  None / "" / whitespace-only all rejected.
            if not (self.reason or "").strip():
                raise ValueError(
                    "Suppression(suppressed=True) requires a non-blank reason "
                    "for auditability (per code-principles.md §E1)"
                )
