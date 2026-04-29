"""
Vulnerability suppression — state and predicates.

Moved from backend/app/api/releases.py:_is_suppressed in B.2 (2026-04-30).
Behavior bit-identical to the prior helper.

Per code-principles.md §E1: a vulnerability is suppressed iff
`suppressed=True` AND (`suppressed_until is None` OR `suppressed_until > now`).
Naive datetimes (no tzinfo) are treated as UTC.

Stage B.4 will add a `Suppression` value object with __post_init__ invariants
(per Constraint B from user 2026-04-30: exactly 3 invariants).
"""
from __future__ import annotations

from datetime import datetime, timezone


def is_suppressed(vuln) -> bool:
    """Return True iff vuln.suppressed AND (suppressed_until is None OR future).

    The argument is duck-typed: anything with `.suppressed` (bool) and
    `.suppressed_until` (datetime | None) attributes is accepted.  ORM
    Vulnerability rows satisfy this; so does any value object that mirrors
    the same shape.
    """
    if not vuln.suppressed:
        return False
    if vuln.suppressed_until is None:
        return True
    ts = vuln.suppressed_until
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < ts
