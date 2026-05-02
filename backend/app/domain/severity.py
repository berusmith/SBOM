"""
Severity ordering + reduction operations.

`SEVERITY_ORDER` is the single canonical mapping (collapsed in B.3 from
backend/app/core/constants.py and backend/app/services/alerts.py:_SEV_ORDER).
The numeric values' ABSOLUTE magnitude does not matter; only their relative
order.  Callers MUST use the ".get(sev, -1)" pattern when comparing arbitrary
severity strings against this map — the -1 default ensures unknown severities
sort BELOW "info" (preserves the prior behavior of alerts.py:_SEV_ORDER which
defaulted to 0 in a 1-indexed scale).

⚠️  DO NOT change the .get() default to 0.  See .refactor-audit/invariants.md
    §VII.1 INV-D1 for the full rationale.  Default 0 would equal info's rank
    (info=0 in this scale), silently flipping the alert-rule filter behavior
    on unknown severities from "filter out" to "pass through".  This is a
    SUBTLE semantic-equivalence trap from the B.3 collapse — codified as an
    invariant precisely because the bug is invisible in code review.

Per code-principles.md §F (module conventions): no Repository pattern,
no port-for-single-impl; the dict is the canonical surface.
"""
from __future__ import annotations

# Canonical severity rank.  info=0; unknown defaults to -1 at call sites.
SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


def highest_severity(vulns) -> str | None:
    """Return the highest-ranked severity in the iterable, or None if empty.

    Unknown severities (and None) fall back to the "info" rank (0) for the
    purpose of this reduce — preserves prior behavior where `v.severity or "info"`
    was the lookup key with default 0.
    """
    if not vulns:
        return None
    return max(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity or "info", 0)).severity
