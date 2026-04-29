"""
Severity ordering + reduction operations.

Moved from backend/app/api/releases.py:_highest_severity in B.2 (2026-04-30).
Behavior bit-identical to the prior helper.

SEVERITY_ORDER stays in backend/app/core/constants.py for B.2 (imported below);
B.3 will collapse the constant — moving SEVERITY_ORDER here AND folding
backend/app/services/alerts.py:_SEV_ORDER into the same canonical mapping.
"""
from __future__ import annotations

# B.2: import the canonical mapping from its current home (core/constants).
# B.3: this import is replaced by an in-file definition + alerts.py is updated.
from app.core.constants import SEVERITY_ORDER


def highest_severity(vulns) -> str | None:
    """Return the highest-ranked severity in the iterable, or None if empty.

    Unknown severities (and None) fall back to the "info" rank (0).
    Order independence: the result depends only on the multiset of severities,
    except that ties between equally-low-ranked severities are resolved by
    Python's stable max (first-occurrence wins).
    """
    if not vulns:
        return None
    return max(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity or "info", 0)).severity
