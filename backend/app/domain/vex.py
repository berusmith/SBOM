"""
VEX state machine (open / in_triage / not_affected / affected / fixed) and
the cross-field invariants between status × justification × response.

**Iter-1 placeholder only.**  Currently the VEX state-machine logic lives
ad-hoc in backend/app/api/vulnerabilities.py PATCH handlers (per
code-principles.md §E3).  Full extraction is iter-2 candidate; this file
exists in iter-1 to reserve the namespace and signal future intent.
"""
