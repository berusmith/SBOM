"""
Domain layer.  Pure business logic, framework-agnostic.

AC-D2 invariant (.refactor-audit/iteration-1/calibration.md §3.3): nothing
under this package may import from `fastapi`, `sqlalchemy`, or `app.api`.
Verified by mechanical grep at the close of Stage B.

Modules:
  suppression  — vulnerability suppression state + invariants
  sla          — SLA tracking + status computation
  severity     — severity ordering + max reduction
  vex          — VEX state machine (placeholder iter-1; full extraction in iter-2)
"""
