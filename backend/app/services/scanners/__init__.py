"""
Scanners — subprocess wrappers and analyzers for source / binary / IaC inputs.

Sub-packages:
  reachability/  — package reachability classifier (Python today; JS/Java in Wave D)

(`trivy_scanner.py`, `syft_scanner.py`, `signature_verifier.py` remain at
`backend/app/services/` for now — moving them into this package is a future
iter scope; per .refactor-audit/architecture.md §4.1.)
"""
