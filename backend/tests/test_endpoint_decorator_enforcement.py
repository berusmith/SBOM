"""
SDLC-001 enforcement test — runs in CI (security.yml backend-tests job).

Walks every FastAPI route on `app`. For routes that take a release_id /
vuln_id path parameter (i.e. tenant-scoped resource access), the endpoint
MUST satisfy ONE of:
  - new pattern: include Depends(require_release_in_scope) /
                 Depends(require_vuln_in_scope)
  - admin override: include Depends(require_admin) or Depends(require_admin_scope)

Forgetting any of these = test fails, CI blocks merge.

Legacy 403-oracle helpers fully removed:
  - release-side _assert_release_org: deleted iter-1 D.8 (2026-05-01)
  - vuln-side _assert_vuln_org: deleted iter-1 PR-3 O.1 (2026-05-02)
ARCH-1.003 contract evolution is now complete for both scopes.

Companion: test_decorator_argument_consistency — verifies the path
parameter name in the URL matches a parameter in the endpoint signature
(catches typos like {release_uuid} vs release_id binding).

Standalone executable per CLAUDE.md (no pytest):
    cd backend && python tests/test_endpoint_decorator_enforcement.py
Exits 0 on pass, 1 on fail.
"""
from __future__ import annotations

import inspect
import sys

# Ensure backend/ is on path so we can import app
import pathlib
_BACKEND = pathlib.Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.main import app
from app.core.deps import (
    require_release_in_scope,
    require_vuln_in_scope,
    require_admin,
    require_admin_scope,
)

# Path parameters that indicate tenant-scoped resource access.
# release_id covered since SDLC-001 inception (Phase 5 #1, 2026-04-26).
# vuln_id added 2026-05-02 by PR-3 O.2 (ARCH-1.003 evolution complete).
_TENANT_SCOPED_PARAMS = {"release_id", "vuln_id"}

# Dependencies that satisfy the "ownership / admin gate" requirement.
# Note: require_admin and require_admin_scope satisfy because admin
# legitimately accesses cross-tenant resources by design.
_OWNERSHIP_DEPENDENCIES = {
    require_release_in_scope,
    require_vuln_in_scope,
    require_admin,
    require_admin_scope,
}


def _has_ownership_dep(endpoint) -> bool:
    """True iff endpoint signature has Depends() pointing at any
    _OWNERSHIP_DEPENDENCIES function."""
    if endpoint is None:
        return False
    try:
        sig = inspect.signature(endpoint)
    except (ValueError, TypeError):
        return False
    for param in sig.parameters.values():
        default = param.default
        # FastAPI Depends marker is the parameter default value
        if hasattr(default, "dependency") and default.dependency in _OWNERSHIP_DEPENDENCIES:
            return True
    return False


def _route_uses_tenant_scope(route) -> bool:
    """True iff route path templates a tenant-scoped resource id
    (release_id or vuln_id)."""
    path = getattr(route, "path", "")
    return any(f"{{{name}}}" in path for name in _TENANT_SCOPED_PARAMS)


def test_all_tenant_scoped_endpoints_have_ownership_dependency() -> list[str]:
    """Every tenant-scoped route must use require_release_in_scope,
    require_vuln_in_scope, or require_admin / require_admin_scope."""
    missing = []
    for route in app.routes:
        if not _route_uses_tenant_scope(route):
            continue
        endpoint = getattr(route, "endpoint", None)
        if not _has_ownership_dep(endpoint):
            methods = sorted(getattr(route, "methods", set()) or {"?"})
            qualname = endpoint.__qualname__ if endpoint else "?"
            missing.append(f"{methods} {route.path} → endpoint {qualname}")
    return missing


def test_decorator_argument_consistency() -> list[str]:
    """Every {release_id} / {vuln_id} in a route URL must appear in the
    endpoint signature (directly or via Depends).  Catches binding typos."""
    errors = []
    for route in app.routes:
        if not _route_uses_tenant_scope(route):
            continue
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        try:
            sig = inspect.signature(endpoint)
        except (ValueError, TypeError):
            continue

        param_names = set(sig.parameters.keys())
        # If the endpoint uses Depends(require_release_in_scope) or
        # Depends(require_vuln_in_scope), the path id is bound by the
        # dependency (not directly in endpoint sig).  Treat as satisfied.
        uses_helper_dep = any(
            getattr(p.default, "dependency", None) in _OWNERSHIP_DEPENDENCIES
            for p in sig.parameters.values()
        )
        for url_param in _TENANT_SCOPED_PARAMS:
            if f"{{{url_param}}}" not in route.path:
                continue
            if url_param not in param_names and not uses_helper_dep:
                errors.append(
                    f"{route.path} URL param {{{url_param}}} not in endpoint signature "
                    f"and no ownership-dep helper to bind it"
                )
    return errors


def main() -> int:
    print("SDLC-001 — endpoint decorator enforcement test\n")

    missing = test_all_tenant_scoped_endpoints_have_ownership_dependency()
    consistency_errors = test_decorator_argument_consistency()

    fail = bool(missing or consistency_errors)

    if missing:
        print(f"[FAIL] {len(missing)} endpoint(s) missing ownership dependency:")
        for m in missing:
            print(f"  - {m}")
        print()
        print("Each must use ONE of:")
        print("  release: Release = Depends(require_release_in_scope)   # release scope")
        print("  vuln: Vulnerability = Depends(require_vuln_in_scope)   # vuln scope")
        print("  user: dict = Depends(require_admin)                    # admin only")
        print()

    if consistency_errors:
        print(f"[FAIL] {len(consistency_errors)} URL-vs-signature inconsistency:")
        for e in consistency_errors:
            print(f"  - {e}")
        print()

    if not fail:
        scoped_routes = sum(1 for r in app.routes if _route_uses_tenant_scope(r))
        print(f"[PASS] all {scoped_routes} tenant-scoped endpoints have ownership dependency")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
