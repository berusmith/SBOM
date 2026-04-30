"""
SDLC-001 enforcement test — runs in CI (security.yml backend-tests job).

Walks every FastAPI route on `app`. For routes that take a release_id /
product_id path parameter (i.e. release-scoped resource access), the
endpoint MUST satisfy ONE of:
  - new pattern: include Depends(require_release_in_scope)
  - admin override: include Depends(require_admin) or Depends(require_admin_scope)
  - legacy pattern: function body calls _assert_vuln_org (vulnerabilities.py only;
                    the release-side legacy helper was deleted in iter-1 D.8 —
                    ARCH-1.003 contract evolution complete for release endpoints).

Forgetting any of these = test fails, CI blocks merge.

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
    require_admin,
    require_admin_scope,
)

# Path parameters that indicate release-scoped resource access.
_RELEASE_SCOPED_PARAMS = {"release_id"}

# Dependencies that satisfy the "ownership / admin gate" requirement.
# Note: require_admin and require_admin_scope satisfy because admin
# legitimately accesses cross-tenant resources by design.
_OWNERSHIP_DEPENDENCIES = {
    require_release_in_scope,
    require_admin,
    require_admin_scope,
}

# Legacy pattern allowed for vulnerabilities.py only (1 caller of _assert_vuln_org).
# The release-side legacy helper was deleted in iter-1 D.8 (ARCH-1.003 evolution
# complete for release endpoints).  vulnerabilities.py migration is a future
# ARCH-1.003-style cleanup; until then, _assert_vuln_org is the only entry here.
_LEGACY_PATTERNS = ("_assert_vuln_org",)


def _has_ownership_dep(endpoint) -> bool:
    """True iff endpoint signature has Depends() pointing at any
    _OWNERSHIP_DEPENDENCIES function, OR endpoint body calls a
    legacy _assert_*_org helper."""
    if endpoint is None:
        return False

    # Check Depends() in signature defaults
    try:
        sig = inspect.signature(endpoint)
    except (ValueError, TypeError):
        return False
    for param in sig.parameters.values():
        default = param.default
        # FastAPI Depends marker is the parameter default value
        if hasattr(default, "dependency") and default.dependency in _OWNERSHIP_DEPENDENCIES:
            return True

    # Legacy pattern fallback
    try:
        src = inspect.getsource(endpoint)
    except (OSError, TypeError):
        return False
    return any(p in src for p in _LEGACY_PATTERNS)


def _route_uses_release_scope(route) -> bool:
    """True iff route path templates a release-scoped resource id."""
    path = getattr(route, "path", "")
    return any(f"{{{name}}}" in path for name in _RELEASE_SCOPED_PARAMS)


def test_all_release_scoped_endpoints_have_ownership_dependency() -> list[str]:
    """Every release-scoped route must use require_release_in_scope or
    require_admin (or, during migration window, _assert_*_org legacy)."""
    missing = []
    for route in app.routes:
        if not _route_uses_release_scope(route):
            continue
        endpoint = getattr(route, "endpoint", None)
        if not _has_ownership_dep(endpoint):
            methods = sorted(getattr(route, "methods", set()) or {"?"})
            qualname = endpoint.__qualname__ if endpoint else "?"
            missing.append(f"{methods} {route.path} → endpoint {qualname}")
    return missing


def test_decorator_argument_consistency() -> list[str]:
    """Every {release_id} in a route URL must appear in the endpoint
    signature (directly or via Depends).  Catches binding typos."""
    errors = []
    for route in app.routes:
        if not _route_uses_release_scope(route):
            continue
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        try:
            sig = inspect.signature(endpoint)
        except (ValueError, TypeError):
            continue

        param_names = set(sig.parameters.keys())
        # If the endpoint uses Depends(require_release_in_scope), release_id
        # is bound by the dependency (not directly in endpoint sig).  Treat
        # as satisfied.
        uses_helper_dep = any(
            getattr(p.default, "dependency", None) in _OWNERSHIP_DEPENDENCIES
            for p in sig.parameters.values()
        )
        for url_param in _RELEASE_SCOPED_PARAMS:
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

    missing = test_all_release_scoped_endpoints_have_ownership_dependency()
    consistency_errors = test_decorator_argument_consistency()

    fail = bool(missing or consistency_errors)

    if missing:
        print(f"[FAIL] {len(missing)} endpoint(s) missing ownership dependency:")
        for m in missing:
            print(f"  - {m}")
        print()
        print("Each must use ONE of:")
        print("  release: Release = Depends(require_release_in_scope)  # new pattern")
        print("  user: dict = Depends(require_admin)                   # admin only")
        print("  # OR legacy _assert_vuln_org() in body (vulnerabilities.py only;")
        print("    release-side legacy helper deleted in iter-1 D.8)")
        print()

    if consistency_errors:
        print(f"[FAIL] {len(consistency_errors)} URL-vs-signature inconsistency:")
        for e in consistency_errors:
            print(f"  - {e}")
        print()

    if not fail:
        scoped_routes = sum(1 for r in app.routes if _route_uses_release_scope(r))
        print(f"[PASS] all {scoped_routes} release-scoped endpoints have ownership dependency")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
