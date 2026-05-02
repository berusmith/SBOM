"""
SDLC-001 enforcement test — runs in CI (security.yml backend-tests job).

Walks every FastAPI route on `app`.

# Tenant-scoped routes ({release_id} / {vuln_id} path params)

Must satisfy ONE of:
  - new pattern: include Depends(require_release_in_scope) /
                 Depends(require_vuln_in_scope)
  - admin override: include Depends(require_admin) or Depends(require_admin_scope)

Legacy 403-oracle helpers fully removed:
  - release-side _assert_release_org: deleted iter-1 D.8 (2026-05-01)
  - vuln-side _assert_vuln_org: deleted iter-1 PR-3 O.1 (2026-05-02)
ARCH-1.003 contract evolution is now complete for both scopes.

# Public token-scoped routes ({token} path param, no JWT)

Added 2026-05-02 by PR-3 P.3 (FU-1.011 close).  Public unauthenticated
endpoints whose path templates a {token} parameter MUST resolve the token
through a known pattern (current: query SbomShareLink.token; future:
Depends(_resolve_share_token)).  AST-style scan of the function source
verifies the resolver call is present — preventative, not perfect; catches
the regression of "someone adds /api/share-stats/{token} that just trusts
the token without validating it".

Forgetting any of the above = test fails, CI blocks merge.

# Companion check

test_decorator_argument_consistency — verifies the path parameter name in
the URL matches a parameter in the endpoint signature (catches typos like
{release_uuid} vs release_id binding).  Covers both tenant- and token-
scoped path params.

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

# Path parameters that indicate public token-resolved resource access.
# Added 2026-05-02 by PR-3 P.3 (FU-1.011 close).  These routes have no JWT;
# the token IS the auth.  See SDLC-001 docstring above for resolver pattern.
_TOKEN_PARAMS = {"token"}

# Dependencies that satisfy the "ownership / admin gate" requirement.
# Note: require_admin and require_admin_scope satisfy because admin
# legitimately accesses cross-tenant resources by design.
_OWNERSHIP_DEPENDENCIES = {
    require_release_in_scope,
    require_vuln_in_scope,
    require_admin,
    require_admin_scope,
}

# Whitelist of accepted token-resolver patterns for {token}-templated routes.
# Either a Depends() helper name (for future migration to a centralized resolver)
# or an inline source-substring check (current pattern).
# Source-substring check is approximate / preventative — catches the regression
# of an endpoint that templates {token} but never queries SbomShareLink at all.
_TOKEN_RESOLVER_DEPS: set = set()  # Future centralized resolver helpers go here, e.g. _resolve_share_token
_TOKEN_RESOLVER_SOURCE_PATTERNS = (
    "SbomShareLink.token",  # current pattern: db.query(SbomShareLink).filter(SbomShareLink.token == ...)
)


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


def _route_uses_token_scope(route) -> bool:
    """True iff route path templates a {token} parameter (public auth)."""
    path = getattr(route, "path", "")
    return any(f"{{{name}}}" in path for name in _TOKEN_PARAMS)


def _has_token_resolver(endpoint) -> bool:
    """True iff endpoint either uses a known resolver Depends helper OR its
    source contains a known token-resolver call pattern."""
    if endpoint is None:
        return False
    # Check Depends() against known resolver helpers
    try:
        sig = inspect.signature(endpoint)
    except (ValueError, TypeError):
        return False
    for param in sig.parameters.values():
        default = param.default
        if hasattr(default, "dependency") and default.dependency in _TOKEN_RESOLVER_DEPS:
            return True
    # Fallback: source-substring scan
    try:
        src = inspect.getsource(endpoint)
    except (OSError, TypeError):
        return False
    return any(p in src for p in _TOKEN_RESOLVER_SOURCE_PATTERNS)


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


def test_all_token_scoped_endpoints_have_resolver() -> list[str]:
    """Every {token}-templated public route must call a known token-resolver
    pattern (FU-1.011 / PR-3 P.3).  Either Depends(...) on a whitelisted
    resolver helper OR source contains a whitelisted resolver call pattern."""
    missing = []
    for route in app.routes:
        if not _route_uses_token_scope(route):
            continue
        endpoint = getattr(route, "endpoint", None)
        if not _has_token_resolver(endpoint):
            methods = sorted(getattr(route, "methods", set()) or {"?"})
            qualname = endpoint.__qualname__ if endpoint else "?"
            missing.append(f"{methods} {route.path} → endpoint {qualname}")
    return missing


def test_decorator_argument_consistency() -> list[str]:
    """Every {release_id} / {vuln_id} / {token} in a route URL must appear in
    the endpoint signature (directly or via Depends).  Catches binding typos."""
    errors = []
    all_scoped_params = _TENANT_SCOPED_PARAMS | _TOKEN_PARAMS
    for route in app.routes:
        if not (_route_uses_tenant_scope(route) or _route_uses_token_scope(route)):
            continue
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        try:
            sig = inspect.signature(endpoint)
        except (ValueError, TypeError):
            continue

        param_names = set(sig.parameters.keys())
        # If the endpoint uses Depends(require_release_in_scope) /
        # Depends(require_vuln_in_scope) / a token-resolver helper, the path
        # id is bound by the dependency (not directly in endpoint sig).
        # Treat as satisfied.
        uses_helper_dep = any(
            getattr(p.default, "dependency", None)
            in (_OWNERSHIP_DEPENDENCIES | _TOKEN_RESOLVER_DEPS)
            for p in sig.parameters.values()
        )
        for url_param in all_scoped_params:
            if f"{{{url_param}}}" not in route.path:
                continue
            if url_param not in param_names and not uses_helper_dep:
                errors.append(
                    f"{route.path} URL param {{{url_param}}} not in endpoint signature "
                    f"and no ownership-dep / token-resolver helper to bind it"
                )
    return errors


def main() -> int:
    print("SDLC-001 — endpoint decorator enforcement test\n")

    missing_tenant = test_all_tenant_scoped_endpoints_have_ownership_dependency()
    missing_token = test_all_token_scoped_endpoints_have_resolver()
    consistency_errors = test_decorator_argument_consistency()

    fail = bool(missing_tenant or missing_token or consistency_errors)

    if missing_tenant:
        print(f"[FAIL] {len(missing_tenant)} tenant-scoped endpoint(s) missing ownership dependency:")
        for m in missing_tenant:
            print(f"  - {m}")
        print()
        print("Each must use ONE of:")
        print("  release: Release = Depends(require_release_in_scope)   # release scope")
        print("  vuln: Vulnerability = Depends(require_vuln_in_scope)   # vuln scope")
        print("  user: dict = Depends(require_admin)                    # admin only")
        print()

    if missing_token:
        print(f"[FAIL] {len(missing_token)} token-scoped endpoint(s) missing resolver pattern:")
        for m in missing_token:
            print(f"  - {m}")
        print()
        print("Each must EITHER:")
        print("  - call a whitelisted resolver Depends() helper, OR")
        print(f"  - contain one of these source patterns: {sorted(_TOKEN_RESOLVER_SOURCE_PATTERNS)}")
        print()

    if consistency_errors:
        print(f"[FAIL] {len(consistency_errors)} URL-vs-signature inconsistency:")
        for e in consistency_errors:
            print(f"  - {e}")
        print()

    if not fail:
        tenant_routes = sum(1 for r in app.routes if _route_uses_tenant_scope(r))
        token_routes = sum(1 for r in app.routes if _route_uses_token_scope(r))
        print(f"[PASS] all {tenant_routes} tenant-scoped endpoints have ownership dependency")
        print(f"[PASS] all {token_routes} token-scoped endpoint(s) have resolver pattern")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
