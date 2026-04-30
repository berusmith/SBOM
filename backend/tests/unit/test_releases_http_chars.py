"""
HTTP characterization for backend/app/api/releases.py — 37 endpoints.

Captures the current HTTP contract BEFORE PR-1 Stages B–E refactor.  Every
test pins what is observable today; the same assertions must pass after each
D.N move (releases.py code shifts; HTTP contract stays).

D.8 (2026-05-01) — ARCH-1.003 contract evolution COMPLETE.  All cross-org
release-id endpoints now return 404 (CWE-204 oracle prevention).  The
prior "legacy 403 vs modern 404" split is gone; every site asserts 404.

Per code-principles.md §H4 (Tidy First) + §J5 + the J5-footnote: this is a
test-only commit (tidy:); no behavior change in backend/app/.

Test budget: ~50 tests, runtime < 5s wall-clock.
"""
from __future__ import annotations

from io import BytesIO

import pytest

# ── 37-endpoint registry ─────────────────────────────────────────────────────

# (method, path_template_with_{rid}, body_kind)
# body_kind:
#   None   = no body / no file
#   "json" = small JSON body (use {} unless the endpoint enforces structure
#            BEFORE the release lookup — none of these do; release lookup runs first)
#   "file" = multipart upload of a tiny placeholder
#   "image"= POST scan-image takes a JSON body with {"image": "..."}
RELEASE_ENDPOINTS: list[tuple[str, str, str | None]] = [
    # SBOM ingestion + re-scan + enrichment (5)
    ("POST",   "/api/releases/{rid}/sbom",                          "file"),
    ("POST",   "/api/releases/{rid}/rescan",                        None),
    ("POST",   "/api/releases/{rid}/enrich-epss",                   None),
    ("POST",   "/api/releases/{rid}/enrich-ghsa",                   None),
    ("POST",   "/api/releases/{rid}/enrich-nvd",                    None),
    # Lifecycle (4)
    ("GET",    "/api/releases/{rid}",                               None),
    ("PATCH",  "/api/releases/{rid}/version",                       "json"),
    ("DELETE", "/api/releases/{rid}",                               None),
    ("PATCH",  "/api/releases/{rid}/notes",                         "json"),
    # Listings + exports (4)
    ("GET",    "/api/releases/{rid}/components",                    None),
    ("GET",    "/api/releases/{rid}/vulnerabilities",               None),
    ("GET",    "/api/releases/{rid}/vulnerabilities/export",        None),
    ("GET",    "/api/releases/{rid}/compliance",                    None),
    # PDF / CSAF / evidence (8)
    ("GET",    "/api/releases/{rid}/report",                        None),
    ("GET",    "/api/releases/{rid}/compliance/iec62443",           None),
    ("GET",    "/api/releases/{rid}/compliance/iec62443-4-2",       None),
    ("GET",    "/api/releases/{rid}/compliance/iec62443-3-3",       None),
    ("GET",    "/api/releases/{rid}/compliance/nis2",               None),
    ("GET",    "/api/releases/{rid}/evidence-package",              None),
    ("GET",    "/api/releases/{rid}/csaf",                          None),
    ("GET",    "/api/releases/{rid}/export/cyclonedx-xml",          None),
    ("GET",    "/api/releases/{rid}/export/spdx-json",              None),
    # Quality / integrity / signature (5)
    ("GET",    "/api/releases/{rid}/sbom-quality",                  None),
    ("GET",    "/api/releases/{rid}/integrity",                     None),
    ("POST",   "/api/releases/{rid}/signature",                     "json"),
    ("GET",    "/api/releases/{rid}/signature/verify",              None),
    ("DELETE", "/api/releases/{rid}/signature",                     None),
    # Lock / stats / gate / graph (4)
    ("POST",   "/api/releases/{rid}/lock",                          None),
    ("POST",   "/api/releases/{rid}/unlock",                        None),
    ("GET",    "/api/releases/{rid}/patch-stats",                   None),
    ("GET",    "/api/releases/{rid}/gate",                          None),
    ("GET",    "/api/releases/{rid}/dependency-graph",              None),
    # Source / scanner / Syft endpoints (5)
    ("POST",   "/api/releases/{rid}/upload-source",                 "file"),
    ("POST",   "/api/releases/{rid}/scan-image",                    "image"),
    ("POST",   "/api/releases/{rid}/scan-iac",                      "file"),
    ("POST",   "/api/releases/{rid}/sbom-from-source",              "file"),
    ("POST",   "/api/releases/{rid}/sbom-from-binary",              "file"),
]

assert len(RELEASE_ENDPOINTS) == 37, f"Expected 37 endpoints, registry has {len(RELEASE_ENDPOINTS)}"

NONEXIST_RID = "00000000-0000-0000-0000-000000000000"


def _request_kwargs_for(body_kind: str | None) -> dict:
    if body_kind is None:
        return {}
    if body_kind == "json":
        return {"json": {}}
    if body_kind == "image":
        return {"json": {"image": "nginx:1.25"}}
    if body_kind == "file":
        return {"files": {"file": ("test.zip", BytesIO(b"PK\x05\x06" + b"\x00" * 18), "application/zip")}}
    raise ValueError(f"Unknown body_kind: {body_kind}")


# ── Set 1 — every endpoint requires Bearer (37 tests) ────────────────────────
# FastAPI HTTPBearer with auto_error=True returns 403 "Not authenticated" when
# no Bearer header is present.  This is the framework-level auth gate.

@pytest.mark.http
@pytest.mark.parametrize("method, path_template, body_kind", RELEASE_ENDPOINTS,
                         ids=lambda v: v if isinstance(v, str) else "")
def test_release_endpoint_requires_bearer(client, method, path_template, body_kind):
    """No Authorization header → HTTPBearer raises 403 "Not authenticated"."""
    url = path_template.format(rid=NONEXIST_RID)
    resp = client.request(method, url, **_request_kwargs_for(body_kind))
    # HTTPBearer's default unauthenticated response is 403, not 401.
    # (401 is reserved for "Bearer present but invalid/expired token".)
    assert resp.status_code == 403, (
        f"{method} {url} expected 403 (no Bearer), got {resp.status_code}: {resp.text[:200]}"
    )


# ── Set 2 — public allowlist verification (4 endpoints) ───────────────────────
# These endpoints are deliberately public per code-principles.md §C1.  They
# must NOT regress to requiring auth during any refactor.

PUBLIC_ENDPOINTS: list[tuple[str, str]] = [
    ("GET", "/health"),
    ("GET", "/api/notice"),
    # /api/auth/login is public but POST and requires JSON body — covered by test_all.py
    # /api/share/{token} requires a valid token — covered by share-link unit tests later
]


@pytest.mark.http
@pytest.mark.parametrize("method, path", PUBLIC_ENDPOINTS)
def test_public_endpoint_no_bearer_required(client, method, path):
    """Public allowlist must not require Authorization."""
    resp = client.request(method, path)
    # 200 OK (or 200-ish — /health returns 200 with degraded marker if DB issue)
    assert resp.status_code == 200, (
        f"{method} {path} expected 200 (public), got {resp.status_code}: {resp.text[:200]}"
    )


# ── Set 3 — cross-org 404 (post-D.8 ARCH-1.003 evolution) ───────────────────
# These tests pin the POST-D.8 behavior: cross-org access on every release-id
# endpoint returns 404 + "Release not found" (CWE-204 oracle prevention).
# Pre-D.8 the legacy sites returned 403; D.8 flipped them all to 404 atomically.

@pytest.fixture
def cross_org_client(db_session):
    """A TestClient configured as a viewer bound to org "orgB".  Used to call
    endpoints scoped to a release that lives under org "orgA" — should produce
    the cross-org rejection."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.database import get_db
    from app.core.deps import get_current_user

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    def _override_get_current_user():
        return {
            "username": "viewer-of-orgB",
            "role":     "viewer",
            "org_id":   "orgB",
            "user_id":  "user-orgB",
        }

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def seeded_orga_release(db_session):
    """Seed orgA → productA → releaseA in the test DB.  Returns release_id."""
    from app.models.organization import Organization
    from app.models.product import Product
    from app.models.release import Release

    orgA = Organization(id="orgA", name="OrgA")
    prodA = Product(id="prodA", organization_id="orgA", name="ProdA")
    rel = Release(id="rel-in-orgA", product_id="prodA", version="1.0.0")
    # Also seed orgB so the viewer's "org_id" maps to a real row
    orgB = Organization(id="orgB", name="OrgB")
    db_session.add_all([orgA, orgB, prodA, rel])
    db_session.commit()
    return "rel-in-orgA"


# 5 representative endpoints — POST-D.8 all use Depends(require_release_in_scope)
# and return 404 on cross-org access (uniform CWE-204 oracle behavior).
CROSS_ORG_PIN_ENDPOINTS: list[tuple[str, str, str | None]] = [
    ("GET",    "/api/releases/{rid}",                       None),
    ("GET",    "/api/releases/{rid}/components",            None),
    ("GET",    "/api/releases/{rid}/vulnerabilities",       None),
    ("GET",    "/api/releases/{rid}/report",                None),
    ("GET",    "/api/releases/{rid}/compliance",            None),    # was already-correct pre-D.8; remains 404
]


@pytest.mark.http
@pytest.mark.parametrize("method, path_template, body_kind", CROSS_ORG_PIN_ENDPOINTS)
def test_cross_org_access_returns_404_post_d8(cross_org_client, seeded_orga_release,
                                              method, path_template, body_kind):
    """POST-D.8 (ARCH-1.003 contract evolution complete): every release-id endpoint
    accessed cross-org returns 404 + 'Release not found' (CWE-204 oracle prevention).

    Pre-D.8 the legacy 4 sites returned 403; D.8 flipped them all to 404 in the
    same commit that deleted the legacy ownership helper.  This test file is the
    test-side anchor for that flip.
    """
    url = path_template.format(rid=seeded_orga_release)
    resp = cross_org_client.request(method, url, **_request_kwargs_for(body_kind))
    assert resp.status_code == 404, (
        f"{method} {url} expected 404 (cross-org, oracle-safe), "
        f"got {resp.status_code}: {resp.text[:200]}"
    )
    # Detail string must be the canonical 'Release not found' (uniform across all
    # 404 paths to defeat oracle differentiation).
    assert resp.json().get("detail") == "Release not found", (
        f"{method} {url} expected detail='Release not found' (uniform per CWE-204), "
        f"got {resp.json()}"
    )
