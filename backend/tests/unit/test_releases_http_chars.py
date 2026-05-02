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


# ── Set 4 — E.2 byte-equality verification (typed body behavior-equivalence) ──
# Per Q-P7-3 + Stage E scope lock: PATCH /version + PATCH /notes accepted typed
# Pydantic bodies in E.2 but MUST behave identically to the prior dict-shape
# handlers.  These 4 boundary inputs lock the equivalence:
#   (1) version=""               → 400 "版本號不可為空" (NOT 422; preserves zh-TW + status)
#   (2) version="   " (ws-only)  → 400 (after strip)
#   (3) notes=4999 chars         → 200, stored as-is
#   (4) notes=5001 chars         → 200, silently truncated to 5000 (NOT 422)

@pytest.fixture
def admin_client(db_session):
    """TestClient configured as an admin (no org_scope; require_admin passes)."""
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
        return {"username": "admin-test", "role": "admin", "org_id": None, "user_id": "u-admin"}

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


@pytest.mark.http
def test_e2_update_version_empty_string_rejects_with_zh_400(admin_client, seeded_orga_release):
    """Boundary 1: version='' → 400 + zh-TW '版本號不可為空' (NOT 422)."""
    resp = admin_client.patch(f"/api/releases/{seeded_orga_release}/version", json={"version": ""})
    assert resp.status_code == 400, f"expected 400, got {resp.status_code}: {resp.text[:200]}"
    assert resp.json()["detail"] == "版本號不可為空"


@pytest.mark.http
def test_e2_update_version_whitespace_only_rejects_with_zh_400(admin_client, seeded_orga_release):
    """Boundary 2: version='   ' → strip → '' → 400 + zh-TW (NOT 422)."""
    resp = admin_client.patch(f"/api/releases/{seeded_orga_release}/version", json={"version": "   "})
    assert resp.status_code == 400, f"expected 400, got {resp.status_code}: {resp.text[:200]}"
    assert resp.json()["detail"] == "版本號不可為空"


@pytest.mark.http
def test_e2_update_notes_below_cap_stored_as_is(admin_client, seeded_orga_release):
    """Boundary 3: notes=4999 chars → 200, stored verbatim (no truncation)."""
    payload = "x" * 4999
    resp = admin_client.patch(f"/api/releases/{seeded_orga_release}/notes", json={"notes": payload})
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    assert resp.json()["notes"] == payload
    assert len(resp.json()["notes"]) == 4999


@pytest.mark.http
def test_e2_update_notes_over_cap_silently_truncated_to_5000(admin_client, seeded_orga_release):
    """Boundary 4: notes=5001 chars → 200, truncated to 5000 (NO 422)."""
    payload = "x" * 5001
    resp = admin_client.patch(f"/api/releases/{seeded_orga_release}/notes", json={"notes": payload})
    assert resp.status_code == 200, f"expected 200 (silent truncation, NOT 422), got {resp.status_code}: {resp.text[:200]}"
    assert len(resp.json()["notes"]) == 5000
    assert resp.json()["notes"] == "x" * 5000


# ── Set 5 — function-body characterization (AC-T2 remediation, post-Phase-9) ──
# Phase 9 verification surfaced AC-T2 fail (pytest-cov 26% < 30% on usecases +
# domain).  These tests target the highest-yield uncovered endpoints in
# usecases/release/ to push coverage above the 30% threshold while exercising
# real handler bodies (not just bearer/auth gates).  Each test:
#   - uses the existing admin_client + seeded_orga_release fixtures (E.2 era),
#     reused unchanged so Set 3 cross-org tests remain unaffected;
#   - asserts at minimum (a) HTTP status code, (b) response shape / key field
#     presence — never just status_code alone;
#   - exercises the function body via authenticated admin + same-org release,
#     so Depends(require_release_in_scope) passes and the handler runs to return.


@pytest.mark.http
def test_get_release_returns_200_with_seed(admin_client, seeded_orga_release):
    """GET /api/releases/{rid} — basic info dict for a release that exists in admin's scope."""
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body["id"] == seeded_orga_release
    assert body["version"] == "1.0.0"
    assert body["locked"] is False
    assert body["has_sbom"] is False  # seeded release has no SBOM file
    assert "created_at" in body


@pytest.mark.http
def test_get_release_components_returns_list(admin_client, seeded_orga_release):
    """GET /api/releases/{rid}/components — returns paginated dict {total, skip, limit, items}."""
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}/components")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body["total"] == 0  # seeded release has no components
    assert body["skip"] == 0
    assert body["limit"] == 2000  # default per handler
    assert body["items"] == []


@pytest.mark.http
def test_get_release_vulnerabilities_returns_list_with_severity(admin_client, seeded_orga_release):
    """GET /api/releases/{rid}/vulnerabilities — returns list (NOT dict) of vuln rows."""
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}/vulnerabilities")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert isinstance(body, list), f"expected list, got {type(body).__name__}: {body!r}"
    assert body == []  # no components → no vulnerabilities


@pytest.mark.http
def test_get_release_gate_returns_pass_or_fail_state(admin_client, seeded_orga_release):
    """GET /api/releases/{rid}/gate — returns {overall, passed, total, checks: [...]} with 6 named checks."""
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}/gate")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    # Shape contract:
    assert "overall" in body and body["overall"] in ("pass", "fail")
    assert "passed" in body and isinstance(body["passed"], int)
    assert "total" in body and isinstance(body["total"], int)
    assert "checks" in body and isinstance(body["checks"], list)
    # Each check has id + label + passed + detail (per lifecycle.py:283-336):
    for c in body["checks"]:
        assert {"id", "label", "passed", "detail"}.issubset(c.keys())
    # Without SBOM uploaded, sbom_uploaded check must be False (sets overall=fail):
    by_id = {c["id"]: c for c in body["checks"]}
    assert by_id["sbom_uploaded"]["passed"] is False
    assert body["overall"] == "fail"  # at least sbom_uploaded fails → overall fail


@pytest.mark.http
def test_get_release_patch_stats_returns_zeroed_struct(admin_client, seeded_orga_release):
    """GET /api/releases/{rid}/patch-stats — empty release returns zeroed counts + patch_rate 0.0."""
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}/patch-stats")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    # Required fields per lifecycle.py:265-269:
    for key in ("total", "fixed", "open", "in_triage", "affected", "not_affected", "patch_rate", "avg_days_to_fix"):
        assert key in body, f"missing field: {key}"
    assert body["total"] == 0
    assert body["fixed"] == 0
    assert body["patch_rate"] == 0.0
    assert body["avg_days_to_fix"] is None  # no fixed-vulns → cannot compute average


@pytest.mark.http
def test_post_lock_then_unlock_release_round_trip(admin_client, seeded_orga_release):
    """POST /lock then POST /unlock — toggles release.locked through both states."""
    # Initial: seeded release is unlocked (Release default).
    lock_resp = admin_client.post(f"/api/releases/{seeded_orga_release}/lock")
    assert lock_resp.status_code == 200, f"lock expected 200, got {lock_resp.status_code}: {lock_resp.text[:200]}"
    assert lock_resp.json() == {"locked": True}

    # Locking already-locked release returns 409 (lifecycle.py:223-224):
    relock_resp = admin_client.post(f"/api/releases/{seeded_orga_release}/lock")
    assert relock_resp.status_code == 409, f"re-lock expected 409, got {relock_resp.status_code}"

    unlock_resp = admin_client.post(f"/api/releases/{seeded_orga_release}/unlock")
    assert unlock_resp.status_code == 200, f"unlock expected 200, got {unlock_resp.status_code}: {unlock_resp.text[:200]}"
    assert unlock_resp.json() == {"locked": False}


# `seeded_release_with_sbom_and_component` fixture promoted to tests/unit/conftest.py
# in PR-2 K.2a (2026-05-02) per Q-PR2-3 (a) — it is now needed by both this file's
# Set 5 tests AND the new test_reports_csaf.py CSAF unit tests.  Single shared
# definition in conftest avoids duplication.


@pytest.mark.http
def test_get_release_sbom_quality_returns_score(admin_client, seeded_release_with_sbom_and_component):
    """GET /api/releases/{rid}/sbom-quality — returns NTIA score dict {score, grade, passed, total, checks}."""
    rid = seeded_release_with_sbom_and_component
    resp = admin_client.get(f"/api/releases/{rid}/sbom-quality")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    # Per services/sbom_parser.py:174 score_sbom contract:
    for key in ("score", "grade", "passed", "total", "checks"):
        assert key in body, f"missing field: {key}"
    assert isinstance(body["score"], int)
    assert body["grade"] in ("A", "B", "C", "D")
    assert isinstance(body["checks"], list)
    assert body["total"] == len(body["checks"])


@pytest.mark.http
def test_get_release_integrity_returns_status(admin_client, seeded_orga_release):
    """GET /api/releases/{rid}/integrity — returns 'no_file' status when SBOM not uploaded.

    Tests the no-file branch (reports.py:444-445); covers the early-return path
    without needing a real file on disk.
    """
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}/integrity")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    # Per reports.py:445 early-return shape:
    assert body["status"] == "no_file"
    assert body["message"] == "尚未上傳 SBOM 檔案"


@pytest.mark.http
def test_get_release_csaf_returns_csaf_doc(admin_client, seeded_release_with_sbom_and_component):
    """GET /api/releases/{rid}/csaf — returns CSAF VEX 2.0 document.

    Requires both SBOM file AND ≥ 1 component (else _lookup_components_for_release
    raises 400).  Uses seeded_release_with_sbom_and_component fixture.
    """
    rid = seeded_release_with_sbom_and_component
    resp = admin_client.get(f"/api/releases/{rid}/csaf")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    # CSAF VEX 2.0 contract — every doc has "document" envelope per CSAF spec:
    assert "document" in body
    assert body["document"].get("category") == "csaf_vex"
    # Content-Disposition attachment header per reports.py:339:
    assert "attachment" in resp.headers.get("content-disposition", "")


@pytest.mark.http
def test_get_release_dependency_graph_returns_nodes_edges(admin_client, seeded_orga_release):
    """GET /api/releases/{rid}/dependency-graph — returns {has_data, nodes, edges, total_nodes, total_edges}.

    Without SBOM file, returns the empty-shape early-return per lifecycle.py:348-349.
    """
    resp = admin_client.get(f"/api/releases/{seeded_orga_release}/dependency-graph")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    # Early-return shape from lifecycle.py:349 (no SBOM file → empty graph):
    assert body["has_data"] is False
    assert body["nodes"] == []
    assert body["edges"] == []
