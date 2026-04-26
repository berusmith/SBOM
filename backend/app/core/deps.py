from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token

_bearer = HTTPBearer()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> dict:
    token = credentials.credentials
    if token.startswith("sbom_"):
        from app.models.api_token import ApiToken, hash_token
        rec = db.query(ApiToken).filter(
            ApiToken.token_hash == hash_token(token),
            ApiToken.revoked == False,  # noqa: E712
        ).first()
        if not rec:
            raise HTTPException(status_code=401, detail="無效或已撤銷的 API token")

        scope = rec.scope or "admin"
        method = request.method.upper()
        if scope == "read" and method != "GET":
            raise HTTPException(status_code=403, detail="此 API Token 為唯讀，不可執行寫入操作")
        if scope == "write" and method == "DELETE":
            raise HTTPException(status_code=403, detail="此 API Token 無刪除權限")

        rec.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return {
            "username": f"apitoken:{rec.name}",
            "role": "admin",
            "org_id": None,
            "user_id": None,
            "api_token_id": rec.id,
            "api_token_scope": scope,
        }
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="無效或過期的 token，請重新登入")
    # Check revocation blacklist
    jti = payload.get("jti")
    if jti:
        from app.models.revoked_token import RevokedToken
        if db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
            raise HTTPException(status_code=401, detail="Token 已登出，請重新登入")
    return payload


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="此操作需要管理員權限")
    # Read-only API tokens never pass admin gates. Write tokens pass (DELETE
    # already blocked at get_current_user). Admin scope or JWT-based admin: full access.
    if user.get("api_token_scope") == "read":
        raise HTTPException(status_code=403, detail="此 API Token 為唯讀，不可執行寫入操作")
    return user


def require_admin_scope(user: dict = Depends(require_admin)) -> dict:
    """Strict admin — blocks write-scope API tokens. For token/user management endpoints."""
    scope = user.get("api_token_scope")
    if scope is not None and scope != "admin":
        raise HTTPException(status_code=403, detail="此操作僅限管理員 Token")
    return user


def get_org_scope(user: dict = Depends(get_current_user)) -> str | None:
    """Admin sees all (returns None). Viewer is scoped to their org_id."""
    if user.get("role") == "admin":
        return None
    org_id = user.get("org_id")
    if not org_id:
        raise HTTPException(status_code=403, detail="帳號未綁定組織，請聯絡管理員")
    return org_id


# ── SDLC-001: mandatory release-ownership middleware ──────────────────────────
# Introduced 2026-04-26 by Phase 5 #1.  Two patterns:
#
#   1. require_release_in_scope — FastAPI dependency that loads + checks.
#      Use as: `release: Release = Depends(require_release_in_scope)`.
#      Forgetting it on a /releases/{release_id}/* endpoint = enforcement
#      test (tests/test_endpoint_decorator_enforcement.py) flags it in CI.
#
#   2. assert_release_in_scope — for callers that already loaded Release.
#      Returns 404 in BOTH "not found" and "cross-org" cases (CWE-204
#      Observable Response Discrepancy / oracle prevention).
#
# Both adopted by SEC-001b / SEC-001d (Phase 5 #3 / #5).
# Existing _assert_release_org in releases.py uses 403 for back-compat;
# migration of those 30 callers is a separate cleanup, not in Phase 5 scope.

def assert_release_in_scope(release, org_scope: str | None) -> None:
    """Combined existence + ownership check.  Returns 404 in both failure
    modes so an attacker cannot distinguish 'doesn't exist' from 'exists
    but not yours' (CWE-204 Observable Response Discrepancy)."""
    if release is None:
        raise HTTPException(status_code=404, detail="Release not found")
    if org_scope and release.product.organization_id != org_scope:
        raise HTTPException(status_code=404, detail="Release not found")


def require_release_in_scope(
    release_id: str,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """FastAPI dependency: load Release by path param, assert ownership,
    return release.  Use as `release: Release = Depends(require_release_in_scope)`.
    Forgetting becomes a CI failure (enforcement test), not silent leak."""
    from sqlalchemy.orm import joinedload
    from app.models.release import Release
    release = (
        db.query(Release)
          .options(joinedload(Release.product))   # avoid N+1 on the org check
          .filter(Release.id == release_id)
          .first()
    )
    assert_release_in_scope(release, org_scope)
    return release
