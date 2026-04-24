import logging
import secrets
import urllib.parse
import urllib.request
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings

logger = logging.getLogger(__name__)
from app.core import audit
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.models.organization import Organization
from app.models.user import User as UserModel

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Hash once at startup for the env-var fallback admin
_env_password_hash = hash_password(settings.ADMIN_PASSWORD)


class LoginPayload(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(payload: LoginPayload, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    # Check DB users first
    db_user = db.query(UserModel).filter(
        UserModel.username == payload.username,
        UserModel.is_active == True,  # noqa: E712
    ).first()
    if db_user:
        if not db_user.hashed_password or not verify_password(payload.password, db_user.hashed_password):
            logger.warning("AUTH_FAIL user=%s ip=%s", payload.username, client_ip)
            audit.record(db, "login_fail",
                         {"username": payload.username, "user_id": db_user.id, "org_id": db_user.organization_id},
                         ip=client_ip)
            db.commit()
            raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
        org_name = db_user.organization.name if db_user.organization else None
        logger.info("AUTH_OK user=%s role=%s ip=%s", db_user.username, db_user.role, client_ip)
        token = create_access_token(db_user.username, db_user.role,
                                    org_id=db_user.organization_id, user_id=db_user.id)
        audit.record(db, "login_ok",
                     {"username": db_user.username, "user_id": db_user.id, "org_id": db_user.organization_id},
                     org_name=org_name, ip=client_ip)
        db.commit()
        return {"access_token": token, "token_type": "bearer"}

    # Fall back to env-var admin (allows login even if DB is empty)
    if payload.username == settings.ADMIN_USERNAME and verify_password(payload.password, _env_password_hash):
        logger.info("AUTH_OK user=%s role=admin ip=%s (env fallback)", payload.username, client_ip)
        token = create_access_token(payload.username, "admin")
        audit.record(db, "login_ok", {"username": payload.username}, ip=client_ip)
        db.commit()
        return {"access_token": token, "token_type": "bearer"}

    logger.warning("AUTH_FAIL user=%s ip=%s", payload.username, client_ip)
    audit.record(db, "login_fail", {"username": payload.username}, ip=client_ip)
    db.commit()
    raise HTTPException(status_code=401, detail="帳號或密碼錯誤")


@router.get("/me")
def me(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.core.plan import get_org_plan, _org_plan
    org_id = user.get("org_id")
    plan = _org_plan(db, org_id) if user.get("role") != "admin" else "professional"
    return {
        "username": user["username"],
        "role":     user["role"],
        "org_id":   org_id,
        "plan":     plan,
    }


# ── OIDC helpers ──────────────────────────────────────────────────────────────

_oidc_enabled = bool(settings.OIDC_ISSUER and settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET)

_oidc_meta: dict = {}   # cached discovery document

def _oidc_discover() -> dict:
    """Fetch and cache the OIDC discovery document."""
    global _oidc_meta
    if _oidc_meta:
        return _oidc_meta
    url = settings.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            _oidc_meta = json.loads(resp.read())
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"OIDC 發現文件載入失敗：{e}")
    return _oidc_meta


def _oidc_redirect_uri(request: Request) -> str:
    if settings.OIDC_REDIRECT_URI:
        return settings.OIDC_REDIRECT_URI
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/auth/oidc/callback"


def _exchange_code(code: str, redirect_uri: str) -> dict:
    """Exchange authorization code for tokens."""
    meta = _oidc_discover()
    token_url = meta["token_endpoint"]
    body = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     settings.OIDC_CLIENT_ID,
        "client_secret": settings.OIDC_CLIENT_SECRET,
    }).encode()
    req = urllib.request.Request(token_url, data=body, method="POST",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OIDC token 交換失敗：{e}")


def _get_userinfo(access_token: str) -> dict:
    """Fetch userinfo from OIDC provider."""
    meta = _oidc_discover()
    userinfo_url = meta.get("userinfo_endpoint", "")
    if not userinfo_url:
        raise HTTPException(status_code=502, detail="OIDC provider 未提供 userinfo endpoint")
    req = urllib.request.Request(userinfo_url,
                                  headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OIDC userinfo 取得失敗：{e}")


# ── OIDC endpoints ────────────────────────────────────────────────────────────

@router.get("/oidc/config")
def oidc_config():
    """Return whether OIDC is enabled (called by frontend Login page)."""
    return {"enabled": _oidc_enabled}


@router.get("/oidc/login")
def oidc_login(request: Request):
    """Redirect browser to OIDC provider authorization endpoint."""
    if not _oidc_enabled:
        raise HTTPException(status_code=404, detail="SSO 未啟用")
    meta = _oidc_discover()
    redirect_uri = _oidc_redirect_uri(request)
    state = secrets.token_urlsafe(16)
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id":     settings.OIDC_CLIENT_ID,
        "redirect_uri":  redirect_uri,
        "scope":         "openid email profile",
        "state":         state,
    })
    auth_url = meta["authorization_endpoint"] + "?" + params
    response = RedirectResponse(url=auth_url)
    response.set_cookie("oidc_state", state, max_age=300, httponly=True, samesite="lax")
    return response


@router.get("/oidc/callback")
def oidc_callback(
    code: str = "",
    state: str = "",
    error: str = "",
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Handle OIDC provider callback, issue JWT, redirect to frontend."""
    if not _oidc_enabled:
        raise HTTPException(status_code=404, detail="SSO 未啟用")
    if error:
        raise HTTPException(status_code=400, detail=f"OIDC 授權失敗：{error}")
    if not code:
        raise HTTPException(status_code=400, detail="缺少 authorization code")

    # Validate state cookie to prevent CSRF
    cookie_state = request.cookies.get("oidc_state", "")
    if not cookie_state or not state or cookie_state != state:
        raise HTTPException(status_code=400, detail="OIDC state 驗證失敗，疑似 CSRF 攻擊")

    # Exchange code for tokens
    redirect_uri = _oidc_redirect_uri(request)
    token_resp = _exchange_code(code, redirect_uri)
    access_token = token_resp.get("access_token", "")

    # Get user info
    userinfo = _get_userinfo(access_token)
    sub      = userinfo.get("sub", "")
    email    = userinfo.get("email", "")
    name     = userinfo.get("name") or userinfo.get("preferred_username") or email.split("@")[0]

    if not sub:
        raise HTTPException(status_code=502, detail="OIDC userinfo 缺少 sub 欄位")

    # Find or create local user
    db_user = db.query(UserModel).filter(UserModel.oidc_sub == sub).first()
    if not db_user:
        # Try matching by email/username
        db_user = db.query(UserModel).filter(UserModel.username == (email or name)).first()
        if db_user:
            db_user.oidc_sub = sub
        else:
            # Create new SSO user (role=viewer by default)
            db_user = UserModel(
                username=email or name,
                hashed_password=None,
                role="viewer",
                is_active=True,
                oidc_sub=sub,
            )
            db.add(db_user)
    db.commit()
    db.refresh(db_user)

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="此帳號已停用")

    jwt_token = create_access_token(
        db_user.username, db_user.role,
        org_id=db_user.organization_id, user_id=db_user.id,
    )
    audit.record(db, "login_ok",
                 {"username": db_user.username, "user_id": db_user.id, "via": "oidc"},
                 ip=request.client.host if request.client else "unknown")
    db.commit()

    # Redirect to /login?sso_token=xxx — Login.jsx reads it, stores in localStorage, then navigates
    frontend_url = settings.ALLOWED_ORIGIN.rstrip("/")
    return RedirectResponse(url=f"{frontend_url}/login?sso_token={jwt_token}")


# ── Password endpoints ─────────────────────────────────────────────────────────

class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password", status_code=204)
def change_password(payload: ChangePasswordPayload, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="新密碼至少 8 個字元")
    db_user = db.query(UserModel).filter(UserModel.username == user["username"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="帳號不存在")
    if not db_user.hashed_password:
        raise HTTPException(status_code=400, detail="SSO 帳號無法修改密碼")
    if not verify_password(payload.current_password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="目前密碼不正確")
    db_user.hashed_password = hash_password(payload.new_password)
    db.commit()
    logger.info("PASSWORD_CHANGE user=%s", user["username"])
    audit.record(db, "password_change", user, resource_label=user["username"])
    db.commit()
