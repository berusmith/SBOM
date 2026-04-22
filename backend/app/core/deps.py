from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from app.core.security import decode_token

_bearer = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    try:
        return decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="無效或過期的 token，請重新登入")


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="此操作需要管理員權限")
    return user


def get_org_scope(user: dict = Depends(get_current_user)) -> str | None:
    """Admin sees all (returns None). Viewer is scoped to their org_id."""
    if user.get("role") == "admin":
        return None
    org_id = user.get("org_id")
    if not org_id:
        raise HTTPException(status_code=403, detail="帳號未綁定組織，請聯絡管理員")
    return org_id
