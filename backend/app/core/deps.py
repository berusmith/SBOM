from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token

_bearer = HTTPBearer()


def get_current_user(
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
        rec.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return {
            "username": f"apitoken:{rec.name}",
            "role": "admin",
            "org_id": None,
            "user_id": None,
            "api_token_id": rec.id,
        }
    try:
        return decode_token(token)
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
