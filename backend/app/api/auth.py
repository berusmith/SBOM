import logging

from fastapi import APIRouter, Depends, HTTPException, Request
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
        if not verify_password(payload.password, db_user.hashed_password):
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
def me(user: dict = Depends(get_current_user)):
    return {"username": user["username"], "role": user["role"], "org_id": user.get("org_id")}
