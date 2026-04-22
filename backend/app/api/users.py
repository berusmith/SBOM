from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_admin
from app.core.security import hash_password
from app.models.user import User

logger = logging.getLogger(__name__)
_PWD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{10,}$")

router = APIRouter(prefix="/api/users", tags=["users"])


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    organization_id: str | None = None


class UserUpdate(BaseModel):
    role: str | None = None
    password: str | None = None
    is_active: bool | None = None
    organization_id: str | None = None


def _serialize(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "organization_id": u.organization_id,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


@router.get("")
def list_users(admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    return [_serialize(u) for u in db.query(User).order_by(User.created_at).all()]


@router.post("", status_code=201)
def create_user(payload: UserCreate, admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    if payload.role not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="role 必須是 admin 或 viewer")
    if payload.role == "viewer" and not payload.organization_id:
        raise HTTPException(status_code=400, detail="viewer 帳號必須綁定組織")
    if not payload.username.strip():
        raise HTTPException(status_code=400, detail="使用者名稱不能為空")
    if not _PWD_RE.match(payload.password):
        raise HTTPException(status_code=400, detail="密碼至少 10 個字元，且須包含英文字母與數字")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="使用者名稱已存在")
    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        organization_id=payload.organization_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("USER_CREATE admin=%s new_user=%s role=%s org=%s", admin["username"], user.username, user.role, user.organization_id)
    return _serialize(user)


@router.patch("/{user_id}")
def update_user(user_id: str, payload: UserUpdate, admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="使用者不存在")
    if payload.role is not None:
        if payload.role not in ("admin", "viewer"):
            raise HTTPException(status_code=400, detail="role 必須是 admin 或 viewer")
        if user.username == admin["username"] and payload.role != "admin":
            raise HTTPException(status_code=400, detail="無法降低自己的權限")
        user.role = payload.role
    if payload.password is not None:
        if not _PWD_RE.match(payload.password):
            raise HTTPException(status_code=400, detail="密碼至少 10 個字元，且須包含英文字母與數字")
        user.hashed_password = hash_password(payload.password)
    if payload.is_active is not None:
        if user.username == admin["username"] and not payload.is_active:
            raise HTTPException(status_code=400, detail="無法停用自己的帳號")
        user.is_active = payload.is_active
    if payload.organization_id is not None:
        user.organization_id = payload.organization_id or None
    db.commit()
    logger.info("USER_UPDATE admin=%s target=%s changes=%s", admin["username"], user.username, payload.model_dump(exclude_none=True, exclude={"password"}))
    return _serialize(user)


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: str, admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="使用者不存在")
    if user.username == admin["username"]:
        raise HTTPException(status_code=400, detail="無法刪除自己的帳號")
    username = user.username
    db.delete(user)
    db.commit()
    logger.info("USER_DELETE admin=%s deleted=%s", admin["username"], username)
