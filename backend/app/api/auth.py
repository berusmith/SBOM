from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.config import settings
from app.core.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Hash once at startup so login comparisons use bcrypt
_password_hash = hash_password(settings.ADMIN_PASSWORD)


class LoginPayload(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(payload: LoginPayload):
    if payload.username != settings.ADMIN_USERNAME or not verify_password(payload.password, _password_hash):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    token = create_access_token(payload.username)
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def me(username: str = Depends(get_current_user)):
    return {"username": username}
