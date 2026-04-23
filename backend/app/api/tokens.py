from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_admin_scope as require_admin
from app.models.api_token import VALID_SCOPES, ApiToken, generate_token

router = APIRouter(prefix="/api/tokens", tags=["api-tokens"])


class TokenCreate(BaseModel):
    name: str
    scope: str = "admin"


@router.get("")
def list_tokens(db: Session = Depends(get_db), user: dict = Depends(require_admin)):
    rows = db.query(ApiToken).order_by(ApiToken.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "prefix": r.prefix,
            "scope": r.scope or "admin",
            "created_by": r.created_by,
            "created_at": r.created_at,
            "last_used_at": r.last_used_at,
            "revoked": r.revoked,
        }
        for r in rows
    ]


@router.post("", status_code=201)
def create_token(payload: TokenCreate, db: Session = Depends(get_db), user: dict = Depends(require_admin)):
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="名稱不可為空")
    if len(name) > 100:
        raise HTTPException(status_code=400, detail="名稱過長（上限 100 字元）")
    scope = (payload.scope or "admin").strip()
    if scope not in VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"scope 必須為 {'/'.join(VALID_SCOPES)}")

    plaintext, h, prefix = generate_token()
    tok = ApiToken(name=name, token_hash=h, prefix=prefix, scope=scope, created_by=user["username"])
    db.add(tok)
    db.commit()
    db.refresh(tok)
    return {
        "id": tok.id,
        "name": tok.name,
        "token": plaintext,
        "prefix": tok.prefix,
        "scope": tok.scope,
        "created_at": tok.created_at,
    }


@router.delete("/{token_id}", status_code=204)
def revoke_token(token_id: str, db: Session = Depends(get_db), user: dict = Depends(require_admin)):
    tok = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not tok:
        raise HTTPException(status_code=404, detail="Token 不存在")
    tok.revoked = True
    db.commit()
