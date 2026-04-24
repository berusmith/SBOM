import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(username: str, role: str = "admin", org_id: str | None = None, user_id: str | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    payload: dict = {
        "sub": username,
        "role": role,
        "exp": expire,
        "jti": str(uuid.uuid4()),   # unique token ID — used for revocation
    }
    if org_id:
        payload["org_id"] = org_id
    if user_id:
        payload["user_id"] = user_id
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    sub = payload.get("sub")
    if not sub:
        raise JWTError("missing sub")
    return {
        "username": sub,
        "role": payload.get("role", "admin"),
        "org_id": payload.get("org_id"),
        "user_id": payload.get("user_id"),
        "jti": payload.get("jti"),
        "exp": payload.get("exp"),
    }
