import re
import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Single source of truth for password complexity: at least 10 chars,
# containing both letters and digits.  Used by /api/users (admin-managed
# accounts), /api/organizations (auto-provisioned viewer at org creation),
# /api/auth/change-password, and /api/auth/reset-password.
_PWD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{10,}$")
PASSWORD_POLICY_MESSAGE = "密碼至少 10 個字元，且須包含英文字母與數字"


def is_password_acceptable(password: str) -> bool:
    """Centralized password policy check."""
    return bool(_PWD_RE.match(password or ""))


def safe_attachment_filename(name: str, default: str = "download") -> str:
    """Strip CR / LF / quote / backslash before placing into a Content-Disposition
    `filename="..."` value, to prevent header injection / response splitting."""
    cleaned = "".join(c for c in (name or "") if c not in ('"', "\r", "\n", "\\"))
    return cleaned or default


# Characters that Excel / LibreOffice will treat as the start of a formula when
# encountered at the very start of a cell (after CSV unquoting).  Prepending a
# single quote — the OWASP-recommended mitigation — converts the cell to a text
# literal without changing its visible content materially.
_CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Escape a cell so spreadsheet apps cannot interpret it as a formula.
    Pass any value through this before writing it into a CSV row."""
    s = "" if value is None else str(value)
    if s and s[0] in _CSV_FORMULA_LEADERS:
        return "'" + s
    return s


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
