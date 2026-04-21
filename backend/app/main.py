import os
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import auth, organizations, products, releases, vulnerabilities, stats, cra, search, settings, policies, users
from app.models import vex_history as _vex_history_model  # noqa: F401 — ensure table is registered
from app.models import brand_config as _brand_config_model  # noqa: F401
from app.models import policy_rule as _policy_rule_model  # noqa: F401
from app.models import user as _user_model  # noqa: F401
from app.core.database import Base, engine, SessionLocal
from app.core.deps import get_current_user

Base.metadata.create_all(bind=engine)

# Seed initial admin user from env vars if users table is empty
from app.models.user import User as _UserModel
from app.core.security import hash_password as _hash_pw
from app.core.config import settings as _cfg

_seed_db = SessionLocal()
try:
    if _seed_db.query(_UserModel).count() == 0:
        _seed_db.add(_UserModel(
            username=_cfg.ADMIN_USERNAME,
            hashed_password=_hash_pw(_cfg.ADMIN_PASSWORD),
            role="admin",
        ))
        _seed_db.commit()
finally:
    _seed_db.close()

# migrate existing tables — add columns that may not exist yet
with engine.connect() as conn:
    vuln_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerabilities)"))}
    for col, typedef in [
        ("justification",   "TEXT"),
        ("response",        "TEXT"),
        ("detail",          "TEXT"),
        ("epss_score",      "REAL"),
        ("epss_percentile", "REAL"),
        ("is_kev",          "INTEGER DEFAULT 0"),
        ("description",     "TEXT"),
        ("cwe",             "TEXT"),
        ("nvd_refs",        "TEXT"),
        ("cvss_v3_score",   "REAL"),
        ("cvss_v3_vector",  "TEXT"),
        ("cvss_v4_score",   "REAL"),
        ("cvss_v4_vector",  "TEXT"),
        ("scanned_at",      "DATETIME"),
        ("fixed_at",        "DATETIME"),
    ]:
        if col not in vuln_cols:
            conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typedef}"))
    conn.commit()

    # releases table migrations
    rel_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(releases)"))}
    for col, typedef in [
        ("sbom_hash", "TEXT"),
        ("locked",    "INTEGER DEFAULT 0"),
    ]:
        if col not in rel_cols:
            conn.execute(text(f"ALTER TABLE releases ADD COLUMN {col} {typedef}"))
    conn.commit()

app = FastAPI(title="SBOM Management Platform", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[_cfg.ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_auth = [Depends(get_current_user)]

app.include_router(auth.router)
app.include_router(organizations.router, dependencies=_auth)
app.include_router(products.router, dependencies=_auth)
app.include_router(releases.router, dependencies=_auth)
app.include_router(vulnerabilities.router, dependencies=_auth)
app.include_router(stats.router, dependencies=_auth)
app.include_router(cra.router, dependencies=_auth)
app.include_router(search.router, dependencies=_auth)
app.include_router(settings.router, dependencies=_auth)
app.include_router(policies.router, dependencies=_auth)
app.include_router(users.router, dependencies=_auth)


@app.get("/health")
def health():
    return {"status": "ok"}


# Serve React SPA in production (STATIC_DIR env var set by systemd)
_static_dir = os.environ.get("STATIC_DIR", "")
if _static_dir and Path(_static_dir).is_dir():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="frontend")
