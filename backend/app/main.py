import os
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import auth, organizations, products, releases, vulnerabilities, stats, cra, search, settings, policies, users, admin, tisax
from app.models import vex_history as _vex_history_model  # noqa: F401 — ensure table is registered
from app.models import brand_config as _brand_config_model  # noqa: F401
from app.models import policy_rule as _policy_rule_model  # noqa: F401
from app.models import user as _user_model  # noqa: F401
from app.models import audit_event as _audit_event_model  # noqa: F401
from app.models import tisax as _tisax_model  # noqa: F401
from app.core.database import Base, engine, SessionLocal
from app.core.deps import get_current_user

from app.models.user import User as _UserModel
from app.core.security import hash_password as _hash_pw
from app.core.config import settings as _cfg

# Run column migrations FIRST so existing tables have new columns before SQLAlchemy queries them.
# Wrap each block in a check so fresh databases (empty tables list) skip gracefully.
_existing_tables = {row[0] for row in engine.connect().execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}

with engine.connect() as conn:
    vuln_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerabilities)"))} if "vulnerabilities" in _existing_tables else set()
    if "vulnerabilities" in _existing_tables:
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
    rel_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(releases)"))} if "releases" in _existing_tables else set()
    for col, typedef in [
        ("sbom_hash", "TEXT"),
        ("locked",    "INTEGER DEFAULT 0"),
    ]:
        if col not in rel_cols:
            conn.execute(text(f"ALTER TABLE releases ADD COLUMN {col} {typedef}"))
    conn.commit()

    # users table — add organization_id
    user_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(users)"))} if "users" in _existing_tables else set()
    if "organization_id" not in user_cols and "users" in _existing_tables:
        conn.execute(text("ALTER TABLE users ADD COLUMN organization_id TEXT REFERENCES organizations(id)"))
    conn.commit()

    # cra_incidents — add org_id
    cra_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(cra_incidents)"))} if "cra_incidents" in _existing_tables else set()
    if "org_id" not in cra_cols and "cra_incidents" in _existing_tables:
        conn.execute(text("ALTER TABLE cra_incidents ADD COLUMN org_id TEXT REFERENCES organizations(id)"))
    conn.commit()

    # Performance indexes — safe to run repeatedly via IF NOT EXISTS
    for _idx in [
        "CREATE INDEX IF NOT EXISTS idx_vuln_cve_id   ON vulnerabilities(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_vuln_severity  ON vulnerabilities(severity)",
        "CREATE INDEX IF NOT EXISTS idx_vuln_status    ON vulnerabilities(status)",
        "CREATE INDEX IF NOT EXISTS idx_vuln_is_kev    ON vulnerabilities(is_kev)",
        "CREATE INDEX IF NOT EXISTS idx_vuln_epss      ON vulnerabilities(epss_score)",
        "CREATE INDEX IF NOT EXISTS idx_comp_purl      ON components(purl)",
        "CREATE INDEX IF NOT EXISTS idx_comp_name      ON components(name)",
        "CREATE INDEX IF NOT EXISTS idx_cra_org        ON cra_incidents(org_id)",
        "CREATE INDEX IF NOT EXISTS idx_cra_status     ON cra_incidents(status)",
    ]:
        conn.execute(text(_idx))
    conn.commit()

# Create any missing tables (new tables like audit_events)
Base.metadata.create_all(bind=engine, checkfirst=True)

# Seed initial admin user from env vars if users table is empty
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
app.include_router(admin.router, dependencies=_auth)
app.include_router(tisax.router, dependencies=_auth)


@app.get("/health")
def health():
    return {"status": "ok"}


# Serve React SPA in production (STATIC_DIR env var set by systemd)
_static_dir = os.environ.get("STATIC_DIR", "")
if _static_dir and Path(_static_dir).is_dir():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="frontend")
