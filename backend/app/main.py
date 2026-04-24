import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import auth, organizations, products, releases, vulnerabilities, stats, cra, search, settings, policies, users, admin, tisax, licenses, firmware, tokens, convert, share
from app.models import vex_history as _vex_history_model  # noqa: F401 — ensure table is registered
from app.models import license_rule as _license_rule_model  # noqa: F401
from app.models import brand_config as _brand_config_model  # noqa: F401
from app.models import policy_rule as _policy_rule_model  # noqa: F401
from app.models import user as _user_model  # noqa: F401
from app.models import audit_event as _audit_event_model  # noqa: F401
from app.models import tisax as _tisax_model  # noqa: F401
from app.models import firmware_scan as _firmware_scan_model  # noqa: F401
from app.models import api_token as _api_token_model  # noqa: F401
from app.models import share_link as _share_link_model  # noqa: F401
from app.models import password_reset_token as _pw_reset_model  # noqa: F401
from app.models import revoked_token as _revoked_token_model  # noqa: F401
from app.core.database import Base, engine, SessionLocal
from app.core.deps import get_current_user

from app.models.user import User as _UserModel
from app.core.security import hash_password as _hash_pw
from app.core.config import settings as _cfg

# ── Column migration helpers ──────────────────────────────────────────────────
from app.core.database import _is_sqlite as _db_is_sqlite  # noqa: E402

_ALLOWED_TABLES = {
    "vulnerabilities", "releases", "components", "users", "organizations",
    "products", "cra_incidents", "alert_config", "api_tokens",
    "vex_statements", "vex_history", "audit_events", "share_links",
    "firmware_scans", "policy_rules", "brand_config", "license_rules",
    "tisax_assessments", "tisax_controls",
}

def _list_columns(conn, table: str) -> set:
    """Return current column names for a table (SQLite or Postgres)."""
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Invalid table name: {table!r}")
    if _db_is_sqlite:
        return {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
    else:
        rows = conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = :t AND table_schema = current_schema()"
        ), {"t": table})
        return {row[0] for row in rows}


def _table_exists(conn, table: str) -> bool:
    if _db_is_sqlite:
        r = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"), {"t": table})
    else:
        r = conn.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_name=:t AND table_schema=current_schema()"
        ), {"t": table})
    return r.fetchone() is not None


def _add_column(conn, table: str, col: str, typedef: str) -> None:
    """Add a column if it doesn't already exist. typedef uses SQLite syntax;
    automatically converts INTEGER→INTEGER and REAL→DOUBLE PRECISION for Postgres."""
    if col in _list_columns(conn, table):
        return
    if not _db_is_sqlite:
        typedef = (typedef
                   .replace("INTEGER DEFAULT 0", "INTEGER DEFAULT 0")
                   .replace("REAL", "DOUBLE PRECISION")
                   .replace("DATETIME", "TIMESTAMP WITH TIME ZONE"))
    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}"))


# ── Run column migrations FIRST ───────────────────────────────────────────────

with engine.connect() as conn:
    if _table_exists(conn, "vulnerabilities"):
        for col, typedef in [
            ("justification",     "TEXT"),
            ("response",          "TEXT"),
            ("detail",            "TEXT"),
            ("epss_score",        "REAL"),
            ("epss_percentile",   "REAL"),
            ("is_kev",            "INTEGER DEFAULT 0"),
            ("description",       "TEXT"),
            ("cwe",               "TEXT"),
            ("nvd_refs",          "TEXT"),
            ("cvss_v3_score",     "REAL"),
            ("cvss_v3_vector",    "TEXT"),
            ("cvss_v4_score",     "REAL"),
            ("cvss_v4_vector",    "TEXT"),
            ("scanned_at",        "DATETIME"),
            ("fixed_at",          "DATETIME"),
            ("suppressed",        "INTEGER DEFAULT 0"),
            ("suppressed_until",  "DATETIME"),
            ("suppressed_reason", "TEXT"),
            ("ghsa_id",           "TEXT"),
            ("ghsa_url",          "TEXT"),
            ("reachability",      "TEXT"),
        ]:
            _add_column(conn, "vulnerabilities", col, typedef)
    conn.commit()

    if _table_exists(conn, "releases"):
        for col, typedef in [
            ("sbom_hash",            "TEXT"),
            ("locked",               "INTEGER DEFAULT 0"),
            ("sbom_signature",       "TEXT"),
            ("signature_public_key", "TEXT"),
            ("signature_algorithm",  "TEXT"),
            ("signer_identity",      "TEXT"),
            ("signed_at",            "TEXT"),
        ]:
            _add_column(conn, "releases", col, typedef)
    conn.commit()

    if _table_exists(conn, "users"):
        _add_column(conn, "users", "organization_id", "TEXT REFERENCES organizations(id)")
        _add_column(conn, "users", "oidc_sub", "TEXT")
    conn.commit()

    if _table_exists(conn, "organizations"):
        _add_column(conn, "organizations", "plan", "TEXT NOT NULL DEFAULT 'starter'")
    conn.commit()

    if _table_exists(conn, "cra_incidents"):
        _add_column(conn, "cra_incidents", "org_id", "TEXT REFERENCES organizations(id)")
    conn.commit()

    if _table_exists(conn, "alert_config"):
        _add_column(conn, "alert_config", "monitor_interval_hours", "INTEGER DEFAULT 24")
        _add_column(conn, "alert_config", "monitor_last_run", "DATETIME")
        _add_column(conn, "alert_config", "alert_min_severity", "TEXT DEFAULT ''")
        _add_column(conn, "alert_config", "alert_kev_always", "INTEGER DEFAULT 1")
        _add_column(conn, "alert_config", "alert_epss_threshold", "REAL DEFAULT 0.0")
    conn.commit()

    if _table_exists(conn, "api_tokens"):
        _add_column(conn, "api_tokens", "scope", "TEXT NOT NULL DEFAULT 'admin'")
    conn.commit()

    if _table_exists(conn, "releases"):
        _add_column(conn, "releases", "notes", "TEXT")
        _add_column(conn, "releases", "sbom_quality_score", "INTEGER")
        _add_column(conn, "releases", "sbom_quality_grade", "TEXT")
    conn.commit()

    if _table_exists(conn, "users"):
        _add_column(conn, "users", "email", "TEXT")
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
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_comp_cve ON vulnerabilities(component_id, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_pw_reset_hash ON password_reset_tokens(token_hash)",
    ]:
        try:
            conn.execute(text(_idx))
        except Exception:
            pass
    conn.commit()

# Create any missing tables (new tables like audit_events)
Base.metadata.create_all(bind=engine, checkfirst=True)

# Security: warn on weak SECRET_KEY at startup
import logging as _logging
_startup_log = _logging.getLogger("sbom.startup")
if _cfg.SECRET_KEY in ("change-me-in-production", "", "secret"):
    _startup_log.warning(
        "⚠️  SECRET_KEY is using an insecure default. "
        "Set a strong random value in backend/.env before production deployment."
    )
if len(_cfg.SECRET_KEY.encode()) < 32:
    _startup_log.warning(
        "⚠️  SECRET_KEY is shorter than 32 bytes. "
        "JWT tokens can be brute-forced. Use at least 32 random bytes."
    )

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

# General API rate limit: 300 req/min per IP (excludes static files)
from app.core.rate_limit import api_limiter, _client_ip as _rl_ip

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    # Only rate-limit API routes; skip static assets, health check
    if path.startswith("/api/") and path != "/health":
        ip = _rl_ip(request)
        if not api_limiter.is_allowed(ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "請求過於頻繁，請稍後再試"},
                headers={"Retry-After": "60"},
            )
    return await call_next(request)

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
app.include_router(licenses.router, dependencies=_auth)
app.include_router(firmware.router, dependencies=_auth)
app.include_router(tokens.router, dependencies=_auth)
app.include_router(convert.router, dependencies=_auth)
# share router: create/list/delete require auth (handled inside router via Depends)
# GET /api/share/{token} is public — no global auth dependency
app.include_router(share.router)


@app.get("/health", tags=["health"])
def health_check():
    """
    Health check endpoint — no auth required.
    Returns DB connectivity status and app version.
    Used by uptime monitors (UptimeRobot, cron, load balancer).
    """
    from datetime import datetime, timezone
    from sqlalchemy import text as _text
    db_status = "ok"
    try:
        with engine.connect() as _c:
            _c.execute(_text("SELECT 1"))
    except Exception:
        db_status = "error"

    from app.services import monitor as _mon
    mon_status = _mon.get_status()

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": "2.0.0",
        "db": db_status,
        "monitor": {
            "running": mon_status.get("running", False),
            "last_run": mon_status.get("last_run"),
            "next_run": mon_status.get("next_run"),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.on_event("startup")
def _purge_expired_tokens():
    """Remove expired revoked tokens — they're no longer valid anyway."""
    from datetime import datetime, timezone
    from app.models.revoked_token import RevokedToken
    _db = SessionLocal()
    try:
        _db.query(RevokedToken).filter(
            RevokedToken.expires_at < datetime.now(timezone.utc)
        ).delete()
        _db.commit()
    finally:
        _db.close()


@app.on_event("startup")
def _start_monitor():
    from app.services import monitor
    monitor.start()


@app.on_event("shutdown")
def _stop_monitor():
    from app.services import monitor
    monitor.stop()




# Serve React SPA in production (STATIC_DIR env var set by systemd)
_static_dir = os.environ.get("STATIC_DIR", "")
if _static_dir and Path(_static_dir).is_dir():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="frontend")
