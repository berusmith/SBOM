from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api import auth, organizations, products, releases, vulnerabilities, stats, cra, search, settings
from app.core.database import Base, engine
from app.core.deps import get_current_user

Base.metadata.create_all(bind=engine)

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
    ]:
        if col not in vuln_cols:
            conn.execute(text(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typedef}"))
    conn.commit()

app = FastAPI(title="SBOM Management Platform", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
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


@app.get("/health")
def health():
    return {"status": "ok"}
