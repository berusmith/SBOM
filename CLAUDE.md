# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Starting the Platform

Backend (port 9100):
```bash
cd C:/Project/SBOM/backend
python -m uvicorn app.main:app --port 9100 --reload
```

Frontend (port 3000):
```bash
cd C:/Project/SBOM/frontend
npm run dev
```

API docs: `http://localhost:9100/docs`

## First-Time Setup (new machine)

```bash
cd C:/Project/SBOM/backend
pip install -r requirements.txt

cd C:/Project/SBOM/frontend
npm install
```

Default login: `admin` / `sbom@2024`

## Testing

No pytest suite. Use stdlib-only ad-hoc scripts (`urllib` + `json`). Both `requests` and `grep -P` are unavailable.

```bash
python - <<'EOF'
import urllib.request, json
req = urllib.request.urlopen("http://localhost:9100/health")
print(json.loads(req.read()))
EOF
```

For authenticated calls, POST to `/api/auth/login` first and pass `Authorization: Bearer <token>`.

## Architecture

### Data Model (cascade delete chain)
```
Organization → Product → Release → Component → Vulnerability
CRAIncident  (platform-wide, no org FK — do NOT query CRAIncident.organization_id)
VexHistory   (per Vulnerability, append-only audit trail)
PolicyRule   (global)
BrandConfig  (global singleton)
AlertConfig  (global singleton)
```
All relationships use `cascade="all, delete-orphan"`. UUID primary keys throughout.

### Backend (`backend/app/`)
- **`main.py`** — FastAPI app, CORS (localhost:3000 only). Schema migrations are inline `ALTER TABLE ADD COLUMN` blocks at startup — never use Alembic; add new columns here.
- **`core/security.py`** — JWT via `python-jose`. `core/deps.py` provides `get_current_user` FastAPI dependency.
- **`api/`** — One router per resource, prefix `/api/<resource>`. Chinese error messages for user-facing 409/400 errors. Auth required on all routes via `Depends(get_current_user)`.
- **`api/stats.py`** — `/api/stats` (dashboard totals), `/api/stats/top-vulns` (top 10 unresolved Critical/High with org/product/release context), `/api/stats/risk-overview` (per-org risk scores). Use `from sqlalchemy import case` (not `func.case`) for conditional ordering.
- **`models/`** — SQLAlchemy ORM. `CRAIncident` has **no** `organization_id` column (platform-wide incidents only).
- **`schemas/`** — Pydantic schemas exist only for Organization, Product, Release. All other routers define inline `BaseModel` classes.
- **`services/sbom_parser.py`** — Parses CycloneDX JSON and SPDX JSON → list of `{name, version, purl, license}`.
- **`services/vuln_scanner.py`** — Calls OSV.dev `/v1/query` per purl, deduplicates by `(component_id, cve_id)`.
- **`services/pdf_report.py`** — fpdf2 with Helvetica (Latin-1 only). Always pass strings through `_s()` helper to strip non-Latin-1 chars before rendering.
- **`services/iec62443_report.py`** — Assesses 11 IEC 62443-4-1 requirements (SM-9, DM-1~5, SUM-1~5) against live DB data.

### Frontend (`frontend/src/`)
- **`api/client.js`** — Axios instance, `baseURL: /api`; Vite proxies `/api` → `http://localhost:9100`.
- **`App.jsx`** — All routes defined here. Add both the import and the `<Route>` when adding a page.
- **`pages/`** — One file per page, hooks-only state (no Redux/Zustand).
- **`components/Layout.jsx`** — Top nav bar. Add entries to the `navItems` array; use `location.pathname.startsWith(item.path)` for active state (except `/` which uses exact match).

### Releases API quirk
`GET /api/products/{id}/releases` returns `{ "product_name": "...", "releases": [...] }` — not a plain array. Always destructure `.releases` from the response.

### CRA Incident State Machine
```
detected → pending_triage → clock_running → t24_submitted → investigating
                          → t72_submitted → remediating → final_submitted → closed
pending_triage → closed  (via close-not-affected)
```
Clock (T+24h / T+72h / T+14d deadlines) starts only at `clock_running` via explicit `start-clock` call, preserving the legal "awareness timestamp".

### VEX Fields
- `status`: open / in_triage / not_affected / affected / fixed
- `justification`: only valid when `status = not_affected` (cleared on save otherwise)
- `response`: only valid when `status = affected` (cleared on save otherwise)
- `detail`: free-text, always valid

## Key Constraints
- Port 9100 only — 8080/8005/8009/8443 conflict with Tomcat on this machine
- SQLite at `backend/sbom.db`; uploaded SBOMs at `backend/uploads/`; brand logos at `backend/uploads/brand/`
- No Docker in this environment
- Platform language: Traditional Chinese (zh-TW)
- EU CRA Article 14 enforcement deadline: 2026-09-11
- `bcrypt` version warning at startup (`(trapped) error reading bcrypt version`) is harmless — passlib/bcrypt compatibility issue, does not affect auth
