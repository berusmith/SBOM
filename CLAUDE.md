# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Starting the Platform

Backend (port 9100):
```bash
# Windows
D:\projects\SBOM\sbom-platform\start_backend.bat

# Or manually
cd D:\projects\SBOM\sbom-platform\backend
python -m uvicorn app.main:app --port 9100 --reload
```

Frontend (port 3000):
```bash
# Windows
D:\projects\SBOM\sbom-platform\start_frontend.bat

# Or manually
cd D:\projects\SBOM\sbom-platform\frontend
npm run dev
```

Interactive API docs: `http://localhost:9100/docs`

## Testing

No pytest test suite exists. Tests are run as ad-hoc Python scripts using `urllib` + `json` (not `requests`, not `grep -P` — both are unavailable in this environment). When writing tests, use only stdlib.

```bash
python - <<'EOF'
import urllib.request, json
req = urllib.request.urlopen("http://localhost:9100/health")
print(json.loads(req.read()))
EOF
```

## Architecture

### Data Model (cascade delete chain)
```
Organization → Product → Release → Component → Vulnerability → VexHistory
                               └── VexStatement (release-level VEX for CSAF export)
                               └── ComplianceMap

CRAIncident   (org-level, independent)
User          (global)
PolicyRule    (global)
BrandConfig   (global singleton)
AlertConfig   (global singleton)
```
All relationships use `cascade="all, delete-orphan"`. UUID primary keys throughout.

### Backend (`backend/app/`)

**`main.py`**
- FastAPI app entry point
- CORS restricted to `ALLOWED_ORIGIN` env var (default `localhost:3000`)
- Inline SQLite migration block at startup — add new `ALTER TABLE ADD COLUMN` here, not via Alembic
- Seeds admin user from `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars on first run
- Serves React SPA from `STATIC_DIR` env var when set (production mode)

**`api/`** — One router per resource, all require JWT except `/api/auth/login`

| Router | Prefix | Key endpoints |
|--------|--------|---------------|
| `auth.py` | `/api/auth` | POST `/login`, GET `/me` |
| `organizations.py` | `/api/organizations` | CRUD + GET `/{id}/products` |
| `products.py` | `/api/products` | CRUD + GET `/{id}/releases`, `/vuln-trend`, `/diff` |
| `releases.py` | `/api/releases` | CRUD + POST `/sbom`, `/rescan`, `/enrich-epss`, `/enrich-nvd`, GET `/vulnerabilities`, `/report`, `/compliance/iec62443`, `/compliance/iec62443-4-2`, `/compliance/iec62443-3-3`, `/evidence-package`, `/csaf`, `/integrity`, POST `/lock`, `/unlock` |
| `vulnerabilities.py` | `/api/vulnerabilities` | PATCH `/{id}/status`, PATCH `/batch`, GET `/{id}/history` |
| `cra.py` | `/api/cra` | CRUD incidents + POST `/start-clock`, `/advance`, `/close-not-affected` |
| `stats.py` | `/api/stats` | GET `/` (dashboard totals), `/risk-overview`, `/top-threats` |
| `search.py` | `/api/search` | GET `/components?q=` |
| `settings.py` | `/api/settings` | GET/POST `/brand`, POST `/brand/logo`, GET/POST `/alerts` |
| `policies.py` | `/api/policies` | CRUD policy rules |
| `users.py` | `/api/users` | CRUD users (admin only) |

Chinese error messages for all user-facing 409/400 errors.

**`models/`** — SQLAlchemy ORM models

| Model | Table | Notes |
|-------|-------|-------|
| `organization.py` | `organizations` | `license_status`: active/trial/expired |
| `product.py` | `products` | FK → organizations |
| `release.py` | `releases` | `sbom_hash` (SHA-256), `locked` bool |
| `component.py` | `components` | `purl` used for CVE scanning |
| `vulnerability.py` | `vulnerabilities` | VEX fields + EPSS + KEV + NVD enrichment + patch tracking |
| `vex.py` | `vex_statements` | Release-level VEX for CSAF 2.0 export |
| `vex_history.py` | `vex_history` | Append-only VEX audit log |
| `cra_incident.py` | `cra_incidents` | State machine + SLA timestamps + append-only audit_log |
| `user.py` | `users` | bcrypt hashed password, role: admin/analyst |
| `policy_rule.py` | `policy_rules` | Custom compliance alert rules |
| `brand_config.py` | `brand_config` | Singleton: logo, company_name, primary_color, footer_text |
| `alert_config.py` | `alert_config` | Singleton: webhook_url, email_to, notify flags |
| `compliance.py` | `compliance_maps` | Release ↔ compliance requirement mapping |

**`schemas/`** — Pydantic schemas for Organization, Product, Release. Other routers use inline `BaseModel`.

**`services/`**

| Service | Description |
|---------|-------------|
| `sbom_parser.py` | Parses CycloneDX JSON and SPDX JSON → `[{name, version, purl, license}]` |
| `vuln_scanner.py` | OSV.dev `/v1/query` per component PURL, deduplicates by `(component_id, cve_id)` |
| `epss.py` | FIRST.org EPSS API — batch fetch exploitation probability scores |
| `kev.py` | CISA KEV catalogue — marks vulnerabilities with `is_kev=True` |
| `nvd.py` | NVD API 2.0 — enriches CVEs with description, CWE, CVSS v3/v4, refs |
| `alerts.py` | Sends Webhook POST and/or SMTP email on new vulnerability events |
| `pdf_report.py` | fpdf2 PDF generation. Uses Helvetica (Latin-1 only); use `_s()` to strip non-Latin-1 chars |
| `iec62443_report.py` | IEC 62443-4-1: 11 SDL requirements (SM-9, DM-1~5, SUM-1~5) assessed against DB data |
| `iec62443_42_report.py` | IEC 62443-4-2: Component-level CR-1~4 requirements |
| `iec62443_33_report.py` | IEC 62443-3-3: System-level FR-1~7 requirements |

### Frontend (`frontend/src/`)

**`api/client.js`** — Axios instance with `baseURL: /api`; Vite proxies `/api` → `http://localhost:9100`

**`App.jsx`** — All routes:

| Route | Page | Description |
|-------|------|-------------|
| `/` | `Dashboard` | Stats, CRA countdown, severity charts |
| `/organizations` | `Organizations` | Customer org management |
| `/organizations/:orgId/products` | `Products` | Product list for an org |
| `/products/:productId/releases` | `Releases` | Release list with vuln trend chart |
| `/releases/:releaseId` | `ReleaseDetail` | SBOM upload, scan, VEX, reports |
| `/releases/diff` | `ReleaseDiff` | Two-version vulnerability diff |
| `/cra` | `CRAIncidents` | CRA Article 14 incident list |
| `/cra/:incidentId` | `CRAIncidentDetail` | Incident detail + SLA clock |
| `/risk-overview` | `RiskOverview` | Cross-org risk ranking |
| `/policies` | `Policies` | Custom policy rule management |
| `/settings` | `Settings` | Brand config + notification config |
| `/search` | `Search` | Global component search |
| `/help` | `Help` | In-app help center (24 articles, full-text search) |

**`components/Layout.jsx`** — Nav sidebar + top search bar. Active state: `location.pathname.startsWith(item.path)`.

### CRA Incident State Machine
```
detected → pending_triage → clock_running → t24_submitted → investigating
                         ↘                → t72_submitted → remediating → final_submitted → closed
                           close-not-affected → closed
```
Clock (T+24h/72h/14d deadlines) starts only at `clock_running` via explicit `start-clock` call, preserving the legal awareness timestamp.

### VEX Fields (on `vulnerabilities` table)
- `status`: `open` / `in_triage` / `not_affected` / `affected` / `fixed`
- `justification`: only valid when `status = not_affected` (cleared otherwise). Values: `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control`
- `response`: only valid when `status = affected` (cleared otherwise). Values: `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available`
- `detail`: free-text, always valid

### Schema Migrations
New columns go in the `main.py` migration block (inline `ALTER TABLE ADD COLUMN IF NOT EXISTS`). No Alembic. Existing migration block covers: `vulnerabilities` (VEX fields, EPSS, KEV, NVD, patch tracking) and `releases` (`sbom_hash`, `locked`).

### Key Constraints
- **Port 9100 only** — 8080/8005/8009/8443 conflict with Tomcat on this machine
- SQLite at `backend/sbom.db`; uploads at `backend/uploads/` — neither tracked by git
- No Docker in dev environment
- Platform language: Traditional Chinese (zh-TW)
- EU CRA Article 14 enforcement deadline: **2026-09-11**
- `deploy/.env.server` contains real credentials — gitignored, never commit

## Documentation
- `docs/api-reference.md` — Full API endpoint reference
- `docs/db-schema.md` — All 13 tables with field descriptions
- `docs/user-manual.md` — Consultant SOP (8-step workflow + scenarios)
- `docs/phase2-spec.md` — Phase 2 feature specs (CSAF import, VEX chain, firmware scan)
- `deploy/ORACLE_CLOUD_SETUP.md` — Production deployment guide
