# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Backend**
```bash
cd backend
python -m uvicorn app.main:app --port 9100 --reload   # dev
python -m uvicorn app.main:app --port 9100            # prod-like
```

**Frontend**
```bash
cd frontend
npm run dev      # dev server (port 3000)
npm run build    # production build → dist/
npm run preview  # serve dist/ locally
```

**Windows shortcuts** (from `sbom-platform/`):
- `start_backend.bat` — kills any existing port 9100 process, then starts backend
- `start_frontend.bat` — starts frontend dev server

**Interactive API docs:** `http://localhost:9100/docs`

## Testing

No pytest suite. Use stdlib-only ad-hoc scripts (`urllib` + `json` — `requests` and `grep -P` are unavailable).

**Full regression suite** (39 tests, run from `sbom-platform/`):
```bash
python test_all.py
```

**Ad-hoc pattern:**
```bash
python - <<'EOF'
import urllib.request, json
# 1. Get token
req = urllib.request.Request("http://localhost:9100/api/auth/login",
    data=json.dumps({"username":"admin","password":"sbom@2024"}).encode(),
    headers={"Content-Type":"application/json"}, method="POST")
token = json.loads(urllib.request.urlopen(req).read())["access_token"]
# 2. Use token
req2 = urllib.request.Request("http://localhost:9100/api/organizations",
    headers={"Authorization": f"Bearer {token}"})
print(json.loads(urllib.request.urlopen(req2).read()))
EOF
```

## Architecture

### Data Model
```
Organization → Product → Release → Component → Vulnerability → VexHistory
                               └── VexStatement  (release-level, for CSAF export)
                               └── ComplianceMap

CRAIncident   (org-level, no FK to products — incidents span product lines)
User / PolicyRule / BrandConfig / AlertConfig  (global, not org-scoped)
```
All FK relationships use `cascade="all, delete-orphan"`. UUID primary keys throughout.

### Backend (`backend/app/`)

**`main.py`**
- Inline SQLite migration block runs at every startup — add `ALTER TABLE ADD COLUMN` here for new columns, not Alembic
- Seeds admin user from env vars if `users` table is empty
- `STATIC_DIR` env var: when set, mounts React `dist/` at `/` for production single-binary mode

**`api/`** — One router per resource, all require JWT Bearer except `/api/auth/login`

| Router | Prefix | Key endpoints |
|--------|--------|---------------|
| `auth.py` | `/api/auth` | POST `/login`, GET `/me` |
| `organizations.py` | `/api/organizations` | CRUD + `/{id}/products` |
| `products.py` | `/api/products` | CRUD + `/{id}/releases`, `/vuln-trend`, `/diff` |
| `releases.py` | `/api/releases` | CRUD + POST `/sbom` `/rescan` `/enrich-epss` `/enrich-nvd` `/lock` `/unlock`; GET `/vulnerabilities` `/report` `/compliance/iec62443` `/compliance/iec62443-4-2` `/compliance/iec62443-3-3` `/evidence-package` `/csaf` `/integrity` `/patch-stats` |
| `vulnerabilities.py` | `/api/vulnerabilities` | PATCH `/{id}/status`, PATCH `/batch`, GET `/{id}/history` |
| `cra.py` | `/api/cra` | CRUD `/incidents` + POST `/start-clock` `/advance` `/close-not-affected` |
| `stats.py` | `/api/stats` | GET `/` `/risk-overview` `/top-threats` |
| `search.py` | `/api/search` | GET `/components?q=` |
| `settings.py` | `/api/settings` | GET/POST `/brand` `/alerts`, POST `/brand/logo` |
| `policies.py` | `/api/policies` | CRUD |
| `users.py` | `/api/users` | CRUD (admin only) |

User-facing 409/400 error messages are in Traditional Chinese (zh-TW).

**`models/`** — SQLAlchemy ORM

| File | Table | Key notes |
|------|-------|-----------|
| `vulnerability.py` | `vulnerabilities` | VEX status/justification/response/detail + EPSS + KEV + NVD enrichment + `scanned_at`/`fixed_at` |
| `release.py` | `releases` | `sbom_hash` (SHA-256 of uploaded file), `locked` bool |
| `cra_incident.py` | `cra_incidents` | SLA timestamps (`awareness_timestamp`, `t24/72/14d_deadline`), append-only `audit_log` string. **No FK to Organization** — incidents are global, not org-scoped |
| `vex.py` | `vex_statements` | Release-level VEX, separate from per-vulnerability status; used by CSAF export |
| `brand_config.py` / `alert_config.py` | singletons | Always one row; GET creates default if missing |

**`schemas/`** — Pydantic v2 schemas exist only for Organization, Product, Release. All other routers define inline `BaseModel` classes.

**`services/`**

| File | Description |
|------|-------------|
| `sbom_parser.py` | CycloneDX + SPDX JSON → `[{name, version, purl, license}]` |
| `vuln_scanner.py` | OSV.dev `/v1/query` per PURL; deduplicates on `(component_id, cve_id)` |
| `epss.py` | FIRST.org EPSS batch API |
| `kev.py` | CISA KEV catalogue → sets `is_kev=True` |
| `nvd.py` | NVD API 2.0 → description, CWE, CVSS v3/v4, refs. Rate-limited: 5 req/30s without key, 50/30s with `NVD_API_KEY` |
| `pdf_report.py` | fpdf2. **Helvetica only (Latin-1)** — always pass text through `_s()` helper to strip non-Latin-1 chars |
| `iec62443_report.py` | 4-1 SDL: SM-9, DM-1~5, SUM-1~5 |
| `iec62443_42_report.py` | 4-2 component: CR-1~4 |
| `iec62443_33_report.py` | 3-3 system: FR-1~7 |
| `alerts.py` | Webhook POST + SMTP email on new vulnerability events |

**`core/config.py`** — Pydantic Settings loaded from `backend/.env`. `DTRACK_URL` / `DTRACK_API_KEY` are legacy fields (Dependency-Track integration was replaced by direct OSV.dev calls); ignore them.

**Python 3.9 compatibility** — The server runs Python 3.9. Use `from __future__ import annotations` at the top of any file that uses `X | Y` union syntax or `list[X]` / `dict[K,V]` in type hints outside of string literals.

### Frontend (`frontend/src/`)

**`api/client.js`** — Axios instance; `baseURL: /api`; JWT token injected from `localStorage.getItem("token")`. Vite proxies `/api` → `http://localhost:9100`.

**`App.jsx`** — All routes. Auth guard (`RequireAuth`) redirects to `/login` if no token.

| Route | Page | Notes |
|-------|------|-------|
| `/` | `Dashboard` | CRA countdown, severity charts, patch stats |
| `/organizations` | `Organizations` | Entry point for org → product → release drill-down |
| `/organizations/:orgId/products` | `Products` | |
| `/products/:productId/releases` | `Releases` | |
| `/releases/:releaseId` | `ReleaseDetail` | Most complex page: SBOM upload, scan, VEX, all report downloads |
| `/releases/diff` | `ReleaseDiff` | Query params `?v1=&v2=` |
| `/cra` / `/cra/:id` | `CRAIncidents` / `CRAIncidentDetail` | |
| `/risk-overview` | `RiskOverview` | Cross-org Critical/High ranking |
| `/policies` | `Policies` | |
| `/settings` | `Settings` | Brand + notifications |
| `/search` | `Search` | Global component search |
| `/help` | `Help` | 24-article in-app help center with full-text search |

State is local React hooks only — no Redux/Zustand.

### CRA Incident State Machine
```
detected
  └→ pending_triage
        ├→ closed            (close-not-affected: confirmed not in scope)
        └→ clock_running     (start-clock: sets awareness_timestamp = T+0)
              └→ t24_submitted   (Early Warning filed, T+24h)
                    └→ investigating
                          └→ t72_submitted   (Notification filed, T+72h)
                                └→ remediating
                                      └→ final_submitted   (Final Report, T+14d after patch)
                                            └→ closed
```

### VEX Fields
- `status`: `open` / `in_triage` / `not_affected` / `affected` / `fixed`
- `justification` (only with `not_affected`): `code_not_present` `code_not_reachable` `requires_configuration` `requires_dependency` `requires_environment` `protected_by_compiler` `protected_at_runtime` `protected_at_perimeter` `protected_by_mitigating_control`
- `response` (only with `affected`): `can_not_fix` `will_not_fix` `update` `rollback` `workaround_available`
- Setting `status` to anything other than the valid parent clears `justification`/`response` automatically

### Key Constraints
- **Port 9100 only** — 8080/8005/8009/8443 conflict with Tomcat on this machine
- No Docker in dev environment
- `backend/sbom.db` and `backend/uploads/` are gitignored; `deploy/.env.server` has real credentials — gitignored
- Schema changes: add `ALTER TABLE ADD COLUMN` to the migration block in `main.py`; SQLite does not support DROP/RENAME COLUMN natively

### Production Server
- **IP**: `161.33.130.101` — Oracle Linux 9.7, 1GB RAM, user `opc`
- **SSH key**: `D:\projects\SBOM\ssh-key-2026-04-21.key` (gitignored, one level above `sbom-platform/`)
- **Deploy**: `bash deploy/deploy.sh` from `sbom-platform/` — builds frontend locally, rsyncs to server, restarts service
- **First deploy**: `bash deploy/first-deploy.sh` — also runs `setup.sh` on server (installs python3.11 + nginx via dnf)
- Node.js is NOT installed on the server; frontend is always built locally then uploaded as `dist/`

## Documentation
- `docs/api-reference.md` — Full API endpoint reference with request/response shapes
- `docs/db-schema.md` — All 13 tables with field-level descriptions
- `docs/user-manual.md` — Consultant SOP (8-step workflow + common scenarios)
- `docs/phase2-spec.md` — Phase 2 specs: CSAF import, VEX chain inheritance, firmware scan
- `docs/TISAX_MODULE_PLAN.md` — TISAX/VDA ISA 6.0 module design (data model, API, UI — not yet implemented)
- `deploy/ORACLE_CLOUD_SETUP.md` — Production server info, firewall setup, deploy steps, ops commands
