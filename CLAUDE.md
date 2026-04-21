# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Starting the Platform

Backend (port 9100, kills existing process first):
```bash
# Windows
D:\projects\SBOM\start_backend.bat

# Or manually
cd D:\projects\SBOM\sbom-platform\backend
python -m uvicorn app.main:app --port 9100 --reload
```

Frontend (port 3000):
```bash
# Windows
D:\projects\SBOM\start_frontend.bat

# Or manually
cd D:\projects\SBOM\sbom-platform\frontend
npm run dev
```

API docs available at `http://localhost:9100/docs` when backend is running.

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
Organization → Product → Release → Component → Vulnerability
CRAIncident (org-level, independent)
```
All relationships use `cascade="all, delete-orphan"`. UUID primary keys throughout.

### Backend (`backend/app/`)
- **`main.py`** — FastAPI app, CORS (localhost:3000 only), and inline SQLite migration block (`ALTER TABLE ADD COLUMN` for columns that may not exist yet — add new columns here, not via Alembic)
- **`api/`** — One router per resource, prefix `/api/<resource>`. Chinese error messages for user-facing 409/400 errors.
- **`models/`** — SQLAlchemy ORM models. Cascade deletes already configured.
- **`schemas/`** — Pydantic schemas (only Organization, Product, Release have schemas; others use inline `BaseModel` in the router file)
- **`services/sbom_parser.py`** — Parses CycloneDX JSON and SPDX JSON, returns list of `{name, version, purl, license}`
- **`services/vuln_scanner.py`** — Calls OSV.dev `/v1/query` per component purl, deduplicates CVEs by `(component_id, cve_id)`
- **`services/pdf_report.py`** — fpdf2 PDF generation. Uses Helvetica (Latin-1 only); use `_s()` sanitizer helper to strip non-Latin-1 characters
- **`services/iec62443_report.py`** — Assesses 11 IEC 62443-4-1 requirements (SM-9, DM-1~5, SUM-1~5) against real DB data, generates PDF

### Frontend (`frontend/src/`)
- **`api/client.js`** — Axios instance with `baseURL: /api`; Vite proxies `/api` → `http://localhost:9100`
- **`App.jsx`** — All routes defined here
- **`pages/`** — One file per page. State management via hooks only, no Redux/Zustand.
- **`components/Layout.jsx`** — Nav sidebar. Use `location.pathname.startsWith(item.path)` for active state.

### CRA Incident State Machine
```
detected → pending_triage → clock_running → t24_submitted → investigating
         → t72_submitted → remediating → final_submitted → closed
```
`pending_triage` can also go directly to `closed` via `close-not-affected`. Clock (T+24h/72h/14d deadlines) starts only at `clock_running` via explicit `start-clock` call, preserving the legal "awareness timestamp".

### VEX Fields
- `status`: open / in_triage / not_affected / affected / fixed
- `justification`: only valid when `status = not_affected` (cleared otherwise)
- `response`: only valid when `status = affected` (cleared otherwise)
- `detail`: free-text, always valid

### Key Constraints
- Port 9100 only — port 8080/8005/8009/8443 conflict with Tomcat on this machine
- SQLite database at `backend/sbom.db`; SBOM files stored in `backend/uploads/`
- No Docker in this environment
- Platform language: Traditional Chinese (zh-TW)
- EU CRA Article 14 enforcement deadline: 2026-09-11
