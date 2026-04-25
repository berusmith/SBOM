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

**Full regression suite** (54 tests, run from the repo root):
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
AuditEvent    (global, append-only)
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
| `auth.py` | `/api/auth` | POST `/login`, GET `/me`（回傳 `plan`）, GET `/oidc/config` `/oidc/login` `/oidc/callback`, POST `/change-password` |
| `organizations.py` | `/api/organizations` | CRUD + `/{id}/products` + PATCH `/{id}/plan`（admin only）|
| `products.py` | `/api/products` | CRUD + `/{id}/releases`, `/vuln-trend` (returns `total` unresolved + `total_all`), `/diff` |
| `releases.py` | `/api/releases` | CRUD + POST `/sbom` `/rescan` `/enrich-epss` `/enrich-nvd` `/enrich-ghsa` `/lock` `/unlock` `/signature` `/scan-image` `/scan-iac` `/upload-source` `/sbom-from-source` `/sbom-from-binary`; GET `/vulnerabilities` `/report` `/compliance/iec62443` `/compliance/iec62443-4-2` `/compliance/iec62443-3-3` `/evidence-package` `/csaf` `/integrity` `/patch-stats` `/gate` `/dependency-graph` `/export/cyclonedx-xml` `/export/spdx-json` `/sbom-quality` `/signature/verify`; DELETE `/signature` |
| `notice.py` | `/api/notice` | GET — public OSS attribution (NOTICE.md plain text) |
| `vulnerabilities.py` | `/api/vulnerabilities` | PATCH `/{id}/status`, PATCH `/batch`, PATCH `/{id}/suppress`, GET `/{id}/history` |
| `cra.py` | `/api/cra` | CRUD `/incidents` + POST `/start-clock` `/advance` `/close-not-affected` |
| `stats.py` | `/api/stats` | GET `/` `/risk-overview` `/top-threats` `/top-risky-components` `/sbom-quality-summary` `/cve-impact` |
| `convert.py` | `/api/convert` | POST `?target=cyclonedx-json\|cyclonedx-xml\|spdx-json` — 格式互轉，回傳下載檔 |
| `share.py` | `/api/releases/{id}/share-link` `/api/share/{token}` | 建立/列出/撤銷分享連結（Professional）；`GET /api/share/{token}` 公開無需登入，支援 `mask_internal` 過濾內部元件，記錄 `download_count` |
| `search.py` | `/api/search` | GET `/components?q=` |
| `settings.py` | `/api/settings` | GET/POST `/brand` `/alerts`, POST `/brand/logo` |
| `policies.py` | `/api/policies` | CRUD |
| `users.py` | `/api/users` | CRUD (admin only); PATCH supports `username` / `password` / `role` / `email` / `organization_id` / `is_active` |
| `admin.py` | `/api/admin` | GET `/activity?date_from=&date_to=` |
| `firmware.py` | `/api/firmware` | POST `/upload`, GET `/scans`, GET `/scans/{id}` |
| `tokens.py` | `/api/tokens` | GET/POST/DELETE — long-lived API keys for CI/CD (prefix `sbom_`); `scope` = `read`/`write`/`admin` enforced by HTTP verb in `deps.get_current_user`; token/user management uses `require_admin_scope` (admin scope only) |

User-facing 409/400 error messages are in Traditional Chinese (zh-TW).

**`models/`** — SQLAlchemy ORM

| File | Table | Key notes |
|------|-------|-----------|
| `vulnerability.py` | `vulnerabilities` | VEX status/justification/response/detail + EPSS + KEV + NVD enrichment + `scanned_at`/`fixed_at` + `suppressed`/`suppressed_until`/`suppressed_reason` + `ghsa_id`/`ghsa_url` + `reachability` (`function_reachable`/`reachable`/`test_only`/`not_found`/`unknown`) |
| `release.py` | `releases` | `sbom_hash` (SHA-256 of uploaded file), `locked` bool, `sbom_signature` / `signature_public_key` / `signature_algorithm` / `signer_identity` / `signed_at` for Sigstore/cosign verification |
| `cra_incident.py` | `cra_incidents` | SLA timestamps (`awareness_timestamp`, `t24/72/14d_deadline`), append-only `audit_log` string. **No FK to Organization** — incidents are global, not org-scoped |
| `vex.py` | `vex_statements` | Release-level VEX, separate from per-vulnerability status; used by CSAF export |
| `user.py` | `users` | `role`: `admin` / `viewer`; `hashed_password` nullable (SSO-only users); `organization_id` nullable FK; `oidc_sub` — OIDC subject identifier for SSO login |
| `organization.py` | `organizations` | `plan`: `starter` / `standard` / `professional` (default `starter`); controls feature access via `core/plan.py` |
| `brand_config.py` / `alert_config.py` | singletons | Always one row; GET creates default if missing |
| `firmware_scan.py` | `firmware_scans` | UUID `id`, `filename`, `status` (pending/running/completed/failed), `progress` (0-100), `components_count`, `emba_output_json`, `error_message`, timestamps |
| `share_link.py` | `sbom_share_links` | `token` (unique URL-safe), `release_id` FK, `expires_at` (nullable), `mask_internal` bool, `download_count`, `created_by` |

**`schemas/`** — Pydantic v2 schemas exist only for Organization, Product, Release. All other routers define inline `BaseModel` classes.

**`services/`**

| File | Description |
|------|-------------|
| `sbom_parser.py` | CycloneDX + SPDX JSON → `[{name, version, purl, license}]`; also extracts `dependencies[]` / `relationships[]` for dependency graph |
| `vuln_scanner.py` | OSV.dev `/v1/query` per PURL; deduplicates on `(component_id, cve_id)` |
| `epss.py` | FIRST.org EPSS batch API |
| `kev.py` | CISA KEV catalogue → sets `is_kev=True` |
| `nvd.py` | NVD API 2.0 → description, CWE, CVSS v3/v4, refs. Rate-limited: 5 req/30s without key, 50/30s with `NVD_API_KEY` |
| `pdf_report.py` | fpdf2. **Helvetica only (Latin-1)** — always pass text through `_s()` helper to strip non-Latin-1 chars |
| `iec62443_report.py` | 4-1 SDL: SM-9, DM-1~5, SUM-1~5 |
| `iec62443_42_report.py` | 4-2 component: CR-1~4 |
| `iec62443_33_report.py` | 3-3 system: FR-1~7 |
| `alerts.py` | Webhook POST + SMTP email on new vulnerability events |
| `firmware_service.py` | EMBA firmware analysis: auto-detect EMBA, run background scans, parse EMBA JSON → component list, demo mode for Windows dev |
| `signature_verifier.py` | SBOM signature verification: ECDSA (cosign/Sigstore default), RSA-PSS, RSA-PKCS1; auto-detect algorithm from public key; extract signer identity from X.509 certs |
| `trivy_scanner.py` | Trivy wrapper: `scan_image(image_ref)` → CycloneDX, `scan_iac(zip_bytes)` → CycloneDX + misconfigs, `extract_misconfigs()` pulls AVD-/DS- findings; 503 if Trivy not installed (no demo mode needed — Trivy is free) |
| `syft_scanner.py` | Syft wrapper (Apache-2.0): `scan_source(zip_bytes)` extracts archive (zip-bomb safe, 500MB cap) and runs `syft <dir>`, `scan_binary(file_bytes, filename)` runs `syft <file>`; both return CycloneDX dict; 503 if Syft not installed |
| `ghsa.py` | GitHub Advisory Database REST API: `fetch_ghsa_for_components(components)` → per-purl advisory list; supports npm/pypi/maven/nuget/cargo/gem/go; optional `GITHUB_TOKEN` (60 req/h without, 5000/h with) |
| `reachability.py` | Three-phase source reachability: `scan_zip(zip_bytes)` → `ScanResult(presence, ast_reachable)`; Phase 1 regex import scan, Phase 2 test-path filtering, Phase 3 Python AST call graph (`_FileAnalyser` — alias tracking, route decorator detection, 1-hop call graph); `classify_vulns()` → `function_reachable`/`reachable`/`test_only`/`not_found` |
| `converter.py` | SBOM format conversion: `convert(content, filename, target)` → `(bytes, filename)`; supports CycloneDX JSON ↔ SPDX JSON, CycloneDX JSON ↔ XML; preserves PURL/License/metadata |
| `monitor.py` | Continuous vulnerability monitoring: `start()`/`stop()` lifecycle hooks, `trigger()` for manual run, `get_status()` for UI; polls OSV.dev on schedule, inserts new vulns, fires alerts |

**`core/config.py`** — Pydantic Settings loaded from `backend/.env`. `DTRACK_URL` / `DTRACK_API_KEY` are legacy fields (Dependency-Track integration was replaced by direct OSV.dev calls); ignore them. OIDC settings: `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URI` (leave empty to disable SSO).

**`core/plan.py`** — Plan feature gating. `FEATURE_PLAN` maps feature keys to minimum plan. `require_plan(feature)` FastAPI dependency raises 402 if org plan insufficient. `check_starter_limit(db, org_id, resource)` enforces Starter data limits (3 products / 10 releases). Admin users always bypass plan checks. Plans: `starter` < `standard` < `professional`.

**Python compatibility** — The production server runs Python 3.11 (installed by `deploy/setup.sh`). Local dev supports 3.11+. The codebase uses `from __future__ import annotations` in several files for forward-compat; keep this habit for any file using `X | Y` unions or `list[X]` outside string literal hints.

### Key helpers in `releases.py`

- `_SLA_DAYS` — dict mapping severity → SLA days (`critical: 7, high: 30, medium: 90, low: 180`)
- `_sla_info(vuln)` — returns `{sla_days, sla_status}` (`overdue` / `warning` / `ok` / `na`); calls `_is_suppressed()` first and returns `na` for suppressed vulns
- `_is_suppressed(vuln)` — checks `vuln.suppressed` and `vuln.suppressed_until` against current UTC time; no cron needed, evaluated on every request

### Frontend (`frontend/src/`)

**`api/client.js`** — Axios instance; `baseURL: /api`; JWT token injected from `localStorage.getItem("token")`. Vite proxies `/api` → `http://localhost:9100`.

**`App.jsx`** — All routes. Auth guard (`RequireAuth`) redirects to `/login` if no token.

| Route | Page | Notes |
|-------|------|-------|
| `/` | `Dashboard` | CRA countdown, severity charts, SLA-overdue card, top-risky-components table, patch stats |
| `/organizations` | `Organizations` | Entry point for org → product → release drill-down |
| `/organizations/:orgId/products` | `Products` | Trend chart with Medium line + hover tooltip |
| `/products/:productId/releases` | `Releases` | |
| `/releases/:releaseId` | `ReleaseDetail` | Most complex page — see below |
| `/releases/diff` | `ReleaseDiff` | Query params `?v1=&v2=` |
| `/cra` / `/cra/:id` | `CRAIncidents` / `CRAIncidentDetail` | |
| `/risk-overview` | `RiskOverview` | Cross-org Critical/High ranking |
| `/policies` | `Policies` | |
| `/settings` | `Settings` | Brand + notifications |
| `/search` | `Search` | Global component search |
| `/help` | `Help` | 24-article in-app help center with full-text search |
| `/admin/activity` | `AdminActivity` | Audit log with date-range filter + CSV export |
| `/firmware` | `FirmwareUpload` | Firmware scan upload, drag-drop, progress tracking, component extraction, auto-refresh |
| `/admin/users` | `Users` | User management (admin only) |
| `/tisax` / `/tisax/:id` | `TISAXAssessments` / `TISAXDetail` | TISAX self-assessment |
| `/profile` | `Profile` | User profile |

State is local React hooks only — no Redux/Zustand.

**`ReleaseDetail.jsx` structure** (most complex page):
- Three tabs: 元件 / 漏洞 / 依賴關係圖
- Policy Gate card (green/red border, 5 checks) rendered above SBOM quality card
- Vuln table: SLA column (hidden lg), suppress button per row alongside VEX edit button
- `severityCounts` and Policy Gate exclude suppressed vulns (`v.suppressed`)
- `displayedVulns` filter: `showSuppressed` toggle switches between suppressed and active vulns
- Upload result shows diff vs previous release version
- Inline components: `DependencyGraph` (SVG, BFS layout), `VexEditButton` + `VexModal`, `SuppressButton` + `SuppressModal`

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

### Suppression (Risk Acceptance)
Separate from VEX status. `suppressed=true` removes a vuln from SLA tracking, severity counts, and Policy Gate checks. `suppressed_until` is an optional UTC expiry — `_is_suppressed()` evaluates it on every request with no background job needed.

### Key Constraints
- **Port 9100 only** — 8080/8005/8009/8443 conflict with Tomcat on this machine
- No Docker in dev environment
- `backend/sbom.db` and `backend/uploads/` are gitignored; `deploy/.env.server` has real credentials — gitignored
- Schema changes: add `ALTER TABLE ADD COLUMN` to the migration block in `main.py`; SQLite does not support DROP/RENAME COLUMN natively
- SQLite runs in **WAL mode** (`PRAGMA journal_mode=WAL` in `core/database.py`) — `sbom.db-shm` and `sbom.db-wal` are normal side-files, gitignored
- No new npm packages — all charts/graphs use pure SVG rendered in React

### CI/CD Tools (`tools/` directory)

**`tools/sbom-cli/`** — Python command-line tool for SBOM operations in CI/CD pipelines
- `sbom.py` — Main CLI with three subcommands:
  - `sbom upload <file> --release <id>` — Upload SBOM file (multipart form-data to `/api/releases/{id}/sbom`)
  - `sbom gate --release <id>` — Check Policy Gate status (GET `/api/releases/{id}/gate`); exit 0 if passed, 1 if failed
  - `sbom diff --v1 <id1> --v2 <id2> [--product <pid>]` — Compare two releases (GET `/api/products/{pid}/diff?from={id1}&to={id2}`)
- `setup.py` — Installable via `pip install -e tools/sbom-cli`; registers `sbom` console script
- Environment variables: `SBOM_API_TOKEN` (required), `SBOM_API_URL` (default: `http://localhost:9100`)
- Pure stdlib (urllib + json), no external dependencies except setuptools

**`tools/sbom-action/`** — GitHub Actions composite action
- `action.yml` — Composite action with inputs: `sbom-file`, `release-id`, `api-token`, `api-url`, `fail-on-gate`, `product-id`
- Steps: Setup Python → Install CLI → Upload SBOM → Check gate → Comment on PR
- Automatically comments on PR with Policy Gate results
- Usage: `uses: ./tools/sbom-action` with secrets for API token

### Production Server
- **Target**: Mac Mini (macOS), `$HOME/sbom/`, no sudo required
- **Service supervisor**: launchd user agent at `~/Library/LaunchAgents/com.sbom.backend.plist`
- **Connection**: env-driven — `SBOM_DEPLOY_HOST` (e.g. `mac-mini.local` / Tailscale name), `SBOM_DEPLOY_USER`, optional `SBOM_DEPLOY_DIR` / `SBOM_SSH_KEY`
- **First deploy**: `SBOM_DEPLOY_HOST=mac-mini.local bash deploy/first-deploy.sh` — uploads bootstrap files, runs `setup-macos.sh` (Homebrew python@3.11, dirs, venv, launchd plist), pauses for manual `.env` edit, then runs `deploy.sh`
- **Routine deploy**: `SBOM_DEPLOY_HOST=mac-mini.local bash deploy/deploy.sh` — local frontend build, tar+ssh upload backend + dist, pip install, reload launchd agent
- Node.js is NOT installed on the Mac Mini; frontend is always built on the dev machine then uploaded as `dist/`

## Documentation
- `docs/api-reference.md` — Full API endpoint reference with request/response shapes
- `docs/db-schema.md` — All tables with field-level descriptions
- `docs/user-manual.md` — Consultant SOP (8-step workflow + common scenarios)
- `docs/phase2-spec.md` — Phase 2 specs: CSAF import, VEX chain inheritance, firmware scan
- `docs/TISAX_MODULE_PLAN.md` — Planned TISAX module: VDA ISA 6.0 self-assessment (63 controls), maturity scoring 0–5, AL2/AL3 gap analysis
- `deploy/MACMINI_SETUP.md` — Mac Mini deployment guide: prerequisites, first-deploy/routine-deploy flows, three connection options (LAN / Tailscale / public+TLS), launchd ops commands
