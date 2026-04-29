---
created: 2026-04-29
purpose: Snapshot of project state at start of first refactor-audit iteration
do_not_edit_after_creation: true (use ledger.md for evolution; this file is frozen)
---

# Refactor Audit — Baseline (frozen 2026-04-29)

This file is the **frozen** starting point. All future iterations measure improvements against these numbers. Do not edit after creation; let `ledger.md` and `architecture.md` track evolution.

## 1. Identity

- **Project**: SBOM Management Platform
- **Domain**: ICS/OT manufacturer compliance (EU CRA, IEC 62443, NIS2, TISAX)
- **Deployment shape today**: LAN-only single-tenant Mac mini; commercialisation target = B2B SaaS within 12 months
- **Primary working directory**: `C:\Claude Code\SBOM Tool`
- **Branch**: `master`, clean working tree at audit start
- **Total commits**: 277
- **Latest commit**: `0faee60` (SEC-027 candidate, 2026-04-29)

## 2. Scale

| Surface | LOC | Files | Notes |
|---|---:|---:|---|
| Backend (Python, `backend/app/`) | 12,737 | 83 | FastAPI + SQLAlchemy |
| Frontend (React, `frontend/src/`) | 12,712 | 47 | React 18 + Vite + Tailwind |
| Tests (Python, `backend/tests/` + repo root) | 869 | 3 | `test_all.py` 255 + `test_full_verification.py` 439 + `test_endpoint_decorator_enforcement.py` 175 |
| Reachability fixtures | 39 fixtures | n/a | Ground-truth corpus, not unit tests |
| Docs (`docs/` + root MD) | n/a | 11+ | `README.md` 323, `CLAUDE.md` 18.5KB, `NEXT_TASK.md` 234, `CHANGELOG.md` 343, `NOTICE.md` 177 |

### Largest files (long-file smell signal — to investigate in Phase 4)

Backend (top 5):
| LOC | File |
|---:|---|
| 2,101 | `backend/app/api/releases.py` ⚠️ god router |
| 518 | `backend/app/services/pdf_shim.py` |
| 425 | `backend/app/api/auth.py` |
| 406 | `backend/app/services/iec62443_report.py` |
| 399 | `backend/app/api/stats.py` |

Frontend (top 5):
| LOC | File |
|---:|---|
| 2,087 | `frontend/src/pages/ReleaseDetail.jsx` ⚠️ god component, 76 useState/useEffect |
| 1,071 | `frontend/src/pages/Help.jsx` (content blob, carry-over UX-033) |
| 842 | `frontend/src/pages/Settings.jsx` |
| 690 | `frontend/src/pages/Dashboard.jsx` |
| 582 | `frontend/src/i18n/zh.js` |

## 3. Dependency footprint

### Backend (`backend/requirements.txt`)
- 17 direct runtime deps (all permissive after Path-B license rotation)
- Notable: fastapi 0.120.4, starlette 0.49.2, sqlalchemy 2.0.49, pydantic 2.9.2, reportlab 4.4.4, pg8000 1.31.5, python-jose, passlib+bcrypt
- `psycopg2-binary` (LGPL) and `fpdf2` (LGPL) deliberately replaced

### Frontend (`frontend/package.json`)
- 6 runtime deps: react 18.3, react-dom, react-router-dom 6, axios, i18next 26, lucide-react
- 5 dev deps: vite 5, tailwindcss 3, postcss, autoprefixer, @vitejs/plugin-react
- **No chart library** — all viz is hand-rolled SVG (deliberate constraint per CLAUDE.md)

## 4. Public-API surface (behavior-equivalence boundary)

### HTTP routes — 21 routers, ~100+ endpoints
- 1 public POST: `/api/auth/login`
- 1 public GET: `/api/notice`, `/health`, `/api/share/{token}`
- All others require `Bearer` (JWT or API token `sbom_…`)
- Largest router by endpoint count: `releases.py` (37), `settings.py` (11), `auth.py` (10), `tisax.py` (8)

### Other surfaces
- DB schema (UUID PKs, `cascade="all, delete-orphan"` throughout, see `docs/db-schema.md`)
- File formats: CycloneDX JSON/XML, SPDX JSON, CSAF JSON
- CLI: `sbom upload | gate | diff` (`tools/sbom-cli/`)
- GitHub Action: `tools/sbom-action/action.yml` composite action
- Webhook formats: Slack Block Kit, Teams MessageCard
- Email format: SMTP HTML/text alerts

## 5. Test posture

- **Integration**: `test_all.py` — 54 stdlib HTTP tests against running backend; CI-gated; `python-dotenv` autoloads `backend/.env`
- **Older**: `test_full_verification.py` — 439 LOC stdlib HTTP, status unclear
- **Structural**: `test_endpoint_decorator_enforcement.py` — CI walks every release route, fails build if `Depends(require_release_in_scope)` missing
- **Reachability corpus**: 39 fixtures + validator + stats + runner (acceptance gate for Wave D sprint)
- **No pytest framework**, **no unit tests**, **no coverage reporting**, **no characterization tests**
- Frontend: zero JS tests

## 6. Performance baseline

- **No formal benchmarks exist.** Only documented optimization is OSV batch (200 → 51 HTTP for 200-component SBOM, recorded in CHANGELOG `[Unreleased]`)
- **No APM**, no production profiling, no Web Vitals collection
- **No load tests**, no synthetic benchmark suite
- Phase 5 of this audit must establish first measurements

## 7. Security baseline (must preserve in any refactor)

A separate **security audit** was completed 2026-04-26 → 2026-04-28 (see `.knowledge/audit/EXECUTIVE-SUMMARY.md`). 26 findings, 12 fix-commits, all Top-10 closed. Controls in place at audit start:

### Authn/authz
- JWT bcrypt + revoked-token blacklist (`RevokedToken`)
- API token `sbom_` prefix, `read|write|admin` scope, enforced in `core/deps.py:get_current_user`
- OIDC SSO (optional)
- Multi-tenant: `require_release_in_scope` dependency + CI enforcement test (SDLC-001)
- 404 (not 403) for cross-org access (CWE-204 oracle prevention)

### Input validation
- Pydantic v2 at every router boundary
- XML billion-laughs blocked: pre-parse `DOCTYPE`/`ENTITY` reject + 5 MB body cap
- Path traversal: `safe_attachment_filename` for downloads
- CSV formula injection: `csv_safe` for all exports
- Zip-bomb cap: 500 MB on source upload extraction

### Transport / boundary
- CORS: explicit origin + method/header whitelist
- Rate limit: 300 req/min/IP global, 10/5min on `/login`, X-Real-IP only (no XFF spoof — neutralised at nginx + uvicorn `--no-proxy-headers`)
- TLS at nginx edge in prod
- `SECRET_KEY` startup guard (refuses default + < 32 bytes when `DEBUG=false`)
- `ADMIN_PASSWORD` startup guard (refuses public defaults when `DEBUG=false`)

### Supply chain & ops
- CI: `pip-audit --strict`, `bandit -ll`, `npm audit --omit=dev`, `gitleaks`, `syft+grype` self-SBOM scan, `test_all.py`, structural enforcement test
- nightly encrypted backup (gpg AES-256, `deploy/backup.sh`)
- Sigstore signature verification on uploaded SBOMs (ECDSA default, RSA-PSS, RSA-PKCS1)

### Open security items at audit start
- **SEC-027 candidate** (admin password .env-to-DB drift) — documented in `.knowledge/audit/SEC-027-candidate-admin-rotation.md`, mitigation choice deferred
- **14 deferred Phase-3 findings** — rated `lan_only: Low`, re-evaluated on commercialisation triggers

## 8. Engineering maturity — initial estimates

These are first-iteration **gut estimates** to be refined by `calibration.md` in Phase 2. Scale 1–10 against world-class reference (Stripe / Linear / TigerBeetle / SQLite for the relevant slice).

| Dimension | Estimate | Reasoning (initial) |
|---|:---:|---|
| 架構清晰度 | 5 | Layers exist (api/services/models/core) but boundary not enforced; god router exists |
| 領域純粹度 | 3 | ORM entities used as domain entities; business logic mixed into routers |
| 抽象成本意識 | 7 | Few unnecessary abstractions; `pdf_shim` is honest about being a shim |
| 可讀性密度 | 7 | Naming generally good; CLAUDE.md gives codebase a strong table of contents |
| 錯誤處理品質 | 5 | 46 broad `except Exception`; user-facing zh-TW messages consistent; no Result type |
| 測試品質 | 3 | Live-HTTP integration only; zero unit; no coverage; no characterization safety net |
| 可觀測性 | 4 | Stdlib `logging.getLogger(__name__)` in places; no structured/correlation/metrics |
| 效能意識 | 5 | OSV batch optimization shows awareness; N+1 risk in 21 routers untested |
| API 設計品質 | 6 | Consistent verbs/prefixes; inline `BaseModel` in 18/21 routers fragments shape |
| 依賴衛生 | 8 | License-clean, version-pinned, CI-audited |
| 建構與工具 | 7 | Vite + uvicorn + bat scripts; CI is real; no Docker dev burden |
| 文件密度 | 9 | CLAUDE.md + NEXT_TASK + CHANGELOG + .knowledge/ + .ui-audit/ — rare for a single-dev project |

**Working hypothesis**: the project is **document-strong, test-weak, architecture-medium**. Refactoring will be unusually safe because docs reflect intent, but unusually risky because there is no characterization safety net under integration smoke tests.
