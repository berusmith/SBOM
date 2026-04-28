---
audience: executive / commercialisation-due-diligence / future-self
length_target: 500–800 words
audit_id: 2026-04-26-security-code-review
audit_period: 2026-04-26 → 2026-04-28
status: closed
internal_detail_links:
  - phase-4-summary-2026-04-26.md         # full Phase 1–4 synthesis
  - phase-6-verification-2026-04-26.md    # full Phase 5 + Phase 6 verification
  - security-audit-2026-04-26.md          # SEC-001 family + SDLC-001
  - security-audit-batch-tlt-2-21.md      # batch findings register (SEC-002…SEC-024)
---

# Executive Summary — SBOM Platform Security Audit (2026-04-26)

## 1. What was audited

The **SBOM Management Platform** — a multi-tenant FastAPI backend
(17 routers, 100+ endpoints) plus React frontend, running LAN-only
on a Mac mini today, B2B SaaS commercialisation planned within
12 months. It stores customer SBOMs, enriches via OSV.dev / NVD /
CISA-KEV, and exports CycloneDX / SPDX / CSAF + IEC 62443 reports.

The audit ran over three days (2026-04-26 → 2026-04-28) in six
phases: recon, STRIDE threat-model, dynamic-PoC finding production,
synthesis + heatmap, remediation, and verification.

## 2. What we found — risk distribution

**26 findings** were produced (25 in Phase 1–3 plus one CI-discovered
addition in Phase 6). Severity is rated under two deployment contexts:
LAN-only today vs hosted-commercial tomorrow.

| Severity   | LAN-only count | If commercialised |
|------------|:--------------:|:-----------------:|
| Critical   | 0              | 0                 |
| High       | 0              | 4                 |
| Medium     | 5              | 10                |
| Low / Info | 21             | 12                |

The headline issues were **multi-tenant data exposure** (four
cross-tenant leaks in license + policy violation endpoints — same
code shape, SEC-001a/b/c/d), **DoS surface** (XML billion-laughs in
the SBOM converter, X-Forwarded-For spoof bypassing rate limits),
and **SDLC gaps** (no enforcement that release endpoints check
ownership; no CI baseline). All findings were issues-by-construction;
no active exploitation observed.

## 3. What we fixed

**Twelve fix/hotfix commits** over three days closed every Top-10
finding plus the architectural SDLC-001 control plus two
audit-discovered additions (SEC-023 and SEC-024). The high-level
narrative:

- **Mandatory release-ownership middleware** (SDLC-001). Replaced
  ad-hoc per-handler checks with a `Depends(require_release_in_scope)`
  dependency plus a CI test that walks every route. The test caught
  a placeholder endpoint three earlier review phases had missed —
  filed as SEC-023, fixed in the same commit.
- **Closed four multi-tenant leaks** (SEC-001a/b/c/d). Summary
  endpoints are admin-only now (403); per-release endpoints return
  404 — not 403 — for cross-org access, so an attacker can't probe
  release IDs by status code (CWE-204 oracle prevention).
- **Hardened the DoS surface** (SEC-002, SEC-003). XML conversion
  rejects `DOCTYPE`/`ENTITY` pre-parse plus a 5 MB body cap;
  X-Forwarded-For spoofing was neutralised at three layers (nginx
  edge clearing, backend reads X-Real-IP, uvicorn `--no-proxy-headers`
  stops its built-in middleware re-trusting the spoof).
- **Supply-chain floor** (SEC-022, SEC-024). `requires-python ≥ 3.11.4`
  in `pyproject.toml`; `pg8000` bumped past `GHSA-wq2g-r956-j8cc`.
- **Encrypted nightly backups** (SEC-014). gpg AES-256 with
  off-host key-file procedure.
- **CI baseline live** (SEC-017). Six-job workflow on every push:
  pip-audit, bandit, npm audit, gitleaks, syft+grype self-SBOM,
  regression suite, and SDLC-001 enforcement test.

Every fix is traceable to a commit SHA on `master` and was re-verified
post-fix with the same dynamic PoC that confirmed the original leak.

## 4. What's not yet fixed

Three near-term items and one long-tail backlog:

- **SEC-024-followup-grype** — the `syft+grype` CI job may stay red
  if other transitive Highs exist beyond pg8000. Pending the next
  CI snapshot post-hotfix.
- **SEC-024-followup-gitleaks** — `gitleaks` job failure cause
  undetermined (Anchore-licence policy vs real leak); needs an
  authenticated GitHub Actions log fetch.
- **SEC-025 candidate** — backend uvicorn process silently exited
  once on the dev Windows machine; not opened as a finding, parked
  behind a three-condition trigger (T8) that promotes it only on
  evidence of recurrence in production.
- **14 deferred Phase-3 findings** — all rated `lan_only: Low` and
  not commercialisation-blocking under the current deployment shape.
  They re-enter scope automatically when the next-cycle triggers fire.

## 5. When the next audit cycle starts

**Trigger-driven, not calendar-driven.** Eight conditions promote work
back into active audit mode (full list in
`phase-6-verification-2026-04-26.md` §6):

- T1 first hosted (non-LAN) customer → severity matrix flips
- T2 first Postgres-backed deployment → pg8000 path live
- T3 first LLM integration PR → SEC-020 family lights up
- T4 externally-facing TLS termination → SDLC-002 perimeter review
- T5 externally-reported vulnerability → re-validate every "fixed"
- T6 calendar fallback at 6 months (2026-10-26)
- T7 major dependency upgrade (FastAPI/SQLAlchemy/React major bump)
- T8 SEC-025 candidate promotion criteria (silent-death recurrence)

Day-to-day, the CI baseline plus the SDLC-001 enforcement test guard
new code automatically — any new endpoint missing the ownership
dependency fails CI before merge.

## 6. Why this audit is trustworthy

**Methodology**: STRIDE, attack trees, abuse cases, dynamic PoCs
(not just static review), DREAD-style risk × exploitation heatmap,
compliance mapping against SOC 2 / ISO 27001 / GDPR / IEC 62443-4-1.

**AI tooling disclosure**: Anthropic's Claude Code was used for
source search, schema drafting, PoC scripting, and commit-message
drafting. The judgment calls — severity ratings, scope decisions,
top-10 priority ordering, the IDOR 403-vs-404 oracle-prevention
call — were human auditor decisions, reviewed at five explicit
stop-gate rounds (rev-1 → rev-5) before remediation began.

**Traceability invariants** (the auditable backbone): every finding
has a status; every "fixed" status references a commit SHA; every
dynamic PoC carries both a frozen pre-fix `poc_metadata` block and a
post-fix `after_fix_verification` block; every post-fix re-run
verdict for the five dynamic PoCs is `NOT_REPRODUCED`. A customer
auditor can pick any finding ID and reach commit + PoC + verification
in three clicks — no orphan findings, no orphan commits.
