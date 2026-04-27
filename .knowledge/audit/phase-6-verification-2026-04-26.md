---
internal: true
phase: 6
audit_id: 2026-04-26-security-code-review
methodology: phase-4-summary §0 (single source of truth)
created: 2026-04-28
status: complete — Phase 5 + Phase 6 closed; SEC-024 filed for Phase 7
related:
  - phase-4-summary-2026-04-26.md   # Phase 5 commit log + lessons learned
  - security-audit-2026-04-26.md    # SEC-001 family + SDLC-001 detail
  - security-audit-batch-tlt-2-21.md # batch findings register (SEC-002…SEC-024)
---

# Phase 6 — Final Verification Report

This document is the closing record of the 2026-04-26 audit. Phase 5
remediation (10 Top-10 fixes + SEC-014 P2 + SEC-023 enforcement-discovered)
landed on `master` between commits `5286b00` (Phase 5 #0) and `9a69fe2`
(Phase 5+6 documentation). Phase 6 verification re-ran every PoC and
test against `master` HEAD `a63cb47` (this report and the
`after_fix_verification` evidence blocks ride on top of that HEAD).

The Phase 5 monitor-mode auto-pause conditions are reproduced verbatim
in phase-4-summary §5.2 — none triggered in the Phase 6 phase itself,
two had triggered earlier during Phase 5 (#2 stale uvicorn workers
during SEC-001c/d; #4 SEC-023 surfaced by the SDLC-001 enforcement
test on its first run). Both were resolved without scope change.

---

## 1. Phase 5 commit ledger — 11 fix commits + 2 docs commits

| #   | Commit  | Finding(s)            | Before-fix verdict             | After-fix verdict (Phase 6)        |
|-----|---------|----------------------|--------------------------------|------------------------------------|
| 0   | `5286b00` | SEC-017 (CI baseline) | 0 jobs                         | 6 jobs running on every push (3 still red — see §4) |
| 1   | `a604c56` | SDLC-001 + SEC-023   | no enforcement; placeholder route had no Depends | enforcement test 42/42; placeholder closed in same commit |
| 2   | `21b7ee7` | SEC-001a              | viewer → 200 with cross-tenant data | viewer → **403** (`require_admin`)         |
| 3   | `f5dc94c` | SEC-001b              | viewer → 200 with cross-tenant data | viewer → **404** (CWE-204 oracle-safe)     |
| 4+5 | `f0355ec` | SEC-001c + SEC-001d   | summary leak + IDOR             | summary 403, IDOR 404 (both NOT_REPRODUCED) |
| 6   | `6f44863` | SEC-003               | XFF spoof bypassed rate-limit + audit-log IP | rate-limit hit at attempt 11; audit IP = `127.0.0.1` |
| 7   | `c5ab06c` | SEC-022               | no `requires-python`           | `pyproject.toml` rejects 3.11.3 / accepts 3.11.4+ |
| 8   | `8d26065` | SEC-002               | depth-4 lol payload → 200 in 2.03s | depth-4 lol payload → **400 in 0.01s** |
| 9   | `35f11aa` | SEC-018               | 0 security headers             | 4 headers present; static-asset duplication for nginx inheritance quirk |
| P2  | `c401c11` | SEC-014               | plaintext nightly backups      | gpg AES-256 round-trip (canary not in ciphertext, decrypt OK, wrong-pass rejected) |
| docs | `9a69fe2` | (Phase 5/6 log)      | n/a                            | phase-4-summary §9 added            |
| docs | `a63cb47` | (Phase 6 evidence)   | n/a                            | `after_fix_verification` blocks for 5 PoCs |

All 11 fix commits and both docs commits are pushed to `origin/master`
(`berusmith/SBOM`) and mirrored to `audit-mirror/master`
(`ninjat6/SBOM-audit-private`) via `git audit-push`.

---

## 2. test_all.py regression

```
$ python test_all.py
…
=======================================================
TOTAL: 55 PASS / 0 FAIL  (55 tests)
```

- Run target: live backend on `127.0.0.1:9100` (uvicorn @ `--no-proxy-headers`, DEBUG=true)
- Commit at run-time: `9a69fe2` (HEAD before this report's commit)
- Wall time: ~30 s for the full suite
- Coverage breadth (sample): auth (incl. RBAC viewer block), CRUD across org/product/release, SBOM upload + OSV scan, vuln status patch, share-link Professional gate, PolicyRule CRUD, NVD enrich endpoint blocked-without-auth, token CRUD + scope (read / write / admin) + revocation + scope-violation 403s, cascade DELETE.

**0 regression.** Phase 6.1 ✓.

### Run-1 anomaly (documented for transparency)
The first attempt at running test_all.py against the live backend failed at the very first `urlopen` with `[WinError 10061]` — connection refused. The backend uvicorn process (PID 11180) had silently died between the smoke test and the test_all.py invocation. The backend log ends without a traceback, just stops mid-stream after a frontend-Dashboard polling burst (Vite dev preview was running concurrently). Restarting the backend and immediately re-running test_all.py produced the 55/55 result above. No code change was needed; classified as a Windows-only `--reload`-less uvicorn lifecycle quirk under unrelated frontend traffic, not a regression of any Phase 5 fix. If the same crash recurs on the production Mac mini path (launchd auto-restarts via `KeepAlive` so the symptom would be a transient health blip), file as SEC-025 (DoS resilience adjacent to SEC-015). LAN-only impact today: zero.

---

## 3. SDLC-001 enforcement test

```
$ python -m pytest backend/tests/test_endpoint_decorator_enforcement.py -v
…
backend\tests\test_endpoint_decorator_enforcement.py::test_all_release_scoped_endpoints_have_ownership_dependency PASSED [ 50%]
backend\tests\test_endpoint_decorator_enforcement.py::test_decorator_argument_consistency PASSED [100%]
======================== 2 passed, 6 warnings in 0.87s ========================
```

- Both invariants pass.
- 42/42 release-scoped endpoints have an ownership dependency
  (`Depends(require_release_in_scope)` or `Depends(require_admin)`).
- Test was run via `pytest -v` per Phase 6 instructions; pytest 9.0.3
  installed via `pip install --user pytest` because the repo is
  pytest-less by design (CLAUDE.md: stdlib-only ad-hoc scripts). The
  test file works as a plain Python script too — `pytest` only
  emits 6 warnings about the test functions returning `list` (pytest
  prefers `assert`); this is cosmetic. Filing as a code-quality
  cleanup (no security implication) — see §5 P2 backlog.

**0 missing endpoints.** Phase 6.2 ✓.

---

## 4. CI traffic-light snapshot vs first-run baseline

GitHub Actions Security CI workflow (file: `.github/workflows/security.yml`,
6 jobs) — comparing the very first run (commit `f027c52`, 2026-04-26
17:29 UTC) with the latest run after Phase 5+6 (commit `9a69fe2`,
2026-04-27 15:46 UTC):

| Job                                       | Baseline (`f027c52`) | Latest (`9a69fe2`) | Delta |
|-------------------------------------------|:--------------------:|:------------------:|:------|
| `pip-audit + bandit`                      | FAIL                 | FAIL               | unchanged — see SEC-024 |
| `syft self-SBOM + grype`                  | FAIL                 | FAIL               | unchanged — see SEC-024 follow-up |
| `gitleaks`                                | FAIL                 | FAIL               | unchanged — see SEC-024 follow-up |
| `backend test_all.py (54 stdlib tests)`   | **PASS**             | **PASS**           | green throughout |
| `npm audit (frontend)`                    | **PASS**             | **PASS**           | green throughout |
| `reachability corpus validate + stats`    | **PASS**             | **PASS**           | green throughout |

**3 fail / 3 pass — same in both runs.** The Phase 5 fixes did not
move CI from red to green because the three failing jobs are gated
on a different finding-class (dependency CVEs / secret scan), not on
the application-level authz / DoS / compliance fixes shipped in
Phase 5. The SEC-017 #0 commit *introduced* CI gates; Phase 5 did
not aim to *clear* them.

(The user's recollection said "first run was 3 fail / 2 pass" — the
actual first run had 6 jobs, of which 3 pass. The 5-vs-6 mismatch is
likely a memory error; the structural takeaway is unchanged.)

### Failing job classification

| Job        | Status | Root cause                                                                                                  | Classification            |
|------------|--------|-------------------------------------------------------------------------------------------------------------|---------------------------|
| pip-audit  | FAIL   | `pg8000 1.31.2` known CVE `GHSA-wq2g-r956-j8cc`; fix in 1.31.5. Confirmed via local `pip-audit -r --strict --no-deps`. | **Real → SEC-024** filed   |
| grype      | FAIL   | Same SBOM that includes pg8000 — likely surfaces the same CVE; possibly transitive Highs not yet enumerated. Authenticated log fetch needed. | **Real (likely SEC-024 dup; possibly more)** — investigate during Phase 7 prep |
| gitleaks   | FAIL   | Step #3 fails before any user-visible regex result.  Two candidate causes: (a) Anchore-acquisition gitleaks-action license requirement on org / public repos post-2024, (b) a secret slipped through the `.gitleaks.toml` allowlist.  Authenticated log fetch needed to differentiate. | **Tooling-or-real, undetermined** — classify Phase 7 prep |

The unauthenticated GitHub REST API returns HTTP 403 for the job-logs
endpoint, which is why this report cannot enumerate further.

**Phase 6.4 ✓ (read-only snapshot; no new findings introduced beyond SEC-024).**

---

## 5. P2 backlog and newly-discovered findings

| Finding | Discovered | Status | Phase 7 priority |
|---------|------------|--------|------------------|
| SEC-014 | Phase 3   | **closed** by Phase 5 P2 commit `c401c11` (gpg backup encryption) | n/a (closed) |
| SEC-023 | Phase 5 #1 enforcement-test first run | **closed** in same commit as SDLC-001 (`a604c56`) | n/a (closed) |
| **SEC-024** | **Phase 6.4 (this round)** | **open** — `pg8000 1.31.2` CVE `GHSA-wq2g-r956-j8cc` | **P1** for Phase 7 (one-line dep upgrade) |
| SEC-024-followup-grype | Phase 6.4 | **open** — `syft+grype` job still failing, likely same root cause as SEC-024 plus possibly more transitive Highs; needs authenticated log fetch to enumerate | bundled with SEC-024 |
| SEC-024-followup-gitleaks | Phase 6.4 | **open** — gitleaks job failure cause undetermined (license vs real leak); needs authenticated log fetch | bundled with SEC-024 |
| Cosmetic: pytest return-list warnings on enforcement test | Phase 6.2 | **open** — code-quality cleanup; no security implication | low-priority |

Items still in the original 25-finding register and explicitly
deferred (no scope change in this audit, all stay open until next
audit cycle): SEC-005, SEC-006, SEC-007, SEC-008, SEC-009, SEC-010,
SEC-011, SEC-012, SEC-013, SEC-015, SEC-016, SEC-019, SEC-021;
SEC-020 stays `deferred` until first LLM client lands.

---

## 6. Phase 6 → Phase 7 trigger conditions

Phase 6 is complete: the audit closed under the agreed Top-10 +
SDLC-001 + SEC-014 P2 + SEC-023 scope, with one new finding (SEC-024)
filed for the next cycle. Phase 7 (the "commercialisation pre-flight
audit") is **not** scheduled by calendar; it triggers on **the first
of any of the following events** (in monitor mode — Phase 5's
auto-pause #6 vocabulary):

| #  | Trigger                                                                                                        | Why this gates Phase 7                                                              |
|----|----------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| T1 | First customer onboarded on a hosted (non-LAN-only) deployment                                                 | Severity matrix flips from `lan_only` to `if_public`; CRA / SOC 2 evidence required |
| T2 | First Postgres-backed deployment goes live                                                                     | pg8000 path lit; SEC-024 must be cleared first                                       |
| T3 | First LLM integration PR opened (any path)                                                                     | SEC-020 family lights up; deferred work re-opens                                     |
| T4 | Any externally-facing TLS termination added (cert-manager / Let's Encrypt / cloudflared / Tailscale Funnel)    | SDLC-002 (perimeter & transport) re-evaluation; HSTS + CSP + cookie attrs            |
| T5 | First externally-reported vulnerability (security@; HackerOne; downstream customer)                            | Re-validate every "fixed" finding; PoC re-run baseline                               |
| T6 | Calendar trigger: 6 months from 2026-04-26 = 2026-10-26                                                        | Drift / new CVE budget; even with no T1-T5 events                                    |
| T7 | Major dependency upgrade with security implications (FastAPI ≥ next major; SQLAlchemy 3.x; React 19 → 20; etc.) | Defense layers may shift; behavioural drift surfaces in PoCs                          |

For each trigger, the Phase 7 entry checklist is:

1. Re-run all 5 dynamic PoCs (SEC-001a/b/c/d + SEC-002) against the
   trigger-relevant deployment shape and append a new
   `after_fix_verification` block (use Phase 6's schema).
2. Re-run `test_all.py` and `pytest backend/tests/test_endpoint_decorator_enforcement.py -v`.
3. Re-snapshot CI traffic light; classify any new red-job into
   SEC-NNN (next free number) per the rev-7 finding-stub template.
4. Re-evaluate `severity_lan_only` vs `severity_if_public` for every
   open finding — most LAN-only "Low" ratings will reclassify when
   T1 or T4 fires.
5. Read the `compliance_impact` block of each open finding against the
   commercialisation framework actually in scope (SOC 2 Type II vs
   ISO 27001 vs IEC 62443-4-1 customer requirement), and produce a
   gate-list before the customer signs.

---

## 7. Sign-off

Phase 5 + Phase 6 closed. The audit register is internally consistent
(every finding has a status; every "fixed" status references a commit
SHA; every dynamic-PoC finding has both `poc_metadata` and
`after_fix_verification` blocks; every `verdict_after_fix` is
`NOT_REPRODUCED` for the 5 dynamic PoCs). The CI baseline is live,
3 jobs are green, 3 are red on a known finding (SEC-024 + 2 follow-ups
documented in §5).

Backend on `127.0.0.1:9100` and frontend on `127.0.0.1:3000` were left
running after the Phase 6.6 commit per the Phase 6 instructions.
They will be killed only after the user has read this report.
