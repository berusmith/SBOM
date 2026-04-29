---
finding_id: SEC-027
status: candidate (not yet through formal phase 1-6 audit)
discovered: 2026-04-29
discovery_anchor:
  - a22005b
  - b6f8bd5
related_formal_findings: none (new finding class)
last_updated: 2026-04-29
audit_id: 2026-04-26-security-code-review
---

# SEC-027 (candidate): Backend admin password rotation lacks .env-to-DB sync

> **Candidate** — discovered out of band during the iter-3 dev session
> on 2026-04-29.  This finding has NOT been through the formal Phase
> 1-6 audit cycle that SEC-001 through SEC-026 went through.  File as
> a stub for proper investigation; severity / CVSS / CWE below are
> first-pass estimates, not committed values.

## Discovery context

Iter-3 commits `a22005b` (move `ADMIN_PASSWORD` out of `test_all.py`
hardcode, raise if env unset) and `b6f8bd5` (`load_dotenv` from
`backend/.env` in `test_all.py`) had landed.  `test_all.py` still
produced 4 PASS / 37 FAIL with the failure cascade rooted at
`Auth: login success` — the password the test sent (read correctly
from `.env`) did not match the DB-stored hash.  Tracing showed the
hash in DB had been written 5 days earlier (admin user
`created_at = 2026-04-24`) under the original known-default password
and was never re-derived after the operator rotated `.env` tonight.

## Problem statement

Backend seeds the initial admin user from `settings.ADMIN_PASSWORD`
*only* when `users` is empty (`main.py:218 — count() == 0`).  After
that one-shot seed, the DB stores the bcrypt hash and never re-reads
`settings.ADMIN_PASSWORD` for the admin user.  Meanwhile
pydantic-settings re-reads `.env` on every startup, so the in-memory
`settings.ADMIN_PASSWORD` tracks `.env` correctly — but runtime
config (env) and persisted credential (DB hash) drift apart silently.

`/api/auth/login` (`auth.py:54-61`) looks up the DB user first; if
`verify_password` fails against the DB hash, it raises HTTP 401 with
no fall-through.  The env-var-only fallback (`auth.py:73-80`) only
runs when `if db_user:` is False, so it does not rescue the
stale-hash situation.

The startup guard at `main.py:204-213` rejects known-default
passwords from a sentinel list (`sbom@2024` etc.); it does NOT
detect "operator rotated `.env` to a strong value but DB hash is
still the previous strong value".

## Reproducer

1. Fresh dev DB.  Set `backend/.env` `ADMIN_PASSWORD = <random-A>`.
   Start backend; admin user seeded with `bcrypt(<A>)`.
2. Operator follows good rotation hygiene: edits `.env` to
   `ADMIN_PASSWORD = <random-B>` (a different strong value).
3. Restart backend.  Startup succeeds: no error, no WARNING, no
   FATAL guard trip (`<B>` is not in the known-default sentinel list).
4. Operator attempts admin login with `<B>`.  Backend returns
   401 `"帳號或密碼錯誤"`.
5. Operator attempts admin login with the OLD `<A>` (e.g. value still
   in their browser autofill / shell history).  Backend returns
   200 OK with a valid JWT.
6. No startup log entry, audit event, or response header indicates
   "rotation incomplete".  The only signal is the operator's own
   401 in step 4.

## Impact

The intended security operation (rotate the admin credential) does
not actually rotate the credential — the live credential is still
the pre-rotation value.  Two failure modes:

- **Routine rotation**: operator believes the new value is in
  effect, stores `<B>` in their password manager / docs / handoff,
  then locks themselves out.  Operational cost only.
- **Rotation triggered by suspected leak of `<A>`**: the leaked
  value remains a valid admin credential indefinitely.  The
  "rotation" provides false assurance.  This is the
  security-critical mode.

Exploitation complexity is zero — the attacker continues to use the
same credential they already had.  There is no exploit *step*; the
absence of effective rotation is itself the vulnerability.

## Severity (candidate, not locked)

- Confidentiality impact (post-leak rotation): **High**
  — leaked credential remains valid post-"rotation"
- Confidentiality impact (routine rotation): **Low**
  — ops headache, no security delta
- Likelihood: **Medium**
  — non-fresh DB is the common state in any deployment older than
  first-deploy; rotation is standard hygiene that many operators
  will hit
- Exploitation complexity: **zero**
  — attacker continues with same credential
- CWE / CVSS / OWASP mapping: **deferred to formal audit phase**

## Proposed mitigation candidates

Listed without recommendation.  Selection deferred to formal audit.

### M1 — Documentation only

Add a rotation runbook to `deploy/MACMINI_SETUP.md` and the root
`CLAUDE.md` "Operations" section: "Rotating `ADMIN_PASSWORD` also
requires updating the DB hash; editing `.env` alone is insufficient".

- **Pros**: zero code change; zero risk of regression.
- **Cons**: relies on operator reading docs; does not prevent the
  silent failure, only renames it from "bug" to "documented gotcha".

### M2 — Startup mismatch warning

After the seed block in `main.py`, look up the existing admin user
and call
`verify_password(settings.ADMIN_PASSWORD, db_admin.hashed_password)`.
If mismatch, log a structured WARNING (not FATAL — startup must not
break for operators who *intentionally* keep DB and env divergent,
e.g. for env-fallback-admin setups).

- **Pros**: active detection; runs once per startup; cost is one
  bcrypt verify; operator sees the signal in stderr.
- **Cons**: adds a bcrypt verify on the startup hot path; warnings
  can be ignored; needs a clean exclusion path for legitimate
  "DB has different admin than env-fallback admin" deployments.

### M3 — Rotate CLI script

Add `python -m app.tools.rotate_admin_password` (or a Makefile /
deploy script target).  It reads `settings.ADMIN_PASSWORD` and
writes the corresponding bcrypt hash into the DB admin row.
Documented as the canonical post-`.env`-edit step.

- **Pros**: explicit operation; auditable (one DB `UPDATE`, one
  log line); side-steps the "did the operator know" question.
- **Cons**: operator still has to know to run it; if forgotten the
  silent failure recurs; couples `.env` reading semantics to yet
  another entry point.

### M4 — Auto-rotate-on-startup

If admin user exists and
`verify_password(settings.ADMIN_PASSWORD, db_admin.hashed_password)`
returns False, automatically re-hash and update the DB row.
Effectively makes `.env` the source of truth.

- **Pros**: matches the operator's mental model ("editing `.env`
  rotates the password"); no extra step.
- **Cons**: surprising behaviour without context comments; if
  `.env` is restored from an older backup, DB silently regresses;
  promotes `.env` write access to "password-rotation authority"
  (already implicit, but now directly weaponized).

## References

- `backend/app/main.py:215-226` — seed-if-empty admin user
  (root cause: single-shot, never re-runs)
- `backend/app/main.py:204-213` — startup guard for known-default
  ADMIN_PASSWORD (does not detect the rotation case)
- `backend/app/api/auth.py:54-61` — DB user found, hash mismatch →
  hard `raise HTTPException(401)`, no fall-through
- `backend/app/api/auth.py:73-80` — env-var fallback admin (gated
  by `if db_user:` being False — does not apply when admin exists
  in DB, which is the rotation case)
- SBOM-audit-private SEC-001 through SEC-026 — **no overlap**.
  This is a new class (rotation hygiene / config-vs-state drift),
  distinct from multi-tenant leak, IDoR, converter parsing,
  supply-chain CVE, and bandit-false-positive clusters
- Discovery anchor commits: `a22005b` + `b6f8bd5` (iter-3
  test_all.py ADMIN_PASSWORD env path).  These did not introduce
  the issue — they surfaced it by removing the
  hardcoded-`sbom@2024` mask that previously hid the .env-DB drift
  whenever DB happened to be seeded under that same default.
