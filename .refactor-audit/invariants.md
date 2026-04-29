---
created: 2026-04-29
purpose: Behavior + security invariants that MUST hold across every refactor commit
status: living document; only appended (existing entries do not get loosened without explicit ledger note)
---

# Refactor Invariants

> This is the **explicit list of things that must not change** under any refactor commit. Phase 8 commits MUST verify against this list. New invariants surface during audits and are appended here.

Cross-references: behavior contract is in `code-principles.md` §B–E (reproduced compactly below). Security baseline is in `baseline.md` §7 (reproduced as a checklist below). Both files explain *why*; this file is the **enforcement checklist** for a single refactor commit.

---

## I. Behavior invariants (per HTTP request)

### I.1 Status code map (must remain identical)
| Condition | Status | Detail style |
|---|:---:|---|
| Missing/invalid Bearer | 401 | `無效或過期的 token，請重新登入` |
| Token revoked | 401 | `Token 已登出，請重新登入` |
| Token has read-scope, request is non-GET | 403 | `此 API Token 為唯讀，不可執行寫入操作` |
| Token has write-scope, request is DELETE | 403 | `此 API Token 無刪除權限` |
| User role is viewer, endpoint requires admin | 403 | `此操作需要管理員權限` |
| Cross-org access to release | **404** | `Release not found` (intentional CWE-204 oracle prevention; never 403) |
| Plan insufficient for feature | 402 | `require_plan` raises with feature-specific zh-TW message |
| Resource not found | 404 | resource-specific zh-TW |
| Validation failure | 422 | Pydantic default |
| State conflict (e.g. release locked, CRA already running) | 409 | resource-specific zh-TW |
| Rate limited | 429 | `請求過於頻繁，請稍後再試`, header `Retry-After: 60` |
| Server error | 500 | generic |

### I.2 Response shape conventions
- JSON with `application/json` content type
- Lists are top-level arrays OR `{ "items": [...], "total": N, "page": P }` for paginated endpoints
- Single objects are top-level (no envelope)
- Datetime is ISO 8601 with timezone (`datetime.now(timezone.utc).isoformat()`)
- IDs are UUID strings
- Boolean fields are JSON `true`/`false`, never `0`/`1` (despite SQLite storing as INT)

### I.3 CORS
- `allow_origins`: explicit `_cfg.ALLOWED_ORIGIN` (single value, NOT `*`)
- `allow_credentials`: True
- `allow_methods`: `["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"]` (whitelist — adding new method is contract change)
- `allow_headers`: `["authorization", "content-type", "accept", "accept-language", "x-requested-with"]`
- `expose_headers`: `["content-disposition"]` (file download flow depends on this)

### I.4 Side effects per public endpoint
Any commit must preserve, for every public endpoint:
- DB rows written (table, columns, count) — verifiable by snapshot diff
- Files written (path pattern, content shape) — `uploads/`, `uploads/brand/`, `~/sbom/backups/` in prod
- Outbound HTTP (which third party, with what headers/body shape) — no new outbound destinations introduced
- Outbound webhooks/SMTP fired — payload format identical
- AuditEvent rows inserted — event_type and key fields identical
- Cache state changes — N/A today (no app-level cache)

### I.5 Concurrency semantics
- `_active_enrichments` set + `_enrichment_lock` (releases.py:56-57) prevents duplicate enrichment per release-id; this guard must remain
- `monitor.start()/stop()` lifecycle owns the background polling thread; refactor must not double-start or leak the thread
- DB session is per-request via `Depends(get_db)`; do not promote sessions to globals

### I.6 Performance characteristics (regression guard)
Today's measured numbers (must not degrade more than 10% without `perf:` tagged commit + measurement):
- OSV scan of 200-component SBOM: **51 HTTP requests** (1 batch + ~50 unique vuln details) — must not regress to N+1
- `_is_suppressed` evaluation: **synchronous, every request** (no cron) — must not become async or DB-fetched
- Index list: 11 indexes declared in `main.py:158-170` — none may be dropped

---

## II. Security invariants (per refactor)

A refactor commit MUST be verifiable against each item below. **`assert_unchanged` for every box**.

### II.1 Authn/authz
- [ ] Every release-id endpoint still triggers `require_release_in_scope` OR `assert_release_in_scope` (CI test verifies)
- [ ] No new endpoint added to the public allowlist (only `/health`, `/api/notice`, `/api/auth/login`, `GET /api/share/{token}`)
- [ ] No path skips `require_admin` / `require_admin_scope` where it was required pre-refactor
- [ ] Admin role check still discriminates `apitoken:` synthetic users correctly (see `core/deps.py:62-66`)
- [ ] OIDC `state` validation still occurs on callback

### II.2 Input validation
- [ ] XML conversion still rejects `DOCTYPE`/`ENTITY` BEFORE parser instantiation
- [ ] XML body still capped at 5 MB
- [ ] Source upload zip still capped at 500 MB extraction
- [ ] Filename downloads still pass through `safe_attachment_filename`
- [ ] CSV cells still pass through `csv_safe`
- [ ] SBOM signature verification still uses `detect_algorithm` based on key type (algorithm field is NOT attacker-controlled)

### II.3 Boundary
- [ ] CORS configuration unchanged (or change is documented as deliberate contract evolution)
- [ ] Rate limit key derivation unchanged (only `X-Real-IP`, not `X-Forwarded-For`)
- [ ] SECRET_KEY guard at startup still fires on default + < 32 bytes when `DEBUG=false`
- [ ] ADMIN_PASSWORD guard at startup still fires on known defaults when `DEBUG=false`

### II.4 Data exposure
- [ ] No new endpoint returns `hashed_password`, `SECRET_KEY`, or any column ending in `_token`/`_secret`/`_key`
- [ ] Error messages do not include stack traces in 5xx responses
- [ ] Logs do not include passwords, tokens, OIDC client_secret
- [ ] Audit log still does not record password contents (only event types)

### II.5 Multi-tenant
- [ ] Every list endpoint that includes per-org data still filters by `get_org_scope` for non-admin
- [ ] No new endpoint returns Org IDs / names without scope check
- [ ] Cross-org access still returns 404 (not 403, not 200, not empty array)

### II.6 Supply chain
- [ ] No new runtime dependency added without justification + alternative analysis
- [ ] No version pin loosened (e.g. `==` → `>=`)
- [ ] No `requirements.txt` line removed without rebuilding the lock
- [ ] No `package.json` `dependencies` line added without `npm audit --omit=dev` clean

---

## III. Observability invariants

- [ ] `logger = logging.getLogger(__name__)` at top of refactored modules (per existing convention in `releases.py:26`)
- [ ] Every existing `logger.warning`/`error`/`exception` call site is preserved (or message is preserved if logger call moved)
- [ ] AuditEvent emissions are not removed; if a code path is moved, the audit emission moves with it
- [ ] `/health` endpoint shape unchanged (`{ status, version, db, monitor: { running, last_run, next_run }, timestamp }`)

---

## IV. Public-contract invariants (cross-commit)

- [ ] OpenAPI `/docs` schema diff: only additions or new optional fields; no removals, renames, or required-field additions
- [ ] DB schema diff: only `ADD COLUMN` (per established pattern); no DROP, no RENAME
- [ ] Webhook payload diff: only additive
- [ ] CLI flag set in `tools/sbom-cli/sbom.py`: only additive; no flag removal or default change
- [ ] GitHub Action input set in `tools/sbom-action/action.yml`: only additive

---

## V. Compatibility regime (current)

> Per user confirmation 2026-04-29: **no external API consumers exist today**. The React frontend is the only known consumer; no API tokens have been issued externally; CLI / GitHub Action / SDK / webhook integrations have not been adopted by any third party.

### V.1 Today's regime: lenient
- No backward-compat obligation to external clients
- Cosmetic body changes (field ordering, extra optional fields) are acceptable
- Adding required validation rules is acceptable IF the React frontend is updated in the same change

### V.2 Discipline still required even under lenient regime
- Any contract change MUST be recorded as a ledger entry (`.refactor-audit/ledger.md` under the executing iteration) so it is auditable later
- The React frontend is a **first-party** consumer — its breakage equals our breakage; coordinate the change in the same commit

### V.3 Trigger to revoke this lenient regime
This entire §V becomes **null and the strict regime in §I/II/III/IV applies** when ANY of the following fires:
- An API token is issued to an external party (customer, partner, internal team outside the React frontend)
- The CLI tool (`tools/sbom-cli/`) is installed by a user beyond the developer
- The GitHub Action (`tools/sbom-action/`) is invoked by an external repo
- A webhook destination is configured to a non-internal endpoint
- Commercialisation announcement is made

The agent (or human) who detects the trigger MUST update this section to "regime: strict" and re-evaluate every refactor commit since the trigger date for contract violations.

## VI. How to use this checklist in Phase 8

For every commit in Phase 8:
1. Read the diff
2. Walk this checklist (§I–IV under whichever regime §V declares); for any item touched by the diff, write evidence in the commit body or `verification.md`
3. If any box cannot be checked, stop the commit and re-plan
4. Items deliberately changed (security-tightening, contract evolution) require an explicit ledger entry referencing the change

Last updated: iter-1, 2026-04-29 (§V added: compatibility regime confirmed lenient until trigger fires)
