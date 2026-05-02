# PR-3 Stage P.1 — Share-Token Endpoint Audit

**Scope**: `backend/app/api/share.py:184` `download_shared_sbom` — the only public unauthenticated route in the codebase that resolves a share-token and serves SBOM content.

**Trigger**: FU-1.010 (ARCH-1.003 root-cause completeness on the public share-token auth path) + FU-1.011 (SDLC-001 enforcement test extension to cover share-token routes).  Pickup deferred from PR-2 due to character mismatch (PR-2 = perf+tidy; share-token audit needed its own surface).  Slippage observation logged as D31 in Stage R.

**Date**: 2026-05-02 (PR-3 branch `refactor/iter-1-pr3-error-handling`, post-Stage O closure)

**Method**: code read end-to-end + cross-reference cascade configuration + grep for caller-side dependence on specific error responses.  Read-only — no production code modified in P.1.

---

## 1. Endpoint structure

```python
@router.get("/api/share/{token}")
def download_shared_sbom(token: str, db: Session = Depends(get_db)):
    lk = db.query(SbomShareLink).filter(SbomShareLink.token == token).first()
    if not lk:
        raise HTTPException(status_code=404, detail="連結不存在或已被撤銷")     # [A]

    now = datetime.now(timezone.utc)
    if lk.expires_at:
        exp = lk.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now:
            raise HTTPException(status_code=410, detail="此分享連結已過期")     # [B]

    release = db.query(Release).filter(Release.id == lk.release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="版本不存在")               # [C]

    sbom = _load_sbom(release)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM 檔案不存在")          # [D]

    sbom = _apply_mask(sbom, lk.mask_internal)
    lk.download_count += 1
    db.commit()
    # ... return content ...                                                    # [E]
```

Five distinguishable response shapes labelled [A]-[E].

## 2. Audit per FU-1.010 four failure modes

### Failure mode 1 — Token not found ([A] above)

| Aspect | Finding |
|---|---|
| HTTP status | 404 |
| Detail message | `"連結不存在或已被撤銷"` (link does not exist or has been revoked) |
| Information disclosure | None — message is generic; no `release_id` / `version` / `product` hint |
| Audit log | **Not recorded** — failed attempt is invisible to ops |
| Verdict | ✓ no oracle leak on the message side; ⚠ audit gap (see §3.2) |

### Failure mode 2 — Token expired ([B] above)

| Aspect | Finding |
|---|---|
| HTTP status | **410 Gone** ← **distinguishable from [A] (404)** |
| Detail message | `"此分享連結已過期"` (this link has expired) ← **also distinguishable from [A]** |
| Information disclosure | Reveals "this token *was* once issued" — distinguishes expired-but-issued from never-issued |
| Practical exploitability | **Negligible**: tokens are 256-bit random (`secrets.token_urlsafe(32)` at `share.py:106`); brute-forcing the keyspace to enumerate expired tokens is computationally infeasible |
| Information value if exploited | Only reveals "some release has been shared at some point" — caller still cannot identify which release, cannot retrieve content (token expired = no data), cannot enumerate across releases |
| Audit log | **Not recorded** |
| Verdict | **Theoretical oracle leak** that contradicts the explicit FU-1.010 spec wording ("HTTP status code is consistent (do not differentiate 'exists but expired' from 'never existed')").  Surgical fix per spec recommendation — see §4. |

### Failure mode 3 — Token's release in another org

| Aspect | Finding |
|---|---|
| Applicability | **N/A by design** |
| Reasoning | This is an **unauthenticated** endpoint.  The share-token IS the auth.  The notion of "caller's org" does not exist on this code path — there is no JWT, no `org_scope`, no user identity to compare against. |
| Architectural model | Bearer capability — possession of the token grants access to the specific release it was minted for, regardless of any caller identity.  This is the deliberate design of share links (cf. PASETO / GitHub gist tokens / Dropbox share links). |
| Verdict | ✓ no concern — the failure mode is not reachable as defined |

### Failure mode 4 — Release deleted while link still active ([C] above)

| Aspect | Finding |
|---|---|
| Reachability in normal operation | **Unreachable** — see §3.1 for cascade verification |
| Defensive code path | [C] handles the impossible state with 404 + `"版本不存在"` |
| Information disclosure | Reveals "share link exists but the underlying release was deleted" — distinguishes from [A] (token never existed) |
| Practical exploitability | Even more theoretical than failure mode 2 because the cascade ensures this state is not reachable from a normal delete flow |
| Audit log | **Not recorded** |
| Verdict | **Dead defensive branch.**  The message non-uniformity is a theoretical leak on a code path that should not execute in practice.  Bundle into the §4 surgical fix. |

### Bonus — SBOM file missing on disk ([D] above)

Not in the original FU-1.010 four-failure-modes spec, but discovered during the audit and worth documenting:

| Aspect | Finding |
|---|---|
| Reachability | Possible if `release.sbom_file_path` is set in DB but the on-disk file was deleted (manual `rm`, disk full, backup-restore mismatch) |
| HTTP status | 404 |
| Detail message | `"SBOM 檔案不存在"` (SBOM file does not exist) — **distinguishable from [A] / [C]** |
| Information disclosure | Reveals "valid token, valid release, but file system state is broken" — most specific leak of the four 404-path messages |
| Practical exploitability | Negligible; requires sysadmin-side state divergence which the attacker cannot induce |
| Verdict | Bundle into the §4 surgical fix for message uniformity |

## 3. Architectural verification

### 3.1 Cascade (failure mode 4 reachability)

Both ORM and DB layers configured:

```
backend/app/models/release.py:37
    share_links = relationship("SbomShareLink", back_populates="release",
                               cascade="all, delete-orphan")

backend/app/models/share_link.py:16
    release_id = Column(String, ForeignKey("releases.id", ondelete="CASCADE"),
                        nullable=False, index=True)
```

Result: deleting a Release auto-deletes all its share links via either path.  Failure mode 4 is reachable only via:
- Direct DB tampering bypassing both ORM and FK (impossible via the API)
- Cascade misconfiguration in a future migration (CI-detectable)
- Foreign key check disabled at the SQLite session level (not configured anywhere in `core/database.py`)

The defensive [C] branch is dead in normal operation.  Keep for defense-in-depth (cheap), but unify its message with [A].

### 3.2 Audit logging gap

`audit.record(...)` is **not called anywhere in `download_shared_sbom`**.  By contrast, all three admin share-link endpoints record audit events:

```
share.py:114    audit.record(db, "share_link_create", ...)
share.py:177    audit.record(db, "share_link_revoke", ...)
```

The download path increments `lk.download_count` on success but writes no audit row.  Failed attempts (token guessing, expired-token retries, post-revocation hits) leave **zero forensic trace**.

This is **out of FU-1.010's original four-failure-modes scope** but is a real observability gap surfaced by this audit.  Fixing it requires:
- New audit event type taxonomy (`share_link_resolve_success` / `_resolve_failure_not_found` / `_resolve_failure_expired` / `_resolve_failure_release_missing` / `_resolve_failure_file_missing`)
- Decision on what client identity to record (request IP via `_client_ip(request)` already available in `core/rate_limit.py`; do NOT log full token — log token prefix only, e.g. first 8 chars, to avoid post-incident credential exposure in audit table)
- Schema decision: reuse `audit_events` (org_id/user_id columns nullable for these unauthenticated rows) vs. introduce a separate `share_link_access_log` table

Estimated 30-50 LOC + audit category enumeration + schema decision.  **Crosses the (a)-surgical-fix threshold — recommend FU-1.014.**

### 3.3 Test coverage gap

`grep -rn '/api/share' backend/tests/` returns 1 reference: a comment in `tests/unit/test_releases_http_chars.py:122` stating "/api/share/{token} requires a valid token — covered by share-link unit tests later".  **No such tests exist.**

The download endpoint has **zero unit-test coverage** for any of its 5 response paths ([A]-[E]).

This is also out of FU-1.010 scope.  P.2 will add at least one test exercising the unified-404 behavior introduced by the message-uniformity fix; comprehensive share-link test suite is FU-1.015 candidate (separate from FU-1.014 audit-logging FU).

## 4. Verdict

**`gap-and-fix-in-PR-3`** for the **message-and-status-code uniformity** items (failure modes 2, 4, [D]).  Surgical fix per the original FU-1.010 spec recommendation:

> "HTTP status code is consistent (do not differentiate 'exists but expired' from 'never existed' — both should 404 with same message, e.g. 'Share link invalid or expired')"

**Estimated P.2 fix LOC**: 3 lines changed in `share.py` + 1 unit test (~25 LOC).  Well within the (a)-surgical-fix budget threshold (≤30 LOC production / Q-PR3-3 (a) decision rule).

**Spawned FUs from this audit**:
- **FU-1.014** — Audit logging integration for `download_shared_sbom` (audit gap §3.2)
- **FU-1.015** — Comprehensive share-link endpoint test suite (test gap §3.3)

Neither blocks PR-3 closure; both will be ledger entries in Stage R alongside D32.

## 5. P.2 fix plan (executed in next commit)

Three message+status changes in `share.py:188`/`196`/`200`/`204` to a single uniform response:

```python
_INVALID_LINK_MSG = "連結無效、已過期或已被撤銷"

# [A] (line 188)  — keep 404; widen message
raise HTTPException(status_code=404, detail=_INVALID_LINK_MSG)

# [B] (line 196)  — change 410 → 404; same message
raise HTTPException(status_code=404, detail=_INVALID_LINK_MSG)

# [C] (line 200)  — keep 404; same message
raise HTTPException(status_code=404, detail=_INVALID_LINK_MSG)

# [D] (line 204)  — keep 404; same message
raise HTTPException(status_code=404, detail=_INVALID_LINK_MSG)
```

UX trade-off rationale: combined-cause message ("連結無效、已過期或已被撤銷" = "link is invalid, has expired, or has been revoked") preserves the user's mental model that "this link might be expired" without the server confirming it on the wire.  Slightly less precise than the current 410-specific message; eliminates the oracle distinction.  Net win — UX cost is small, oracle-uniformity is the spec.

Test addition: `backend/tests/unit/test_share_token.py` — one fixture, three parametrized cases (token-not-found / expired / release-missing) all asserting 404 + `_INVALID_LINK_MSG`.  Pins the post-fix behavior so a future regression that re-introduces a 410 or different message will fail CI.

## 6. P.3 — SDLC-001 share-token coverage (separate concern)

FU-1.011 spec calls for extending `tests/test_endpoint_decorator_enforcement.py` to flag any future `release_id`-templated route that lacks an ownership check, **regardless of whether the auth shape is JWT or share-token**.

Current state (post-Stage O.2): test enforces `release_id` and `vuln_id` path params via `_TENANT_SCOPED_PARAMS` set; would catch a hypothetical future route like `@router.get("/api/share-link-stats/{release_id}")` without an ownership dep.

**Stage P.3 question**: should the SDLC-001 test also enforce that any `{token}`-templated public route has a known token-resolver helper (per FU-1.011's AST whitelist proposal)?

**P.3 verdict**: extend with a second weaker assertion — `_TOKEN_PARAMS = {"token"}` set; for those routes, require either (a) the function body calls `db.query(SbomShareLink).filter(...token==token...)` (current pattern) or (b) future helper named `_resolve_share_token`.  The AST scan is approximate — preventative, not perfect — but matches FU-1.011's design intent.

P.3 is a test-only commit landing after P.2.

---

**End of P.1 audit.**  P.2 (production fix) and P.3 (SDLC-001 extension) follow as separate commits per pr3-plan.md §3 stage breakdown.
