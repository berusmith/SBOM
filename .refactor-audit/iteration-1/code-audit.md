---
iteration: 1
phase: 4 — Code Quality Audit
date: 2026-04-29
status: complete (read-only); findings feed Phase 7 plan
finding_id_prefix: CODE-1.NNN
---

# Iteration 1 — Code Quality Audit

> Findings are anchored to Fowler's *Refactoring* code-smell catalogue + SOLID + this project's `code-principles.md`. Architecture-level issues are in `architecture-audit.md` and not duplicated here.

---

## 4.1 Long Methods / Long Classes

### [CODE-1.001] `upload_sbom` — 142 LOC, 12 distinct responsibilities
- **Severity**: P1(嚴重)
- **Category**: Code Smell / Long Method
- **Trigger**: Phase 4 deep read of `releases.py:178-319`
- **Location**: `backend/app/api/releases.py:178-319`
- **Observation**: One function does:
  1. Lookup release + ownership check
  2. Check locked status
  3. Read upload (with size cap)
  4. Validate SBOM (try/except → 400)
  5. Parse SBOM (try/except → 400)
  6. Save file to disk + compute SHA-256
  7. Cache SBOM quality score (silent `except Exception: pass`)
  8. Capture previous-release snapshot for diff
  9. Delete + reinsert components
  10. Run OSV scan
  11. Enrich (EPSS, KEV, GHSA)
  12. Audit + diff + return
- **Why it matters**: 142 LOC of mixed concerns; impossible to unit test any single step; the `except Exception: pass` at line 220 silently swallows quality-grade computation failures (CODE-1.012)
- **Reference**: Fowler *Refactoring* §6 "Extract Function"; Litestar service-layer pattern: handler is < 20 LOC, calls into use-case
- **Refactor Type**: **Extract Function** ×7 → orchestrator that calls them in sequence
- **Behavior-Equivalence Risk**: **Medium** — operation order within a single transaction must be preserved; commit boundaries (currently 5 commits in this function) must not change
- **Security Impact**: 2-fold positive — (a) extracted size validation becomes testable; (b) the silent `except Exception: pass` becomes visible
- **Recommendation** (Phase 7 plan):
  ```python
  # services/usecases/release/upload_sbom.py
  def upload_sbom(release_id, file_content, filename, user, db) -> UploadResult:
      release = _load_unlocked_release(db, release_id)
      validated = _validate_and_parse(file_content, filename)
      _save_to_disk(release, validated.content)
      release.sbom_hash = _compute_hash(validated.content)
      release.sbom_quality_score, release.sbom_quality_grade = _score_quality(validated.parsed)
      prev = _snapshot_previous(db, release)
      _replace_components(db, release, validated.components)
      vulns = _scan_and_persist(db, release, validated.components)
      _enrich_all(db, release, vulns, validated.components)
      audit.record(db, "sbom_upload", user, ...)
      diff = _compute_diff(validated.components, vulns, prev)
      db.commit()
      return UploadResult(components=len(validated.components), vulns=len(vulns), diff=diff)
  ```
- **Test Strategy**: function-level pytest unit tests on each `_helper`; HTTP characterization on the orchestrator (preserves response shape)
- **Effort**: M
- **Risk of Fix**: medium
- **Confidence**: High

### [CODE-1.002] `download_evidence_package` — 154 LOC, 5 outputs assembled inline
- **Severity**: P1(嚴重)
- **Category**: Code Smell / Long Method
- **Trigger**: reading `releases.py:937-1091`
- **Location**: `backend/app/api/releases.py:937-1091`
- **Observation**: Builds 4 separate output documents (vex_summary.json, csaf_vex.json, vulnerability_report.pdf, sbom.json) inline plus a manifest with SHA-256 checksums, then ZIPs them. The "build CSAF vulnerabilities list" block (lines 985-1023) duplicates the same structure built by the standalone `export_csaf` endpoint (lines 1094-1190).
- **Why it matters**: 154 LOC; CSAF construction duplicated in 2 endpoints (DRY violation); PDF construction call (lines 1045-1048) duplicates the simpler `download_report` (line 768-775)
- **Reference**: Fowler "Extract Function" + "Substitute Algorithm"
- **Refactor Type**: **Extract Function** for each of the 4 outputs; **Substitute Algorithm** for the duplicated CSAF construction
- **Behavior-Equivalence Risk**: **Medium** — the ZIP contents (folder name pattern, manifest field order, file names) are part of the contract; byte-equality of the manifest matters
- **Security Impact**: positive (extracting PDF + CSAF builders means the placeholder `https://example.com` namespace bug — CODE-1.014 — can be fixed in one place)
- **Recommendation**: extract `build_csaf_doc(release, components, vulns) -> dict`, `build_vex_summary(...)`, `build_evidence_zip(parts) -> bytes`. CSAF reused by `export_csaf` AND `download_evidence_package`
- **Effort**: M
- **Confidence**: High

### [CODE-1.003] 4 PDF report endpoints duplicate the same 5-step pattern
- **Severity**: P2(中等)
- **Category**: Duplicate Code / Shotgun Surgery target
- **Trigger**: reading `releases.py:715-934` (`download_report`, `download_iec62443_report`, `download_iec62443_42_report`, `download_iec62443_33_report`, `download_nis2_report`)
- **Location**: `releases.py:715-934`
- **Observation**: Each follows the identical pattern:
  ```
  release = db.query(Release).filter(...).first()
  if not release: raise 404
  product, org = _assert_release_org(...)
  components_raw = db.query(Component).options(selectinload(...)).all()
  if not components_raw: raise 400
  components = [{...} for c in components_raw]
  vulns = [{...} for c in components_raw for v in c.vulnerabilities]
  pdf_bytes = <generator>.generate(org_name, product_name, version, components, vulns, ...)
  return Response(content=pdf_bytes, media_type="application/pdf", headers={...})
  ```
  Each generator differs in arguments (some take `cra_incidents`, some take `brand`, some don't) but the surrounding scaffold is identical.
- **Why it matters**: a change to "how to look up org/product" must be applied 5 times (Shotgun Surgery); a new compliance report = copy-paste of 30 LOC
- **Refactor Type**: **Form Template Method** OR **Pull Up Method** with parameterised generator
- **Behavior-Equivalence Risk**: low — output PDF bytes must be identical; scaffold is incidental
- **Recommendation**: extract `_render_compliance_pdf(release_id, generator_fn, *, include_cra_incidents=False, include_brand=False, filename_prefix="...")` — the 5 endpoints become 5 one-liner wrappers
- **Effort**: M
- **Confidence**: High

### [CODE-1.004] CycloneDX XML / SPDX JSON exports built inline in router
- **Severity**: P2(中等)
- **Category**: Architecture / Module / Code Smell
- **Trigger**: reading `releases.py:1193-1308`
- **Location**: `releases.py:1193-1236` (XML), `releases.py:1239-1307` (SPDX JSON)
- **Observation**: 80+ LOC each, building XML/JSON document structures inline in the router function. `services/converter.py` exists for CycloneDX↔SPDX↔XML conversion but is not used here.
- **Why it matters**: format-construction logic in routers; cannot be unit-tested without HTTP roundtrip; format evolution requires touching the router
- **Refactor Type**: **Move Method** to `services/converter.py` (or `services/exporters/`)
- **Behavior-Equivalence Risk**: low if move is bit-identical
- **Recommendation**: move both functions to `services/converter.py`; router becomes a 5-line wrapper
- **Effort**: M
- **Confidence**: High

---

## 4.2 SOLID

### [CODE-1.005] `releases.py` violates SRP, OCP, ISP simultaneously
- **Severity**: rolled up into ARCH-1.001 (god router)
- See `architecture-audit.md`

### [CODE-1.006] `audit.record(db, event_type, user, ...)` — `user` param accepts `dict | None` but is poorly typed
- **Severity**: P3(優化)
- **Category**: SOLID / DIP
- **Trigger**: `core/audit.py:6-26`
- **Location**: `backend/app/core/audit.py`
- **Observation**: Signature is `record(db, event_type, user: dict, ...)`. Sometimes called with a User-shaped dict from JWT (`user["username"]`), sometimes with a raw `{"username": ..., "user_id": ..., "org_id": ...}` literal (auth.py:57-59). No validation; `user.get("username", "")` returns empty string silently if dict is wrong shape — audit row with empty username
- **Recommendation**: define `AuditActor(BaseModel)` with required `username`, optional `user_id`, `org_id`, `org_name`. Convert at boundary
- **Effort**: S
- **Confidence**: High

---

## 4.3 Naming & readability

### [CODE-1.007] Inconsistent camelCase vs snake_case in CycloneDX export
- **Severity**: P3(優化)
- **Category**: Naming / Consistency
- **Trigger**: `releases.py:1265-1294` (SPDX) uses camelCase for SPDX field names (correct) but the surrounding Python uses snake_case
- **Location**: SPDX export — this is **correct** because SPDX schema is camelCase. Not a finding. Skip.

### [CODE-1.008] `_assert_release_org` returns `(product, org)` tuple — positional return obscures intent
- **Severity**: P3(優化)
- **Category**: Naming / Function design
- **Trigger**: 12+ call sites pattern: `product, org = _assert_release_org(release, org_scope, db)`
- **Location**: `releases.py:87-93` definition; calls scattered throughout
- **Observation**: The function does: ownership check (raise 403), AND fetches product, AND fetches org. Three responsibilities, returns 2 of them. Callers always destructure as `product, org = ...`. If a caller only needs the check, it still pays for the 2 queries.
- **Reference**: Fowler "Replace Parameter with Method" / "Split Function"
- **Refactor Type**: **Split Function** — one for ownership check (covered by ARCH-1.003 migration to `require_release_in_scope`), one for `(product, org)` lookup
- **Recommendation**: as part of ARCH-1.003 cleanup; rename returned tuple or use NamedTuple `ReleaseContext(product, org)`
- **Effort**: S
- **Confidence**: High

---

## 4.4 Function design

### [CODE-1.009] `rescan_vulnerabilities` author admits new-vuln detection is "tricky"
- **Severity**: P2(中等)
- **Category**: Function design / Smell
- **Trigger**: `releases.py:374-406` and the inline comment "Simpler: query newly added vulns... is tricky, use all_vulns filtered"
- **Location**: `backend/app/api/releases.py:374-406`
- **Observation**: The function attempts to identify newly-added vulns 3 different ways within the same 30-line block:
  1. (line 376-385) Build `new_vuln_details` from `vuln_results` and `existing_cves` minus current scan
  2. (line 386-400) Discard the above; rebuild `new_vuln_details` from `comp.vulnerabilities` filtered by `status == "open"` and `cve_id in scan_vulns`
  3. (line 406) Slice `new_vuln_details[:new_count]` — assumes the list order matches insertion order, which the second approach doesn't guarantee
- **Why it matters**: bug-prone; the second `new_vuln_details = []` (line 386) silently overwrites the first (line 378). The slice `[:new_count]` may mismatch the actual newly-added vulns. Notification recipient sees wrong CVE list.
- **Refactor Type**: **Substitute Algorithm** — track newly-inserted vuln IDs in a set during the insertion loop (line 343-364)
- **Behavior-Equivalence Risk**: Medium — fixing this changes which CVEs appear in the alert payload (today potentially wrong, tomorrow correct). Per D1 lenient regime, alert payload is acceptable to evolve, but coordinate with monitor.py's similar logic
- **Recommendation**:
  ```python
  newly_added: list[Vulnerability] = []
  for purl, vulns in vuln_results.items():
      ...
      for v in vulns:
          if cve_id in existing_cves or cve_id in seen_in_scan: continue
          new_v = Vulnerability(...)
          db.add(new_v)
          newly_added.append(new_v)
          new_count += 1
  db.commit()
  for v in newly_added: db.refresh(v)
  ```
  Then `new_vuln_details` derives from `newly_added` directly.
- **Effort**: S
- **Risk of Fix**: medium (change to alert content)
- **Confidence**: High

### [CODE-1.010] Login rate limiter is IP-only — username enumeration possible
- **Severity**: P2(中等)
- **Category**: Function design / Security-adjacent
- **Trigger**: `core/rate_limit.py:46-78` + `auth.py:47`
- **Location**: `backend/app/core/rate_limit.py:check_login_rate_limit` (IP-only)
- **Observation**: Login limiter keys on `_client_ip(request)` only. An attacker on a single IP can try `(user1, pw)` 10 times, then `(user2, pw)` 10 times — but wait, that's still 10 attempts per IP per 5 min limit. Actually re-read: limit is 10 attempts per 5 minutes per IP (line 40). So an attacker on one IP gets 10 password attempts total per 5 min, regardless of username. **OK actually that's fine.** The limiter prevents both single-username brute force AND username enumeration in a single counter.
- **Reclassification**: this is **NOT a finding** — the design is correct. Strikethrough.
- **Severity**: ~~P2~~ → **none (not a finding)**

### [CODE-1.011] Quality grade computation silently swallowed via `except Exception: pass`
- **Severity**: P2(中等)
- **Category**: Error handling / Function design
- **Trigger**: `releases.py:215-221`
- **Location**: `backend/app/api/releases.py:215-221`
- **Observation**:
  ```python
  try:
      from app.services.sbom_parser import score_sbom
      quality = score_sbom(json.loads(content))
      release.sbom_quality_score = quality["score"]
      release.sbom_quality_grade = quality["grade"]
  except Exception:
      pass
  ```
  Silent failure: SBOM uploaded successfully, but `sbom_quality_score` and `sbom_quality_grade` stay None. Frontend shows "no quality data" with no log entry indicating WHY.
- **Why it matters**: violates code-principles.md §G2 (`logger.exception` for internal errors). Hides bugs in `score_sbom` (e.g. malformed SBOM that passed `validate` but fails `score_sbom`).
- **Recommendation**:
  ```python
  try:
      ...
  except Exception:
      logger.exception("Quality score computation failed for release %s", release_id)
  ```
- **Effort**: S
- **Risk of Fix**: nil (logging only)
- **Confidence**: High

### [CODE-1.012] `update_version` and `update_notes` accept `body: dict` (untyped)
- **Severity**: P2(中等)
- **Category**: Function design / API design
- **Trigger**: `releases.py:537-552`, `releases.py:1502-1514`
- **Location**: `backend/app/api/releases.py:537,1502`
- **Observation**: Both PATCH endpoints take `body: dict` and read `body.get("version")` / `body.get("notes")` manually. No validation of length, type, character set. Notes is capped at 5000 via `str(...)[:5000]` — silent truncation, no error
- **Why it matters**: violates `code-principles.md` §B7 indirectly (OpenAPI loses field shape); silent truncation hides data loss
- **Recommendation**:
  ```python
  class ReleaseVersionUpdate(BaseModel):
      version: str = Field(min_length=1, max_length=100)

  class ReleaseNotesUpdate(BaseModel):
      notes: str = Field(default="", max_length=5000)
  ```
  Pydantic returns 422 on length violation instead of silent truncation
- **Effort**: S
- **Confidence**: High

### [CODE-1.013] `download_evidence_package` and `export_csaf` use placeholder `https://example.com` as namespace
- **Severity**: P2(中等)
- **Category**: Function design / Bug
- **Trigger**: `releases.py:1013` `"namespace": f"https://example.com"`, `releases.py:1171` `f"https://example.com/{org_name.lower().replace(' ', '-')}"`
- **Location**: `backend/app/api/releases.py:1013,1171`
- **Observation**: CSAF VEX documents require a `publisher.namespace` URI. Both code paths hard-code `https://example.com`. The CSAF spec requires a real authority URL; downstream tooling that validates against the spec will warn or reject
- **Why it matters**: deliverable artifacts (CSAF VEX exports) carry obviously-bogus publisher namespaces, hurting credibility with auditors / downstream tooling
- **Reference**: CSAF 2.0 §3.1.6 publisher.namespace — must be a valid IRI in a domain controlled by the publisher
- **Recommendation**: derive from a configurable `CSAF_NAMESPACE` env var (default to `https://<ALLOWED_ORIGIN>` or `f"https://sbom-platform.local/{org_slug}"`); document in `.env.example`
- **Effort**: S
- **Risk of Fix**: low — output namespace string changes; downstream consumers are zero per D1
- **Confidence**: High

---

## 4.5 Error handling

### [CODE-1.014] 46 broad `except Exception` clauses — triage list
- **Severity**: P2(中等) — triage outcome dictates per-site fix
- **Category**: Error handling
- **Trigger**: `grep -rn "except Exception\|except:" backend/app --include="*.py" | wc -l → 46`
- **Location**: spread across `auth.py` (3), `firmware.py` (4), `releases.py` (4), `main.py` (2), `alerts.py` (1), `monitor.py` (3), `nvd.py` (?), `epss.py` (?), `kev.py` (?), and others
- **Observation** (categorised by intent):
  - **Legitimate top-level boundary** (~25 sites): wrapping unknown external errors and translating to a user-facing zh-TW HTTPException OR logging then continuing — these are **fine**
  - **Background-task safety nets** (~10 sites): `_task` functions in `enrich_ghsa` / `enrich_nvd`, monitor's main loop — wrapping the entire job to prevent thread death — also **fine** (logger.exception accompanies)
  - **Silent swallows** (~5 sites): `releases.py:220` (quality score — see CODE-1.011), `main.py:173` (index creation), `releases.py:1606` (gate quality grade computation) — **smell**, fix
  - **Translate-and-raise** (~6 sites): auth.py:119/148/164 wrapping urllib for OIDC — these become specific exception types in a future iter
- **Why it matters**: 46 broad `except` is high; without per-site classification, future contributors copy-paste the pattern
- **Recommendation**:
  - Iter-1 fixes the ~5 silent swallows (~CODE-1.011 covers one)
  - Per-site triage table goes into `known-debt.md` DEBT-009 with action labels (fine / fix-this-iter / followup)
- **Effort**: M (triage all sites; fix only silent ones)
- **Confidence**: Medium (need full site enumeration before triage is complete)

### [CODE-1.015] OIDC `_exchange_code` does not validate `id_token` — silently uses access_token
- **Severity**: P3(優化) — flagged for future security audit
- **Category**: Error handling / Security
- **Trigger**: reading `auth.py:131-149`
- **Location**: `backend/app/api/auth.py:131-149` and `_get_userinfo`
- **Observation**: After exchanging the authorization code, the response contains both `access_token` and `id_token`. Code uses `access_token` to call `userinfo_endpoint` and trusts the result. The `id_token` (a JWT) is never validated against issuer/audience/signature.
- **Why it matters**: validating `id_token` would catch:
  - Wrong issuer (token from another IdP forced into our flow)
  - Wrong audience (token issued for another app)
  - Token expiry
  - Signature tampering
  - Currently the userinfo flow trusts that the access_token is meaningful AND that the userinfo endpoint returns a sub bound to that token
- **Reference**: OIDC Core spec §3.1.3.7 ID Token Validation
- **Recommendation**: out of iter-1 scope (security audit lane). File as `.knowledge/audit/SEC-028-candidate-oidc-id-token.md`
- **Effort**: M (need jwks_uri fetch + signature verification)
- **Confidence**: High that the gap exists

---

## 4.6 Comments & documentation

### [CODE-1.016] `enrich_ghsa` returns `new_count` that no caller uses
- **Severity**: P3(優化)
- **Category**: Dead code / Smell
- **Trigger**: `releases.py:175` returns `new_count` from `_enrich_ghsa`; only callers (`upload_sbom:291`, `enrich_ghsa:464`, `monitor.py`?) ignore the return value
- **Location**: `releases.py:175`
- **Observation**: function returns a number; no caller reads it; the value is dead
- **Recommendation**: either propagate it to the response (would be useful debug info: "X new GHSA-only vulns added") or drop it
- **Effort**: S
- **Confidence**: High

### [CODE-1.017] `_enrichment_lock` + `_active_enrichments` set lack module docstring explaining single-process assumption
- **Severity**: P3(優化)
- **Category**: Comments / Documentation
- **Trigger**: `releases.py:56-57` — globals declared without context
- **Location**: `backend/app/api/releases.py:56-57`
- **Observation**: Globals with no comment about their scope (single-process). A future reader running `uvicorn --workers 4` to load-balance would silently break the contract.
- **Recommendation**:
  ```python
  # Per-process registry of releases currently being enriched. Single-process
  # assumption (single uvicorn worker); multi-worker deploys would each have
  # their own set + lock with no coordination — see ARCH-1.007.
  _active_enrichments: set[str] = set()
  _enrichment_lock = threading.Lock()
  ```
- **Effort**: S
- **Confidence**: High

---

## 4.7 Duplication

### [CODE-1.018] Identical compliance-PDF orchestration pattern duplicated 5×
- See CODE-1.003

### [CODE-1.019] CSAF document construction duplicated between `download_evidence_package` and `export_csaf`
- See CODE-1.002

### [CODE-1.020] `_SLA_DAYS = {...}` defined twice
- **Severity**: P2(中等)
- **Category**: Duplication
- **Trigger**: `releases.py:61` AND `stats.py:86` — both files declare `_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}`
- **Location**: `backend/app/api/releases.py:61` + `backend/app/api/stats.py:86`
- **Observation**: Same constant in 2 places. Diverges silently if one is updated.
- **Recommendation**: move to `domain/sla.py` per ARCH-1.002; both routers import from there
- **Effort**: S
- **Confidence**: High

### [CODE-1.021] Severity ordering mapping duplicated across 3 places
- **Severity**: P2(中等)
- **Category**: Duplication
- **Trigger**: `core/constants.py:1` (`SEVERITY_ORDER`) + `alerts.py:199` (`_SEV_ORDER`) + JS frontend (`SEVERITY_COLOR` indirectly)
- **Location**:
  - `backend/app/core/constants.py:1` — `SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}`
  - `backend/app/services/alerts.py:199` — `_SEV_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}`
- **Observation**: Two orderings, slightly different scales (`info=0` vs `info=1`). Confusion guaranteed.
- **Recommendation**: keep one canonical `SEVERITY_ORDER` in `domain/severity.py`; alerts.py imports it
- **Effort**: S
- **Risk of Fix**: low (verify alert rule comparison still works with new scale — should be order-preserving regardless of base)
- **Confidence**: High

---

## 4.8 Dead code

### [CODE-1.022] `dtrack_project_uuid` column on Release is dead — see ARCH-1.010

### [CODE-1.023] `cra_incidents = [{"status": i.status} for i in incidents_raw]` is dropped between collection and use in some paths
- (skip — needs more verification)

### [CODE-1.024] Unused module-level `_oidc_meta: dict = {}` initialiser shadowed inside `_oidc_discover`
- (covered by ARCH-1.008)

---

## 4.9 Consistency

### [CODE-1.025] Module-level imports inside functions — defensive style or legacy?
- **Severity**: P3(優化)
- **Category**: Consistency
- **Trigger**: 30+ sites of `from app.X.Y import Z` *inside* a function body (e.g. `releases.py:216,459,500`, `monitor.py:34-44`, `auth.py:90,290,356-357,401`)
- **Location**: scattered
- **Observation**: Two patterns coexist: top-level imports vs deferred-import inside function bodies. Some are legitimate (avoid circular imports — e.g. monitor.py imports models lazily); others are arbitrary
- **Recommendation**: opportunistic cleanup during the `releases.py` split; not a dedicated finding
- **Effort**: S (per file)
- **Confidence**: Medium

### [CODE-1.026] `_assert_release_org` uses 403; `assert_release_in_scope` uses 404 — see ARCH-1.003

---

## 4.10 Test quality

### [CODE-1.027] Zero unit tests
- **Severity**: P0(阻斷 for the refactor plan)
- **Category**: Test quality
- **Trigger**: Phase 1 inventory — only `test_all.py` (HTTP integration), `test_full_verification.py` (HTTP integration), `test_endpoint_decorator_enforcement.py` (structural)
- **Location**: `backend/tests/`
- **Observation**: There are no function-level tests for any helper. `_is_suppressed`, `_sla_info`, `_highest_severity`, `_validate_webhook_url`, `score_sbom`, `_parse_vuln`, `_extract_packages_regex`, `_query_batch`, etc. — none have a unit test.
- **Why it matters**: per `calibration.md` §3.3 AC-T1, the refactor's safety net depends on function-level tests. Without them, the god-router split is gated only by HTTP integration tests (slow, coarse, can't catch invariant regressions).
- **Reference**: Feathers *Working Effectively with Legacy Code* — characterization tests are the safety net before behavior-preserving refactor
- **Recommendation**: Phase 7 plan opens with adding `backend/requirements-dev.txt` (pytest), `backend/tests/unit/`, and writing characterization tests for the helpers about to be moved (Suppression, SLA, Severity, OSV parsing, Webhook validation)
- **Effort**: M (test infrastructure setup + ~30–50 characterization tests)
- **Risk of Fix**: nil (additive)
- **Confidence**: High

### [CODE-1.028] `test_full_verification.py` (439 LOC) status / coverage unverified
- **Severity**: P3(優化)
- **Category**: Test quality / Documentation
- **Trigger**: Phase 1 inventory; not sure if it's still wired into CI
- **Location**: `test_full_verification.py`
- **Observation**: 439 LOC stdlib HTTP test file at repo root. CI's `security.yml` runs only `test_all.py`. Either this file is obsolete (DEBT-002 deferral), or it should be in CI.
- **Recommendation**: investigate Phase 7; either delete (Tidy commit) or wire to CI
- **Effort**: S
- **Confidence**: Medium

---

## Summary table

| ID | Severity | Cat | Title | Effort |
|---|:---:|---|---|:---:|
| CODE-1.001 | P1 | Long Method | `upload_sbom` 142 LOC | M |
| CODE-1.002 | P1 | Long Method | `download_evidence_package` 154 LOC | M |
| CODE-1.003 | P2 | Duplicate | 4 PDF endpoints duplicate scaffold | M |
| CODE-1.004 | P2 | Module | XML/SPDX export inline in router | M |
| CODE-1.005 | (rolled up to ARCH-1.001) | | | |
| CODE-1.006 | P3 | SOLID/DIP | `audit.record(user: dict)` poorly typed | S |
| CODE-1.007 | (not a finding) | | | |
| CODE-1.008 | P3 | Naming | `_assert_release_org` returns tuple | S |
| CODE-1.009 | P2 | Function | `rescan` new-vuln detection has bug | S |
| CODE-1.010 | (not a finding) | | | |
| CODE-1.011 | P2 | Error | Quality grade `except Exception: pass` | S |
| CODE-1.012 | P2 | Function | `update_version` / `update_notes` `body: dict` | S |
| CODE-1.013 | P2 | Bug | CSAF namespace `https://example.com` | S |
| CODE-1.014 | P2 | Error | 46 broad `except` triage | M |
| CODE-1.015 | P3 | Security | OIDC `id_token` not validated | M (deferred to security lane) |
| CODE-1.016 | P3 | Dead code | `_enrich_ghsa` returns unused | S |
| CODE-1.017 | P3 | Comments | Concurrency globals lack docstring | S |
| CODE-1.018 | (rolled into CODE-1.003) | | | |
| CODE-1.019 | (rolled into CODE-1.002) | | | |
| CODE-1.020 | P2 | Duplicate | `_SLA_DAYS` in 2 files | S |
| CODE-1.021 | P2 | Duplicate | Severity order in 2 files (different scales) | S |
| CODE-1.022 | (rolled into ARCH-1.010) | | | |
| CODE-1.025 | P3 | Consistency | Inline imports vs top-level | S (opportunistic) |
| CODE-1.026 | (rolled into ARCH-1.003) | | | |
| CODE-1.027 | P0 | Test | Zero unit tests | M (prereq) |
| CODE-1.028 | P3 | Test | `test_full_verification.py` status unclear | S |

**Distinct findings**: 18 (after rollups removed)
**Severity distribution**: P0 ×1, P1 ×2, P2 ×9, P3 ×6

End of code-audit.md
