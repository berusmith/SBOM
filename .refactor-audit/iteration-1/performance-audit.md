---
iteration: 1
phase: 5 — Performance Audit
date: 2026-04-29
status: complete (read-only); measurements deferred to Phase 8
finding_id_prefix: PERF-1.NNN
scope: 4 hot-spots per D6 — list endpoints with N+1 risk, PDF cold start, OSV batch (cite-only), ReleaseDetail.jsx render
---

# Iteration 1 — Performance Audit

> Per protocol §5.1: any finding without measurement is **Confidence: Low**. This iter establishes 4 hot-spot benchmarks (per D6) but does not run them in Phase 5 — measurement is deferred to Phase 8 alongside the related refactor (so before/after numbers are produced together).
>
> Per D6.3 (user feedback iter-1): hot-spot (3) **OSV batch** is **NOT re-measured** — `CHANGELOG.md:73-80` already documents 200→51 HTTP + 5.9s smoke test. Phase 8 will commit a reproducer script `backend/tests/bench/bench_osv.py` that reproduces the lodash@4.17.20 + django@3.0.0 + log4j-core@2.14.0 smoke test.

---

## 5.1 Measurement state

- **No formal benchmarks exist today** (per `recon.md` §6).
- **No APM, no production telemetry, no Web Vitals** in frontend.
- **Documented optimization**: OSV batch rewrite (CHANGELOG.md:73-80) — 200-component / 50-unique-vuln SBOM from ~200 HTTP → 1+50 = 51 HTTP, with a smoke test (3 PURLs, 42 vulns, 5.9s).
- **All findings below carry Confidence: Low or Medium** until measured. Phase 8's perf commits are paired with measurement scripts.

---

## 5.2 Hot-spot 1 — list endpoints with N+1 / overfetch risk

### [PERF-1.001] `get_stats.overdue_count` pulls every active vuln to Python for date comparison
- **Severity**: P2(中等)
- **Category**: Database / List endpoint
- **Trigger**: reading `stats.py:86-103`
- **Location**: `backend/app/api/stats.py:86-103`
- **Observation**:
  ```python
  active_vulns = (
      base.filter(...).with_entities(Vulnerability.severity, Vulnerability.scanned_at).all()
  )
  for sev, scanned_at in active_vulns:
      if sev not in _SLA_DAYS: continue
      ts = scanned_at.replace(tzinfo=timezone.utc) if scanned_at.tzinfo is None else scanned_at
      if (now - ts).days > _SLA_DAYS[sev]:
          overdue_count += 1
  ```
  For an org with 5,000 active vulns, this pulls 5,000 `(severity, scanned_at)` tuples over the wire and iterates in Python. `core/database.days_between` already exists (cross-DB SQL helper) — the entire computation could be a single `SELECT COUNT(*) WHERE days_between(now, scanned_at) > CASE severity WHEN 'critical' THEN 7 ...` query
- **Why it matters**: dashboard load time is gated on this. 5,000-row roundtrip + Python loop could be 100ms+ on SQLite, more on Postgres-over-network
- **Reference**: PostgreSQL — push computation to the engine; this is exactly what `days_between` exists for (introduced in `core/database.py:9-18`, currently used only in `stats.py:74` for avg-days-to-fix)
- **Refactor Type**: **Substitute Algorithm** — push to SQL with `func.case()`
- **Behavior-Equivalence Risk**: Low — compares same numbers; only the location of comparison changes. Edge case: `scanned_at` NULLs — current code guards `Vulnerability.scanned_at.isnot(None)`; SQL version inherits same guard
- **Recommendation**:
  ```python
  from sqlalchemy import case
  cutoff_expr = case(
      (Vulnerability.severity == "critical", 7),
      (Vulnerability.severity == "high", 30),
      (Vulnerability.severity == "medium", 90),
      (Vulnerability.severity == "low", 180),
      else_=99999,
  )
  overdue_count = base.filter(
      Vulnerability.status.notin_(["fixed", "not_affected"]),
      Vulnerability.scanned_at.isnot(None),
      days_between(func.now(), Vulnerability.scanned_at) > cutoff_expr,
  ).count()
  ```
- **Test Strategy**: characterization test seeds N vulns with varying severity + scanned_at, asserts pre/post `overdue_vulns` count matches
- **Effort**: S
- **Performance Data** (theoretical, **Confidence: Medium**):
  - Before: O(N) row fetch + Python loop; ~1ms per 100 rows + ~50μs per row Python work
  - After: O(1) DB call; the engine does the work in the index-scan
  - 5,000 rows: estimated 50–150ms → ~5–10ms (10–30× faster)
- **Confidence**: Medium (theoretical)

### [PERF-1.002] `get_stats` issues 7+ separate queries for one dashboard load
- **Severity**: P3(優化)
- **Category**: Database / List endpoint
- **Trigger**: reading `stats.py:33-126`
- **Location**: `backend/app/api/stats.py:33-126`
- **Observation**: `get_stats` (the dashboard endpoint) issues at least:
  1. orgs count
  2. products count
  3. releases count (with optional join)
  4. components count (with optional join)
  5. severity counts (group_by)
  6. status counts (group_by)
  7. avg_days_to_fix (avg + days_between)
  8. cra_incidents counts (×2 — total and active)
  9. overdue_count (5K-row pull, see PERF-1.001)
  Each is a separate DB roundtrip. On Postgres-over-network this adds latency.
- **Why it matters**: dashboard is the most-loaded endpoint; 9 sequential queries × ~5–20ms each on Postgres = ~50–180ms cumulative DB time per dashboard load
- **Refactor Type**: **Substitute Algorithm** — combine into 1–3 queries (CTE, UNION ALL) OR use `asyncio.gather` with parallel queries (less benefit on SQLite, more on Postgres)
- **Behavior-Equivalence Risk**: Low — output JSON shape identical; query plan changes
- **Recommendation**: not in iter-1 scope. Park as DEBT-015. Once PERF-1.001 is fixed (the biggest win in `get_stats`), measure again; if dashboard still feels slow, attack the multi-query pattern
- **Effort**: M
- **Confidence**: Low (no measurement)

### [PERF-1.003] `notify_new_vulns` filters AFTER computing details; `monitor._do_scan_all` builds full details for every vuln
- **Severity**: P3(優化)
- **Category**: Application logic
- **Trigger**: reading `monitor.py:74-91` + `alerts.py:236-239`
- **Location**: `backend/app/services/monitor.py:74-91` builds `new_details` for every detected vuln; `backend/app/services/alerts.py:236-239` filters them via `_passes_alert_rule`
- **Observation**: monitor builds full `new_details` dict (cve_id, severity, cvss_score, epss_score, is_kev, component) for EVERY new vuln, then alerts filter on (severity ≥ min_severity, EPSS ≥ threshold, KEV always). If config has `min_severity = "critical"`, monitor still builds details for every low/medium vuln.
- **Why it matters**: minor — the work per vuln is small (a dict literal). At scale (1000s of vulns per scan), measurable but not visible
- **Recommendation**: out of iter-1 scope; opportunistic cleanup if `monitor.py` is touched
- **Effort**: S
- **Confidence**: Low

### [PERF-1.004] `list_components` and `list_vulnerabilities` correctly use `selectinload` — POSITIVE FINDING
- **Severity**: n/a (positive)
- **Trigger**: `releases.py:585`, `releases.py:621`
- **Observation**: Both endpoints use `.options(selectinload(Component.vulnerabilities))` to prevent N+1. Pagination capped (5000 components, 1000 vulns).
- **Why noted**: confirms that the project knows this pattern; do not regress

---

## 5.3 Hot-spot 2 — PDF report generation (reportlab cold start)

### [PERF-1.005] First PDF endpoint hit eats reportlab module import + font load
- **Severity**: P3(優化)
- **Category**: Backend / Cold start
- **Trigger**: theoretical knowledge of reportlab; not yet measured
- **Location**: every PDF endpoint (5 in `releases.py`, 1 in `tisax.py`); first call per process
- **Observation**: `reportlab` is a heavy module; first import triggers font discovery + canvas registration. Subsequent calls are cached. Cold start = first PDF endpoint after process start.
- **Why it matters**: `start_backend.bat` launches uvicorn; first user to download a report after restart pays the tax (~200–800ms theoretical)
- **Recommendation**: warm at startup — `from app.services import pdf_report` in `lifespan`. **One-line fix.**
- **Test Strategy**: micro-benchmark in `backend/tests/bench/bench_pdf_cold.py` — measure `time_to_first_pdf` with and without warmup; document
- **Effort**: S
- **Performance Data** (theoretical, **Confidence: Low**):
  - Before: cold call ~200–800ms first time, ~50–150ms subsequent
  - After: same; cold cost moved to startup (already 1–3s anyway)
  - Net user-visible improvement: ~200–700ms on the first report request after restart
- **Confidence**: Low (need measurement)

### [PERF-1.006] PDF endpoints re-fetch components 4× per request via `selectinload`
- **Severity**: P3(優化)
- **Category**: Database
- **Trigger**: reading PDF endpoints
- **Observation**: `download_iec62443_42_report` (line 840-866) builds a `components_raw` list and a separate `vulns` flat list from it. Each PDF endpoint duplicates this — fine for one endpoint per request, but if the user clicks 5 PDF buttons, the same release fetches 5×.
- **Why it matters**: single-user usage = noise; multi-user = small. Acceptable.
- **Recommendation**: not in iter-1 scope

---

## 5.4 Hot-spot 3 — OSV batch scan (cited, NOT re-measured per D6.3)

### [PERF-1.007] OSV batch optimization — cite existing evidence + add reproducer script
- **Severity**: n/a (already optimised)
- **Category**: Performance / Reproducibility
- **Trigger**: D6.3 — "do not re-measure; cite + reproducer script"
- **Location**: `backend/app/services/vuln_scanner.py:146-189` (the optimised implementation); `CHANGELOG.md:73-80` (the documented benchmark)
- **Existing evidence**:
  - **Methodology**: 2-phase (Phase 1 = `POST /v1/querybatch` ≤ 1000 PURLs; Phase 2 = parallel `GET /v1/vulns/{id}` for unique IDs)
  - **Improvement**: 200 elements / 50 unique vulns: ~200 HTTP → 1+50 = 51 HTTP
  - **Smoke test**: lodash@4.17.20 (5 vulns) + django@3.0.0 (30) + log4j-core@2.14.0 (7, including Log4Shell CVE-2021-45046 critical/9.5) — total 42 vulns, 5.9 seconds end-to-end on the dev machine
- **Recommendation** (Phase 8):
  - Add `backend/tests/bench/bench_osv.py` (~30 LOC stdlib) that reproduces the smoke test and prints `purl, vuln_count, elapsed_seconds`
  - Run before any future change to `vuln_scanner.py` to verify regression budget (5.9s ± 50%)
  - Commit with `tidy: bench(osv): committable reproducer for the documented 200→51 optimization`
- **Behavior-Equivalence Risk**: nil (no code change to scanner)
- **Effort**: S (script only)
- **Confidence**: High (existing evidence is solid; reproducer script is mechanical)

### [PERF-1.008] `vuln_scanner._fetch_vuln` opens new `httpx.Client` per call
- **Severity**: P2(中等)
- **Category**: Network / Cold connections
- **Trigger**: reading `vuln_scanner.py:135-143`
- **Location**: `backend/app/services/vuln_scanner.py:138`
- **Observation**:
  ```python
  def _fetch_vuln(vuln_id: str) -> tuple[str, dict | None]:
      try:
          with httpx.Client(timeout=30) as client:   # ← new client per call
              resp = client.get(OSV_VULN_URL.format(vuln_id=vuln_id))
              resp.raise_for_status()
          return vuln_id, _parse_vuln(resp.json())
  ```
  Each of the 50+ parallel detail fetches creates a fresh `httpx.Client` = fresh TCP connection + fresh TLS handshake to OSV.dev. With 20 parallel workers, up to 20 concurrent handshakes to the same host are wasted (HTTP/1.1 connection pool would have reused them; HTTP/2 would have multiplexed)
- **Why it matters**: TLS handshake = ~50–100ms per connection over typical internet. 50 unique vulns × ~75ms wasted = ~3.75s of avoidable latency in the ~5.9s smoke test = **63% of the smoke-test time is TLS overhead**
- **Refactor Type**: **Substitute Algorithm** — share one `httpx.Client(http2=True)` across the ThreadPool workers
- **Behavior-Equivalence Risk**: Low — output identical; only network behavior changes
- **Recommendation**:
  ```python
  def scan_components(components: list) -> dict:
      ...
      with httpx.Client(timeout=30, http2=True) as client:
          # Phase 1
          for i in range(0, len(purls), _BATCH_SIZE):
              chunk_results = _query_batch(client, purls[i:i + _BATCH_SIZE])
              ...
          # Phase 2 — share the same client across workers
          detail_cache = {}
          with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
              futures = {pool.submit(_fetch_vuln_with_client, client, vid): vid for vid in unique_ids}
              ...
  ```
  Note: `httpx.Client` is thread-safe per docs; no extra lock needed
- **Test Strategy**: re-run the smoke test (3 PURLs benchmark from PERF-1.007) before/after; expected 5.9s → ~3–4s
- **Effort**: S
- **Performance Data** (theoretical, **Confidence: Medium**):
  - Before: 5.9s for 3 PURLs / 42 vulns
  - After: estimated 3.0–4.0s (~30–50% reduction)
  - Per-PURL improvement scales linearly with vuln count
- **Confidence**: Medium (need measurement)

---

## 5.5 Hot-spot 4 — `ReleaseDetail.jsx` 76 hooks render

### [PERF-1.009] `ReleaseDetail.jsx` — 76 useState/useEffect on a 2087-LOC component
- **Severity**: P2(中等) — but **out of iter-1 scope** (UX-034 carry-over deferral)
- **Category**: Frontend / Render
- **Trigger**: `grep -c "useState\|useEffect" frontend/src/pages/ReleaseDetail.jsx → 76` + LOC = 2087
- **Location**: `frontend/src/pages/ReleaseDetail.jsx:65-2087`
- **Observation**: 76 distinct useState/useEffect calls in one component. Each setState triggers a full re-render of the 2087-LOC subtree (3 tabs + multiple inline modals: VexEditButton, VexModal, SuppressButton, SuppressModal, DependencyGraph). React.memo / useMemo / useCallback are used in places (line 47-63 for STATUS_LABEL, JUSTIFICATION_OPTIONS, RESPONSE_OPTIONS) but the bulk of the component is unmemoised
- **Why it matters**: typing in any input, toggling any checkbox, opening any modal = re-renders 2087 LOC of JSX. On a 1000-vuln release the cost compounds.
- **Reference**: Sentry frontend's component-size discipline; React DevTools Profiler is the standard measurement tool
- **Refactor Type**: **Extract Class** (component decomposition) is the proper fix — this is what UX-034 carry-over targets
- **Behavior-Equivalence Risk**: Medium — changing render behavior may shift focus / scroll; UX testing needed
- **Recommendation**: **out of iter-1 scope** per Q4 (frontend deferred). Park as DEBT-005 (already exists) + DEBT-016 (perf-specific aspect). When iter-3+ tackles UX-034, the perf benchmark goes in tandem
- **Test Strategy** (when in scope): React Profiler + production build + interaction tests (input typing, modal open/close)
- **Effort**: L (whole component decomposition)
- **Performance Data** (theoretical, **Confidence: Low**): no measurement yet; React DevTools Profiler in dev mode would quantify; rough estimate: each interaction may cost 30–80ms vs ~5ms after decomposition
- **Confidence**: Low

---

## 5.6 Other observations (not findings, but recorded)

- **Indexes are well-defined** at `main.py:158-170` — 11 indexes covering vulnerability hot-paths (cve_id, severity, status, is_kev, epss, component_id, purl, name, cra org/status, password reset hash) plus the unique constraint `uq_comp_cve`
- **`selectinload`** is used in list endpoints (positive — see PERF-1.004)
- **Pagination** is enforced (`list_components` 5000 cap, `list_vulnerabilities` 1000 cap)
- **`days_between` cross-DB helper** exists but only used in 1 place (`stats.py:74`); PERF-1.001 expands its use
- **WAL mode** (`PRAGMA journal_mode=WAL`) at `core/database.py:28` — good for concurrent reads with SQLite
- **`busy_timeout=5000`** at `core/database.py:29` — avoids `database is locked` errors

---

## Summary table

| ID | Severity | Category | Hot-spot | Effort | Confidence | Expected Δ |
|---|:---:|---|---|:---:|---|---|
| PERF-1.001 | P2 | Database | (1) overdue_count Python loop → SQL | S | Medium | 10–30× on stats.overdue |
| PERF-1.002 | P3 | Database | (1) get_stats 9 queries → CTE | M | Low | unmeasured |
| PERF-1.003 | P3 | App logic | monitor builds details before filter | S | Low | small |
| PERF-1.004 | n/a (positive) | Database | selectinload preventing N+1 | — | High | already optimal |
| PERF-1.005 | P3 | Cold start | (2) reportlab warmup at lifespan | S | Low | 200–700ms first PDF |
| PERF-1.006 | P3 | Database | PDF endpoints re-fetch | — | Low | not in scope |
| PERF-1.007 | n/a (cite) | Reproducibility | (3) OSV batch reproducer script | S | High | reproducible benchmark |
| PERF-1.008 | P2 | Network | (3) shared httpx.Client across pool | S | Medium | ~30–50% on OSV detail phase |
| PERF-1.009 | P2 | Frontend | (4) ReleaseDetail.jsx 76 hooks | L | Low | deferred to UX-034 iter |

**Severity distribution**: P2 ×3, P3 ×4, n/a ×2 (positive observations)

## Iter-1 in-scope perf actions

- **PERF-1.001** (S, Medium confidence) — push overdue_count to SQL using existing `days_between` helper
- **PERF-1.005** (S, Low confidence) — reportlab warmup at lifespan
- **PERF-1.007** (S, High confidence) — commit `bench_osv.py` reproducer script (cite-only)
- **PERF-1.008** (S, Medium confidence) — share `httpx.Client` across OSV detail-fetch ThreadPool

Together: 4 small commits, all behavior-equivalent, all measurable improvement OR positive infrastructure (reproducer script).

End of performance-audit.md
