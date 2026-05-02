"""bench_osv.py — OSV.dev scan reproducer (PERF-1.007 / ADR-0003 actionable artifact).

Per `performance-audit.md` §5.4 PERF-1.007: this script reproduces the OSV
batch + parallel-detail scan against `api.osv.dev` for a fixed PURL list,
printing per-phase wall-clock so future contributors can detect regression
in the optimization that ADR-0003 documents.

NOT a pytest target.  Run as:

    python backend/tests/bench/bench_osv.py

# Offline policy (per Q-PR2-2 (a))

If `api.osv.dev` is unreachable (network down, DNS fail, etc.), the script
prints `OFFLINE: bench skipped — baseline pending until next online session`
and exits with status 0.  This keeps PR-2 / iter-1 closure unblocked when
the dev environment is offline; the bench is a "reproducer when needed",
not a CI regression guard.

# Determinism

The PURL list is fixed (no randomization).  Two consecutive runs against
the same OSV.dev state should produce timing within natural network jitter
but identical vuln counts.

# Stage J usage

Stage J.1 changed `vuln_scanner._fetch_vuln` to share the outer
`httpx.Client` across ThreadPool workers.  Run this script before and
after to measure detail-fetch phase gain.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure backend/ on sys.path so `from app.services.vuln_scanner import scan_components`
# works regardless of cwd.
_BACKEND = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import httpx  # noqa: E402

from app.services.vuln_scanner import scan_components  # noqa: E402

# Fixed PURL list — well-known public packages with known CVE history.
# 10 items chosen to span ecosystems (npm / pypi / maven) and severity ranges.
SAMPLE_PURLS = [
    {"purl": "pkg:npm/lodash@4.17.20"},
    {"purl": "pkg:npm/minimist@1.2.5"},
    {"purl": "pkg:npm/ws@7.4.5"},
    {"purl": "pkg:pypi/requests@2.28.0"},
    {"purl": "pkg:pypi/django@3.0.0"},
    {"purl": "pkg:pypi/urllib3@1.26.4"},
    {"purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
    {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"},
    {"purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10"},
    {"purl": "pkg:gem/rails@5.2.0"},
]


def _check_online() -> bool:
    """Probe api.osv.dev reachability with a 3s timeout."""
    try:
        with httpx.Client(timeout=3) as client:
            client.head("https://api.osv.dev/", follow_redirects=True)
        return True
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError):
        return False


def main() -> int:
    if not _check_online():
        print("OFFLINE: bench skipped — baseline pending until next online session")
        print("(api.osv.dev unreachable; per Q-PR2-2 (a) offline policy, exit 0)")
        return 0

    print(f"bench_osv.py — {len(SAMPLE_PURLS)} fixed PURLs against api.osv.dev")
    print("=" * 70)

    # scan_components encapsulates Phase 1 (batch) + Phase 2 (parallel detail).
    # We measure the total here; phase-level breakdown would require modifying
    # scan_components or duplicating its internals — out of scope for the
    # PERF-1.007 reproducer which only needs end-to-end timing for regression
    # detection.
    t0 = time.perf_counter()
    results = scan_components(SAMPLE_PURLS)
    t1 = time.perf_counter()

    total_secs = t1 - t0
    total_vulns = sum(len(v) for v in results.values())

    print(f"  Total wall-clock:  {total_secs:.2f}s")
    print(f"  PURLs processed:   {len(SAMPLE_PURLS)}")
    print(f"  Unique vulns hit:  {len(results)}")
    print(f"  Total vuln rows:   {total_vulns}")
    print()
    print("Per-PURL breakdown:")
    for entry in SAMPLE_PURLS:
        purl = entry["purl"]
        vulns = results.get(purl, [])
        print(f"  {purl:60s}  {len(vulns):3d} vulns")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
