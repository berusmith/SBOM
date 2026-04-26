"""
Query OSV.dev for vulnerabilities by PURL.

Two-phase strategy (much faster than the old per-PURL /v1/query loop):

  Phase 1  POST /v1/querybatch with up to 1000 PURLs at once.
           OSV returns a compact list of {id, modified} stubs per query —
           no severity, no aliases.  One round-trip per chunk of ≤1000.

  Phase 2  For each *unique* vuln id seen across all packages, GET
           /v1/vulns/{id} in parallel to retrieve the full record
           (severity, aliases, database_specific, CVSS vectors).

For an SBOM with 200 components and 50 unique vulnerabilities, this drops
the OSV traffic from ~200 HTTP calls down to 1 batch + 50 detail calls.
For larger SBOMs the savings grow super-linearly because vulns repeat
across components (e.g. the same lodash CVE matched by 30 transitive
deps is fetched exactly once).

Public contract is unchanged — `scan_components(components) -> dict`
keyed by PURL → list of {cve_id, cvss_score, severity, cvss_v4_vector}.
Drop-in replacement for the previous implementation.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{vuln_id}"

# OSV documents 1000 queries / batch as the upper bound.  We stay one
# below to leave headroom for any future tightening.
_BATCH_SIZE  = 1000

# Detail fetches are independent GETs and cheap on OSV's side.  20 keeps
# us well under any reasonable rate ceiling while still saturating most
# residential / cloud egress.
_MAX_WORKERS = 20

_TEXT_TO_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MODERATE": 5.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
}

_TEXT_TO_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _parse_vuln(vuln: dict) -> dict:
    # prefer CVE alias over GHSA/PYSEC id
    cve_id = vuln.get("id", "")
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # severity from database_specific (most reliable text label)
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    severity = _TEXT_TO_SEVERITY.get(db_sev)
    cvss_score = _TEXT_TO_CVSS.get(db_sev)

    # fallback: try numeric score from severity array
    cvss_v4_vector = None
    if cvss_score is None:
        for sev in vuln.get("severity", []):
            try:
                cvss_score = float(sev.get("score", ""))
                break
            except (ValueError, TypeError):
                pass

    # extract CVSS v4 vector string if present
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V4":
            cvss_v4_vector = sev.get("score")
            break

    if severity is None:
        severity = _numeric_to_severity(cvss_score)

    return {"cve_id": cve_id, "cvss_score": cvss_score, "severity": severity, "cvss_v4_vector": cvss_v4_vector}


def _numeric_to_severity(score) -> str:
    if score is None:
        return "info"
    score = float(score)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _query_batch(client: httpx.Client, purls: list[str]) -> list[list[str]]:
    """
    POST /v1/querybatch for one chunk.  Returns a list-of-lists aligned
    with the input PURLs, each inner list being the vuln *ids* matched
    for that PURL.  Empty list = no matches for that PURL.

    Network failures degrade silently to "no vulns for this chunk" so a
    transient OSV outage cannot crash an SBOM upload.
    """
    body = {"queries": [{"package": {"purl": p}} for p in purls]}
    try:
        resp = client.post(OSV_BATCH_URL, json=body)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except httpx.HTTPError:
        return [[] for _ in purls]

    out: list[list[str]] = []
    for entry in results:
        vuln_ids = [v.get("id", "") for v in entry.get("vulns", []) if v.get("id")]
        out.append(vuln_ids)
    # Defensive: if OSV ever returns fewer entries than queries, pad with
    # empties so the index alignment holds.
    while len(out) < len(purls):
        out.append([])
    return out


def _fetch_vuln(vuln_id: str) -> tuple[str, dict | None]:
    """GET /v1/vulns/{id} for a single vuln.  Returns (id, parsed) or (id, None) on failure."""
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(OSV_VULN_URL.format(vuln_id=vuln_id))
            resp.raise_for_status()
        return vuln_id, _parse_vuln(resp.json())
    except httpx.HTTPError:
        return vuln_id, None


def scan_components(components: list) -> dict:
    """
    Returns dict keyed by purl -> list of {cve_id, cvss_score, severity, cvss_v4_vector}.
    Skips components without a purl.

    Implementation: batched OSV queries followed by parallel detail fetches
    for each unique vuln id.  See module docstring for the rationale.
    """
    purls = [c["purl"] for c in components if c.get("purl")]
    if not purls:
        return {}

    # Phase 1 — batch all PURLs in chunks of ≤_BATCH_SIZE.
    purl_to_vuln_ids: dict[str, list[str]] = {}
    unique_ids: set[str] = set()
    with httpx.Client(timeout=60) as client:
        for i in range(0, len(purls), _BATCH_SIZE):
            chunk = purls[i:i + _BATCH_SIZE]
            chunk_results = _query_batch(client, chunk)
            for purl, ids in zip(chunk, chunk_results):
                if ids:
                    purl_to_vuln_ids[purl] = ids
                    unique_ids.update(ids)

    if not unique_ids:
        return {}

    # Phase 2 — fetch each unique vuln in parallel.  One vuln id maps to
    # one parsed record regardless of how many PURLs reference it.
    detail_cache: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_fetch_vuln, vid): vid for vid in unique_ids}
        for future in as_completed(futures):
            vid, parsed = future.result()
            if parsed is not None:
                detail_cache[vid] = parsed

    # Stitch back: for each PURL, look up parsed record for each matched id.
    results: dict[str, list[dict]] = {}
    for purl, ids in purl_to_vuln_ids.items():
        parsed_list = [detail_cache[vid] for vid in ids if vid in detail_cache]
        if parsed_list:
            results[purl] = parsed_list
    return results
