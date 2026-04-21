"""
Fetch CVE details from NVD API 2.0.
Rate limits: 5 req/30s without key, 50 req/30s with key.
"""
import json
import time

import httpx

from app.core.config import settings

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DELAY_NO_KEY = 7.0   # seconds between requests without API key
_DELAY_KEY    = 0.7   # seconds between requests with API key


def _delay():
    time.sleep(_DELAY_KEY if settings.NVD_API_KEY else _DELAY_NO_KEY)


def fetch_cve(cve_id: str) -> dict:
    """
    Returns {description, cwe, refs, cvss_v3_score, cvss_v3_vector,
             cvss_v4_score, cvss_v4_vector} or {} on failure.
    """
    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
    try:
        resp = httpx.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=15)
        if resp.status_code == 429:
            time.sleep(35)
            resp = httpx.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0]["cve"]
    except Exception:
        return {}

    # Description (English preferred)
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d["value"]
            break

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwes.append(v)
    cwe = ",".join(dict.fromkeys(cwes))  # deduplicate, preserve order

    # References (top 5)
    refs = [r["url"] for r in cve.get("references", [])[:5]]

    # CVSS v3.1
    cvss_v3_score, cvss_v3_vector = None, None
    for m in cve.get("metrics", {}).get("cvssMetricV31", []):
        d = m.get("cvssData", {})
        cvss_v3_score  = d.get("baseScore")
        cvss_v3_vector = d.get("vectorString")
        break

    # CVSS v4.0
    cvss_v4_score, cvss_v4_vector = None, None
    for m in cve.get("metrics", {}).get("cvssMetricV40", []):
        d = m.get("cvssData", {})
        cvss_v4_score  = d.get("baseScore")
        cvss_v4_vector = d.get("vectorString")
        break

    return {
        "description":    description,
        "cwe":            cwe,
        "nvd_refs":       json.dumps(refs),
        "cvss_v3_score":  cvss_v3_score,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v4_score":  cvss_v4_score,
        "cvss_v4_vector": cvss_v4_vector,
    }


def enrich_vulns_nvd(vulns: list, db) -> int:
    """Fetch NVD data for each unique CVE and persist. Returns count updated."""
    seen: dict[str, dict] = {}
    updated = 0
    for v in vulns:
        if not v.cve_id or not v.cve_id.startswith("CVE-"):
            continue
        if v.cve_id not in seen:
            data = fetch_cve(v.cve_id)
            seen[v.cve_id] = data
            if data:
                _delay()
        else:
            data = seen[v.cve_id]

        if not data:
            continue
        v.description    = data.get("description") or v.description
        v.cwe            = data.get("cwe") or v.cwe
        v.nvd_refs       = data.get("nvd_refs") or v.nvd_refs
        if data.get("cvss_v3_score") is not None:
            v.cvss_v3_score  = data["cvss_v3_score"]
            v.cvss_v3_vector = data.get("cvss_v3_vector")
        if data.get("cvss_v4_score") is not None:
            v.cvss_v4_score  = data["cvss_v4_score"]
            v.cvss_v4_vector = data.get("cvss_v4_vector")
        updated += 1

    db.commit()
    return updated
