"""
Query OSV.dev API for vulnerabilities by PURL.
Uses individual /v1/query per component to get full details (batch API is too minimal).
"""
import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

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
    if cvss_score is None:
        for sev in vuln.get("severity", []):
            try:
                cvss_score = float(sev.get("score", ""))
                break
            except (ValueError, TypeError):
                pass

    if severity is None:
        severity = _numeric_to_severity(cvss_score)

    return {"cve_id": cve_id, "cvss_score": cvss_score, "severity": severity}


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


def scan_components(components: list[dict]) -> dict[str, list[dict]]:
    """
    Returns dict keyed by purl -> list of {cve_id, cvss_score, severity}.
    Skips components without a purl.
    """
    results: dict[str, list[dict]] = {}

    with httpx.Client(timeout=30) as client:
        for component in components:
            purl = component.get("purl", "")
            if not purl:
                continue
            try:
                resp = client.post(
                    OSV_QUERY_URL,
                    json={"package": {"purl": purl}},
                )
                resp.raise_for_status()
            except httpx.HTTPError:
                continue

            vulns = [_parse_vuln(v) for v in resp.json().get("vulns", [])]
            if vulns:
                results[purl] = vulns

    return results
