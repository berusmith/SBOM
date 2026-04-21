"""
Fetch CISA Known Exploited Vulnerabilities (KEV) catalog.
Returns set of CVE IDs confirmed exploited in the wild.
"""
import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_cve_ids() -> set[str]:
    """Returns set of CVE IDs in the CISA KEV catalog."""
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(KEV_URL)
            resp.raise_for_status()
            return {v["cveID"] for v in resp.json().get("vulnerabilities", [])}
    except httpx.HTTPError:
        return set()
