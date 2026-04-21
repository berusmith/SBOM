"""
Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.
Returns exploitation probability (0-1) for each CVE.
"""
import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
_CHUNK = 500


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Returns {cve_id: {epss: float, percentile: float}} for known CVEs."""
    if not cve_ids:
        return {}

    results: dict[str, dict] = {}
    with httpx.Client(timeout=30) as client:
        for i in range(0, len(cve_ids), _CHUNK):
            chunk = cve_ids[i : i + _CHUNK]
            try:
                resp = client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                resp.raise_for_status()
                for item in resp.json().get("data", []):
                    cve = item.get("cve", "")
                    try:
                        results[cve] = {
                            "epss": float(item["epss"]),
                            "percentile": float(item["percentile"]),
                        }
                    except (KeyError, ValueError):
                        pass
            except httpx.HTTPError:
                pass
    return results
