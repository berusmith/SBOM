"""
Fetch GitHub Security Advisories (GHSA) for a list of components.
Uses the GitHub Advisory Database REST API (no auth required, 60 req/h;
set GITHUB_TOKEN env var / config for 5000 req/h).

Returns per-purl list of advisories: {ghsa_id, cve_id, severity, cvss_score, description, url}
"""
from __future__ import annotations

import time
import urllib.parse
import urllib.request
import json
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

_BASE = "https://api.github.com/advisories"

# Map PURL type → GitHub Advisory ecosystem name
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm":      "npm",
    "pypi":     "pip",
    "maven":    "maven",
    "nuget":    "nuget",
    "cargo":    "rust",
    "gem":      "rubygems",
    "composer": "composer",
    "go":       "go",
    "hex":      "erlang",
    "pub":      "pub",
    "swift":    "swift",
}

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "moderate": "medium",
    "low":      "low",
}


def _purl_to_ecosystem_package(purl: str) -> tuple[str, str] | None:
    """
    Parse pkg:type/[namespace/]name@version → (ecosystem, package_name).
    Returns None if the PURL type is not supported.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    try:
        rest = purl[4:]                          # strip "pkg:"
        ptype, rest = rest.split("/", 1)
        name_ver = rest.split("@")[0]            # drop version
        ecosystem = _ECOSYSTEM_MAP.get(ptype.lower())
        if not ecosystem:
            return None
        # For maven: namespace/artifact — GHSA expects "group:artifact"
        if ptype.lower() == "maven" and "/" in name_ver:
            parts = name_ver.split("/", 1)
            package = f"{parts[0]}:{parts[1]}"
        else:
            # For npm scoped packages: @scope/name → keep as-is
            package = name_ver
        return ecosystem, package
    except Exception:
        return None


def _get(url: str) -> list:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sbom-platform/1.0",
    }
    token = getattr(settings, "GITHUB_TOKEN", "") or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning("GHSA fetch failed %s: %s", url, e)
        return []


def fetch_ghsa_for_components(components: list[dict]) -> dict[str, list[dict]]:
    """
    components: list of {purl, name, version}
    Returns {purl: [advisory_dict, ...]}
    advisory_dict: {ghsa_id, cve_id, severity, cvss_score, description, url}
    """
    results: dict[str, list[dict]] = {}
    # Deduplicate by (ecosystem, package) to avoid redundant API calls
    seen: dict[tuple, list[str]] = {}
    for comp in components:
        purl = comp.get("purl") or ""
        ep = _purl_to_ecosystem_package(purl)
        if ep:
            seen.setdefault(ep, []).append(purl)

    for (ecosystem, package), purls in seen.items():
        params = urllib.parse.urlencode({
            "ecosystem": ecosystem,
            "affects": package,
            "per_page": 50,
        })
        url = f"{_BASE}?{params}"
        advisories = _get(url)
        if not isinstance(advisories, list):
            continue

        parsed: list[dict] = []
        for adv in advisories:
            ghsa_id = adv.get("ghsa_id", "")
            cve_id = adv.get("cve_id") or ""
            severity_raw = (adv.get("severity") or "").lower()
            severity = _SEVERITY_MAP.get(severity_raw, severity_raw)
            cvss_score = None
            if adv.get("cvss"):
                try:
                    cvss_score = float(adv["cvss"].get("score", 0) or 0) or None
                except (TypeError, ValueError):
                    pass
            parsed.append({
                "ghsa_id":    ghsa_id,
                "cve_id":     cve_id,
                "severity":   severity,
                "cvss_score": cvss_score,
                "description": (adv.get("summary") or "")[:500],
                "url":         adv.get("html_url") or f"https://github.com/advisories/{ghsa_id}",
            })

        for purl in purls:
            results[purl] = parsed

        # Respect rate limit — GitHub unauthenticated: 60/h = 1/6s
        time.sleep(0.1 if getattr(settings, "GITHUB_TOKEN", "") else 1.5)

    return results
