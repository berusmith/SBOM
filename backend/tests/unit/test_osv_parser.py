"""
Function-level characterization for `_parse_vuln` and `_numeric_to_severity`
(in backend/app/services/vuln_scanner.py:59 and :94).

These do NOT move during PR-1.  Tests guard against silent regression when
PR-2 F.3 changes how the OSV `httpx.Client` is shared (PERF-1.008) — the
parsing logic is unchanged but the call site rewires.
"""
from __future__ import annotations

import pytest

from app.services.vuln_scanner import _parse_vuln, _numeric_to_severity


# ── _numeric_to_severity bands ────────────────────────────────────────────────

@pytest.mark.function_level
@pytest.mark.parametrize("score, expected", [
    (None, "info"),
    (0.0, "low"),
    (3.9, "low"),
    (4.0, "medium"),
    (6.9, "medium"),
    (7.0, "high"),
    (8.9, "high"),
    (9.0, "critical"),
    (10.0, "critical"),
])
def test_numeric_to_severity_bands(score, expected):
    assert _numeric_to_severity(score) == expected


# ── _parse_vuln: CVE alias preferred over GHSA/PYSEC id ──────────────────────

@pytest.mark.function_level
def test_cve_alias_wins_over_ghsa_id():
    vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["PYSEC-2023-1", "CVE-2023-12345", "OTHER"],
        "database_specific": {"severity": "HIGH"},
    }
    parsed = _parse_vuln(vuln)
    assert parsed["cve_id"] == "CVE-2023-12345"


@pytest.mark.function_level
def test_no_cve_alias_falls_back_to_id():
    vuln = {"id": "GHSA-only", "aliases": ["PYSEC-2023-1"], "database_specific": {"severity": "LOW"}}
    parsed = _parse_vuln(vuln)
    assert parsed["cve_id"] == "GHSA-only"


# ── _parse_vuln: severity from database_specific text label ──────────────────

@pytest.mark.function_level
@pytest.mark.parametrize("text, sev, score", [
    ("CRITICAL", "critical", 9.5),
    ("HIGH",     "high",     7.5),
    ("MODERATE", "medium",   5.0),
    ("MEDIUM",   "medium",   5.0),
    ("LOW",      "low",      2.0),
])
def test_severity_from_db_specific_label(text, sev, score):
    parsed = _parse_vuln({"id": "X", "database_specific": {"severity": text}})
    assert parsed["severity"] == sev
    assert parsed["cvss_score"] == score


# ── _parse_vuln: numeric fallback when text absent ───────────────────────────

@pytest.mark.function_level
def test_numeric_fallback_when_text_severity_absent():
    vuln = {
        "id": "X",
        "severity": [{"type": "CVSS_V3", "score": "8.5"}],
    }
    parsed = _parse_vuln(vuln)
    assert parsed["cvss_score"] == 8.5
    assert parsed["severity"] == "high"  # 8.5 → high band


@pytest.mark.function_level
def test_invalid_numeric_score_handled_gracefully():
    """If the score string is not parseable as float, fall back to None / info."""
    vuln = {"id": "X", "severity": [{"type": "CVSS_V3", "score": "not-a-number"}]}
    parsed = _parse_vuln(vuln)
    assert parsed["cvss_score"] is None
    assert parsed["severity"] == "info"


# ── _parse_vuln: CVSS v4 vector extraction ───────────────────────────────────

@pytest.mark.function_level
def test_cvss_v4_vector_extracted_when_present():
    vuln = {
        "id": "X",
        "database_specific": {"severity": "HIGH"},
        "severity": [
            {"type": "CVSS_V3", "score": "7.5"},
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
        ],
    }
    parsed = _parse_vuln(vuln)
    assert parsed["cvss_v4_vector"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.mark.function_level
def test_cvss_v4_vector_none_when_absent():
    parsed = _parse_vuln({"id": "X", "database_specific": {"severity": "HIGH"}})
    assert parsed["cvss_v4_vector"] is None


# ── _parse_vuln: missing everything yields safe defaults ─────────────────────

@pytest.mark.function_level
def test_completely_empty_vuln_safe_defaults():
    parsed = _parse_vuln({"id": "X"})
    assert parsed["cve_id"] == "X"
    assert parsed["cvss_score"] is None
    assert parsed["severity"] == "info"
    assert parsed["cvss_v4_vector"] is None
