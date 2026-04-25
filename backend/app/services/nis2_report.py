"""
NIS2 Directive Article 21 Cybersecurity Risk Management assessment and PDF report.
Assesses software supply chain posture against SBOM-relevant NIS2 controls.
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from app.services.pdf_shim import XPos, YPos
from app.services.cjk_pdf import CjkPDF, _latin as _s

STATUS_COLOR = {
    "satisfied":      (22, 163, 74),
    "partial":        (202, 138, 4),
    "not_satisfied":  (220, 38, 38),
    "not_applicable": (107, 114, 128),
}
STATUS_LABEL = {
    "satisfied":      "Satisfied",
    "partial":        "Partial",
    "not_satisfied":  "Not Satisfied",
    "not_applicable": "N/A",
}


def assess(components: list[dict], vulns: list[dict], cra_incidents: list[dict] | None = None) -> list[dict]:
    """Assess NIS2 Article 21 controls from SBOM + vulnerability data."""
    cra_incidents = cra_incidents or []
    total = len(vulns)
    critical_open = [v for v in vulns if v.get("severity") == "critical" and v.get("status") not in ("fixed", "not_affected")]
    high_open     = [v for v in vulns if v.get("severity") == "high"     and v.get("status") not in ("fixed", "not_affected")]
    fixed         = sum(1 for v in vulns if v.get("status") == "fixed")
    not_affected  = sum(1 for v in vulns if v.get("status") == "not_affected")
    vex_assessed  = fixed + not_affected + sum(1 for v in vulns if v.get("status") == "affected")
    patch_rate    = int(fixed / total * 100) if total else 0
    kev_open      = [v for v in vulns if v.get("is_kev") and v.get("status") not in ("fixed", "not_affected")]

    reqs = []

    # Art. 21.2(b) — Incident handling
    open_incidents   = sum(1 for i in cra_incidents if i.get("status") not in ("closed",))
    closed_incidents = sum(1 for i in cra_incidents if i.get("status") == "closed")
    if not cra_incidents:
        status, evidence = "partial", (
            "No CRA incidents recorded. Incident handling capability cannot be confirmed from SBOM data alone. "
            "Recommend establishing an incident response procedure aligned with NIS2 Article 23 reporting timelines "
            "(T+24h Early Warning / T+72h Notification / T+30d Final Report)."
        )
    elif open_incidents == 0:
        status, evidence = "satisfied", (
            f"All {closed_incidents} recorded incidents are closed. "
            "Incident lifecycle management is in place (CRA T+24h/72h/14d workflow)."
        )
    else:
        status, evidence = "partial", (
            f"{open_incidents} incident(s) currently open / in progress. "
            f"{closed_incidents} closed. Incident tracking is active; ensure NIS2 Art. 23 reporting timelines are met."
        )
    reqs.append({
        "id": "Art. 21.2(b)", "article": "21.2(b)",
        "title": "Incident Handling",
        "description": "Entities shall have policies and procedures for handling security incidents, including detection, response, and recovery.",
        "status": status, "evidence": evidence,
    })

    # Art. 21.2(d) — Supply chain security
    with_purl    = sum(1 for c in components if c.get("purl"))
    with_license = sum(1 for c in components if c.get("license"))
    purl_rate    = int(with_purl / len(components) * 100) if components else 0
    lic_rate     = int(with_license / len(components) * 100) if components else 0
    if not components:
        status, evidence = "not_applicable", "No SBOM data available for supply chain assessment."
    elif purl_rate >= 80 and lic_rate >= 70:
        status, evidence = "satisfied", (
            f"SBOM covers {len(components)} components with {purl_rate}% PURL identification "
            f"and {lic_rate}% license coverage. Supply chain traceability is strong."
        )
    elif purl_rate >= 50:
        status, evidence = "partial", (
            f"{purl_rate}% of {len(components)} components have unique identifiers (PURL). "
            f"{lic_rate}% have license data. Improve PURL coverage to enhance supply chain visibility."
        )
    else:
        status, evidence = "not_satisfied", (
            f"Only {purl_rate}% of {len(components)} components have PURL identifiers. "
            "Low SBOM completeness undermines supply chain security (NIS2 Art. 21.2(d))."
        )
    reqs.append({
        "id": "Art. 21.2(d)", "article": "21.2(d)",
        "title": "Supply Chain Security",
        "description": "Entities shall address security in supply chain, including software component provenance and integrity.",
        "status": status, "evidence": evidence,
    })

    # Art. 21.2(e) — Vulnerability management (network/IS acquisition & maintenance)
    if total == 0:
        status, evidence = "not_applicable", f"No vulnerabilities detected across {len(components)} components."
    elif not critical_open and not high_open and not kev_open:
        status, evidence = "satisfied", (
            f"No unresolved Critical/High CVEs or KEV entries. "
            f"Patch rate: {patch_rate}%. VEX assessed: {vex_assessed}/{total} vulnerabilities."
        )
    elif patch_rate >= 70 and not kev_open:
        status, evidence = "partial", (
            f"Patch rate {patch_rate}%. {len(critical_open)} Critical and {len(high_open)} High CVEs unresolved. "
            "No actively exploited (KEV) vulnerabilities. Remediation in progress."
        )
    else:
        kev_str = f" Includes {len(kev_open)} actively exploited (CISA KEV) CVE(s)." if kev_open else ""
        status, evidence = "not_satisfied", (
            f"Low patch rate ({patch_rate}%). {len(critical_open)} Critical, {len(high_open)} High unresolved.{kev_str} "
            "Immediate vulnerability remediation required."
        )
    reqs.append({
        "id": "Art. 21.2(e)", "article": "21.2(e)",
        "title": "Vulnerability & Patch Management",
        "description": "Entities shall implement processes for acquiring, developing and maintaining network and IS, including vulnerability handling and disclosure.",
        "status": status, "evidence": evidence,
    })

    # Art. 21.2(h) — Cryptography (crypto-weakness CVEs)
    crypto_cwes = ("CWE-326", "CWE-327", "CWE-310", "CWE-311", "CWE-330", "CWE-338", "CWE-916")
    crypto_vulns = [v for v in vulns if any(c in (v.get("cwe") or "") for c in crypto_cwes)]
    open_crypto  = [v for v in crypto_vulns if v.get("status") not in ("fixed", "not_affected")]
    if not crypto_vulns:
        status, evidence = "satisfied", (
            f"No cryptographic weakness CVEs (CWE-326/327/310/311/330/338/916) detected "
            f"across {len(components)} components. Cryptographic implementations appear adequate."
        )
    elif not open_crypto:
        status, evidence = "satisfied", (
            f"{len(crypto_vulns)} cryptographic CVE(s) identified and all resolved."
        )
    elif len(open_crypto) <= 2:
        status, evidence = "partial", (
            f"{len(open_crypto)} unresolved cryptographic weakness CVE(s): "
            + ", ".join(v.get("cve_id", "") for v in open_crypto[:3]) + "."
        )
    else:
        status, evidence = "not_satisfied", (
            f"{len(open_crypto)} unresolved cryptographic weakness CVEs detected. "
            "Review encryption policies and upgrade affected components."
        )
    reqs.append({
        "id": "Art. 21.2(h)", "article": "21.2(h)",
        "title": "Cryptography Policies",
        "description": "Entities shall implement policies on cryptography and, where appropriate, encryption.",
        "status": status, "evidence": evidence,
    })

    # Art. 21.2(i) — Asset management / SBOM completeness
    ntia_score = 0
    ntia_max   = 4
    if components:        ntia_score += 1
    if with_purl > 0:     ntia_score += 1
    if with_license > 0:  ntia_score += 1
    if purl_rate >= 80:   ntia_score += 1
    ntia_pct = int(ntia_score / ntia_max * 100)
    if ntia_pct >= 75:
        status, evidence = "satisfied", (
            f"SBOM asset inventory covers {len(components)} components ({purl_rate}% with unique identifiers). "
            "NTIA minimum elements satisfied. Asset visibility supports NIS2 Art. 21.2(i)."
        )
    elif components:
        status, evidence = "partial", (
            f"SBOM present with {len(components)} components, but completeness is {ntia_pct}% of NTIA minimum elements. "
            "Improve PURL and license coverage."
        )
    else:
        status, evidence = "not_satisfied", "No SBOM data — asset inventory is missing."
    reqs.append({
        "id": "Art. 21.2(i)", "article": "21.2(i)",
        "title": "Asset Management & Access Control",
        "description": "Entities shall maintain an inventory of ICT assets; SBOM provides software asset visibility.",
        "status": status, "evidence": evidence,
    })

    return reqs


class NIS2Report(CjkPDF):
    def __init__(self, org: str, product: str, version: str):
        super().__init__()
        self.org, self.product, self.version = org, product, version
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.sfb(9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 7, f"NIS2 Directive Article 21 Assessment  |  {self.t(self.product)} {self.t(self.version)}", align="L")
        self.ln(1)
        self.set_draw_color(200, 200, 200)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.sf("", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8,
            f"Page {self.page_no()}  |  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  NIS2 Directive (EU) 2022/2555",
            align="C")


def _section_title(pdf, title):
    pdf.sfb(12)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(241, 245, 249)
    pdf.cell(0, 8, pdf.t(f"  {title}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _table_header(pdf, cols, widths):
    pdf.sfb(9)
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    for col, w in zip(cols, widths):
        pdf.cell(w, 7, f" {col}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)


def _req_row(pdf, art_id, title, status_label, color):
    pdf.sfb(8)
    pdf.set_text_color(30, 30, 30)
    pdf.set_fill_color(250, 250, 252)
    pdf.cell(30, 6, f" {art_id}", fill=True)
    pdf.sf("", 8)
    pdf.cell(120, 6, pdf.t(f" {title}"), fill=True)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.sfb(8)
    pdf.cell(30, 6, f" {status_label}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)


def generate(org_name: str, product_name: str, version: str,
             components: list[dict], vulns: list[dict],
             cra_incidents: list[dict] | None = None) -> bytes:
    reqs = assess(components, vulns, cra_incidents)

    score_map = {"satisfied": 1.0, "partial": 0.5, "not_satisfied": 0.0, "not_applicable": None}
    scored = [(r, score_map[r["status"]]) for r in reqs if score_map[r["status"]] is not None]
    pct = int(sum(s for _, s in scored) / len(scored) * 100) if scored else 0
    sat = sum(1 for r in reqs if r["status"] == "satisfied")
    par = sum(1 for r in reqs if r["status"] == "partial")
    ns  = sum(1 for r in reqs if r["status"] == "not_satisfied")

    # Compliance level estimate
    level = "Level 1" if pct >= 40 else "Below Level 1"
    if pct >= 75: level = "Level 2"
    if pct >= 90: level = "Level 3"

    pdf = NIS2Report(org_name, product_name, version)
    pdf.add_page()

    # Title
    pdf.sfb(18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "NIS2 Directive Article 21 Assessment", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.sf("", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 6, pdf.t(f"Organization: {org_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, pdf.t(f"Product: {product_name}  |  Version: {version}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Assessment Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, "Directive: NIS2 (EU) 2022/2555  |  SBOM-based assessment of Art. 21 controls", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Score
    _section_title(pdf, "Compliance Posture")
    score_color = (22, 163, 74) if pct >= 75 else (202, 138, 4) if pct >= 50 else (220, 38, 38)
    pdf.sfb(32)
    pdf.set_text_color(*score_color)
    pdf.cell(40, 14, f"{pct}%", new_x=XPos.RIGHT, new_y=YPos.LAST)
    pdf.sf("", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 14, pdf.t(f"  {level}  ({sat} Satisfied / {par} Partial / {ns} Not Satisfied)"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    bar_w = 160
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(bar_w, 5, "", fill=True, new_x=XPos.LEFT, new_y=YPos.LAST)
    pdf.set_fill_color(*score_color)
    pdf.cell(int(bar_w * pct / 100), 5, "", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Note
    pdf.sf("", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.set_fill_color(255, 251, 235)
    pdf.multi_cell(0, 5,
        "Note: This SBOM-based assessment covers NIS2 Article 21 controls that can be evaluated from "
        "software component data. Controls requiring organizational or infrastructure evidence "
        "(Art. 21.2(a)(c)(f)(g)(j)) are outside SBOM scope and require separate assessment.",
        fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Summary table
    _section_title(pdf, "Article 21 Controls Summary")
    _table_header(pdf, ["Article", "Control", "Status"], [30, 120, 30])
    for r in reqs:
        _req_row(pdf, r["id"], r["title"], STATUS_LABEL[r["status"]], STATUS_COLOR[r["status"]])
    pdf.ln(6)

    # Detailed findings
    _section_title(pdf, "Detailed Findings")
    for r in reqs:
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_fill_color(241, 245, 249)
        pdf.sfb(10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, pdf.t(f"  {r['id']} — {r['title']}"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.sf("", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(22, 6, "Status:", new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.set_fill_color(*STATUS_COLOR[r["status"]])
        pdf.set_text_color(255, 255, 255)
        pdf.sfb(9)
        pdf.cell(28, 6, f" {STATUS_LABEL[r['status']]}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.sfi(9)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(0, 5, pdf.t(f"Requirement: {r['description']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.sf("", 9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5, pdf.t(f"Evidence: {r['evidence']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    out = BytesIO()
    pdf.output(out)
    return out.getvalue()
