"""
IEC 62443-4-2 Component Security Requirements assessment and PDF generator.
Evaluates software components against key Capability Requirements (CRs).
"""
from datetime import datetime, timezone
from io import BytesIO

from fpdf import FPDF, XPos, YPos


def _s(text) -> str:
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


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


def assess(components: list[dict], vulns: list[dict]) -> list[dict]:
    total = len(vulns)
    critical_open = [v for v in vulns if v.get("severity") == "critical" and v.get("status") not in ("fixed", "not_affected")]
    high_open     = [v for v in vulns if v.get("severity") == "high"     and v.get("status") not in ("fixed", "not_affected")]
    fixed         = sum(1 for v in vulns if v.get("status") == "fixed")
    not_affected  = sum(1 for v in vulns if v.get("status") == "not_affected")
    vex_assessed  = fixed + not_affected + sum(1 for v in vulns if v.get("status") == "affected")
    patch_rate    = int(fixed / total * 100) if total else 0
    clean_comps   = sum(1 for c in components if c.get("vuln_count", 0) == 0 or c.get("highest_severity") is None)

    reqs = []

    # CR 2.1 — Authorization enforcement
    # Infer from presence of auth-related CVEs (CWE-287, CWE-306, CWE-798)
    auth_cves = [v for v in vulns if any(kw in (v.get("cwe") or "") for kw in ("CWE-287", "CWE-306", "CWE-798", "CWE-862", "CWE-863"))]
    unresolved_auth = [v for v in auth_cves if v.get("status") not in ("fixed", "not_affected")]
    if not auth_cves:
        status, evidence = "satisfied", (
            f"No authentication/authorization-related CVEs (CWE-287/306/798/862/863) identified "
            f"among {total} vulnerabilities in {len(components)} components."
        )
    elif not unresolved_auth:
        status, evidence = "satisfied", (
            f"{len(auth_cves)} authorization-related CVE(s) identified and all resolved (fixed or confirmed not-affected)."
        )
    elif len(unresolved_auth) <= 2:
        status, evidence = "partial", (
            f"{len(unresolved_auth)} unresolved authorization-related CVE(s): "
            + ", ".join(v.get("cve_id", "") for v in unresolved_auth[:3]) + ". Remediation required."
        )
    else:
        status, evidence = "not_satisfied", (
            f"{len(unresolved_auth)} unresolved authorization-related CVEs. "
            "Component authorization enforcement is at risk."
        )
    reqs.append({
        "id": "CR 2.1", "clause": "7.2.1",
        "title": "Authorization enforcement",
        "description": "Components shall enforce authorization for all actions taken by users, software processes, and devices.",
        "status": status, "evidence": evidence,
    })

    # CR 3.4 — Software and information integrity
    # Assess based on integrity/injection CVEs (CWE-20, CWE-502, CWE-78, CWE-94)
    integrity_cves = [v for v in vulns if any(kw in (v.get("cwe") or "") for kw in ("CWE-20", "CWE-502", "CWE-78", "CWE-94", "CWE-74"))]
    unresolved_int = [v for v in integrity_cves if v.get("status") not in ("fixed", "not_affected")]
    if not integrity_cves:
        status, evidence = "satisfied", (
            f"No input validation or injection vulnerabilities (CWE-20/74/78/94/502) detected across {len(components)} components."
        )
    elif not unresolved_int:
        status, evidence = "satisfied", (
            f"{len(integrity_cves)} integrity-related CVE(s) resolved. Software integrity posture is acceptable."
        )
    elif critical_open:
        status, evidence = "not_satisfied", (
            f"{len(unresolved_int)} unresolved integrity/injection CVE(s). "
            f"Includes {len([v for v in critical_open if v in integrity_cves])} critical severity items."
        )
    else:
        status, evidence = "partial", (
            f"{len(unresolved_int)} unresolved integrity-related CVE(s) at medium/low severity. "
            "Monitoring recommended."
        )
    reqs.append({
        "id": "CR 3.4", "clause": "7.3.4",
        "title": "Software and information integrity",
        "description": "Components shall provide mechanisms to validate software and configuration integrity.",
        "status": status, "evidence": evidence,
    })

    # CR 3.9 — Protection of audit information (log-related CVEs)
    reqs.append({
        "id": "CR 3.9", "clause": "7.3.9",
        "title": "Protection of audit information",
        "description": "Components shall protect audit logs from unauthorized access, modification, and deletion.",
        "status": "partial",
        "evidence": (
            "SBOM-based assessment cannot directly verify audit log protection mechanisms. "
            f"Platform records VEX state changes with timestamps for {total} vulnerabilities. "
            "Manual review of component audit logging capabilities recommended."
        ),
    })

    # CR 7.1 — Denial of service protection
    dos_cves = [v for v in vulns if any(kw in (v.get("cwe") or "") for kw in ("CWE-400", "CWE-770", "CWE-404", "CWE-835"))]
    unresolved_dos = [v for v in dos_cves if v.get("status") not in ("fixed", "not_affected")]
    if not dos_cves:
        status, evidence = "satisfied", (
            f"No denial-of-service related CVEs (CWE-400/404/770/835) detected."
        )
    elif not unresolved_dos:
        status, evidence = "satisfied", f"{len(dos_cves)} DoS-related CVE(s) all resolved."
    else:
        status, evidence = "partial" if len(unresolved_dos) <= 3 else "not_satisfied", (
            f"{len(unresolved_dos)} unresolved DoS vulnerability(ies): "
            + ", ".join(v.get("cve_id", "") for v in unresolved_dos[:3])
        )
    reqs.append({
        "id": "CR 7.1", "clause": "7.7.1",
        "title": "Denial of service protection",
        "description": "Components shall maintain essential functions during denial of service events.",
        "status": status, "evidence": evidence,
    })

    # CR 7.3 — Control system backup
    reqs.append({
        "id": "CR 7.3", "clause": "7.7.3",
        "title": "Control system backup",
        "description": "Components shall provide mechanisms to back up configuration and state.",
        "status": "not_applicable",
        "evidence": "Backup capability assessment requires functional testing outside SBOM analysis scope.",
    })

    # Overall component vulnerability posture (custom summary)
    if total == 0:
        status, evidence = "not_applicable", f"No vulnerabilities found across {len(components)} components."
    elif len(critical_open) == 0 and len(high_open) == 0:
        status, evidence = "satisfied", (
            f"All {len(components)} components have acceptable vulnerability posture. "
            f"{patch_rate}% patch rate. No unresolved Critical or High severity CVEs."
        )
    elif patch_rate >= 70:
        status, evidence = "partial", (
            f"{patch_rate}% patch rate. {len(critical_open)} unresolved Critical, {len(high_open)} unresolved High CVEs. "
            f"{clean_comps}/{len(components)} components have no active CVEs."
        )
    else:
        status, evidence = "not_satisfied", (
            f"Low patch rate ({patch_rate}%). {len(critical_open)} Critical and {len(high_open)} High CVEs unresolved. "
            f"Immediate remediation required for SL-2+ compliance."
        )
    reqs.append({
        "id": "SL-Vuln", "clause": "—",
        "title": "Component Vulnerability Posture (SL Assessment)",
        "description": "Overall component security level based on known vulnerability status and remediation progress.",
        "status": status, "evidence": evidence,
    })

    return reqs


class IEC4_2Report(FPDF):
    def __init__(self, org: str, product: str, version: str):
        super().__init__()
        self.org, self.product, self.version = org, product, version
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 7, f"IEC 62443-4-2 Component Security Report  |  {_s(self.product)} {_s(self.version)}", align="L")
        self.ln(1)
        self.set_draw_color(200, 200, 200)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8,
            f"Page {self.page_no()}  |  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  IEC 62443-4-2",
            align="C")


def generate(org_name: str, product_name: str, version: str,
             components: list[dict], vulns: list[dict]) -> bytes:
    reqs = assess(components, vulns)

    score_map = {"satisfied": 1.0, "partial": 0.5, "not_satisfied": 0.0, "not_applicable": None}
    scored = [(r, score_map[r["status"]]) for r in reqs if score_map[r["status"]] is not None]
    pct = int(sum(s for _, s in scored) / len(scored) * 100) if scored else 0
    sat = sum(1 for r in reqs if r["status"] == "satisfied")
    par = sum(1 for r in reqs if r["status"] == "partial")
    ns  = sum(1 for r in reqs if r["status"] == "not_satisfied")

    # SL estimate
    sl = "SL-1" if pct >= 40 else "SL-0 (Below Minimum)"
    if pct >= 75: sl = "SL-2"
    if pct >= 90: sl = "SL-3"

    pdf = IEC4_2Report(org_name, product_name, version)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "IEC 62443-4-2 Component Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 6, _s(f"Organization: {org_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, _s(f"Product: {product_name}  |  Version: {version}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Assessment Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, "Standard: IEC 62443-4-2:2019  |  Software Component (SC) Capability Requirements", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Score + SL
    _section_title(pdf, "Security Level Assessment")
    score_color = (22, 163, 74) if pct >= 75 else (202, 138, 4) if pct >= 50 else (220, 38, 38)
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(*score_color)
    pdf.cell(40, 14, f"{pct}%", new_x=XPos.RIGHT, new_y=YPos.LAST)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 14, _s(f"  Estimated {sl}  ({sat} Satisfied / {par} Partial / {ns} Not Satisfied)"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    bar_w = 160
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(bar_w, 5, "", fill=True, new_x=XPos.LEFT, new_y=YPos.LAST)
    pdf.set_fill_color(*score_color)
    pdf.cell(int(bar_w * pct / 100), 5, "", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Component summary
    _section_title(pdf, "Component Inventory Summary")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 6, _s(f"Total Components: {len(components)}   |   Total CVEs: {len(vulns)}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Requirements table
    _section_title(pdf, "Capability Requirements Summary")
    _table_header(pdf, ["Req.", "Clause", "Title", "Status"], [22, 18, 100, 30])
    for r in reqs:
        _req_row(pdf, r["id"], r["clause"], r["title"], STATUS_LABEL[r["status"]], STATUS_COLOR[r["status"]])
    pdf.ln(6)

    # Detailed findings
    _section_title(pdf, "Detailed Findings")
    for r in reqs:
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, _s(f"  {r['id']} (Clause {r['clause']}) — {r['title']}"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(22, 6, "Status:", new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.set_fill_color(*STATUS_COLOR[r["status"]])
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(28, 6, f" {STATUS_LABEL[r['status']]}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(0, 5, _s(f"Requirement: {r['description']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5, _s(f"Evidence: {r['evidence']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    out = BytesIO()
    pdf.output(out)
    return out.getvalue()


def _section_title(pdf, title):
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(241, 245, 249)
    pdf.cell(0, 8, _s(f"  {title}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _table_header(pdf, cols, widths):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    for col, w in zip(cols, widths):
        pdf.cell(w, 7, f" {col}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)


def _req_row(pdf, req_id, clause, title, status_label, color):
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(30, 30, 30)
    pdf.set_fill_color(250, 250, 252)
    pdf.cell(22, 6, f" {req_id}", fill=True)
    pdf.cell(18, 6, f" {clause}", fill=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(100, 6, _s(f" {title}"), fill=True)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(30, 6, f" {status_label}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)
