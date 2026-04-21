"""
IEC 62443-3-3 System Security Requirements assessment and PDF generator.
Evaluates system-level security posture from SBOM and vulnerability data.
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


def assess(components: list[dict], vulns: list[dict], cra_incidents: list[dict]) -> list[dict]:
    total = len(vulns)
    critical_open = sum(1 for v in vulns if v.get("severity") == "critical" and v.get("status") not in ("fixed", "not_affected"))
    high_open     = sum(1 for v in vulns if v.get("severity") == "high"     and v.get("status") not in ("fixed", "not_affected"))
    fixed         = sum(1 for v in vulns if v.get("status") == "fixed")
    not_affected  = sum(1 for v in vulns if v.get("status") == "not_affected")
    patch_rate    = int(fixed / total * 100) if total else 0
    active_inc    = sum(1 for i in cra_incidents if i.get("status") != "closed")
    resolved_inc  = sum(1 for i in cra_incidents if i.get("status") in ("final_submitted", "closed"))

    reqs = []

    # SR 1.1 — Human user identification and authentication
    auth_cves = [v for v in vulns if any(k in (v.get("cwe") or "") for k in ("CWE-287", "CWE-306", "CWE-798", "CWE-284"))]
    unres_auth = sum(1 for v in auth_cves if v.get("status") not in ("fixed", "not_affected"))
    if not auth_cves:
        status, evidence = "satisfied", f"No authentication-related CVEs detected across {len(components)} system components."
    elif unres_auth == 0:
        status, evidence = "satisfied", f"{len(auth_cves)} authentication CVE(s) all resolved via patch or VEX analysis."
    elif unres_auth <= 2:
        status, evidence = "partial", f"{unres_auth} unresolved authentication vulnerability(ies). Priority remediation needed."
    else:
        status, evidence = "not_satisfied", f"{unres_auth} unresolved authentication vulnerabilities. System-wide authentication enforcement at risk."
    reqs.append({"id": "SR 1.1", "clause": "3.1.1", "title": "Human user identification and authentication",
                 "description": "The system shall identify and authenticate all human users.", "status": status, "evidence": evidence})

    # SR 2.1 — Authorization enforcement
    reqs.append({"id": "SR 2.1", "clause": "3.2.1", "title": "Authorization enforcement",
                 "description": "The system shall enforce authorizations for all requests by users, software processes, and devices.",
                 "status": "partial",
                 "evidence": (
                     "System-level authorization enforcement requires architectural review beyond SBOM scope. "
                     f"SBOM analysis covers {len(components)} components. "
                     "Recommend conducting access control matrix review separately."
                 )})

    # SR 3.3 — Security functionality verification
    if total == 0:
        status, evidence = "partial", "No vulnerabilities found. SBOM scan completed but functional security testing is required separately."
    elif patch_rate >= 80:
        status, evidence = "satisfied", (
            f"Systematic vulnerability management in place: {patch_rate}% remediation rate across {total} CVEs. "
            "CSAF 2.0 VEX export supports machine-readable security status verification."
        )
    elif patch_rate >= 40:
        status, evidence = "partial", (
            f"Vulnerability management active ({patch_rate}% remediation). {critical_open} Critical, {high_open} High CVEs unresolved. "
            "Complete functional security testing recommended."
        )
    else:
        status, evidence = "not_satisfied", (
            f"Insufficient remediation ({patch_rate}%). {critical_open} Critical and {high_open} High CVEs unresolved. "
            "Security functionality verification cannot be confirmed."
        )
    reqs.append({"id": "SR 3.3", "clause": "3.3.3", "title": "Security functionality verification",
                 "description": "The system shall provide the ability to verify the intended operation of security functions.",
                 "status": status, "evidence": evidence})

    # SR 3.4 — Software and information integrity
    injection_cves = sum(1 for v in vulns if any(k in (v.get("cwe") or "") for k in ("CWE-20", "CWE-94", "CWE-502", "CWE-74")))
    unres_inj = sum(1 for v in vulns if any(k in (v.get("cwe") or "") for k in ("CWE-20", "CWE-94", "CWE-502", "CWE-74")) and v.get("status") not in ("fixed", "not_affected"))
    if injection_cves == 0:
        status, evidence = "satisfied", "No code injection or deserialization vulnerabilities detected."
    elif unres_inj == 0:
        status, evidence = "satisfied", f"{injection_cves} integrity-related CVE(s) all resolved."
    else:
        status = "partial" if unres_inj <= 3 else "not_satisfied"
        evidence = f"{unres_inj} unresolved integrity/injection vulnerability(ies) affecting system software integrity."
    reqs.append({"id": "SR 3.4", "clause": "3.3.4", "title": "Software and information integrity",
                 "description": "The system shall provide mechanisms to detect unauthorized changes to software and data.",
                 "status": status, "evidence": evidence})

    # SR 6.1 — Audit log accessibility
    reqs.append({"id": "SR 6.1", "clause": "3.6.1", "title": "Audit log accessibility",
                 "description": "The system shall provide the ability to generate audit records for defined events.",
                 "status": "partial",
                 "evidence": (
                     "Platform maintains VEX state change audit logs with timestamps for all vulnerability status changes. "
                     f"CRA incident management provides T+24h/72h/14d audit trail for {len(cra_incidents)} incident(s). "
                     "System-level audit logging requires verification against component specifications."
                 )})

    # SR 7.1 — DoS protection
    dos_cves = [v for v in vulns if any(k in (v.get("cwe") or "") for k in ("CWE-400", "CWE-770", "CWE-404", "CWE-835"))]
    unres_dos = sum(1 for v in dos_cves if v.get("status") not in ("fixed", "not_affected"))
    if not dos_cves:
        status, evidence = "satisfied", "No DoS-related vulnerabilities detected in the system component set."
    elif unres_dos == 0:
        status, evidence = "satisfied", f"{len(dos_cves)} DoS-related CVE(s) all resolved."
    else:
        status = "partial" if unres_dos <= 2 else "not_satisfied"
        evidence = f"{unres_dos} unresolved DoS vulnerability(ies) may impact system availability."
    reqs.append({"id": "SR 7.1", "clause": "3.7.1", "title": "Denial of service protection",
                 "description": "The system shall maintain essential functions under denial of service conditions.",
                 "status": status, "evidence": evidence})

    # SR 7.6 — Network and security configuration settings
    reqs.append({"id": "SR 7.6", "clause": "3.7.6", "title": "Network and security configuration settings",
                 "description": "The system shall provide the ability to be configured in accordance with best security practices.",
                 "status": "not_applicable",
                 "evidence": "Network configuration assessment is beyond SBOM-based analysis scope. Requires separate network security review."})

    # CRA incident management summary
    if not cra_incidents:
        status, evidence = "not_applicable", "No CRA incidents recorded. Requirement applicable when actively-exploited vulnerabilities are confirmed."
    elif resolved_inc > 0:
        status, evidence = "satisfied", (
            f"{resolved_inc} CRA incident(s) completed with full T+24h/72h/14d notification workflow. "
            f"{active_inc} active incident(s) in progress."
        )
    elif active_inc > 0:
        status, evidence = "partial", f"{active_inc} active CRA incident(s) in progress. Notification timeline compliance being tracked."
    else:
        status, evidence = "not_applicable", "No active CRA incidents."
    reqs.append({"id": "CRA", "clause": "EU 2019/1020",
                 "title": "Active exploitation incident response (CRA Art. 14)",
                 "description": "The product supplier shall notify ENISA within 24h of confirming an actively-exploited vulnerability.",
                 "status": status, "evidence": evidence})

    return reqs


class IEC3_3Report(FPDF):
    def __init__(self, org, product, version):
        super().__init__()
        self.org, self.product, self.version = org, product, version
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 7, f"IEC 62443-3-3 System Security Report  |  {_s(self.product)} {_s(self.version)}", align="L")
        self.ln(1)
        self.set_draw_color(200, 200, 200)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8,
            f"Page {self.page_no()}  |  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  IEC 62443-3-3",
            align="C")


def generate(org_name: str, product_name: str, version: str,
             components: list[dict], vulns: list[dict], cra_incidents: list[dict]) -> bytes:
    reqs = assess(components, vulns, cra_incidents)

    score_map = {"satisfied": 1.0, "partial": 0.5, "not_satisfied": 0.0, "not_applicable": None}
    scored = [(r, score_map[r["status"]]) for r in reqs if score_map[r["status"]] is not None]
    pct = int(sum(s for _, s in scored) / len(scored) * 100) if scored else 0
    sat = sum(1 for r in reqs if r["status"] == "satisfied")
    par = sum(1 for r in reqs if r["status"] == "partial")
    ns  = sum(1 for r in reqs if r["status"] == "not_satisfied")

    sl = "SL-1" if pct >= 40 else "SL-0 (Below Minimum)"
    if pct >= 75: sl = "SL-2"
    if pct >= 90: sl = "SL-3"

    pdf = IEC3_3Report(org_name, product_name, version)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "IEC 62443-3-3 System Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 6, _s(f"Organization: {org_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, _s(f"Product: {product_name}  |  Version: {version}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Assessment Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, "Standard: IEC 62443-3-3:2013  |  System Security Requirements (SR) — SBOM-based Assessment",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

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

    _section_title(pdf, "System Requirements Summary")
    _table_header(pdf, ["Req.", "Clause", "Title", "Status"], [22, 22, 96, 30])
    for r in reqs:
        _req_row(pdf, r["id"], r["clause"], r["title"], STATUS_LABEL[r["status"]], STATUS_COLOR[r["status"]])
    pdf.ln(6)

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
    pdf.set_fill_color(250, 250, 252)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(22, 6, f" {req_id}", fill=True)
    pdf.cell(22, 6, f" {clause}", fill=True)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(96, 6, _s(f" {title}"), fill=True)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(30, 6, f" {status_label}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)
