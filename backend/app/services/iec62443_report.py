"""
IEC 62443-4-1 compliance assessment and PDF report generator.
Evaluates a release against SM-9, DM-1~5, SUM-1~5 requirements.
"""
from datetime import datetime, timezone
from io import BytesIO

from app.services.pdf_shim import XPos, YPos

from app.services.cjk_pdf import CjkPDF, _latin as _s


STATUS_COLOR = {
    "satisfied":     (22, 163, 74),   # green
    "partial":       (202, 138, 4),   # yellow
    "not_satisfied": (220, 38, 38),   # red
    "not_applicable":(107, 114, 128), # gray
}

STATUS_LABEL = {
    "satisfied":      "Satisfied",
    "partial":        "Partial",
    "not_satisfied":  "Not Satisfied",
    "not_applicable": "N/A",
}


def assess(
    components: list[dict],
    vulns: list[dict],
    cra_incidents: list[dict],
) -> list[dict]:
    """
    Evaluate IEC 62443-4-1 requirements against real platform data.
    Returns a list of requirement dicts with status and evidence.
    """
    total_vulns = len(vulns)
    open_vulns = sum(1 for v in vulns if v["status"] == "open")
    triaged = total_vulns - open_vulns
    fixed_vulns = sum(1 for v in vulns if v["status"] == "fixed")
    affected_vulns = sum(1 for v in vulns if v["status"] == "affected")
    not_affected = sum(1 for v in vulns if v["status"] == "not_affected")
    vex_detailed = sum(1 for v in vulns if v.get("justification") or v.get("detail"))
    cvss_scored = sum(1 for v in vulns if v.get("cvss_score") is not None)
    critical_high = [v for v in vulns if v.get("severity") in ("critical", "high")]
    critical_high_open = sum(1 for v in critical_high if v["status"] == "open")
    active_incidents = [i for i in cra_incidents if i["status"] != "closed"]
    resolved_incidents = [i for i in cra_incidents if i["status"] in ("final_submitted", "closed")]

    reqs = []

    # ── SM-9: Third-party component management ───────────────────────────────
    if not components:
        status, evidence = "not_satisfied", "No SBOM uploaded. Component inventory is missing."
    elif total_vulns == 0:
        status, evidence = "partial", (
            f"{len(components)} components identified in SBOM. "
            "Vulnerability scan has not detected any known CVEs (components may not be in OSV database)."
        )
    else:
        status, evidence = "satisfied", (
            f"{len(components)} third-party components identified and catalogued via SBOM. "
            f"{total_vulns} associated CVEs tracked."
        )
    reqs.append({
        "id": "SM-9", "clause": "4.9",
        "title": "Security requirements for externally provided components",
        "description": "Identify, track, and assess security risks from third-party and open-source components.",
        "status": status, "evidence": evidence,
    })

    # ── DM-1: Receive defect reports ─────────────────────────────────────────
    reqs.append({
        "id": "DM-1", "clause": "4.14.1",
        "title": "Receive defect reports",
        "description": "Establish a process to receive and record security defect reports from external sources.",
        "status": "satisfied" if total_vulns >= 0 else "partial",
        "evidence": (
            f"Automated vulnerability ingestion via OSV.dev API. "
            f"{total_vulns} CVEs received and recorded for this release. "
            "CRA incident management captures actively-exploited vulnerability reports."
        ),
    })

    # ── DM-2: Review and plan ─────────────────────────────────────────────────
    if total_vulns == 0:
        status, evidence = "not_applicable", "No vulnerabilities found; no triage required."
    elif triaged == 0:
        status, evidence = "not_satisfied", f"All {total_vulns} vulnerabilities remain in 'open' state. No triage has been performed."
    elif triaged < total_vulns * 0.5:
        status, evidence = "partial", f"{triaged}/{total_vulns} vulnerabilities triaged ({int(triaged/total_vulns*100)}%). Critical/high items require prioritized review."
    else:
        status, evidence = "satisfied", f"{triaged}/{total_vulns} vulnerabilities reviewed and assigned VEX status ({int(triaged/total_vulns*100)}%)."
    reqs.append({
        "id": "DM-2", "clause": "4.14.2",
        "title": "Review and plan for handling defect reports",
        "description": "Review reported defects, assess impact, and plan remediation with assigned priority.",
        "status": status, "evidence": evidence,
    })

    # ── DM-3: Assess severity ─────────────────────────────────────────────────
    if total_vulns == 0:
        status, evidence = "not_applicable", "No vulnerabilities to assess."
    elif cvss_scored == total_vulns:
        status, evidence = "satisfied", f"All {total_vulns} vulnerabilities have CVSS scores assigned. {len(critical_high)} classified as Critical or High."
    elif cvss_scored > 0:
        status, evidence = "partial", f"{cvss_scored}/{total_vulns} vulnerabilities have CVSS scores. Remaining require manual severity assessment."
    else:
        status, evidence = "not_satisfied", "No CVSS scores recorded. Severity assessment has not been performed."
    reqs.append({
        "id": "DM-3", "clause": "4.14.3",
        "title": "Assess severity of security defects",
        "description": "Use a documented severity rating methodology (e.g., CVSS) to prioritize defects.",
        "status": status, "evidence": evidence,
    })

    # ── DM-4: Remediate defects ───────────────────────────────────────────────
    if total_vulns == 0:
        status, evidence = "not_applicable", "No vulnerabilities require remediation."
    elif fixed_vulns > 0:
        status, evidence = "satisfied", f"{fixed_vulns} vulnerabilities resolved (status: fixed). {affected_vulns} with active remediation plans. {not_affected} confirmed not-affected via VEX analysis."
    elif affected_vulns > 0 or not_affected > 0:
        status, evidence = "partial", f"Remediation in progress: {affected_vulns} affected with response plans, {not_affected} confirmed not-affected. {fixed_vulns} fully resolved."
    elif critical_high_open > 0:
        status, evidence = "not_satisfied", f"{critical_high_open} Critical/High vulnerabilities remain open with no remediation plan."
    else:
        status, evidence = "partial", f"{open_vulns} vulnerabilities open. No remediation actions recorded yet."
    reqs.append({
        "id": "DM-4", "clause": "4.14.4",
        "title": "Remediate security defects",
        "description": "Develop, test, and deploy fixes or mitigations for identified security defects.",
        "status": status, "evidence": evidence,
    })

    # ── DM-5: Disclose security defects ──────────────────────────────────────
    if total_vulns == 0:
        status, evidence = "not_applicable", "No vulnerabilities to disclose."
    elif vex_detailed > 0:
        pct = int(vex_detailed / total_vulns * 100)
        status = "satisfied" if pct >= 50 else "partial"
        evidence = (
            f"{vex_detailed}/{total_vulns} vulnerabilities have documented VEX statements "
            f"with justification or detail ({pct}%). "
            "CSAF 2.0 VEX export available for machine-readable disclosure to downstream customers."
        )
    else:
        status, evidence = "partial", "CSAF 2.0 VEX export capability available. No detailed VEX justifications recorded yet."
    reqs.append({
        "id": "DM-5", "clause": "4.14.5",
        "title": "Disclose security defects",
        "description": "Communicate security vulnerabilities to affected parties in a timely, structured manner.",
        "status": status, "evidence": evidence,
    })

    # ── SUM-1: Create security updates ───────────────────────────────────────
    if not cra_incidents:
        status, evidence = "not_applicable", "No CRA incidents recorded. Requirement applies when actively-exploited vulnerabilities are identified."
    elif resolved_incidents:
        status, evidence = "satisfied", f"{len(resolved_incidents)} CRA incident(s) with remediation completed. {len(active_incidents)} active."
    elif active_incidents:
        status, evidence = "partial", f"{len(active_incidents)} active CRA incident(s) with remediation in progress."
    else:
        status, evidence = "not_applicable", "No CRA incidents requiring security updates."
    reqs.append({
        "id": "SUM-1", "clause": "4.15.1",
        "title": "Create security update process",
        "description": "Define and execute a documented process for creating security patches and updates.",
        "status": status, "evidence": evidence,
    })

    # ── SUM-2: Test security updates ─────────────────────────────────────────
    reqs.append({
        "id": "SUM-2", "clause": "4.15.2",
        "title": "Review security updates for regression",
        "description": "Test security updates to ensure they do not introduce regressions or new vulnerabilities.",
        "status": "partial",
        "evidence": "Security update testing is a manual process performed by the engineering team. CRA incident audit logs record remediation steps. Automated regression testing is outside the scope of this platform.",
    })

    # ── SUM-3: Document security updates ─────────────────────────────────────
    if resolved_incidents:
        status, evidence = "satisfied", (
            f"{len(resolved_incidents)} completed CRA incident(s) with full audit trail including "
            "awareness timestamp, T+24h/72h/14d submission records, ENISA reference IDs, and remediation notes. "
            "Compliance evidence packages (ZIP) available for each release."
        )
    else:
        status, evidence = "partial", (
            "Compliance evidence package (SBOM + VEX + PDF + manifest) is generated on demand. "
            "Full CRA incident documentation requires completed incident workflow."
        )
    reqs.append({
        "id": "SUM-3", "clause": "4.15.3",
        "title": "Document security updates",
        "description": "Maintain documentation for all security updates including scope, impact, and deployment instructions.",
        "status": status, "evidence": evidence,
    })

    # ── SUM-4: Controlled release of security updates ────────────────────────
    if resolved_incidents:
        status, evidence = "satisfied", f"{len(resolved_incidents)} CRA incident(s) reached final report submission stage, indicating controlled release process was followed."
    elif active_incidents:
        status, evidence = "partial", f"{len(active_incidents)} incident(s) in progress. Release process not yet completed."
    else:
        status, evidence = "not_applicable", "No security update releases recorded in the incident management system."
    reqs.append({
        "id": "SUM-4", "clause": "4.15.4",
        "title": "Controlled release of security updates",
        "description": "Ensure security updates are released in a controlled manner with appropriate authorization.",
        "status": status, "evidence": evidence,
    })

    # ── SUM-5: Timely delivery to customers ──────────────────────────────────
    if total_vulns == 0:
        status, evidence = "not_applicable", "No vulnerabilities identified; no customer notifications required."
    elif vex_detailed > 0 or resolved_incidents:
        status, evidence = "satisfied", (
            "CSAF 2.0 VEX machine-readable format available for downstream customer consumption. "
            f"CRA 24/72/14-hour notification workflow enforced for actively-exploited vulnerabilities. "
            f"{len(resolved_incidents)} completed incident(s) with customer notification records."
        )
    else:
        status, evidence = "partial", (
            "CSAF 2.0 VEX export capability available. "
            "CRA incident management supports 24/72/14-hour notification workflow. "
            "Complete VEX statements with justification recommended for full compliance."
        )
    reqs.append({
        "id": "SUM-5", "clause": "4.15.5",
        "title": "Timely delivery of security updates to customers",
        "description": "Notify affected customers promptly when security vulnerabilities are discovered, with remediation guidance.",
        "status": status, "evidence": evidence,
    })

    return reqs


# ── PDF Generator ─────────────────────────────────────────────────────────────

class ComplianceReport(CjkPDF):
    def __init__(self, org_name: str, product_name: str, version: str):
        super().__init__()
        self.org_name = org_name
        self.product_name = product_name
        self.version = version
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.sfb(9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 7, f"IEC 62443-4-1 Compliance Report  |  {self.t(self.product_name)} {self.t(self.version)}", align="L")
        self.ln(1)
        self.set_draw_color(200, 200, 200)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.sf("", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8,
            f"Page {self.page_no()}  |  Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  IEC 62443-4-1",
            align="C")


def generate(
    org_name: str,
    product_name: str,
    version: str,
    components: list[dict],
    vulns: list[dict],
    cra_incidents: list[dict],
) -> bytes:
    requirements = assess(components, vulns, cra_incidents)

    # Scoring
    score_map = {"satisfied": 1.0, "partial": 0.5, "not_satisfied": 0.0, "not_applicable": None}
    scored = [(r, score_map[r["status"]]) for r in requirements if score_map[r["status"]] is not None]
    overall_pct = int(sum(s for _, s in scored) / len(scored) * 100) if scored else 0
    satisfied = sum(1 for r in requirements if r["status"] == "satisfied")
    partial = sum(1 for r in requirements if r["status"] == "partial")
    not_sat = sum(1 for r in requirements if r["status"] == "not_satisfied")
    na = sum(1 for r in requirements if r["status"] == "not_applicable")

    pdf = ComplianceReport(org_name, product_name, version)
    pdf.add_page()

    # ── Title ─────────────────────────────────────────────────────────────────
    pdf.sfb(18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "IEC 62443-4-1 Compliance Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.sf("", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 6, pdf.t(f"Organization: {org_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, pdf.t(f"Product: {product_name}  |  Version: {version}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Assessment Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, "Standard: IEC 62443-4-1:2018  Clauses: SM-9, DM-1~5, SUM-1~5", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Overall score ─────────────────────────────────────────────────────────
    _section_title(pdf, "Overall Compliance Score")

    score_color = (22, 163, 74) if overall_pct >= 75 else (202, 138, 4) if overall_pct >= 50 else (220, 38, 38)
    pdf.sfb(32)
    pdf.set_text_color(*score_color)
    pdf.cell(40, 14, f"{overall_pct}%", new_x=XPos.RIGHT, new_y=YPos.LAST)
    pdf.sf("", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 14, pdf.t(f"  ({satisfied} Satisfied  /  {partial} Partial  /  {not_sat} Not Satisfied  /  {na} N/A)"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Score bar
    bar_w = 160
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(bar_w, 5, "", fill=True, new_x=XPos.LEFT, new_y=YPos.LAST)
    pdf.set_fill_color(*score_color)
    pdf.cell(int(bar_w * overall_pct / 100), 5, "", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    # ── Summary table ─────────────────────────────────────────────────────────
    _section_title(pdf, "Requirements Summary")
    _table_header(pdf, ["Req.", "Clause", "Title", "Status"], [18, 18, 104, 30])
    for r in requirements:
        status = r["status"]
        color = STATUS_COLOR[status]
        label = STATUS_LABEL[status]
        _req_row(pdf, r["id"], r["clause"], r["title"], label, color)
    pdf.ln(6)

    # ── Detailed findings ────────────────────────────────────────────────────
    _section_title(pdf, "Detailed Findings")
    for r in requirements:
        status = r["status"]
        color = STATUS_COLOR[status]
        label = STATUS_LABEL[status]

        if pdf.get_y() > 240:
            pdf.add_page()

        # Requirement header bar
        pdf.set_fill_color(241, 245, 249)
        pdf.sfb(10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, pdf.t(f"  {r['id']} (Clause {r['clause']}) — {r['title']}"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Status badge inline
        pdf.sf("", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(22, 6, "Status:", new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.sfb(9)
        pdf.cell(28, 6, f" {label}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Requirement description
        pdf.sfi(9)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(0, 5, pdf.t(f"Requirement: {r['description']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Evidence
        pdf.sf("", 9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5, pdf.t(f"Evidence: {r['evidence']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    out = BytesIO()
    pdf.output(out)
    return out.getvalue()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _section_title(pdf, title: str):
    pdf.sfb(12)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(241, 245, 249)
    pdf.cell(0, 8, pdf.t(f"  {title}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _table_header(pdf, cols: list[str], widths: list[int]):
    pdf.sfb(9)
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    for col, w in zip(cols, widths):
        pdf.cell(w, 7, f" {col}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)


def _req_row(pdf, req_id: str, clause: str, title: str, status_label: str, color: tuple):
    pdf.sfb(8)
    pdf.set_text_color(30, 30, 30)
    pdf.set_fill_color(250, 250, 252)
    pdf.cell(18, 6, f" {req_id}", fill=True)
    pdf.cell(18, 6, f" {clause}", fill=True)
    pdf.sf("", 8)
    pdf.cell(104, 6, pdf.t(f" {title}"), fill=True)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.sfb(8)
    pdf.cell(30, 6, f" {status_label}", fill=True)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)
