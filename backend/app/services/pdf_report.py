"""
Generate a PDF vulnerability report for a Release using fpdf2.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from io import BytesIO

from app.services.pdf_shim import FPDF, XPos, YPos


def _s(text) -> str:
    """Sanitize text to Latin-1 safe for Helvetica font."""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


SEVERITY_COLOR = {
    "critical": (220, 38, 38),
    "high":     (234, 88, 12),
    "medium":   (202, 138, 4),
    "low":      (37, 99, 235),
    "info":     (107, 114, 128),
}

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}


class SBOMReport(FPDF):
    def __init__(self, org_name: str, product_name: str, version: str, brand: dict):
        super().__init__()
        self.org_name = org_name
        self.product_name = product_name
        self.version = version
        self.brand = brand
        self.primary_rgb = _hex_to_rgb(brand.get("primary_color") or "#1e3a8a")
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        company = self.brand.get("company_name") or "SBOM Platform"
        self.cell(0, 8, _s(f"{company}  |  {self.product_name} {self.version}"), align="L")
        self.ln(2)
        r, g, b = self.primary_rgb
        self.set_draw_color(r, g, b)
        self.set_line_width(0.5)
        self.line(15, self.get_y(), 195, self.get_y())
        self.set_draw_color(0, 0, 0)
        self.set_line_width(0.2)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150, 150, 150)
        footer_text = self.brand.get("report_footer") or ""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        right = f"Page {self.page_no()}  |  {ts}"
        if footer_text:
            self.cell(0, 4, _s(footer_text), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 4, right, align="R")


def _severity_counts(vulns: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        s = v.get("severity") or "info"
        counts[s] = counts.get(s, 0) + 1
    return counts


def generate(
    org_name: str,
    product_name: str,
    version: str,
    components: list[dict],
    vulns: list[dict],
    brand: dict | None = None,
) -> bytes:
    if brand is None:
        brand = {}

    pdf = SBOMReport(org_name, product_name, version, brand)
    primary_rgb = pdf.primary_rgb
    pdf.add_page()

    # ── Logo + Title block ────────────────────────────────────────
    logo_path = brand.get("logo_path")
    if logo_path and os.path.exists(logo_path):
        try:
            pdf.image(logo_path, x=15, y=pdf.get_y(), h=18)
            pdf.ln(22)
        except Exception:
            pass  # logo load failed — continue without it

    company = brand.get("company_name") or ""
    tagline = brand.get("tagline") or ""

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*primary_rgb)
    title_text = _s(company) if company else "SBOM Vulnerability Report"
    pdf.cell(0, 10, title_text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if tagline:
        pdf.set_font("Helvetica", "I", 11)
        pdf.set_text_color(100, 100, 120)
        pdf.cell(0, 6, _s(tagline), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    if company:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, "SBOM Vulnerability Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 7, _s(f"Organization: {org_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, _s(f"Product: {product_name}  |  Version: {version}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, f"Report Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # ── Summary ──────────────────────────────────────────────────
    _section_title(pdf, "Executive Summary", primary_rgb)
    counts = _severity_counts(vulns)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 7, _s(f"Total components scanned: {len(components)}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, _s(f"Total vulnerabilities found: {len(vulns)}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts[sev]
        if count == 0:
            continue
        r, g, b = SEVERITY_COLOR[sev]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        label = f"{SEVERITY_LABEL[sev]}: {count}"
        pdf.cell(len(label) * 4 + 4, 8, label, fill=True, new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.cell(3, 8, "", new_x=XPos.RIGHT, new_y=YPos.LAST)
    pdf.ln(12)

    # ── Components table ─────────────────────────────────────────
    _section_title(pdf, "Component Inventory", primary_rgb)
    _table_header(pdf, ["Component", "Version", "License", "Vulns", "Highest Risk"],
                       [65, 30, 45, 20, 30], primary_rgb)

    for c in components:
        sev = c.get("highest_severity")
        sev_label = SEVERITY_LABEL.get(sev, "—") if sev else "—"
        sev_color = SEVERITY_COLOR.get(sev, (107, 114, 128)) if sev else (180, 180, 180)
        _table_row(pdf,
            [c["name"], c.get("version") or "—", c.get("license") or "—",
             str(c.get("vuln_count") or 0), sev_label],
            [65, 30, 45, 20, 30],
            highlight_last=sev_color if sev else None)

    pdf.ln(6)

    # ── Vulnerability detail table ────────────────────────────────
    _section_title(pdf, "Vulnerability Details", primary_rgb)
    _table_header(pdf, ["CVE / ID", "Component", "CVSS", "Severity", "Status"],
                       [55, 45, 18, 25, 27], primary_rgb)

    for v in vulns:
        sev = v.get("severity") or "info"
        sev_color = SEVERITY_COLOR.get(sev, (107, 114, 128))
        comp_str = f"{v['component_name']} {v.get('component_version','')}"
        _table_row(pdf,
            [v["cve_id"], comp_str,
             str(v["cvss_score"]) if v["cvss_score"] is not None else "—",
             SEVERITY_LABEL.get(sev, sev.upper()),
             v.get("status", "open").replace("_", " ")],
            [55, 45, 18, 25, 27],
            highlight_col=3, highlight_color=sev_color)

    out = BytesIO()
    pdf.output(out)
    return out.getvalue()


# ── Helpers ───────────────────────────────────────────────────────

def _section_title(pdf: FPDF, title: str, primary_rgb: tuple = (30, 41, 59)):
    r, g, b = primary_rgb
    # lighten: blend with white at 90%
    lr = int(r * 0.15 + 255 * 0.85)
    lg = int(g * 0.15 + 255 * 0.85)
    lb = int(b * 0.15 + 255 * 0.85)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(r, g, b)
    pdf.set_fill_color(lr, lg, lb)
    pdf.cell(0, 9, _s(f"  {title}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _table_header(pdf: FPDF, cols: list[str], widths: list[int], primary_rgb: tuple = (30, 41, 59)):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*primary_rgb)
    pdf.set_text_color(255, 255, 255)
    for col, w in zip(cols, widths):
        pdf.cell(w, 7, _s(f" {col}"), fill=True, border=0)
    pdf.ln()
    pdf.set_text_color(30, 30, 30)


def _table_row(
    pdf: FPDF,
    cells: list[str],
    widths: list[int],
    highlight_last: tuple | None = None,
    highlight_col: int | None = None,
    highlight_color: tuple | None = None,
):
    pdf.set_font("Helvetica", "", 8)
    fill_color = (248, 250, 252) if pdf.page % 2 == 0 else (255, 255, 255)

    if pdf.get_y() > 260:
        pdf.add_page()
        return

    for i, (cell, w) in enumerate(zip(cells, widths)):
        text = _s(str(cell))[:30]
        if highlight_col is not None and i == highlight_col and highlight_color:
            pdf.set_fill_color(*highlight_color)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(w, 6, f" {text}", fill=True)
            pdf.set_fill_color(*fill_color)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 8)
        elif i == len(cells) - 1 and highlight_last:
            pdf.set_fill_color(*highlight_last)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(w, 6, f" {text}", fill=True)
            pdf.set_fill_color(*fill_color)
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 8)
        else:
            pdf.set_fill_color(*fill_color)
            pdf.cell(w, 6, f" {text}", fill=True)
    pdf.ln()
