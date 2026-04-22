"""
TISAX VDA ISA 6.0 Gap Analysis PDF Report (fpdf2).
Attempts to load a CJK font so Traditional Chinese content renders properly.
Falls back to Latin-1 stripping if no suitable font is found.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from io import BytesIO

from fpdf import FPDF, XPos, YPos

# ── Font detection ────────────────────────────────────────────────────────────
_CJK_CANDIDATES = [
    # Windows
    "C:/Windows/Fonts/NotoSansTC-VF.ttf",
    "C:/Windows/Fonts/mingliu.ttc",
    "C:/Windows/Fonts/msjh.ttc",
    # Linux (installed via dnf/apt)
    "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/wqy-zenhei/wqy-zenhei.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJKtc-Regular.otf",
]
_CJK_FONT_PATH: str | None = next(
    (p for p in _CJK_CANDIDATES if os.path.exists(p)), None
)


def _s(text) -> str:
    """Sanitize text to Latin-1 for Helvetica fallback."""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _t(text: str, use_cjk: bool) -> str:
    return text if use_cjk else _s(text)


# ── Colours ───────────────────────────────────────────────────────────────────
STATUS_RGB = {
    "compliant":  (22,  163, 74),
    "near":       (202, 138, 4),
    "gap":        (220, 38,  38),
    "unassessed": (107, 114, 128),
}
STATUS_LABEL = {
    "compliant":  "達標",
    "near":       "接近",
    "gap":        "缺口",
    "unassessed": "未評",
}
MATURITY_LABEL = {
    0: "0-未執行", 1: "1-臨時", 2: "2-已執行",
    3: "3-可預測", 4: "4-可測量", 5: "5-最佳化",
}


class TISAXReport(FPDF):
    def __init__(self, org_name: str, module_label: str, level: str, use_cjk: bool):
        super().__init__()
        self.org_name    = org_name
        self.module_label = module_label
        self.level       = level
        self.use_cjk     = use_cjk
        self.set_margins(15, 18, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def _font(self, style: str = "", size: int = 10):
        if self.use_cjk:
            # CJK variable fonts don't have separate bold face; use size bump instead
            bump = 1 if style == "B" else 0
            self.set_font("CJK", "", size + bump)
        else:
            self.set_font("Helvetica", style, size)

    def header(self):
        self._font("", 8)
        self.set_text_color(120, 120, 120)
        title = _t(f"TISAX {self.module_label} — {self.level}  |  {self.org_name}", self.use_cjk)
        self.cell(0, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(30, 64, 175)
        self.set_line_width(0.4)
        self.line(15, self.get_y(), self.w - 15, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-14)
        self._font("", 7)
        self.set_text_color(160, 160, 160)
        self.cell(0, 6, _t(f"第 {self.page_no()} 頁", self.use_cjk), align="C")


# ── Public entry point ────────────────────────────────────────────────────────

def generate(
    org_name: str,
    assessment: dict,      # from _assessment_summary()
    chapters: list[dict],  # assessment["chapters"]
    gap_report: dict,      # from get_gap_report()
) -> bytes:
    use_cjk = _CJK_FONT_PATH is not None
    module_label = assessment.get("module_label", assessment.get("module", ""))
    level        = assessment.get("assessment_level", "AL2")

    pdf = TISAXReport(org_name, module_label, level, use_cjk)

    if use_cjk:
        pdf.add_font("CJK", "", _CJK_FONT_PATH)

    pdf.add_page()

    # ── Title block ──────────────────────────────────────────────────────────
    pdf._font("B", 18)
    pdf.set_text_color(30, 64, 175)
    pdf.cell(0, 10, _t("TISAX 自評報告", use_cjk), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf._font("", 11)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 7, _t(f"組織：{org_name}", use_cjk), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, _t(f"模組：{module_label}　評估等級：{level}", use_cjk), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pdf._font("", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, _t(f"產製日期：{now}", use_cjk), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # ── Summary scorecard ────────────────────────────────────────────────────
    by_status = assessment.get("by_status", {})
    total     = assessment.get("total_controls", 0)
    readiness = gap_report.get("readiness", 0)
    go_nogo   = gap_report.get("go_nogo", "NO-GO")
    threshold = gap_report.get("al_threshold", 0.9)

    _section_title(pdf, _t("整體摘要", use_cjk), use_cjk)

    col_w = (pdf.w - 30) / 4
    cards = [
        ("達標", by_status.get("compliant", 0), STATUS_RGB["compliant"]),
        ("接近", by_status.get("near", 0),      STATUS_RGB["near"]),
        ("缺口", by_status.get("gap", 0),       STATUS_RGB["gap"]),
        ("未評", by_status.get("unassessed", 0), STATUS_RGB["unassessed"]),
    ]
    x0 = pdf.get_x()
    y0 = pdf.get_y()
    for label, val, rgb in cards:
        pdf.set_xy(x0, y0)
        pdf.set_fill_color(*rgb)
        pdf.set_draw_color(*rgb)
        pdf.rect(x0, y0, col_w - 2, 18, style="F")
        pdf._font("B", 14)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(x0, y0 + 1)
        pdf.cell(col_w - 2, 8, str(val), align="C")
        pdf._font("", 7)
        pdf.set_xy(x0, y0 + 9)
        pdf.cell(col_w - 2, 7, _t(label, use_cjk), align="C")
        x0 += col_w
    pdf.set_xy(15, y0 + 20)
    pdf.ln(2)

    # readiness bar
    bar_w = pdf.w - 30
    pdf._font("", 9)
    pdf.set_text_color(50, 50, 50)
    go_label = "GO ✓" if go_nogo == "GO" else "NO-GO ✗"
    pdf.cell(0, 6,
        _t(f"達標率：{readiness*100:.1f}%　（{level} 門檻 {threshold*100:.0f}%）　判定：{go_label}", use_cjk),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_fill_color(229, 231, 235)
    pdf.rect(15, pdf.get_y(), bar_w, 5, style="F")
    fill_rgb = STATUS_RGB["compliant"] if go_nogo == "GO" else STATUS_RGB["gap"]
    pdf.set_fill_color(*fill_rgb)
    pdf.rect(15, pdf.get_y(), bar_w * min(readiness, 1.0), 5, style="F")
    pdf.ln(8)

    # ── Gap table ─────────────────────────────────────────────────────────────
    gaps = gap_report.get("gaps", [])
    if gaps:
        pdf.add_page()
        _section_title(pdf, _t(f"缺口項目（{len(gaps)} 項）— 需優先改善", use_cjk), use_cjk)
        _control_table(pdf, gaps, use_cjk, highlight_rgb=STATUS_RGB["gap"])

    near = gap_report.get("near", [])
    if near:
        if pdf.get_y() > pdf.h - 60:
            pdf.add_page()
        _section_title(pdf, _t(f"接近項目（{len(near)} 項）", use_cjk), use_cjk)
        _control_table(pdf, near, use_cjk, highlight_rgb=STATUS_RGB["near"])

    # ── Full control listing ──────────────────────────────────────────────────
    pdf.add_page()
    _section_title(pdf, _t("完整控制項清單", use_cjk), use_cjk)

    for ch_data in chapters:
        chapter = ch_data.get("chapter", "")
        controls = ch_data.get("controls", [])

        # chapter header
        pdf._font("B", 9)
        pdf.set_fill_color(239, 246, 255)
        pdf.set_text_color(30, 64, 175)
        pdf.cell(0, 7, _t(chapter, use_cjk), fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # control rows
        col_num = 18
        col_name = pdf.w - 30 - col_num - 14 - 14 - 22
        for c in controls:
            if pdf.get_y() > pdf.h - 25:
                pdf.add_page()
            srgb = STATUS_RGB.get(c["status"], STATUS_RGB["unassessed"])
            pdf.set_text_color(*srgb)
            pdf._font("", 7)
            pdf.cell(col_num, 6, c["control_number"])
            pdf.set_text_color(50, 50, 50)
            # truncate name to fit column
            name = _t(c["name"], use_cjk)
            pdf.cell(col_name, 6, name)
            pdf.cell(14, 6, str(c["current_maturity"]), align="C")
            pdf.cell(14, 6, str(c["target_maturity"]),  align="C")
            pdf.set_text_color(*srgb)
            status_txt = _t(STATUS_LABEL.get(c["status"], c["status"]), use_cjk)
            pdf.cell(22, 6, status_txt, align="C",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_draw_color(229, 231, 235)
            pdf.set_line_width(0.1)
            pdf.line(15, pdf.get_y(), pdf.w - 15, pdf.get_y())

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _section_title(pdf: TISAXReport, title: str, use_cjk: bool):
    pdf._font("B", 11)
    pdf.set_text_color(30, 64, 175)
    pdf.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(147, 197, 253)
    pdf.set_line_width(0.3)
    pdf.line(15, pdf.get_y(), pdf.w - 15, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(50, 50, 50)


def _control_table(pdf: TISAXReport, controls: list[dict], use_cjk: bool, highlight_rgb: tuple):
    col_num  = 18
    col_name = pdf.w - 30 - col_num - 14 - 14 - 40
    col_own  = 30

    # header
    pdf._font("B", 8)
    pdf.set_fill_color(248, 250, 252)
    pdf.set_text_color(100, 116, 139)
    for label, w in [
        (_t("編號", use_cjk),    col_num),
        (_t("控制項名稱", use_cjk), col_name),
        (_t("當前", use_cjk),    14),
        (_t("目標", use_cjk),    14),
        (_t("差距", use_cjk),    14),
        (_t("負責人", use_cjk),  col_own),
    ]:
        pdf.cell(w, 6, label, fill=True)
    pdf.ln()

    pdf._font("", 8)
    for c in controls:
        if pdf.get_y() > pdf.h - 20:
            pdf.add_page()
        gap_val = c["target_maturity"] - c["current_maturity"]
        pdf.set_text_color(100, 116, 139)
        pdf.cell(col_num, 6, c["control_number"])
        pdf.set_text_color(50, 50, 50)
        pdf.cell(col_name, 6, _t(c["name"], use_cjk))
        pdf.set_text_color(*highlight_rgb)
        pdf.cell(14, 6, str(c["current_maturity"]), align="C")
        pdf.set_text_color(50, 50, 50)
        pdf.cell(14, 6, str(c["target_maturity"]), align="C")
        pdf.set_text_color(*highlight_rgb)
        pdf.cell(14, 6, f"-{gap_val}" if gap_val > 0 else "0", align="C")
        pdf.set_text_color(50, 50, 50)
        pdf.cell(col_own, 6, _t(c.get("owner") or "—", use_cjk),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(229, 231, 235)
        pdf.set_line_width(0.1)
        pdf.line(15, pdf.get_y(), pdf.w - 15, pdf.get_y())
    pdf.ln(4)
