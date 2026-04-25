"""
fpdf2-compatible API on top of reportlab (BSD-3-Clause).

This shim replaces fpdf2 (LGPL-3.0) with the BSD-3-Clause `reportlab`
without rewriting every existing report generator.  It implements only
the subset of fpdf2's API actually used by SBOM Platform's PDF
generators — see the audit comment at the top of each method.

Coordinate system: fpdf2 has Y growing DOWN from the top-left;
reportlab Canvas has Y growing UP from the bottom-left.  This shim
keeps the fpdf2 mental model (Y down, top-origin) and translates at
draw time.

Public API mirrored from fpdf2:
    FPDF()      with set_margins, set_auto_page_break, set_font,
                set_text_color, set_fill_color, set_draw_color,
                set_line_width, add_page, cell, multi_cell, line,
                image, ln, get_y, set_y, page_no, output, page,
                add_font, header(), footer()
    XPos        enum: LMARGIN, RIGHT, LEFT
    YPos        enum: NEXT, LAST, TOP

Not implemented (we don't use them): set_x, get_x, set_xy, link,
underline, get_string_width-with-cell-style behavior nuances, advanced
table flow.  If a future report needs one of those, prefer rewriting
that report in reportlab Platypus rather than extending the shim.
"""
from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas


# ── XPos / YPos enums (fpdf2 compatibility) ──────────────────────────────────
class XPos:
    LMARGIN = "LMARGIN"
    RIGHT = "RIGHT"
    LEFT = "LEFT"


class YPos:
    NEXT = "NEXT"
    LAST = "LAST"
    TOP = "TOP"


# ── Font registry (process-global; reportlab needs a unique name per font) ──
_REGISTERED_FONTS: dict[str, str] = {}   # logical_name → registered_name


def _font_key(family: str, style: str) -> str:
    """Map (family, style) → reportlab font name."""
    style = (style or "").upper()
    return f"{family}-{style}" if style else family


def _ensure_builtin(family: str, style: str) -> str:
    """Map fpdf2 built-in names to reportlab built-ins."""
    style = (style or "").upper()
    fam = family.lower()
    if fam in ("helvetica", "arial"):
        if "B" in style and "I" in style:
            return "Helvetica-BoldOblique"
        if "B" in style:
            return "Helvetica-Bold"
        if "I" in style:
            return "Helvetica-Oblique"
        return "Helvetica"
    if fam == "courier":
        if "B" in style:
            return "Courier-Bold"
        return "Courier"
    if fam == "times":
        if "B" in style and "I" in style:
            return "Times-BoldItalic"
        if "B" in style:
            return "Times-Bold"
        if "I" in style:
            return "Times-Italic"
        return "Times-Roman"
    # Fall back: assume custom font registered via add_font
    key = _font_key(family, style)
    return _REGISTERED_FONTS.get(key, "Helvetica")


class FPDF:
    """fpdf2-compatible facade.  Subclass this to override header()/footer().

    Usage mirrors fpdf2:
        pdf = FPDF()
        pdf.set_margins(15, 15, 15)
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Title")
        pdf.output(buffer)
    """

    DEFAULT_MARGIN = 10.0    # mm — fpdf2 default
    LINE_HEIGHT_RATIO = 1.25 # internal: text leading vs font size

    def __init__(self, orientation: str = "P", unit: str = "mm", format: str = "A4"):
        # Page geometry (mm).  We only support A4 portrait — that's what every
        # existing report uses.  If we ever add landscape we'll branch here.
        if format != "A4" or orientation != "P":
            raise NotImplementedError(f"shim only supports A4 portrait (got {format}/{orientation})")
        self.w = 210.0   # A4 width mm
        self.h = 297.0   # A4 height mm

        # Margins (mm)
        self.l_margin = self.DEFAULT_MARGIN
        self.t_margin = self.DEFAULT_MARGIN
        self.r_margin = self.DEFAULT_MARGIN
        self.b_margin = self.DEFAULT_MARGIN

        # Auto page break
        self._auto_page_break = True
        self._page_break_margin = 20.0
        # Internal flag — set True while footer() / header() runs so they
        # can draw cells near the page edge without retriggering a page break
        # (matches fpdf2's behavior).
        self._in_header_footer = False

        # Cursor (in fpdf2 coords: top-left origin, Y down, mm)
        self.x = self.l_margin
        self.y = self.t_margin

        # Drawing state
        self._font_family = "Helvetica"
        self._font_style = ""
        self._font_size = 12.0
        self._fill = (1.0, 1.0, 1.0)
        self._text = (0.0, 0.0, 0.0)
        self._draw = (0.0, 0.0, 0.0)
        self._line_width = 0.2 / mm   # fpdf2 default ~ 0.2mm

        # Page tracking
        self.page = 0
        self._buffer = BytesIO()
        self._canvas: rl_canvas.Canvas | None = None
        self._page_started = False

    # ── Margin / auto-break ────────────────────────────────────────────────
    def set_margins(self, left: float, top: float, right: float | None = None) -> None:
        self.l_margin = float(left)
        self.t_margin = float(top)
        if right is not None:
            self.r_margin = float(right)
        if self.x < self.l_margin:
            self.x = self.l_margin
        if self.y < self.t_margin:
            self.y = self.t_margin

    def set_auto_page_break(self, auto: bool, margin: float = 0) -> None:
        self._auto_page_break = bool(auto)
        self._page_break_margin = float(margin)

    # ── Page break helper ─────────────────────────────────────────────────
    def _y_to_rl(self, y_mm: float) -> float:
        """Convert fpdf2 Y (top-down mm) to reportlab Y (bottom-up points)."""
        return (self.h - y_mm) * mm

    def _check_page_break(self, line_h_mm: float) -> None:
        if not self._auto_page_break or self._in_header_footer:
            return
        if self.y + line_h_mm > self.h - self._page_break_margin:
            self.add_page(same=True)

    def add_page(self, orientation: str = "", same: bool = False) -> None:
        # Finish previous page (footer + showPage).  We mark _in_header_footer
        # so cells drawn from footer() do NOT cascade into another add_page().
        if self._page_started and self._canvas is not None:
            self._in_header_footer = True
            try:
                self.footer()
            finally:
                self._in_header_footer = False
            self._canvas.showPage()
        # Start new page
        if self._canvas is None:
            self._canvas = rl_canvas.Canvas(self._buffer, pagesize=A4)
            self._canvas.setLineWidth(self._line_width * mm)
        self.page += 1
        self._page_started = True
        self.x = self.l_margin
        self.y = self.t_margin
        # Re-apply state
        self._apply_font()
        self._apply_text_color()
        self._apply_fill_color()
        self._apply_draw_color()
        # Run header() inside the same guard.
        self._in_header_footer = True
        try:
            self.header()
        finally:
            self._in_header_footer = False

    # ── Header / footer (subclass overrides) ──────────────────────────────
    def header(self) -> None:
        pass

    def footer(self) -> None:
        pass

    # ── Font ──────────────────────────────────────────────────────────────
    def set_font(self, family: str | None = None, style: str = "", size: float | None = None) -> None:
        if family:
            self._font_family = family
        if style is not None:
            self._font_style = style or ""
        if size:
            self._font_size = float(size)
        self._apply_font()

    def _apply_font(self) -> None:
        if self._canvas is None:
            return
        font_name = _ensure_builtin(self._font_family, self._font_style)
        try:
            self._canvas.setFont(font_name, self._font_size)
        except Exception:
            self._canvas.setFont("Helvetica", self._font_size)

    def add_font(self, family: str, style: str = "", fname: str = "", uni: bool = True) -> None:
        """Register a TTF/OTF/TTC font.  fpdf2 signature compatible."""
        if not fname or not Path(fname).exists():
            return
        key = _font_key(family, style)
        if key in _REGISTERED_FONTS:
            return
        # reportlab needs a unique font name; use family+style.
        rl_name = key
        try:
            # subfontIndex helps for .ttc (collection) files which carry
            # multiple weights — fpdf2 callers point bold at the same .ttc
            # so try index 0 first; if it fails, try index 1 (bold).
            ext = Path(fname).suffix.lower()
            subfont = 1 if (ext == ".ttc" and "B" in style.upper()) else 0
            try:
                pdfmetrics.registerFont(TTFont(rl_name, fname, subfontIndex=subfont))
            except Exception:
                # Fall back without subfontIndex (most TTF/OTF)
                pdfmetrics.registerFont(TTFont(rl_name, fname))
            _REGISTERED_FONTS[key] = rl_name
        except Exception:
            # Silently ignore — caller already has a Helvetica fallback path
            pass

    # ── Colors ────────────────────────────────────────────────────────────
    def set_text_color(self, r: int, g: int = 0, b: int = 0) -> None:
        self._text = (r / 255, g / 255, b / 255)
        self._apply_text_color()

    def _apply_text_color(self) -> None:
        if self._canvas is not None:
            self._canvas.setFillColorRGB(*self._text)

    def set_fill_color(self, r: int, g: int = 0, b: int = 0) -> None:
        self._fill = (r / 255, g / 255, b / 255)
        self._apply_fill_color()

    def _apply_fill_color(self) -> None:
        # Reportlab uses fill color for both text and shapes.  We track the
        # most recent text vs fill request and apply the right one before
        # drawing operations.  cell() handles both cases explicitly.
        pass

    def set_draw_color(self, r: int, g: int = 0, b: int = 0) -> None:
        self._draw = (r / 255, g / 255, b / 255)
        self._apply_draw_color()

    def _apply_draw_color(self) -> None:
        if self._canvas is not None:
            self._canvas.setStrokeColorRGB(*self._draw)

    def set_line_width(self, w: float) -> None:
        self._line_width = float(w)
        if self._canvas is not None:
            self._canvas.setLineWidth(self._line_width * mm)

    # ── Drawing ───────────────────────────────────────────────────────────
    def line(self, x1: float, y1: float, x2: float, y2: float) -> None:
        if self._canvas is None:
            return
        self._canvas.line(x1 * mm, self._y_to_rl(y1), x2 * mm, self._y_to_rl(y2))

    def rect(self, x: float, y: float, w: float, h: float, style: str = "") -> None:
        """Draw a rectangle.  style: '' or 'D' = stroke only, 'F' = fill only,
        'DF' / 'FD' = fill + stroke (matches fpdf2 semantics)."""
        if self._canvas is None:
            return
        s = (style or "").upper()
        do_fill = "F" in s
        do_stroke = ("D" in s) or (not s)
        if do_fill:
            self._canvas.setFillColorRGB(*self._fill)
        if do_stroke:
            self._canvas.setStrokeColorRGB(*self._draw)
        self._canvas.rect(x * mm, self._y_to_rl(y + h), w * mm, h * mm,
                          stroke=int(do_stroke), fill=int(do_fill))

    def image(self, path: str, x: float | None = None, y: float | None = None,
              w: float = 0, h: float = 0) -> None:
        if self._canvas is None or not path or not os.path.exists(path):
            return
        if x is None:
            x = self.x
        if y is None:
            y = self.y
        # reportlab anchors image at bottom-left in points; drawImage takes
        # height in points.  Convert mm.
        try:
            from reportlab.lib.utils import ImageReader
            img = ImageReader(path)
            iw, ih = img.getSize()
            if w == 0 and h == 0:
                w = iw / 2.83464567   # auto-size in mm at 72dpi
                h = ih / 2.83464567
            elif w == 0:
                w = iw * (h / ih)
            elif h == 0:
                h = ih * (w / iw)
            self._canvas.drawImage(
                img,
                x * mm,
                self._y_to_rl(y + h),
                width=w * mm,
                height=h * mm,
                preserveAspectRatio=True,
                mask="auto",
            )
        except Exception:
            pass   # silently swallow — same as fpdf2's lenient image handling

    # ── Text ──────────────────────────────────────────────────────────────
    def get_string_width(self, txt: str) -> float:
        if self._canvas is None:
            return 0.0
        font_name = _ensure_builtin(self._font_family, self._font_style)
        try:
            return self._canvas.stringWidth(str(txt), font_name, self._font_size) / mm
        except Exception:
            return self._canvas.stringWidth(str(txt), "Helvetica", self._font_size) / mm

    def cell(self, w: float = 0, h: float = 0, txt: str = "", border: int | str = 0,
             align: str = "L", fill: bool = False, link: str = "",
             new_x: str = XPos.RIGHT, new_y: str = YPos.TOP, **_) -> None:
        """Draw a single-line cell with optional fill and border."""
        if self._canvas is None:
            return
        text = "" if txt is None else str(txt)

        # Width=0 means "rest of line"
        if w == 0:
            w = self.w - self.r_margin - self.x
        if h == 0:
            h = self._font_size * self.LINE_HEIGHT_RATIO / 2.83464567

        self._check_page_break(h)

        x0 = self.x
        y0 = self.y
        # Fill rect first (reportlab Y is bottom-up, so the rect's bottom-left
        # is at y0+h in fpdf2 coords)
        if fill:
            self._canvas.setFillColorRGB(*self._fill)
            self._canvas.rect(x0 * mm, self._y_to_rl(y0 + h), w * mm, h * mm,
                              stroke=0, fill=1)
            self._canvas.setFillColorRGB(*self._text)
        else:
            self._canvas.setFillColorRGB(*self._text)

        # Border: 1 = all sides; otherwise we ignore (no current report uses
        # selective borders, only 0 or 1)
        if border == 1 or border == "1":
            self._canvas.setStrokeColorRGB(*self._draw)
            self._canvas.rect(x0 * mm, self._y_to_rl(y0 + h), w * mm, h * mm,
                              stroke=1, fill=0)

        # Text positioning: vertical center of cell, horizontal alignment
        if text:
            txt_w = self.get_string_width(text)
            if align == "C":
                tx = x0 + (w - txt_w) / 2
            elif align == "R":
                tx = x0 + w - txt_w - 1
            else:   # L (default)
                tx = x0 + 1   # 1mm padding to match fpdf2 behavior
            # Baseline ~ 70% down the cell — eyeballed to match fpdf2
            baseline_y_mm = y0 + h * 0.72
            font_name = _ensure_builtin(self._font_family, self._font_style)
            try:
                self._canvas.setFont(font_name, self._font_size)
                self._canvas.drawString(tx * mm, self._y_to_rl(baseline_y_mm), text)
            except Exception:
                self._canvas.setFont("Helvetica", self._font_size)
                self._canvas.drawString(tx * mm, self._y_to_rl(baseline_y_mm), text)

        # Cursor advance
        if new_x == XPos.RIGHT:
            self.x = x0 + w
        elif new_x == XPos.LMARGIN:
            self.x = self.l_margin
        elif new_x == XPos.LEFT:
            self.x = x0
        if new_y == YPos.NEXT:
            self.y = y0 + h
        elif new_y == YPos.TOP:
            self.y = y0   # leave Y unchanged (fpdf2's TOP)
        elif new_y == YPos.LAST:
            pass

    def multi_cell(self, w: float = 0, h: float = 0, txt: str = "", border: int = 0,
                   align: str = "L", fill: bool = False, **kwargs) -> None:
        """Wrap text into multiple lines, advancing Y after each."""
        if self._canvas is None:
            return
        text = "" if txt is None else str(txt)
        if w == 0:
            w = self.w - self.r_margin - self.x
        if h == 0:
            h = self._font_size * self.LINE_HEIGHT_RATIO / 2.83464567

        # Word-wrap.  This is naive but matches what fpdf2 does for ASCII;
        # for wider unicode we rely on the actual measured width.
        max_text_w = w - 2   # account for cell padding
        words = text.split(" ")
        lines: list[str] = []
        cur = ""
        for word in words:
            trial = (cur + " " + word).strip() if cur else word
            if self.get_string_width(trial) <= max_text_w:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = word
        if cur:
            lines.append(cur)
        if not lines:
            lines = [""]

        # Also handle explicit \n
        flat: list[str] = []
        for ln in lines:
            flat.extend(ln.split("\n"))

        x0 = self.x
        for ln in flat:
            self.cell(w, h, ln, border=border, align=align, fill=fill,
                      new_x=XPos.LMARGIN if x0 == self.l_margin else XPos.LEFT,
                      new_y=YPos.NEXT)

    def ln(self, h: float | None = None) -> None:
        if h is None:
            h = self._font_size * self.LINE_HEIGHT_RATIO / 2.83464567
        self.x = self.l_margin
        self.y += h
        self._check_page_break(0)

    # ── Cursor ────────────────────────────────────────────────────────────
    def get_y(self) -> float:
        return self.y

    def get_x(self) -> float:
        return self.x

    def set_y(self, y: float) -> None:
        if y < 0:
            y = self.h + y   # fpdf2 negative-Y = from-bottom
        self.y = float(y)
        self.x = self.l_margin

    def set_x(self, x: float) -> None:
        if x < 0:
            x = self.w + x   # fpdf2 negative-X = from-right
        self.x = float(x)

    def set_xy(self, x: float, y: float) -> None:
        # fpdf2 sets x AFTER y so set_y's reset of x doesn't override
        self.set_y(y)
        self.set_x(x)

    def page_no(self) -> int:
        return self.page

    # ── Output ────────────────────────────────────────────────────────────
    def output(self, dest: BytesIO | str | None = None) -> bytes:
        if self._canvas is None:
            # No content drawn — produce an empty PDF
            self._canvas = rl_canvas.Canvas(self._buffer, pagesize=A4)
            self.page += 1
        # Finish current page
        if self._page_started:
            self._in_header_footer = True
            try:
                self.footer()
            finally:
                self._in_header_footer = False
            self._canvas.showPage()
            self._page_started = False
        self._canvas.save()
        data = self._buffer.getvalue()
        if isinstance(dest, BytesIO):
            dest.write(data)
            return b""
        if isinstance(dest, str):
            Path(dest).write_bytes(data)
            return b""
        return data
