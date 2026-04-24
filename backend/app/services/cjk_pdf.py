"""
CJK-aware FPDF base class.
All IEC 62443 compliance reports inherit from CjkPDF.
"""
from __future__ import annotations

from fpdf import FPDF

from app.services.font_manager import setup_cjk_fonts, cjk_font_name


def _latin(text: str) -> str:
    """Fallback: strip non-Latin-1 for Helvetica."""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


class CjkPDF(FPDF):
    """fpdf2 subclass that auto-detects CJK font availability."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cjk: bool = setup_cjk_fonts(self)
        self._fn: str = cjk_font_name()

    # ── Font helpers ──────────────────────────────────────────────────────────

    def sf(self, style: str = "", size: float = 10) -> None:
        """Set font — uses CJK family if available, Helvetica otherwise."""
        # fpdf2 TTC collections need index; msyh.ttc contains multiple weights
        self.set_font(self._fn, style if not self._cjk else "", size)

    def sfb(self, size: float = 10) -> None:
        """Set bold font."""
        if self._cjk:
            self.set_font(self._fn, "B", size)
        else:
            self.set_font("Helvetica", "B", size)

    def sfi(self, size: float = 10) -> None:
        """Set italic font (CJK has no true italic — falls back to regular)."""
        if self._cjk:
            self.set_font(self._fn, "", size)
        else:
            self.set_font("Helvetica", "I", size)

    # ── Text helper ───────────────────────────────────────────────────────────

    def t(self, text: object) -> str:
        """Safe text: pass-through with CJK font, Latin-1 strip otherwise."""
        return str(text) if self._cjk else _latin(str(text))
