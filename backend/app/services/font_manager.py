"""
CJK font manager for PDF generation.

Looks for NotoSansSC TTF fonts in priority order:
  1. backend/fonts/  (bundled or manually placed)
  2. System font directories (Linux / Windows / macOS)
  3. Auto-download from Google Fonts CDN (one-time, cached)

Usage:
  from app.services.font_manager import setup_cjk_fonts, cjk_font_name
  setup_cjk_fonts(pdf)            # register fonts with fpdf2 instance
  pdf.set_font(cjk_font_name())   # use CJK font
"""
from __future__ import annotations

import logging
import os
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Font file locations ────────────────────────────────────────────────────────
_FONTS_DIR = Path(__file__).resolve().parent.parent.parent / "fonts"

_DOWNLOAD_URLS = {
    "regular": (
        "https://github.com/googlefonts/noto-cjk/raw/main/Sans/SubsetOTF/SC/"
        "NotoSansSC-Regular.otf",
        # fallback: noto-fonts main repo TTF
        "https://github.com/notofonts/noto-cjk/releases/download/"
        "Sans2.004R/06_NotoSansSC.zip",
    ),
    # Simpler source: Google Fonts static CDN
    "regular_cdn": "https://fonts.gstatic.com/s/notosanssc/v36/"
                   "k3kXo84MPvpLmixcA63oeALhLOCT-xFf3LdFhRa4zsRktg.woff2",
}

# TTF files we'll look for / download
_FONT_FILES = {
    "regular": "NotoSansSC-Regular.ttf",
    "bold":    "NotoSansSC-Bold.ttf",
}

# Direct OTF download from notofonts/noto-cjk (Adobe-compatible OTF, fpdf2 supports OTF)
_TTF_URLS = {
    "regular": [
        # notofonts/noto-cjk Subset OTF (SC = Simplified Chinese)
        "https://github.com/notofonts/noto-cjk/raw/main/Sans/SubsetOTF/SC/NotoSansSC-Regular.otf",
        # jsDelivr CDN mirror (more reliable)
        "https://cdn.jsdelivr.net/gh/notofonts/noto-cjk@main/Sans/SubsetOTF/SC/NotoSansSC-Regular.otf",
        # WQY Microhei fallback (smaller, Latin-compliant TTF)
        "https://github.com/anthonyfok/fonts-wqy-microhei/raw/master/wqy-microhei.ttc",
    ],
    "bold": [
        "https://github.com/notofonts/noto-cjk/raw/main/Sans/SubsetOTF/SC/NotoSansSC-Bold.otf",
        "https://cdn.jsdelivr.net/gh/notofonts/noto-cjk@main/Sans/SubsetOTF/SC/NotoSansSC-Bold.otf",
    ],
}

# Windows system CJK fonts (already on most Windows machines)
_WINDOWS_CJK_FONTS = [
    Path("C:/Windows/Fonts/msyh.ttc"),       # Microsoft YaHei
    Path("C:/Windows/Fonts/msyhbd.ttc"),     # Microsoft YaHei Bold
    Path("C:/Windows/Fonts/simsun.ttc"),     # SimSun
    Path("C:/Windows/Fonts/simhei.ttf"),     # SimHei
    Path("C:/Windows/Fonts/mingliu.ttc"),    # MingLiU
]

# System font search paths
_SYSTEM_PATHS = [
    # Linux
    Path("/usr/share/fonts"),
    Path("/usr/local/share/fonts"),
    # macOS
    Path("/Library/Fonts"),
    Path(os.path.expanduser("~/Library/Fonts")),
    # Windows
    Path("C:/Windows/Fonts"),
]

_SYSTEM_FONT_NAMES = [
    "NotoSansSC-Regular.ttf",
    "NotoSansSC-Bold.ttf",
    "wqy-microhei.ttc",          # WenQuanYi Micro Hei (common on Linux)
    "NotoSansCJKsc-Regular.otf",
    "DroidSansFallback.ttf",
]

_cached: dict[str, Path | None] = {}


def _find_system_font(name: str) -> Path | None:
    for base in _SYSTEM_PATHS:
        if not base.exists():
            continue
        for p in base.rglob(name):
            if p.is_file():
                return p
    return None


def _download_font(style: str) -> Path | None:
    _FONTS_DIR.mkdir(parents=True, exist_ok=True)
    urls = _TTF_URLS.get(style, [])
    if isinstance(urls, str):
        urls = [urls]

    for url in urls:
        ext = ".otf" if url.endswith(".otf") else ".ttc" if url.endswith(".ttc") else ".ttf"
        dest = _FONTS_DIR / (_FONT_FILES[style].replace(".ttf", ext))
        logger.info("Downloading CJK font from %s", url[:70])
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sbom-platform/1.0"})
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = resp.read()
            if len(data) < 100_000:   # sanity check — real font > 100KB
                continue
            dest.write_bytes(data)
            logger.info("CJK font downloaded: %s (%d KB)", dest.name, len(data) // 1024)
            return dest
        except Exception as e:
            logger.warning("Download failed (%s): %s", url[:50], e)
    return None


def get_font_path(style: str = "regular") -> Path | None:
    """Return path to a CJK TTF font file, or None if unavailable."""
    if style in _cached:
        return _cached[style]

    # 1. Check bundled fonts dir
    bundled = _FONTS_DIR / _FONT_FILES.get(style, "")
    if bundled.exists():
        _cached[style] = bundled
        return bundled

    # 2. Check Windows CJK fonts first (fast, no search needed)
    for wp in _WINDOWS_CJK_FONTS:
        if wp.exists():
            logger.info("Using Windows CJK font: %s", wp.name)
            _cached[style] = wp
            return wp

    # 3. Check system fonts (Linux/macOS)
    for name in _SYSTEM_FONT_NAMES:
        p = _find_system_font(name)
        if p:
            logger.info("Using system CJK font: %s", p)
            _cached[style] = p
            return p

    # 3. Try download (regular only; bold falls back to regular)
    if style == "regular":
        p = _download_font("regular")
        _cached[style] = p
        return p

    if style == "bold":
        # try to download bold
        p = _download_font("bold")
        if not p:
            p = get_font_path("regular")  # fallback to regular
        _cached[style] = p
        return p

    _cached[style] = None
    return None


_CJK_REGISTERED: set[int] = set()   # fpdf instance id → registered


def setup_cjk_fonts(pdf) -> bool:
    """
    Register CJK fonts with an fpdf2 FPDF instance.
    Returns True if fonts were successfully registered.
    """
    obj_id = id(pdf)
    if obj_id in _CJK_REGISTERED:
        return True

    reg = get_font_path("regular")
    if not reg:
        logger.warning("No CJK font available — PDF will use Latin-1 fallback")
        return False

    bold = get_font_path("bold") or reg  # bold fallback to regular

    try:
        pdf.add_font("NotoSansSC", style="", fname=str(reg))
        pdf.add_font("NotoSansSC", style="B", fname=str(bold))
        _CJK_REGISTERED.add(obj_id)
        return True
    except Exception as e:
        logger.warning("Failed to register CJK fonts: %s", e)
        return False


def cjk_available() -> bool:
    return get_font_path("regular") is not None


def cjk_font_name() -> str:
    return "NotoSansSC" if cjk_available() else "Helvetica"
