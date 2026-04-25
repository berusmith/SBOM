"""
Public OSS-attribution endpoint.

Serves NOTICE.md (the project-root third-party notices file) as plain text so
the frontend About page can display it without bundling the file into the
SPA.  No authentication: this is intentionally public so downstream operators,
auditors, and end users can verify license compliance.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from app.core.config import BACKEND_DIR

router = APIRouter(prefix="/api/notice", tags=["notice"])

# NOTICE.md lives at the repo root, one level up from BACKEND_DIR.
_NOTICE_PATH = BACKEND_DIR.parent / "NOTICE.md"

# Read once at import — the file is part of the deployed bundle and never
# mutates at runtime.  If absent at import (e.g. dev tree without sync), we
# defer the error to first request rather than failing startup.
_CACHED: str | None = None


def _load_notice() -> str:
    global _CACHED
    if _CACHED is not None:
        return _CACHED
    if not _NOTICE_PATH.exists():
        raise HTTPException(status_code=404, detail="NOTICE.md not bundled in this deployment")
    _CACHED = _NOTICE_PATH.read_text(encoding="utf-8")
    return _CACHED


@router.get("", response_class=PlainTextResponse)
def get_notice() -> PlainTextResponse:
    """Return the NOTICE.md content as text/markdown."""
    text = _load_notice()
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")
