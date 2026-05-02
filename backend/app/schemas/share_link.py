"""Pydantic schemas for share-link endpoints (admin + public).

Extracted from inline `BaseModel` in backend/app/api/share.py during E.1
(2026-05-01) per .refactor-audit/iteration-1/refactor-plan.md §3.10.

Scope per Stage E lock: only schemas in D-touched modules move here.  Other
17 router files retain their inline schemas (FU-1.012 candidate).
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class ShareLinkCreate(BaseModel):
    """Request body for POST /api/releases/{release_id}/share-link."""
    expires_hours: Optional[int] = 72   # None = never expires
    mask_internal: bool = False
