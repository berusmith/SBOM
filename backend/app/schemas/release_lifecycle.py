"""Pydantic schemas for release lifecycle PATCH endpoints.

Added in E.2 (2026-05-01) per .refactor-audit/iteration-1/refactor-plan.md §3.10.

DESIGN: BEHAVIOR-EQUIVALENT to the prior `body: dict` pattern (per Q-P7-3,
not a contract evolution).  Field validators use `mode="before"` to mirror
the handler's pre-existing behavior:
  - update_version: str(body.get("version") or "").strip() — coerce + strip
    BUT empty-after-strip still raises 400 in the handler (NOT 422 here)
    to preserve the zh-TW message and status code that current callers see
  - update_notes:   str(body.get("notes", "") or "")[:5000] — coerce + truncate
    silently at 5000 chars (NO 422 on overflow); empty becomes None in handler

The schemas exist for OpenAPI surface + IDE typeahead; runtime semantics
unchanged from the dict-shape predecessor.
"""
from __future__ import annotations

from pydantic import BaseModel, field_validator


class ReleaseVersionUpdate(BaseModel):
    """Body for PATCH /api/releases/{release_id}/version.

    The handler raises 400 "版本號不可為空" if the post-strip value is empty.
    No min_length/max_length here — that would emit 422 (Pydantic default)
    and lose the zh-TW message; preserved as 400 in the handler.
    """
    version: str

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_strip(cls, v) -> str:
        # Mirrors handler today: (body.get("version") or "").strip()
        return str(v if v is not None else "").strip()


class ReleaseNotesUpdate(BaseModel):
    """Body for PATCH /api/releases/{release_id}/notes.

    notes is silently TRUNCATED at 5000 chars (NO 422 emitted on overflow);
    handler converts empty string to None for storage.
    """
    notes: str = ""

    @field_validator("notes", mode="before")
    @classmethod
    def _coerce_truncate(cls, v) -> str:
        # Mirrors handler today: str(body.get("notes", "") or "")[:5000]
        return str(v if v is not None else "")[:5000]
