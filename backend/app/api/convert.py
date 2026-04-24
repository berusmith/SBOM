from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response

from app.core.deps import get_current_user
from app.services.converter import convert as _convert, SUPPORTED_TARGETS

router = APIRouter(prefix="/api/convert", tags=["convert"])

_MIME = {
    "cyclonedx-json": "application/json",
    "cyclonedx-xml":  "application/xml",
    "spdx-json":      "application/json",
}


@router.post("")
async def convert_sbom(
    target: str,
    file: UploadFile = File(...),
    _user: dict = Depends(get_current_user),
):
    """
    轉換 SBOM 格式。
    target: cyclonedx-json | cyclonedx-xml | spdx-json
    """
    if target not in SUPPORTED_TARGETS:
        raise HTTPException(status_code=400, detail=f"不支援的目標格式：{target}，可選：{', '.join(SUPPORTED_TARGETS)}")

    MAX = 20 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX:
        raise HTTPException(status_code=400, detail="檔案超過 20MB 上限")

    try:
        out_bytes, suggested_name = _convert(content, file.filename or "sbom", target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    mime = _MIME.get(target, "application/octet-stream")
    return Response(
        content=out_bytes,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{suggested_name}"'},
    )
