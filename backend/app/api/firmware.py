from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, Depends
from sqlalchemy import desc
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.core.config import BACKEND_DIR
from app.core.database import SessionLocal, get_db
from app.core.deps import get_current_user, get_org_scope, require_admin
from app.models.firmware_scan import FirmwareScan
from app.models.organization import Organization
from app.models.release import Release
from app.models.component import Component
from app.models.product import Product
from app.services.firmware_service import FirmwareService
import uuid
import json
from pathlib import Path
from datetime import datetime

# Anchor under backend/ so the location doesn't depend on process cwd.
FIRMWARE_UPLOAD_DIR = BACKEND_DIR / "firmware_uploads"
FIRMWARE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Firmware blobs are large by nature (router/IoT images often 100-300MB), but
# we still need an upper bound to prevent memory-exhaustion DoS.
MAX_FIRMWARE_SIZE = 500 * 1024 * 1024   # 500 MB

router = APIRouter(prefix="/api/firmware", tags=["firmware"])
firmware_service = FirmwareService()

class ImportAsReleaseRequest(BaseModel):
    product_id: str
    version: str


@router.post("/upload")
async def upload_firmware(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    _admin: dict = Depends(require_admin),
):
    """上傳韌體檔案並開始掃描"""
    db = SessionLocal()
    try:
        scan_id = str(uuid.uuid4())

        # Read with hard cap to avoid OOM (read 1 byte over the limit so we can detect overflow)
        contents = await file.read(MAX_FIRMWARE_SIZE + 1)
        if len(contents) > MAX_FIRMWARE_SIZE:
            raise HTTPException(status_code=400, detail=f"韌體檔案超過 {MAX_FIRMWARE_SIZE // (1024*1024)}MB 上限")

        # Strip path separators from filename to prevent traversal
        safe_name = Path(file.filename or "firmware.bin").name
        file_path = str(FIRMWARE_UPLOAD_DIR / f"{scan_id}_{safe_name}")
        with open(file_path, "wb") as f:
            f.write(contents)

        # Create scan record
        scan = FirmwareScan(
            id=scan_id,
            filename=safe_name,
            file_path=file_path,
            status="pending",
            progress=0
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Start background scanning task
        if background_tasks:
            background_tasks.add_task(firmware_service.run_scan, scan_id, file_path)

        return {
            "scan_id": scan_id,
            "filename": safe_name,
            "status": "pending",
            "created_at": scan.created_at.isoformat() if scan.created_at else None
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@router.get("/scans")
async def list_scans(_admin: dict = Depends(require_admin)):
    """列出所有韌體掃描任務 (admin only — firmware scans are not org-scoped)"""
    db = SessionLocal()
    try:
        scans = db.query(FirmwareScan).order_by(desc(FirmwareScan.created_at)).all()
        return [
            {
                "id": s.id,
                "filename": s.filename,
                "status": s.status,
                "progress": s.progress,
                "components_count": s.components_count,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in scans
        ]
    finally:
        db.close()

@router.get("/scans/{scan_id}")
async def get_scan_status(scan_id: str, _admin: dict = Depends(require_admin)):
    """檢查掃描進度與結果"""
    db = SessionLocal()
    try:
        scan = db.query(FirmwareScan).filter(FirmwareScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        result = {
            "id": scan.id,
            "filename": scan.filename,
            "status": scan.status,
            "progress": scan.progress,
            "components_count": scan.components_count,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message
        }

        # Parse components from EMBA output if available
        if scan.status == "completed" and scan.emba_output_json:
            try:
                emba_output = json.loads(scan.emba_output_json)
                components = firmware_service.parse_emba_components(emba_output)
                result["components"] = components
            except Exception:
                result["components"] = []
        else:
            result["components"] = []

        return result
    finally:
        db.close()

@router.post("/scans/{scan_id}/import-as-release")
async def import_scan_as_release(
    scan_id: str,
    payload: ImportAsReleaseRequest,
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """將韌體掃描結果匯入為產品版本"""
    try:
        # Verify scan exists and is completed
        scan = db.query(FirmwareScan).filter(FirmwareScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")

        # Verify product exists AND belongs to caller's org (server-side, not from payload)
        product = db.query(Product).filter(Product.id == payload.product_id).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        if org_scope and product.organization_id != org_scope:
            raise HTTPException(status_code=403, detail="無權在此產品建立版本")

        # Create release
        release = Release(
            id=str(uuid.uuid4()),
            product_id=payload.product_id,
            version=payload.version
        )
        db.add(release)
        db.flush()

        # Parse and import components
        components_list = []
        if scan.emba_output_json:
            try:
                emba_output = json.loads(scan.emba_output_json)
                components_data = firmware_service.parse_emba_components(emba_output)

                for comp_data in components_data:
                    component = Component(
                        id=str(uuid.uuid4()),
                        release_id=release.id,
                        name=comp_data.get("name", "Unknown"),
                        version=comp_data.get("version"),
                        purl=None,
                        license=None
                    )
                    db.add(component)
                    components_list.append(component)
            except Exception:
                pass

        db.commit()
        db.refresh(release)

        return {
            "release_id": release.id,
            "product_id": payload.product_id,
            "version": payload.version,
            "component_count": len(components_list),
            "org_id": product.organization_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
