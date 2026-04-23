from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, Depends
from sqlalchemy import desc
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.core.database import SessionLocal, get_db
from app.models.firmware_scan import FirmwareScan
from app.models.release import Release
from app.models.component import Component
from app.models.product import Product
from app.services.firmware_service import FirmwareService
import uuid
import json
from datetime import datetime

router = APIRouter(prefix="/api/firmware", tags=["firmware"])
firmware_service = FirmwareService()

class ImportAsReleaseRequest(BaseModel):
    product_id: str
    version: str
    org_id: str

@router.post("/upload")
async def upload_firmware(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    """上傳韌體檔案並開始掃描"""
    db = SessionLocal()
    try:
        scan_id = str(uuid.uuid4())

        # Save file
        file_path = f"backend/firmware_uploads/{scan_id}_{file.filename}"
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        # Create scan record
        scan = FirmwareScan(
            id=scan_id,
            filename=file.filename,
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
            "filename": file.filename,
            "status": "pending",
            "created_at": scan.created_at.isoformat() if scan.created_at else None
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        db.close()

@router.get("/scans")
async def list_scans():
    """列出所有韌體掃描任務"""
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
async def get_scan_status(scan_id: str):
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
                import json
                emba_output = json.loads(scan.emba_output_json)
                components = firmware_service.parse_emba_components(emba_output)
                result["components"] = components
            except:
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
    db: Session = Depends(get_db)
):
    """將韌體掃描結果匯入為產品版本"""
    try:
        # Verify scan exists and is completed
        scan = db.query(FirmwareScan).filter(FirmwareScan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")

        # Verify product exists
        product = db.query(Product).filter(Product.id == payload.product_id).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

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
            except Exception as e:
                pass

        db.commit()
        db.refresh(release)

        return {
            "release_id": release.id,
            "product_id": payload.product_id,
            "version": payload.version,
            "component_count": len(components_list),
            "org_id": payload.org_id
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
