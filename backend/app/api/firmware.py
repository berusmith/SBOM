from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from sqlalchemy import desc
from app.core.database import SessionLocal
from app.models.firmware_scan import FirmwareScan
from app.services.firmware_service import FirmwareService
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/firmware", tags=["firmware"])
firmware_service = FirmwareService()

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
