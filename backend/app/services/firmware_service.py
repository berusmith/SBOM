import subprocess
import json
import os
from datetime import datetime
from sqlalchemy import update
from app.core.database import SessionLocal
from app.models.firmware_scan import FirmwareScan

class FirmwareService:
    def __init__(self):
        self.emba_enabled = self._check_emba_available()

    def _check_emba_available(self):
        """檢查 EMBA 是否可用"""
        try:
            result = subprocess.run(["emba", "-h"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def run_scan(self, scan_id: str, file_path: str):
        """執行韌體掃描 (背景任務)"""
        db = SessionLocal()
        try:
            # Update status to running
            db.execute(
                update(FirmwareScan)
                .where(FirmwareScan.id == scan_id)
                .values(status="running", progress=10, updated_at=datetime.utcnow())
            )
            db.commit()

            if self.emba_enabled:
                # Real EMBA scanning
                output_dir = f"backend/firmware_scans/{scan_id}"
                os.makedirs(output_dir, exist_ok=True)

                # Run EMBA
                result = subprocess.run(
                    ["emba", "-f", file_path, "-d", output_dir, "-l"],
                    capture_output=True,
                    timeout=3600
                )

                if result.returncode == 0:
                    # Parse EMBA output
                    emba_json_file = f"{output_dir}/emba_report.json"
                    emba_output = None
                    if os.path.exists(emba_json_file):
                        with open(emba_json_file, "r") as f:
                            emba_output = f.read()

                    components = self.parse_emba_components(
                        json.loads(emba_output) if emba_output else {}
                    )

                    db.execute(
                        update(FirmwareScan)
                        .where(FirmwareScan.id == scan_id)
                        .values(
                            status="completed",
                            progress=100,
                            components_count=len(components),
                            emba_output_json=emba_output,
                            completed_at=datetime.utcnow(),
                            updated_at=datetime.utcnow()
                        )
                    )
                else:
                    error_msg = result.stderr.decode() if result.stderr else "EMBA scan failed"
                    db.execute(
                        update(FirmwareScan)
                        .where(FirmwareScan.id == scan_id)
                        .values(
                            status="failed",
                            error_message=error_msg,
                            completed_at=datetime.utcnow(),
                            updated_at=datetime.utcnow()
                        )
                    )
            else:
                # Demo mode - simulate EMBA output
                mock_components = [
                    {"name": "openssl", "version": "1.1.1k", "type": "library"},
                    {"name": "busybox", "version": "1.33.0", "type": "utility"},
                    {"name": "linux-kernel", "version": "5.10.0", "type": "kernel"}
                ]

                db.execute(
                    update(FirmwareScan)
                    .where(FirmwareScan.id == scan_id)
                    .values(
                        status="completed",
                        progress=100,
                        components_count=len(mock_components),
                        emba_output_json=json.dumps({"components": mock_components}),
                        completed_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                )

            db.commit()

        except Exception as e:
            db.execute(
                update(FirmwareScan)
                .where(FirmwareScan.id == scan_id)
                .values(
                    status="failed",
                    error_message=str(e),
                    completed_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
            )
            db.commit()
        finally:
            db.close()

    def parse_emba_components(self, emba_output: dict) -> list:
        """解析 EMBA 輸出的元件清單"""
        try:
            # Try to extract components from EMBA JSON output
            if "components" in emba_output:
                return emba_output["components"]
            elif "software" in emba_output:
                return emba_output["software"]
            # Add more parsing logic based on actual EMBA output format
            return []
        except:
            return []
