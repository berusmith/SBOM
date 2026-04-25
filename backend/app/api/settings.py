import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import BACKEND_DIR, settings
from app.core.database import get_db
from app.core.deps import require_admin
from app.models.alert_config import AlertConfig
from app.models.brand_config import BrandConfig
from app.services.alerts import send_email, send_webhook

router = APIRouter(prefix="/api/settings", tags=["settings"])

# Anchor under backend/ so the location doesn't depend on process cwd.
BRAND_UPLOAD_DIR = str(BACKEND_DIR / "uploads" / "brand")
os.makedirs(BRAND_UPLOAD_DIR, exist_ok=True)

# Logo upload: only well-known raster formats. SVG is excluded — it can carry
# JavaScript that would execute when rendered as <img> in some browsers /
# directly in a tab, so allowing it would create a stored-XSS vector.
_ALLOWED_LOGO_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
_ALLOWED_LOGO_MIME = {
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".webp": "image/webp",
}


def _get_or_create_alert(db: Session) -> AlertConfig:
    cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
    if not cfg:
        cfg = AlertConfig(id="default", webhook_url="", alert_email_to="")
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _get_or_create_brand(db: Session) -> BrandConfig:
    cfg = db.query(BrandConfig).filter(BrandConfig.id == "default").first()
    if not cfg:
        cfg = BrandConfig(id="default")
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


# ── Alert settings ────────────────────────────────────────────────

@router.get("/alerts")
def get_alert_settings(db: Session = Depends(get_db)):
    cfg = _get_or_create_alert(db)
    return {
        "webhook_url":            cfg.webhook_url or "",
        "alert_email_to":         cfg.alert_email_to or "",
        "monitor_interval_hours": cfg.monitor_interval_hours if cfg.monitor_interval_hours is not None else 24,
        "smtp_configured":        bool(settings.SMTP_HOST and settings.SMTP_USER),
        "smtp_host":              settings.SMTP_HOST,
        "smtp_port":              settings.SMTP_PORT,
        "smtp_user":              settings.SMTP_USER,
        "smtp_from":              settings.SMTP_FROM or settings.SMTP_USER,
        # Alert rules
        "alert_min_severity":     cfg.alert_min_severity or "",
        "alert_kev_always":       bool(cfg.alert_kev_always if cfg.alert_kev_always is not None else 1),
        "alert_epss_threshold":   cfg.alert_epss_threshold or 0.0,
    }


# ── Monitor endpoints ─────────────────────────────────────────────

@router.get("/monitor")
def get_monitor_status():
    from app.services.monitor import get_status
    return get_status()


@router.post("/monitor/trigger")
def trigger_monitor(_admin: dict = Depends(require_admin)):
    from app.services.monitor import trigger
    return trigger()


class AlertSettingsUpdate(BaseModel):
    webhook_url:            Optional[str]   = None
    alert_email_to:         Optional[str]   = None
    monitor_interval_hours: Optional[int]   = None
    alert_min_severity:     Optional[str]   = None   # ""|info|low|medium|high|critical
    alert_kev_always:       Optional[bool]  = None
    alert_epss_threshold:   Optional[float] = None   # 0.0–1.0


@router.patch("/alerts")
def update_alert_settings(payload: AlertSettingsUpdate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _get_or_create_alert(db)
    if payload.webhook_url is not None:
        cfg.webhook_url = payload.webhook_url.strip()
    if payload.alert_email_to is not None:
        cfg.alert_email_to = payload.alert_email_to.strip()
    if payload.monitor_interval_hours is not None:
        if payload.monitor_interval_hours not in (0, 6, 12, 24, 48, 72):
            raise HTTPException(status_code=400, detail="interval_hours 必須為 0/6/12/24/48/72")
        cfg.monitor_interval_hours = payload.monitor_interval_hours
    if payload.alert_min_severity is not None:
        valid_sev = ("", "info", "low", "medium", "high", "critical")
        if payload.alert_min_severity not in valid_sev:
            raise HTTPException(status_code=400, detail="alert_min_severity 必須為 info/low/medium/high/critical 或空字串")
        cfg.alert_min_severity = payload.alert_min_severity
    if payload.alert_kev_always is not None:
        cfg.alert_kev_always = int(payload.alert_kev_always)
    if payload.alert_epss_threshold is not None:
        if not (0.0 <= payload.alert_epss_threshold <= 1.0):
            raise HTTPException(status_code=400, detail="alert_epss_threshold 必須介於 0.0 和 1.0 之間")
        cfg.alert_epss_threshold = payload.alert_epss_threshold
    db.commit()
    db.refresh(cfg)
    return {"webhook_url": cfg.webhook_url or "", "alert_email_to": cfg.alert_email_to or ""}


@router.post("/alerts/test-webhook")
def test_webhook(_admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _get_or_create_alert(db)
    if not cfg.webhook_url:
        raise HTTPException(status_code=400, detail="尚未設定 Webhook URL")
    err = send_webhook(cfg.webhook_url, {
        "event": "test",
        "message": "SBOM Platform webhook 測試訊息",
    })
    if err:
        raise HTTPException(status_code=502, detail=f"Webhook 發送失敗：{err}")
    return {"ok": True}


@router.post("/alerts/test-email")
def test_email(_admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _get_or_create_alert(db)
    if not cfg.alert_email_to or not cfg.alert_email_to.strip():
        raise HTTPException(status_code=400, detail="尚未設定收件信箱")
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        raise HTTPException(status_code=400, detail="SMTP 未設定（請在 .env 設定 SMTP_HOST / SMTP_USER / SMTP_PASSWORD）")
    err = send_email(
        subject="[SBOM Platform] Email 通知測試",
        body="這是 SBOM Platform 的 Email 通知測試訊息，收到代表設定正確。",
        to=cfg.alert_email_to,
    )
    if err:
        raise HTTPException(status_code=502, detail=f"Email 發送失敗：{err}")
    return {"ok": True}


# ── Brand settings ────────────────────────────────────────────────

def _brand_response(cfg: BrandConfig) -> dict:
    return {
        "company_name":  cfg.company_name or "",
        "tagline":       cfg.tagline or "",
        "primary_color": cfg.primary_color or "#1e3a8a",
        "report_footer": cfg.report_footer or "",
        "has_logo":      bool(cfg.logo_path and os.path.exists(cfg.logo_path)),
    }


@router.get("/brand")
def get_brand(db: Session = Depends(get_db)):
    return _brand_response(_get_or_create_brand(db))


class BrandUpdate(BaseModel):
    company_name:  Optional[str] = None
    tagline:       Optional[str] = None
    primary_color: Optional[str] = None
    report_footer: Optional[str] = None


@router.patch("/brand")
def update_brand(payload: BrandUpdate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _get_or_create_brand(db)
    if payload.company_name is not None:
        cfg.company_name = payload.company_name.strip()
    if payload.tagline is not None:
        cfg.tagline = payload.tagline.strip()
    if payload.primary_color is not None:
        color = payload.primary_color.strip()
        if not color.startswith("#") or len(color) not in (4, 7):
            raise HTTPException(status_code=400, detail="顏色格式錯誤，請使用 #RRGGBB")
        cfg.primary_color = color
    if payload.report_footer is not None:
        cfg.report_footer = payload.report_footer.strip()
    db.commit()
    return _brand_response(cfg)


@router.post("/brand/logo")
async def upload_logo(
    file: UploadFile = File(...),
    _admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    # Extension is the source of truth — content-type is client-supplied and
    # easily spoofed.  Reject SVG explicitly: SVG can embed <script>.
    raw_name = file.filename or "logo.png"
    ext = os.path.splitext(raw_name)[1].lower()
    if ext not in _ALLOWED_LOGO_EXT:
        raise HTTPException(
            status_code=400,
            detail="僅支援 PNG / JPG / JPEG / GIF / WebP（不接受 SVG 等可執行格式）",
        )

    # 2 MB cap (read 1 byte over to detect overflow without buffering more)
    data = await file.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Logo 大小不可超過 2MB")

    # Drop the old file if present so we don't leak deleted formats.
    cfg = _get_or_create_brand(db)
    if cfg.logo_path and os.path.exists(cfg.logo_path):
        try:
            os.remove(cfg.logo_path)
        except OSError:
            pass

    # Always write under a server-controlled name; never reuse user filename.
    logo_path = os.path.join(BRAND_UPLOAD_DIR, f"logo{ext}")
    with open(logo_path, "wb") as f:
        f.write(data)
    cfg.logo_path = logo_path
    db.commit()
    return {"ok": True, "has_logo": True}


@router.delete("/brand/logo")
def delete_logo(_admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _get_or_create_brand(db)
    if cfg.logo_path and os.path.exists(cfg.logo_path):
        os.remove(cfg.logo_path)
    cfg.logo_path = None
    db.commit()
    return {"ok": True, "has_logo": False}


@router.get("/brand/logo")
def get_logo(db: Session = Depends(get_db)):
    cfg = _get_or_create_brand(db)
    if not cfg.logo_path or not os.path.exists(cfg.logo_path):
        raise HTTPException(status_code=404, detail="尚未上傳 Logo")
    # Pin media_type from the on-disk extension (server-controlled), not from
    # libmagic / mimetypes guessing on user-supplied bytes.
    ext = os.path.splitext(cfg.logo_path)[1].lower()
    media_type = _ALLOWED_LOGO_MIME.get(ext, "application/octet-stream")
    return FileResponse(cfg.logo_path, media_type=media_type)
