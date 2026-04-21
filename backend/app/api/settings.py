from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.alert_config import AlertConfig
from app.services.alerts import send_email, send_webhook

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _get_or_create(db: Session) -> AlertConfig:
    cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
    if not cfg:
        cfg = AlertConfig(id="default", webhook_url="", alert_email_to="")
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


@router.get("/alerts")
def get_alert_settings(db: Session = Depends(get_db)):
    cfg = _get_or_create(db)
    return {
        "webhook_url": cfg.webhook_url or "",
        "alert_email_to": cfg.alert_email_to or "",
        "smtp_configured": bool(settings.SMTP_HOST and settings.SMTP_USER),
        "smtp_host": settings.SMTP_HOST,
        "smtp_port": settings.SMTP_PORT,
        "smtp_user": settings.SMTP_USER,
        "smtp_from": settings.SMTP_FROM or settings.SMTP_USER,
    }


class AlertSettingsUpdate(BaseModel):
    webhook_url: Optional[str] = None
    alert_email_to: Optional[str] = None


@router.patch("/alerts")
def update_alert_settings(payload: AlertSettingsUpdate, db: Session = Depends(get_db)):
    cfg = _get_or_create(db)
    if payload.webhook_url is not None:
        cfg.webhook_url = payload.webhook_url.strip()
    if payload.alert_email_to is not None:
        cfg.alert_email_to = payload.alert_email_to.strip()
    db.commit()
    db.refresh(cfg)
    return {"webhook_url": cfg.webhook_url or "", "alert_email_to": cfg.alert_email_to or ""}


@router.post("/alerts/test-webhook")
def test_webhook(db: Session = Depends(get_db)):
    cfg = _get_or_create(db)
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
def test_email(db: Session = Depends(get_db)):
    cfg = _get_or_create(db)
    if not cfg.alert_email_to:
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
