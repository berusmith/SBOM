"""
Send webhook and email alerts when new vulnerabilities are found.
"""
import logging
import smtplib
import time
from email.mime.text import MIMEText

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


def _get_config(db):
    from app.models.alert_config import AlertConfig
    cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
    if not cfg:
        cfg = AlertConfig(id="default", webhook_url="", alert_email_to="")
        db.add(cfg)
        db.commit()
    return cfg


def send_webhook(url: str, payload: dict, max_retries: int = 3) -> str:
    """POST payload to webhook URL with exponential backoff. Returns '' on success."""
    last_err = ""
    for attempt in range(max_retries):
        try:
            resp = httpx.post(url, json=payload, timeout=10)
            resp.raise_for_status()
            return ""
        except Exception as e:
            last_err = str(e)
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)   # 1s, 2s before retry 2 and 3
    return last_err


def send_email(subject: str, body: str, to: str) -> str:
    """Send plain-text email via SMTP. Returns '' on success, error message on failure."""
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        return "SMTP 未設定（請在 .env 設定 SMTP_HOST / SMTP_USER / SMTP_PASSWORD）"
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
        msg["To"] = to
        if settings.SMTP_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(msg["From"], [to], msg.as_bytes())
        server.quit()
        return ""
    except Exception as e:
        return str(e)


def notify_new_vulns(db, release_info: dict, new_vulns: list) -> dict:
    """
    Send alerts for new vulnerabilities found during rescan.
    release_info: {org, product, version, release_id}
    new_vulns: list of {cve_id, severity, epss_score, is_kev, component}
    Returns {webhook_sent, email_sent, errors}
    """
    if not new_vulns:
        return {"webhook_sent": False, "email_sent": False, "errors": []}

    cfg = _get_config(db)
    kev_vulns = [v for v in new_vulns if v.get("is_kev")]
    critical   = [v for v in new_vulns if v.get("severity") == "critical"]

    subject = (
        f"[SBOM] {release_info['product']} {release_info['version']} — "
        f"發現 {len(new_vulns)} 個新漏洞"
        + (f"（含 {len(kev_vulns)} 個 KEV）" if kev_vulns else "")
    )

    lines = [
        f"產品：{release_info['org']} / {release_info['product']} {release_info['version']}",
        f"新增漏洞數：{len(new_vulns)}",
        f"  - Critical：{len(critical)}",
        f"  - CISA KEV：{len(kev_vulns)}",
        "",
        "漏洞清單（最多 20 筆）：",
    ]
    for v in new_vulns[:20]:
        kev_flag = " [KEV]" if v.get("is_kev") else ""
        epss = f" EPSS={v['epss_score']*100:.1f}%" if v.get("epss_score") else ""
        lines.append(f"  {v['cve_id']}{kev_flag}  {v.get('severity','?').upper()}  元件:{v.get('component','')}{epss}")

    body = "\n".join(lines)

    payload = {
        "event": "new_vulnerabilities",
        "product": release_info["product"],
        "org": release_info["org"],
        "version": release_info["version"],
        "release_id": release_info["release_id"],
        "new_vuln_count": len(new_vulns),
        "kev_count": len(kev_vulns),
        "critical_count": len(critical),
        "vulnerabilities": new_vulns[:50],
    }

    errors = []
    webhook_sent = False
    email_sent = False

    if cfg.webhook_url:
        err = send_webhook(cfg.webhook_url, payload)
        if err:
            logger.error("Webhook notification failed for release %s: %s", release_info.get("release_id"), err)
            errors.append(f"Webhook: {err}")
        else:
            webhook_sent = True

    if cfg.alert_email_to:
        err = send_email(subject, body, cfg.alert_email_to)
        if err:
            logger.error("Email notification failed for release %s: %s", release_info.get("release_id"), err)
            errors.append(f"Email: {err}")
        else:
            email_sent = True

    return {"webhook_sent": webhook_sent, "email_sent": email_sent, "errors": errors}
