"""
Send webhook and email alerts when new vulnerabilities are found.
"""
import ipaddress
import logging
import smtplib
import socket
import time
from email.mime.text import MIMEText
from urllib.parse import urlparse

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


def _validate_webhook_url(url: str) -> str:
    """SSRF guard: reject non-http(s) schemes, private/loopback/link-local IPs,
    and cloud metadata endpoints.  Returns "" on success or an error message.
    DNS is resolved here so attackers can't bypass via a public-looking hostname
    that points at 127.0.0.1 / 169.254.169.254."""
    if not url:
        return "Webhook URL is empty"
    try:
        parsed = urlparse(url)
    except Exception as e:
        return f"Invalid URL: {e}"

    if parsed.scheme not in ("http", "https"):
        return f"Only http/https are allowed (got {parsed.scheme!r})"
    host = parsed.hostname
    if not host:
        return "Webhook URL has no host"

    # Resolve all A/AAAA records for the hostname; reject if ANY resolves into
    # a forbidden range (defense-in-depth — a hostile DNS that returns one
    # public + one private answer must not slip through).
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return f"DNS resolution failed: {e}"

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            return f"Webhook host resolves to a non-routable address ({ip_str})"
    return ""


def _get_config(db):
    from app.models.alert_config import AlertConfig
    cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
    if not cfg:
        cfg = AlertConfig(id="default", webhook_url="", alert_email_to="")
        db.add(cfg)
        db.commit()
    return cfg


def _is_slack_url(url: str) -> bool:
    return "hooks.slack.com" in url


def _is_teams_url(url: str) -> bool:
    return "webhook.office.com" in url or ("microsoft.com" in url and "webhook" in url)


def _slack_payload(payload: dict) -> dict:
    """Format notification as Slack Block Kit message."""
    release_info = payload
    count    = payload.get("new_vuln_count", 0)
    critical = payload.get("critical_count", 0)
    kev      = payload.get("kev_count", 0)
    color    = "#FF0000" if critical > 0 or kev > 0 else "#FF9900"
    title    = f"🔴 {count} New Vulnerabilities — {release_info.get('product', '')} {release_info.get('version', '')}"

    fields = [
        {"type": "mrkdwn", "text": f"*Organization*\n{release_info.get('org', '—')}"},
        {"type": "mrkdwn", "text": f"*Product / Version*\n{release_info.get('product', '—')} {release_info.get('version', '')}"},
        {"type": "mrkdwn", "text": f"*New CVEs*\n{count}"},
        {"type": "mrkdwn", "text": f"*Critical*\n{critical}"},
    ]
    if kev:
        fields.append({"type": "mrkdwn", "text": f"*KEV (actively exploited)*\n{kev}"})

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "fields": fields},
    ]
    top_vulns = payload.get("vulnerabilities", [])[:5]
    if top_vulns:
        lines = "\n".join(f"• `{v['cve_id']}` [{v.get('severity','?').upper()}] {v.get('component','')}" for v in top_vulns)
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Top Vulnerabilities*\n{lines}"}})

    return {"blocks": blocks, "attachments": [{"color": color, "fallback": title}]}


def _teams_payload(payload: dict) -> dict:
    """Format notification as Microsoft Teams MessageCard."""
    count    = payload.get("new_vuln_count", 0)
    critical = payload.get("critical_count", 0)
    kev      = payload.get("kev_count", 0)
    color    = "FF0000" if critical > 0 or kev > 0 else "FF9900"
    title    = f"🔴 {count} New Vulnerabilities Detected"

    facts = [
        {"name": "Organization", "value": payload.get("org", "—")},
        {"name": "Product / Version", "value": f"{payload.get('product', '—')} {payload.get('version', '')}"},
        {"name": "New CVEs", "value": str(count)},
        {"name": "Critical", "value": str(critical)},
    ]
    if kev:
        facts.append({"name": "KEV (actively exploited)", "value": str(kev)})

    top_vulns = payload.get("vulnerabilities", [])[:5]
    vuln_text = "<br>".join(f"• {v['cve_id']} [{v.get('severity','?').upper()}] {v.get('component','')}" for v in top_vulns)

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": title,
        "sections": [
            {"activityTitle": title, "facts": facts},
            *(([{"text": f"**Top Vulnerabilities**<br>{vuln_text}"}]) if vuln_text else []),
        ],
    }


def send_webhook(url: str, payload: dict, max_retries: int = 3) -> str:
    """POST payload to webhook URL with exponential backoff.
    Auto-detects Slack / Teams URLs and reformats payload accordingly.
    Refuses to send to private / loopback / metadata endpoints (SSRF guard)."""
    err = _validate_webhook_url(url)
    if err:
        logger.warning("Webhook rejected: %s (url=%s)", err, url)
        return err

    if _is_slack_url(url):
        body = _slack_payload(payload)
    elif _is_teams_url(url):
        body = _teams_payload(payload)
    else:
        body = payload

    last_err = ""
    for attempt in range(max_retries):
        try:
            # Disable redirect following so the server can't bounce us to a
            # private address after the validation has already passed.
            resp = httpx.post(url, json=body, timeout=10, follow_redirects=False)
            resp.raise_for_status()
            return ""
        except Exception as e:
            last_err = str(e)
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    return last_err


def send_email(subject: str, body: str, to: str) -> str:
    """Send plain-text email via SMTP. `to` may be comma-separated addresses."""
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        return "SMTP 未設定（請在 .env 設定 SMTP_HOST / SMTP_USER / SMTP_PASSWORD）"
    recipients = [addr.strip() for addr in to.split(",") if addr.strip()]
    if not recipients:
        return "收件人地址為空"
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
        msg["To"] = ", ".join(recipients)
        if settings.SMTP_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(msg["From"], recipients, msg.as_bytes())
        server.quit()
        return ""
    except Exception as e:
        return str(e)


_SEV_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _passes_alert_rule(vuln: dict, cfg) -> bool:
    """Return True if this vuln should trigger a notification based on alert rules."""
    # KEV: always notify if kev_always is set
    if getattr(cfg, "alert_kev_always", 1) and vuln.get("is_kev"):
        return True
    # Severity threshold
    min_sev = getattr(cfg, "alert_min_severity", "") or ""
    if min_sev:
        vuln_rank = _SEV_ORDER.get(vuln.get("severity", "info"), 0)
        min_rank  = _SEV_ORDER.get(min_sev, 0)
        if vuln_rank < min_rank:
            return False
    # EPSS threshold
    threshold = getattr(cfg, "alert_epss_threshold", 0.0) or 0.0
    if threshold > 0:
        epss = vuln.get("epss_score") or 0.0
        if epss < threshold:
            return False
    return True


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

    # Apply alert rules — filter which vulns trigger notifications
    filtered_vulns = [v for v in new_vulns if _passes_alert_rule(v, cfg)]
    if not filtered_vulns:
        return {"webhook_sent": False, "email_sent": False, "errors": [], "filtered": True}
    new_vulns = filtered_vulns

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
