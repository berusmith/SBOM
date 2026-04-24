"""
Continuous vulnerability monitoring service.
Background thread periodically rescans all non-locked releases against OSV.dev
and fires alerts when new CVEs are found.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_stop_event     = threading.Event()
_scan_lock      = threading.Lock()
_is_scanning    = False
_last_run_dt: datetime | None = None
_last_run_count: int = 0
_last_skip_dt: datetime | None = None   # last time trigger() was called but scan was already running
_scheduler_thread: threading.Thread | None = None


def _do_scan_all() -> int:
    """Scan all non-locked releases. Returns total new vuln count."""
    global _is_scanning, _last_run_dt, _last_run_count

    with _scan_lock:
        if _is_scanning:
            return 0
        _is_scanning = True

    total_new = 0
    from app.core.database import SessionLocal
    from app.models.release import Release
    from app.models.component import Component
    from app.models.vulnerability import Vulnerability
    from app.models.product import Product
    from app.models.organization import Organization
    from app.models.alert_config import AlertConfig
    from app.services import vuln_scanner
    from app.services.epss import fetch_epss
    from app.services.kev import fetch_kev_cve_ids
    from app.services.alerts import notify_new_vulns

    db = SessionLocal()
    try:
        releases = db.query(Release).filter(Release.locked == False).all()  # noqa: E712
        logger.info("Monitor: scanning %d releases", len(releases))

        for release in releases:
            try:
                comps = db.query(Component).filter(Component.release_id == release.id).all()
                if not comps:
                    continue

                comp_list = [{"name": c.name, "version": c.version, "purl": c.purl or ""} for c in comps]
                vuln_results = vuln_scanner.scan_components(comp_list)
                purl_map = {c.purl: c for c in comps if c.purl}

                new_count = 0
                new_details: list[dict] = []
                for purl, vulns in vuln_results.items():
                    comp = purl_map.get(purl)
                    if not comp:
                        continue
                    existing = {v.cve_id for v in comp.vulnerabilities}
                    seen: set[str] = set()
                    for v in vulns:
                        cve_id = v["cve_id"]
                        if cve_id in existing or cve_id in seen:
                            continue
                        seen.add(cve_id)
                        db.add(Vulnerability(
                            component_id=comp.id,
                            cve_id=cve_id,
                            cvss_score=v["cvss_score"],
                            severity=v["severity"],
                            cvss_v4_vector=v.get("cvss_v4_vector"),
                            status="open",
                        ))
                        new_count += 1
                        new_details.append({
                            "cve_id": cve_id,
                            "severity": v["severity"],
                            "cvss_score": v.get("cvss_score"),
                            "epss_score": None,
                            "is_kev": False,
                            "component": f"{comp.name}@{comp.version or ''}",
                        })

                if new_count > 0:
                    db.commit()
                    # Enrich with EPSS + KEV
                    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release.id).all()
                    cve_ids = [v.cve_id for v in all_vulns]
                    epss_data = fetch_epss(cve_ids)
                    kev_ids   = fetch_kev_cve_ids()
                    for v in all_vulns:
                        if v.cve_id in epss_data:
                            v.epss_score       = epss_data[v.cve_id]["epss"]
                            v.epss_percentile  = epss_data[v.cve_id]["percentile"]
                        if v.cve_id in kev_ids:
                            v.is_kev = True
                    db.commit()

                    for d in new_details:
                        if d["cve_id"] in epss_data:
                            d["epss_score"] = epss_data[d["cve_id"]]["epss"]
                        if d["cve_id"] in kev_ids:
                            d["is_kev"] = True

                    product = db.query(Product).filter(Product.id == release.product_id).first()
                    org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
                    notify_new_vulns(db, {
                        "org":        org.name if org else "",
                        "product":    product.name if product else "",
                        "version":    release.version,
                        "release_id": release.id,
                    }, new_details)
                    logger.info("Monitor: +%d vulns in %s %s", new_count,
                                product.name if product else "?", release.version)
                    total_new += new_count

            except Exception:
                logger.exception("Monitor: error scanning release %s", release.id)
                db.rollback()

        # Check for expired suppressions — auto-unsuppress and notify
        try:
            from app.models.vulnerability import Vulnerability as _Vuln
            now_utc = datetime.now(timezone.utc)
            expired = db.query(_Vuln).filter(
                _Vuln.suppressed == True,   # noqa: E712
                _Vuln.suppressed_until.isnot(None),
                _Vuln.suppressed_until < now_utc,
            ).all()
            for v in expired:
                v.suppressed = False
                v.suppressed_until = None
                logger.info("Monitor: suppression expired for %s", v.cve_id)
            if expired:
                db.commit()
                from app.services.alerts import notify_new_vulns
                expired_details = [{"cve_id": v.cve_id, "severity": v.severity,
                                     "cvss_score": v.cvss_score, "epss_score": v.epss_score,
                                     "is_kev": bool(v.is_kev), "component": ""} for v in expired]
                notify_new_vulns(db, {
                    "org": "", "product": "多個產品", "version": "",
                    "release_id": "",
                }, expired_details)
                logger.info("Monitor: %d suppression(s) expired and re-activated", len(expired))
        except Exception:
            logger.exception("Monitor: error checking expired suppressions")

        now = datetime.now(timezone.utc)
        _last_run_dt    = now
        _last_run_count = total_new

        cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
        if cfg:
            cfg.monitor_last_run = now
            db.commit()

        logger.info("Monitor: scan complete — %d new vulns", total_new)

    except Exception:
        logger.exception("Monitor: scan failed")
    finally:
        db.close()
        with _scan_lock:
            _is_scanning = False

    return total_new


def _scheduler_loop() -> None:
    logger.info("Monitor scheduler thread started")
    time.sleep(30)  # let app fully initialise

    while not _stop_event.is_set():
        try:
            from app.core.database import SessionLocal
            from app.models.alert_config import AlertConfig
            db = SessionLocal()
            try:
                cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
                interval_h = int(cfg.monitor_interval_hours or 0) if cfg else 0
            finally:
                db.close()

            if interval_h > 0:
                if _last_run_dt is None:
                    _do_scan_all()
                else:
                    elapsed_h = (datetime.now(timezone.utc) - _last_run_dt).total_seconds() / 3600
                    if elapsed_h >= interval_h:
                        _do_scan_all()
        except Exception:
            logger.exception("Monitor: scheduler loop error")

        for _ in range(60):
            if _stop_event.is_set():
                break
            time.sleep(1)

    logger.info("Monitor scheduler thread stopped")


# ── Public API ────────────────────────────────────────────────────────────────

def start() -> None:
    global _last_run_dt, _scheduler_thread
    try:
        from app.core.database import SessionLocal
        from app.models.alert_config import AlertConfig
        db = SessionLocal()
        try:
            cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
            if cfg and cfg.monitor_last_run:
                ts = cfg.monitor_last_run
                _last_run_dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        finally:
            db.close()
    except Exception:
        logger.exception("Monitor: failed to restore last_run from DB")

    _stop_event.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop, daemon=True, name="monitor-scheduler"
    )
    _scheduler_thread.start()


def stop() -> None:
    _stop_event.set()


def trigger() -> dict:
    global _last_skip_dt
    with _scan_lock:
        if _is_scanning:
            _last_skip_dt = datetime.now(timezone.utc)
            return {"status": "already_running", "skipped_at": _last_skip_dt.isoformat()}
    threading.Thread(target=_do_scan_all, daemon=True, name="monitor-trigger").start()
    return {"status": "started"}


def get_status() -> dict:
    with _scan_lock:
        scanning = _is_scanning

    from app.core.database import SessionLocal
    from app.models.alert_config import AlertConfig
    db = SessionLocal()
    try:
        cfg = db.query(AlertConfig).filter(AlertConfig.id == "default").first()
        interval_h   = int(cfg.monitor_interval_hours or 0) if cfg else 0
        db_last_run  = cfg.monitor_last_run if cfg else None
    finally:
        db.close()

    # Prefer in-memory value (more accurate), fall back to DB
    last = _last_run_dt
    if last is None and db_last_run:
        last = db_last_run if db_last_run.tzinfo else db_last_run.replace(tzinfo=timezone.utc)

    next_run = None
    if last and interval_h > 0:
        next_run = (last + timedelta(hours=interval_h)).isoformat()

    return {
        "interval_hours":      interval_h,
        "is_scanning":         scanning,
        "running":             bool(_scheduler_thread and _scheduler_thread.is_alive()),
        "last_run":            last.isoformat() if last else None,
        "last_run_new_count":  _last_run_count,
        "next_run":            next_run,
        "last_skip":           _last_skip_dt.isoformat() if _last_skip_dt else None,
    }
