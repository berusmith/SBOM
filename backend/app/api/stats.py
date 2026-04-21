from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.models.vex_history import VexHistory  # noqa: F401 — ensure model loaded

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
def get_stats(db: Session = Depends(get_db)):
    orgs = db.query(Organization).count()
    products = db.query(Product).count()
    releases = db.query(Release).count()
    components = db.query(Component).count()

    vuln_rows = db.query(Vulnerability.severity, Vulnerability.status, Vulnerability.scanned_at, Vulnerability.fixed_at).all()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {"open": 0, "in_triage": 0, "not_affected": 0, "affected": 0, "fixed": 0}
    days_list = []
    total_fixed = 0
    for sev, status, scanned_at, fixed_at in vuln_rows:
        s = sev or "info"
        severity_counts[s] = severity_counts.get(s, 0) + 1
        st = status or "open"
        status_counts[st] = status_counts.get(st, 0) + 1
        if st == "fixed":
            total_fixed += 1
            if fixed_at and scanned_at:
                delta = fixed_at - scanned_at
                days_list.append(delta.total_seconds() / 86400)

    total_vulns = len(vuln_rows)
    patch_rate = round(total_fixed / total_vulns * 100, 1) if total_vulns else 0.0
    avg_days = round(sum(days_list) / len(days_list), 1) if days_list else None

    active_incidents = db.query(CRAIncident).filter(CRAIncident.status != "closed").count()
    total_incidents = db.query(CRAIncident).count()

    return {
        "organizations": orgs,
        "products": products,
        "releases": releases,
        "components": components,
        "vulnerabilities": {
            "total": total_vulns,
            "by_severity": severity_counts,
            "by_status": status_counts,
        },
        "patch_tracking": {
            "patch_rate": patch_rate,
            "fixed": total_fixed,
            "avg_days_to_fix": avg_days,
        },
        "cra_incidents": {
            "total": total_incidents,
            "active": active_incidents,
        },
    }
