from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
def get_stats(db: Session = Depends(get_db)):
    orgs = db.query(Organization).count()
    products = db.query(Product).count()
    releases = db.query(Release).count()
    components = db.query(Component).count()

    vuln_rows = db.query(Vulnerability.severity, Vulnerability.status).all()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {"open": 0, "in_triage": 0, "not_affected": 0, "affected": 0, "fixed": 0}
    for sev, status in vuln_rows:
        s = sev or "info"
        severity_counts[s] = severity_counts.get(s, 0) + 1
        st = status or "open"
        status_counts[st] = status_counts.get(st, 0) + 1

    active_incidents = db.query(CRAIncident).filter(CRAIncident.status != "closed").count()
    total_incidents = db.query(CRAIncident).count()

    return {
        "organizations": orgs,
        "products": products,
        "releases": releases,
        "components": components,
        "vulnerabilities": {
            "total": len(vuln_rows),
            "by_severity": severity_counts,
            "by_status": status_counts,
        },
        "cra_incidents": {
            "total": total_incidents,
            "active": active_incidents,
        },
    }
