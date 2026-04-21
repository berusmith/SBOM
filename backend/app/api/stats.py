from fastapi import APIRouter, Depends
from sqlalchemy import func
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


@router.get("/risk-overview")
def get_risk_overview(db: Session = Depends(get_db)):
    orgs = db.query(Organization).all()
    result = []

    for org in orgs:
        products = db.query(Product).filter(Product.organization_id == org.id).all()
        product_ids = [p.id for p in products]
        if not product_ids:
            result.append({
                "org_id": org.id,
                "org_name": org.name,
                "products": 0,
                "releases": 0,
                "total_vulns": 0,
                "critical": 0,
                "high": 0,
                "unpatched_critical": 0,
                "unpatched_high": 0,
                "patch_rate": 0.0,
                "active_incidents": 0,
                "risk_score": 0,
            })
            continue

        release_rows = db.query(Release).filter(Release.product_id.in_(product_ids)).all()
        release_ids = [r.id for r in release_rows]

        if not release_ids:
            result.append({
                "org_id": org.id,
                "org_name": org.name,
                "products": len(products),
                "releases": 0,
                "total_vulns": 0,
                "critical": 0,
                "high": 0,
                "unpatched_critical": 0,
                "unpatched_high": 0,
                "patch_rate": 0.0,
                "active_incidents": 0,
                "risk_score": 0,
            })
            continue

        component_ids_q = db.query(Component.id).filter(Component.release_id.in_(release_ids)).subquery()
        vulns = db.query(
            Vulnerability.severity, Vulnerability.status
        ).filter(Vulnerability.component_id.in_(component_ids_q)).all()

        total = len(vulns)
        critical = sum(1 for v in vulns if v.severity == "critical")
        high = sum(1 for v in vulns if v.severity == "high")
        fixed = sum(1 for v in vulns if v.status == "fixed")
        unpatched_critical = sum(1 for v in vulns if v.severity == "critical" and v.status not in ("fixed", "not_affected"))
        unpatched_high = sum(1 for v in vulns if v.severity == "high" and v.status not in ("fixed", "not_affected"))
        patch_rate = round(fixed / total * 100, 1) if total else 0.0

        active_incidents = db.query(CRAIncident).filter(
            CRAIncident.organization_id == org.id,
            CRAIncident.status != "closed"
        ).count()

        # Risk score: weighted sum (higher = worse)
        risk_score = unpatched_critical * 10 + unpatched_high * 3 + active_incidents * 5

        result.append({
            "org_id": org.id,
            "org_name": org.name,
            "products": len(products),
            "releases": len(release_rows),
            "total_vulns": total,
            "critical": critical,
            "high": high,
            "unpatched_critical": unpatched_critical,
            "unpatched_high": unpatched_high,
            "patch_rate": patch_rate,
            "active_incidents": active_incidents,
            "risk_score": risk_score,
        })

    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result
