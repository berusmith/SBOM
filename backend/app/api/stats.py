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
    orgs       = db.query(Organization).count()
    products   = db.query(Product).count()
    releases   = db.query(Release).count()
    components = db.query(Component).count()

    # Severity counts via SQL GROUP BY (avoids loading all rows)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in db.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all():
        severity_counts[sev or "info"] = severity_counts.get(sev or "info", 0) + cnt

    # Status counts via SQL GROUP BY
    status_counts = {"open": 0, "in_triage": 0, "not_affected": 0, "affected": 0, "fixed": 0}
    for st, cnt in db.query(Vulnerability.status, func.count(Vulnerability.id)).group_by(Vulnerability.status).all():
        status_counts[st or "open"] = status_counts.get(st or "open", 0) + cnt

    total_vulns = sum(severity_counts.values())
    fixed_count = status_counts.get("fixed", 0)
    patch_rate  = round(fixed_count / total_vulns * 100, 1) if total_vulns else 0.0

    # Average days to fix via SQL (julianday diff)
    avg_raw = db.query(
        func.avg(
            func.julianday(Vulnerability.fixed_at) - func.julianday(Vulnerability.scanned_at)
        )
    ).filter(
        Vulnerability.status == "fixed",
        Vulnerability.fixed_at.isnot(None),
        Vulnerability.scanned_at.isnot(None),
    ).scalar()
    avg_days = round(float(avg_raw), 1) if avg_raw is not None else None

    active_incidents = db.query(CRAIncident).filter(CRAIncident.status != "closed").count()
    total_incidents  = db.query(CRAIncident).count()

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
            "fixed": fixed_count,
            "avg_days_to_fix": avg_days,
        },
        "cra_incidents": {
            "total": total_incidents,
            "active": active_incidents,
        },
    }


@router.get("/risk-overview")
def get_risk_overview(db: Session = Depends(get_db)):
    # 5 bulk queries instead of N×4 per-org queries

    # 1. All orgs
    orgs = {o.id: o for o in db.query(Organization).all()}

    # 2. Product count per org
    prod_counts = dict(
        db.query(Product.organization_id, func.count(Product.id))
        .group_by(Product.organization_id).all()
    )

    # 3. Release count per org (via product join)
    rel_counts = dict(
        db.query(Product.organization_id, func.count(Release.id))
        .join(Release, Release.product_id == Product.id)
        .group_by(Product.organization_id).all()
    )

    # 4. Vuln aggregates per org: one row per (org_id, severity, status)
    vuln_rows = (
        db.query(
            Product.organization_id,
            Vulnerability.severity,
            Vulnerability.status,
            func.count(Vulnerability.id).label("cnt"),
        )
        .join(Release,     Release.product_id     == Product.id)
        .join(Component,   Component.release_id   == Release.id)
        .join(Vulnerability, Vulnerability.component_id == Component.id)
        .group_by(Product.organization_id, Vulnerability.severity, Vulnerability.status)
        .all()
    )

    # 5. Total active incidents (CRAIncident has no org FK — use global count)
    total_active_incidents = (
        db.query(func.count(CRAIncident.id))
        .filter(CRAIncident.status != "closed")
        .scalar() or 0
    )
    inc_counts = {}  # no per-org breakdown available

    # Aggregate vuln data per org in Python
    _blank = lambda: {"total": 0, "critical": 0, "high": 0,
                      "unpatched_critical": 0, "unpatched_high": 0, "fixed": 0}
    org_vulns = {}
    for org_id, severity, status, cnt in vuln_rows:
        d = org_vulns.setdefault(org_id, _blank())
        d["total"] += cnt
        if severity == "critical":
            d["critical"] += cnt
        if severity == "high":
            d["high"] += cnt
        if severity == "critical" and status not in ("fixed", "not_affected"):
            d["unpatched_critical"] += cnt
        if severity == "high" and status not in ("fixed", "not_affected"):
            d["unpatched_high"] += cnt
        if status == "fixed":
            d["fixed"] += cnt

    result = []
    for org_id, org in orgs.items():
        v          = org_vulns.get(org_id, _blank())
        total      = v["total"]
        patch_rate = round(v["fixed"] / total * 100, 1) if total else 0.0
        risk_score = v["unpatched_critical"] * 10 + v["unpatched_high"] * 3
        result.append({
            "org_id":             org_id,
            "org_name":           org.name,
            "products":           prod_counts.get(org_id, 0),
            "releases":           rel_counts.get(org_id, 0),
            "total_vulns":        total,
            "critical":           v["critical"],
            "high":               v["high"],
            "unpatched_critical": v["unpatched_critical"],
            "unpatched_high":     v["unpatched_high"],
            "patch_rate":         patch_rate,
            "active_incidents":   total_active_incidents,
            "risk_score":         risk_score,
        })

    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result


@router.get("/top-threats")
def get_top_threats(db: Session = Depends(get_db)):
    # Active (unresolved) KEV count
    kev_count = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.is_kev == True,  # noqa: E712
        Vulnerability.status.notin_(["fixed", "not_affected"]),
    ).scalar() or 0

    # Top 5 by EPSS score, unresolved only
    top_epss = (
        db.query(
            Vulnerability.cve_id,
            Vulnerability.epss_score,
            Vulnerability.severity,
            Vulnerability.is_kev,
            Component.name.label("component_name"),
        )
        .join(Component, Component.id == Vulnerability.component_id)
        .filter(
            Vulnerability.epss_score.isnot(None),
            Vulnerability.status.notin_(["fixed", "not_affected"]),
        )
        .order_by(Vulnerability.epss_score.desc())
        .limit(5)
        .all()
    )

    return {
        "active_kev_count": kev_count,
        "top_epss": [
            {
                "cve_id":     r.cve_id,
                "epss_score": round(r.epss_score, 4) if r.epss_score else None,
                "severity":   r.severity,
                "is_kev":     bool(r.is_kev),
                "component":  r.component_name,
            }
            for r in top_epss
        ],
    }
