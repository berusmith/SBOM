from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_org_scope
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.models.vex_history import VexHistory  # noqa: F401 — ensure model loaded

router = APIRouter(prefix="/api/stats", tags=["stats"])


def _vuln_base_query(db, org_scope):
    """Return a base query on Vulnerability joined to org chain when scoped."""
    if not org_scope:
        return db.query(Vulnerability)
    return (
        db.query(Vulnerability)
        .join(Component, Component.id == Vulnerability.component_id)
        .join(Release, Release.id == Component.release_id)
        .join(Product, Product.id == Release.product_id)
        .filter(Product.organization_id == org_scope)
    )


@router.get("")
def get_stats(org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    orgs = db.query(Organization).filter(Organization.id == org_scope).count() if org_scope else db.query(Organization).count()

    prod_q = db.query(Product)
    if org_scope:
        prod_q = prod_q.filter(Product.organization_id == org_scope)
    products = prod_q.count()

    rel_q = db.query(Release)
    if org_scope:
        rel_q = rel_q.join(Product, Product.id == Release.product_id).filter(Product.organization_id == org_scope)
    releases = rel_q.count()

    comp_q = db.query(Component)
    if org_scope:
        comp_q = comp_q.join(Release, Release.id == Component.release_id).join(Product, Product.id == Release.product_id).filter(Product.organization_id == org_scope)
    components = comp_q.count()

    # Severity counts — build full join first, then group
    base = _vuln_base_query(db, org_scope)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in base.with_entities(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all():
        severity_counts[sev or "info"] = severity_counts.get(sev or "info", 0) + cnt

    # Status counts
    status_counts = {"open": 0, "in_triage": 0, "not_affected": 0, "affected": 0, "fixed": 0}
    for st, cnt in base.with_entities(Vulnerability.status, func.count(Vulnerability.id)).group_by(Vulnerability.status).all():
        status_counts[st or "open"] = status_counts.get(st or "open", 0) + cnt

    total_vulns = sum(severity_counts.values())
    fixed_count = status_counts.get("fixed", 0)
    patch_rate  = round(fixed_count / total_vulns * 100, 1) if total_vulns else 0.0

    # Average days to fix
    avg_raw = (
        base.filter(
            Vulnerability.status == "fixed",
            Vulnerability.fixed_at.isnot(None),
            Vulnerability.scanned_at.isnot(None),
        )
        .with_entities(func.avg(func.julianday(Vulnerability.fixed_at) - func.julianday(Vulnerability.scanned_at)))
        .scalar()
    )
    avg_days = round(float(avg_raw), 1) if avg_raw is not None else None

    inc_q = db.query(CRAIncident)
    if org_scope:
        inc_q = inc_q.filter(CRAIncident.org_id == org_scope)
    active_incidents = inc_q.filter(CRAIncident.status != "closed").count()
    total_incidents  = inc_q.count()

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
def get_risk_overview(org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    # Bulk queries for all orgs (or scoped to one org for viewers)
    org_q = db.query(Organization)
    if org_scope:
        org_q = org_q.filter(Organization.id == org_scope)
    orgs = {o.id: o for o in org_q.all()}

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

    # 5. Active incidents (scoped by org_id if available)
    inc_q = db.query(func.count(CRAIncident.id)).filter(CRAIncident.status != "closed")
    if org_scope:
        inc_q = inc_q.filter(CRAIncident.org_id == org_scope)
    total_active_incidents = inc_q.scalar() or 0
    inc_counts = {}  # per-org breakdown not needed (shown in totals)

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
def get_top_threats(org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    base = _vuln_base_query(db, org_scope)

    kev_count = (
        base.filter(Vulnerability.is_kev == True, Vulnerability.status.notin_(["fixed", "not_affected"]))  # noqa: E712
        .with_entities(func.count(Vulnerability.id))
        .scalar() or 0
    )

    top_epss_q = (
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
    )
    if org_scope:
        top_epss_q = top_epss_q.join(Release, Release.id == Component.release_id).join(Product, Product.id == Release.product_id).filter(Product.organization_id == org_scope)
    top_epss = top_epss_q.order_by(Vulnerability.epss_score.desc()).limit(5).all()

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
