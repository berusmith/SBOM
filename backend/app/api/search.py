from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.constants import SEVERITY_ORDER
from app.core.database import get_db
from app.core.deps import get_org_scope
from app.models.component import Component
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("/components")
def search_components(q: str = Query(..., min_length=1), org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    """Search components by name, scoped to the user's org if viewer."""
    pattern = f"%{q}%"
    rows_q = (
        db.query(Component, Release, Product, Organization)
        .join(Release, Release.id == Component.release_id)
        .join(Product, Product.id == Release.product_id)
        .join(Organization, Organization.id == Product.organization_id)
        .filter(Component.name.ilike(pattern))
    )
    if org_scope:
        rows_q = rows_q.filter(Product.organization_id == org_scope)
    rows = rows_q.order_by(Component.name).limit(200).all()

    if not rows:
        return {"query": q, "total": 0, "results": []}

    # Bulk-load all vulnerabilities for matched components in one query
    comp_ids = [c.id for c, _, _, _ in rows]
    all_vulns = db.query(Vulnerability).filter(Vulnerability.component_id.in_(comp_ids)).all()
    vulns_by_comp: dict = {}
    for v in all_vulns:
        vulns_by_comp.setdefault(v.component_id, []).append(v)

    results = []
    for c, release, product, org in rows:
        vulns = vulns_by_comp.get(c.id, [])
        highest = max(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity or "info", 0), default=None)
        kev_count = sum(1 for v in vulns if v.is_kev)
        results.append({
            "component_id": c.id,
            "component_name": c.name,
            "component_version": c.version or "",
            "purl": c.purl or "",
            "release_id": release.id,
            "release_version": release.version,
            "product_id": product.id,
            "product_name": product.name,
            "org_id": org.id,
            "org_name": org.name,
            "vuln_count": len(vulns),
            "highest_severity": highest.severity if highest else None,
            "kev_count": kev_count,
        })

    return {"query": q, "total": len(results), "results": results}
