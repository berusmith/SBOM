from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_org_scope
from app.models.component import Component
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/search", tags=["search"])

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@router.get("/components")
def search_components(q: str = Query(..., min_length=1), org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    """Search components by name, scoped to the user's org if viewer."""
    pattern = f"%{q}%"
    comp_q = (
        db.query(Component)
        .join(Release, Release.id == Component.release_id)
        .join(Product, Product.id == Release.product_id)
        .filter(Component.name.ilike(pattern))
    )
    if org_scope:
        comp_q = comp_q.filter(Product.organization_id == org_scope)
    components = comp_q.order_by(Component.name).limit(200).all()

    results = []
    for c in components:
        release = db.query(Release).filter(Release.id == c.release_id).first()
        if not release:
            continue
        product = db.query(Product).filter(Product.id == release.product_id).first()
        org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None

        vulns = c.vulnerabilities
        highest = max(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity or "info", 0), default=None)
        kev_count = sum(1 for v in vulns if v.is_kev)

        results.append({
            "component_id": c.id,
            "component_name": c.name,
            "component_version": c.version or "",
            "purl": c.purl or "",
            "release_id": release.id,
            "release_version": release.version,
            "product_id": product.id if product else None,
            "product_name": product.name if product else "",
            "org_id": org.id if org else None,
            "org_name": org.name if org else "",
            "vuln_count": len(vulns),
            "highest_severity": highest.severity if highest else None,
            "kev_count": kev_count,
        })

    return {"query": q, "total": len(results), "results": results}
