from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.component import Component
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.schemas.release import ReleaseCreate, ReleaseResponse

router = APIRouter(prefix="/api/products", tags=["products"])


@router.post("/{product_id}/releases", response_model=ReleaseResponse)
def create_release(product_id: str, payload: ReleaseCreate, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    release = Release(product_id=product_id, version=payload.version)
    db.add(release)
    db.commit()
    db.refresh(release)
    return release


@router.delete("/{product_id}", status_code=204)
def delete_product(product_id: str, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    db.delete(product)
    db.commit()


@router.get("/{product_id}/releases")
def list_releases(product_id: str, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    releases = db.query(Release).filter(Release.product_id == product_id).all()
    return {"product_name": product.name, "releases": releases}


@router.get("/{product_id}/diff")
def diff_releases(
    product_id: str,
    from_release: str = Query(..., alias="from"),
    to_release: str = Query(..., alias="to"),
    db: Session = Depends(get_db),
):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    rel_from = db.query(Release).filter(Release.id == from_release, Release.product_id == product_id).first()
    rel_to   = db.query(Release).filter(Release.id == to_release,   Release.product_id == product_id).first()
    if not rel_from or not rel_to:
        raise HTTPException(status_code=404, detail="指定的版本不存在或不屬於此產品")

    def _comp_key(c: Component) -> str:
        return f"{c.name}@{c.version or ''}"

    def _get_components(release_id: str):
        return {_comp_key(c): c for c in db.query(Component).filter(Component.release_id == release_id).all()}

    def _get_cves(release_id: str) -> dict:
        result = {}
        for c in db.query(Component).filter(Component.release_id == release_id).all():
            for v in c.vulnerabilities:
                result[v.cve_id] = {"cve_id": v.cve_id, "component": _comp_key(c),
                                    "severity": v.severity, "cvss_score": v.cvss_score,
                                    "epss_score": v.epss_score, "is_kev": bool(v.is_kev)}
        return result

    comps_from = _get_components(from_release)
    comps_to   = _get_components(to_release)
    cves_from  = _get_cves(from_release)
    cves_to    = _get_cves(to_release)

    keys_from = set(comps_from); keys_to = set(comps_to)
    cve_from_set = set(cves_from); cve_to_set = set(cves_to)

    return {
        "product_name": product.name,
        "from_version": rel_from.version,
        "to_version": rel_to.version,
        "components": {
            "added":   [{"name": k.split("@")[0], "version": k.split("@")[1]} for k in sorted(keys_to - keys_from)],
            "removed": [{"name": k.split("@")[0], "version": k.split("@")[1]} for k in sorted(keys_from - keys_to)],
            "unchanged": len(keys_from & keys_to),
        },
        "vulnerabilities": {
            "added":   sorted([cves_to[k]   for k in cve_to_set  - cve_from_set], key=lambda x: x["cvss_score"] or 0, reverse=True),
            "removed": sorted([cves_from[k] for k in cve_from_set - cve_to_set],  key=lambda x: x["cvss_score"] or 0, reverse=True),
            "unchanged": len(cve_from_set & cve_to_set),
        },
    }
