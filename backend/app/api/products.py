from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.product import Product
from app.models.release import Release
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
