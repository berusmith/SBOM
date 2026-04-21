from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.organization import Organization
from app.models.product import Product
from app.schemas.organization import OrganizationCreate, OrganizationResponse
from app.schemas.product import ProductCreate, ProductResponse

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


class OrganizationUpdate(BaseModel):
    name: str


@router.post("", response_model=OrganizationResponse)
def create_organization(payload: OrganizationCreate, db: Session = Depends(get_db)):
    org = Organization(name=payload.name, license_status=payload.license_status)
    db.add(org)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="客戶名稱已存在")
    db.refresh(org)
    return org


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(db: Session = Depends(get_db)):
    return db.query(Organization).all()


@router.post("/{org_id}/products", response_model=ProductResponse)
def create_product(org_id: str, payload: ProductCreate, db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    product = Product(organization_id=org_id, name=payload.name, description=payload.description)
    db.add(product)
    db.commit()
    db.refresh(product)
    return product


@router.patch("/{org_id}", response_model=OrganizationResponse)
def update_organization(org_id: str, payload: OrganizationUpdate, db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org.name = payload.name.strip()
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="客戶名稱已存在")
    db.refresh(org)
    return org


@router.delete("/{org_id}", status_code=204)
def delete_organization(org_id: str, db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    db.delete(org)
    db.commit()


@router.get("/{org_id}/products", response_model=list[ProductResponse])
def list_products(org_id: str, db: Session = Depends(get_db)):
    return db.query(Product).filter(Product.organization_id == org_id).all()
