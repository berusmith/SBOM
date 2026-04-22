from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_org_scope, require_admin
from app.models.organization import Organization
from app.models.product import Product
from app.schemas.organization import OrganizationCreate, OrganizationResponse
from app.schemas.product import ProductCreate, ProductResponse

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


class OrganizationUpdate(BaseModel):
    name: str


@router.post("", response_model=OrganizationResponse)
def create_organization(payload: OrganizationCreate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
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
def list_organizations(org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    q = db.query(Organization)
    if org_scope:
        q = q.filter(Organization.id == org_scope)
    return q.all()


@router.post("/{org_id}/products", response_model=ProductResponse)
def create_product(org_id: str, payload: ProductCreate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    product = Product(organization_id=org_id, name=payload.name, description=payload.description)
    db.add(product)
    db.commit()
    db.refresh(product)
    return product


@router.patch("/{org_id}", response_model=OrganizationResponse)
def update_organization(org_id: str, payload: OrganizationUpdate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
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
def delete_organization(org_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    db.delete(org)
    db.commit()


@router.get("/{org_id}/products", response_model=list[ProductResponse])
def list_products(org_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    if org_scope and org_scope != org_id:
        raise HTTPException(status_code=403, detail="無權存取此組織")
    return db.query(Product).filter(Product.organization_id == org_id).all()
