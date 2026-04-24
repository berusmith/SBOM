from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import get_org_scope, require_admin
from app.core.security import hash_password
from app.core.plan import check_starter_limit
from app.models.organization import Organization
from app.models.product import Product
from app.models.user import User
from app.schemas.organization import OrganizationCreate, OrganizationResponse
from app.schemas.product import ProductCreate, ProductResponse

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


class OrganizationUpdate(BaseModel):
    name: str


@router.post("")
def create_organization(payload: OrganizationCreate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):  # noqa: E501
    if payload.username and len(payload.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="帳號至少 3 個字元")
    if payload.password and len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="密碼至少 6 個字元")
    if payload.username and db.query(User).filter(User.username == payload.username.strip()).first():
        raise HTTPException(status_code=409, detail="帳號名稱已存在")

    org = Organization(
        name=payload.name.strip(),
        license_status=payload.license_status,
        plan=getattr(payload, "plan", "starter") or "starter",
    )
    db.add(org)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="客戶名稱已存在")

    account_created = False
    if payload.username and payload.password:
        user = User(
            username=payload.username.strip(),
            hashed_password=hash_password(payload.password),
            role="viewer",
            organization_id=org.id,
        )
        db.add(user)
        account_created = True

    db.commit()
    db.refresh(org)
    audit.record(db, "org_create", _admin, resource_id=org.id, resource_label=org.name)
    db.commit()
    return {
        "id": org.id,
        "name": org.name,
        "license_status": org.license_status,
        "plan": org.plan,
        "created_at": org.created_at,
        "account_created": account_created,
        "username": payload.username.strip() if account_created else None,
    }


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    q = db.query(Organization)
    if org_scope:
        q = q.filter(Organization.id == org_scope)
    return q.all()


@router.post("/{org_id}/products", response_model=ProductResponse)
def create_product(org_id: str, payload: ProductCreate, user: dict = Depends(require_admin),
                   org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    if org_scope and org_scope != org_id:
        raise HTTPException(status_code=403, detail="無權在此組織建立產品")
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    check_starter_limit(db, org_id, "products")
    product = Product(organization_id=org_id, name=payload.name, description=payload.description)
    db.add(product)
    db.commit()
    db.refresh(product)
    audit.record(db, "product_create", user, resource_id=product.id, resource_label=product.name, org_name=org.name)
    db.commit()
    return product


@router.patch("/{org_id}", response_model=OrganizationResponse)
def update_organization(org_id: str, payload: OrganizationUpdate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    old_name = org.name
    org.name = payload.name.strip()
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="客戶名稱已存在")
    audit.record(db, "org_update", _admin, resource_id=org_id, resource_label=f"{old_name} → {org.name}")
    db.commit()
    db.refresh(org)
    return org


class PlanUpdate(BaseModel):
    plan: str   # starter | standard | professional


@router.patch("/{org_id}/plan")
def update_org_plan(org_id: str, payload: PlanUpdate, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin only: set the plan for an organization."""
    if payload.plan not in ("starter", "standard", "professional"):
        raise HTTPException(status_code=400, detail="plan 必須為 starter / standard / professional")
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    old_plan = org.plan
    org.plan = payload.plan
    db.commit()
    audit.record(db, "org_plan_change", _admin, resource_id=org_id, resource_label=f"{org.name}: {old_plan} → {payload.plan}")
    db.commit()
    return {"id": org_id, "plan": org.plan}


@router.delete("/{org_id}", status_code=204)
def delete_organization(org_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org_name = org.name
    db.delete(org)
    db.commit()
    audit.record(db, "org_delete", _admin, resource_id=org_id, resource_label=org_name)
    db.commit()


@router.get("/{org_id}/products", response_model=list[ProductResponse])
def list_products(org_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    if org_scope and org_scope != org_id:
        raise HTTPException(status_code=403, detail="無權存取此組織")
    if not db.query(Organization).filter(Organization.id == org_id).first():
        raise HTTPException(status_code=404, detail="組織不存在")
    return db.query(Product).filter(Product.organization_id == org_id).all()
