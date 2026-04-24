"""
Plan definitions and feature guards.

Plans:
  starter      — free/eval, limited features and data volume
  standard     — core compliance (CRA + IEC 62443-4-1)
  professional — full compliance (all IEC 62443 + TISAX + Reachability + ...)

Usage in routers:
  from app.core.plan import require_plan
  ...
  @router.get("/{release_id}/compliance/iec62443-4-2")
  def iec42(..., _=Depends(require_plan("professional", release_id=release_id))):
      ...
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, get_org_scope

# ── Plan hierarchy ─────────────────────────────────────────────────────────────
_PLAN_RANK = {"starter": 0, "standard": 1, "professional": 2}

# ── Starter limits ─────────────────────────────────────────────────────────────
STARTER_LIMITS = {
    "products":  3,
    "releases":  10,   # total across all products in the org
    "users":     2,
}

# ── Feature → minimum plan ────────────────────────────────────────────────────
FEATURE_PLAN: dict[str, str] = {
    # Standard+ features
    "cra":              "standard",
    "iec62443_41":      "standard",
    "epss":             "standard",
    "kev":              "standard",
    "ghsa":             "standard",
    "monitor":          "standard",
    "sso":              "standard",
    "convert":          "standard",
    "sbom_quality":     "standard",
    "cve_impact":       "standard",
    # Professional features
    "iec62443_42":      "professional",
    "iec62443_33":      "professional",
    "tisax":            "professional",
    "reachability":     "professional",
    "signature":        "professional",
    "trivy":            "professional",
}


def _org_plan(db: Session, org_id: str | None) -> str:
    """Return the plan for an org. Admin (no org) gets 'professional'."""
    if not org_id:
        return "professional"
    from app.models.organization import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    return (org.plan if org else "starter") or "starter"


def _meets_plan(org_plan: str, required: str) -> bool:
    return _PLAN_RANK.get(org_plan, 0) >= _PLAN_RANK.get(required, 0)


def require_plan(feature: str):
    """
    FastAPI dependency that raises 402 if the current user's org plan
    does not include the requested feature.
    Admin users (no org scope) always pass.
    """
    required = FEATURE_PLAN.get(feature, "starter")

    def _check(
        user: dict = Depends(get_current_user),
        org_scope: str | None = Depends(get_org_scope),
        db: Session = Depends(get_db),
    ):
        if user.get("role") == "admin":
            return   # admin always has access
        org_id = org_scope or user.get("org_id")
        plan = _org_plan(db, org_id)
        if not _meets_plan(plan, required):
            raise HTTPException(
                status_code=402,
                detail=f"此功能需要 {required.capitalize()} 方案，目前為 {plan.capitalize()} 方案",
            )
    return _check


def get_org_plan(
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
) -> str:
    """Dependency that returns the current org's plan string."""
    if user.get("role") == "admin":
        return "professional"
    org_id = org_scope or user.get("org_id")
    return _org_plan(db, org_id)


def check_starter_limit(db: Session, org_id: str, resource: str) -> None:
    """
    Raise 402 if the org is on Starter plan and has hit the resource limit.
    resource: 'products' | 'releases'
    """
    plan = _org_plan(db, org_id)
    if plan != "starter":
        return
    limit = STARTER_LIMITS.get(resource, 999)

    from app.models.product import Product
    from app.models.release import Release

    if resource == "products":
        count = db.query(Product).filter(Product.organization_id == org_id).count()
    elif resource == "releases":
        count = (
            db.query(Release)
            .join(Product, Product.id == Release.product_id)
            .filter(Product.organization_id == org_id)
            .count()
        )
    else:
        return

    if count >= limit:
        raise HTTPException(
            status_code=402,
            detail=f"Starter 方案上限：每組織最多 {limit} 個{resource}。升級至 Standard 方案以解除限制。",
        )
