from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class OrganizationCreate(BaseModel):
    name: str
    license_status: Literal["active", "trial", "expired"] = "trial"
    plan: Literal["starter", "standard", "professional"] = "starter"
    username: Optional[str] = None
    password: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    license_status: str
    plan: str = "starter"
    created_at: datetime

    class Config:
        from_attributes = True
