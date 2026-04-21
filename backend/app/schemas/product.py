from typing import Optional

from pydantic import BaseModel


class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None


class ProductResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: Optional[str]

    class Config:
        from_attributes = True
