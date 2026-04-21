from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ReleaseCreate(BaseModel):
    version: str


class ReleaseResponse(BaseModel):
    id: str
    product_id: str
    version: str
    sbom_file_path: Optional[str]
    dtrack_project_uuid: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
