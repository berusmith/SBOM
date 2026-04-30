"""SBOM upload — POST /api/releases/{release_id}/sbom.  Filled in D.2."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/releases", tags=["releases"])
