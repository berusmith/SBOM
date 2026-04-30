"""Report endpoints — PDF / CSAF / evidence / format export.  Filled in D.4."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/releases", tags=["releases"])
