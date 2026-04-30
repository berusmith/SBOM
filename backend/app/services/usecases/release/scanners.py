"""Scanner endpoints — Trivy / Syft / reachability source scan.  Filled in D.6."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/releases", tags=["releases"])
