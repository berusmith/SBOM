"""Enrichment endpoints — rescan + EPSS + NVD + GHSA.  Filled in D.3."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/releases", tags=["releases"])
