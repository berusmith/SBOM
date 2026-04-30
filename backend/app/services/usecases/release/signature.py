"""Signature endpoints — upload / verify / delete.  Filled in D.5 (J5 carve-out)."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/releases", tags=["releases"])
