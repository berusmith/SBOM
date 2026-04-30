"""Lifecycle endpoints — get / patch / delete / list / lock / gate / graph.  Filled in D.7."""
from fastapi import APIRouter

router = APIRouter(prefix="/api/releases", tags=["releases"])
