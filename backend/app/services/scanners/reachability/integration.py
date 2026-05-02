"""
Wave-D dispatcher for reachability analysis.

This is the orchestration entry point.  Today (iter-1), it routes to the
single Python analyzer.  Wave D sprint #3 extends this module to:
  - Detect what language(s) the source uses
  - Dispatch each language to its analyzer (python_analyzer / js_analyzer /
    java_analyzer)
  - Merge per-analyzer ScanResult outputs into one canonical ScanResult

The Wave-D contract in __init__.py freezes the PUBLIC interface (scan_zip
+ classify_vulns + ScanResult shape + PackagePresence shape).  Wave D may
freely modify the body of THIS module — internal dispatch is implementation
detail, not part of the public surface.

`classify_vulns` and the `ScanResult` / `PackagePresence` types are
re-exported from python_analyzer at the package level (__init__.py); they
are language-agnostic by design (a label is a label regardless of which
analyzer produced it) so they don't need a dispatcher wrapper.
"""
from __future__ import annotations

from . import python_analyzer
from .python_analyzer import ScanResult


def scan_zip(zip_bytes: bytes) -> ScanResult:
    """Dispatch entry for source-zip scanning.

    Iter-1: routes directly to python_analyzer.scan_zip.
    Wave D: extended to detect language(s) and merge per-language results.

    Pre/post-conditions / Raises: see the Wave-D contract in
    backend/app/services/scanners/reachability/__init__.py.
    """
    return python_analyzer.scan_zip(zip_bytes)
