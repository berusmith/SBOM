"""
Reachability Phase 1 — import-level analysis.

Unzips uploaded source archive and scans all .py / .js / .ts files for
import statements. Returns a set of normalised package names that are
actually imported by the project.

Normalisation: lowercase, replace - with _ (pip convention).
"""
from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

# ── limits ────────────────────────────────────────────────────────────────────
MAX_ZIP_BYTES   = 50 * 1024 * 1024   # 50 MB total zip
MAX_FILE_BYTES  = 1 * 1024 * 1024    # skip single files > 1 MB
MAX_FILES       = 5_000              # guard against zip bombs

# ── regex patterns ─────────────────────────────────────────────────────────────
# Python:  import X  /  import X.y  /  from X import  /  from X.y import
_PY_IMPORT = re.compile(
    r"""^\s*(?:import|from)\s+([\w][\w.]*)""",
    re.MULTILINE,
)

# JS/TS:  require('X')  require("X")  from 'X'  from "X"
# captures the first path segment (the package name, not ./local paths)
_JS_REQUIRE = re.compile(
    r"""(?:require|from)\s*[\(\s]['"]((?:@[\w-]+/)?[\w][\w.-]*)['"]""",
)


def _normalise(name: str) -> str:
    """Lowercase + replace hyphens with underscores (pip/npm convention)."""
    return name.lower().split(".")[0].replace("-", "_")


def _is_text_file(name: str) -> bool:
    return name.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))


def scan_zip(zip_bytes: bytes) -> set[str]:
    """
    Scan a zip archive for import statements.
    Returns a set of normalised package names found in the source code.
    Raises ValueError for oversized or invalid zips.
    """
    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise ValueError(f"壓縮檔超過 {MAX_ZIP_BYTES // 1024 // 1024} MB 上限")

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ValueError("無效的 zip 檔案")

    imported: set[str] = set()
    file_count = 0

    for info in zf.infolist():
        # Safety: skip directories and dangerous paths
        name = info.filename
        if info.is_dir():
            continue
        if ".." in name or name.startswith("/"):
            continue
        if file_count >= MAX_FILES:
            break
        if not _is_text_file(name):
            continue
        if info.file_size > MAX_FILE_BYTES:
            continue

        file_count += 1
        try:
            content = zf.read(name).decode("utf-8", errors="ignore")
        except Exception:
            continue

        if name.endswith(".py"):
            for m in _PY_IMPORT.finditer(content):
                pkg = _normalise(m.group(1))
                if pkg:
                    imported.add(pkg)
        else:
            for m in _JS_REQUIRE.finditer(content):
                pkg = m.group(1)
                # skip relative imports: ./foo, ../bar
                if pkg.startswith("."):
                    continue
                # scoped npm: @scope/name → keep full but also add bare name
                imported.add(_normalise(pkg))

    zf.close()
    return imported


def classify_vulns(
    vulns,
    imported_packages: set[str],
    purl_to_comp: dict,
) -> dict[str, str]:
    """
    For each vuln, determine reachability based on whether the component's
    package name appears in imported_packages.

    Returns {vuln_id: "imported" | "not_found"}
    """
    result: dict[str, str] = {}
    for v in vulns:
        comp = purl_to_comp.get(v.component_id)
        if comp is None:
            result[v.id] = "unknown"
            continue
        pkg_name = _normalise(comp.name)
        result[v.id] = "imported" if pkg_name in imported_packages else "not_found"
    return result
