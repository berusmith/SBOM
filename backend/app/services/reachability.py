"""
Reachability Phase 2 — module-level analysis.

Phase 1: did the project import this package at all?
Phase 2: was it only imported in test / script directories?

scan_zip() returns a PackagePresence dict:
  {normalised_pkg: {"main": bool, "test": bool}}

classify_vulns() maps each vuln to:
  "reachable"  — imported in main source
  "test_only"  — imported only in test/script paths
  "not_found"  — not imported anywhere
  "unknown"    — component not found in comp map
"""
from __future__ import annotations

import io
import re
import zipfile

# ── limits ────────────────────────────────────────────────────────────────────
MAX_ZIP_BYTES  = 50 * 1024 * 1024
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_FILES      = 5_000

# Path segments that indicate a test / non-production file
_TEST_SEGMENTS = frozenset({
    "test", "tests", "spec", "specs",
    "__test__", "__tests__",
    "scripts", "script",
    "fixtures", "fixture",
    "e2e", "integration",
    "conftest",        # pytest conftest files
})

# ── regex patterns ─────────────────────────────────────────────────────────────
_PY_IMPORT = re.compile(
    r"""^\s*(?:import|from)\s+([\w][\w.]*)""",
    re.MULTILINE,
)
_JS_REQUIRE = re.compile(
    r"""(?:require|from)\s*[\(\s]['"]((?:@[\w-]+/)?[\w][\w.-]*)['"]""",
)


def _normalise(name: str) -> str:
    return name.lower().split(".")[0].replace("-", "_")


def _is_test_path(path: str) -> bool:
    """Return True if any segment of the path looks like a test directory."""
    lower = path.lower().replace("\\", "/")
    parts = lower.split("/")
    # Check directory segments (not the filename itself)
    for part in parts[:-1]:
        if part in _TEST_SEGMENTS:
            return True
    # Also catch filenames like test_foo.py or foo.test.js / foo.spec.ts
    filename = parts[-1]
    if filename.startswith("test_") or filename.startswith("spec_"):
        return True
    stem = filename.rsplit(".", 1)[0]
    if stem.endswith((".test", ".spec")):
        return True
    return False


def _is_text_file(name: str) -> bool:
    return name.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))


def _extract_packages(content: str, filename: str) -> set[str]:
    pkgs: set[str] = set()
    if filename.endswith(".py"):
        for m in _PY_IMPORT.finditer(content):
            pkg = _normalise(m.group(1))
            if pkg:
                pkgs.add(pkg)
    else:
        for m in _JS_REQUIRE.finditer(content):
            pkg = m.group(1)
            if pkg.startswith("."):
                continue
            pkgs.add(_normalise(pkg))
    return pkgs


# Type alias for clarity
PackagePresence = dict[str, dict[str, bool]]  # {pkg: {"main": bool, "test": bool}}


def scan_zip(zip_bytes: bytes) -> PackagePresence:
    """
    Scan a zip archive and return per-package presence info.
    Raises ValueError for oversized or invalid zips.
    """
    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise ValueError(f"壓縮檔超過 {MAX_ZIP_BYTES // 1024 // 1024} MB 上限")

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ValueError("無效的 zip 檔案")

    presence: PackagePresence = {}
    file_count = 0

    for info in zf.infolist():
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

        is_test = _is_test_path(name)
        for pkg in _extract_packages(content, name):
            entry = presence.setdefault(pkg, {"main": False, "test": False})
            if is_test:
                entry["test"] = True
            else:
                entry["main"] = True

    zf.close()
    return presence


def classify_vulns(
    vulns,
    presence: PackagePresence,
    comp_map: dict,
) -> dict[str, str]:
    """
    Map each vuln to a reachability label.
    comp_map: {component_id -> component_obj}
    """
    result: dict[str, str] = {}
    for v in vulns:
        comp = comp_map.get(v.component_id)
        if comp is None:
            result[v.id] = "unknown"
            continue
        pkg = _normalise(comp.name)
        info = presence.get(pkg)
        if info is None:
            result[v.id] = "not_found"
        elif info["main"]:
            result[v.id] = "reachable"
        elif info["test"]:
            result[v.id] = "test_only"
        else:
            result[v.id] = "not_found"
    return result
