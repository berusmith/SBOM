"""
Validate every meta.yaml under tests/fixtures/reachability/ against the
rules in _schema/meta.schema.yaml.  Pure stdlib + PyYAML — no jsonschema.

Run from repo root:
    python backend/tests/fixtures/reachability/_tools/validate_meta.py
Exits 0 if all valid, 1 with a summary of failures otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LANG_DIRS = ("python", "javascript", "typescript", "java")

REQUIRED_FIELDS = (
    "fixture_type", "language", "expected_reachable",
    "expected_label", "transitive_only", "notes",
)
CONDITIONAL_FIELDS_CVE = (
    "cve_id", "package", "ecosystem", "affected_versions",
    "vulnerable_symbols", "import_names",
)
ENUMS = {
    "fixture_type":   {"cve_reachability", "framework_mechanism"},
    "language":       {"python", "javascript", "typescript", "java"},
    "expected_label": {
        "function_reachable", "reachable", "test_only", "not_found",
        "unknown_acceptable",
    },
    "ecosystem":      {"pypi", "npm", "maven", "go", "cargo", "rubygems"},
}

REACHABLE_LABELS    = {"function_reachable", "reachable", "unknown_acceptable"}
UNREACHABLE_LABELS  = {"not_found", "test_only", "unknown_acceptable"}


def _check_one(path: Path) -> list[str]:
    """Return list of error strings (empty = valid)."""
    errs: list[str] = []
    try:
        with path.open(encoding="utf-8") as f:
            meta = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    except OSError as exc:
        return [f"cannot read: {exc}"]

    if not isinstance(meta, dict):
        return ["meta.yaml must be a top-level mapping"]

    for f in REQUIRED_FIELDS:
        if f not in meta:
            errs.append(f"missing required field: {f}")

    for k, allowed in ENUMS.items():
        if k in meta and meta[k] not in allowed:
            errs.append(f"{k}={meta[k]!r} not in {sorted(allowed)}")

    for k in ("expected_reachable", "transitive_only"):
        if k in meta and not isinstance(meta[k], bool):
            errs.append(f"{k} must be bool, got {type(meta[k]).__name__}")

    if meta.get("fixture_type") == "cve_reachability":
        for f in CONDITIONAL_FIELDS_CVE:
            if not meta.get(f):
                errs.append(f"cve_reachability fixture missing required field: {f}")
        syms = meta.get("vulnerable_symbols")
        if syms is not None and (not isinstance(syms, list) or not syms):
            errs.append("vulnerable_symbols must be a non-empty list")
        imps = meta.get("import_names")
        if imps is not None and (not isinstance(imps, list) or not imps):
            errs.append("import_names must be a non-empty list")

    er = meta.get("expected_reachable")
    el = meta.get("expected_label")
    if er is True and el not in REACHABLE_LABELS:
        errs.append(
            f"expected_reachable=true but expected_label={el!r} "
            f"(must be one of {sorted(REACHABLE_LABELS)})"
        )
    if er is False and el not in UNREACHABLE_LABELS:
        errs.append(
            f"expected_reachable=false but expected_label={el!r} "
            f"(must be one of {sorted(UNREACHABLE_LABELS)})"
        )

    fix_lang_dir = path.parents[1].name
    if meta.get("language") and meta["language"] != fix_lang_dir:
        errs.append(
            f"language={meta['language']!r} but fixture lives under "
            f"{fix_lang_dir}/ — directory and field must agree"
        )

    return errs


def main() -> int:
    metas = sorted(
        m for d in LANG_DIRS for m in (ROOT / d).rglob("meta.yaml")
    )
    if not metas:
        print(f"no meta.yaml found under {ROOT}")
        return 0

    failed: list[tuple[Path, list[str]]] = []
    for m in metas:
        errs = _check_one(m)
        if errs:
            failed.append((m, errs))

    print(f"checked {len(metas)} meta.yaml file(s)")
    if not failed:
        print("[OK] all valid")
        return 0

    print(f"[FAIL] {len(failed)} fixture(s) failed validation:")
    for m, errs in failed:
        rel = m.relative_to(ROOT)
        print(f"\n  {rel}")
        for e in errs:
            print(f"    - {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
