"""
Run the existing Python reachability analyzer (app.services.reachability)
against every Python fixture in the corpus and report FP/FN.

JS/TS/Java fixtures are listed but skipped — the analyzer is Python-only
today; sprint #3 (Wave D) extends coverage and this runner already has
the wiring in place to flip them on.

Run from repo root:
    python backend/tests/fixtures/reachability/_runner/run_corpus.py
Exits 0 if FP/FN both 0 on Python track; non-zero otherwise.
"""
from __future__ import annotations

import io
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

import yaml

ROOT     = Path(__file__).resolve().parents[1]
REPO     = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO / "backend"))

from app.services.reachability import scan_zip   # noqa: E402

LANG_DIRS  = ("python", "javascript", "typescript", "java")
SUPPORTED  = {"python"}                            # what scan_zip understands today

REACHABLE_LABELS    = {"function_reachable", "reachable"}
UNREACHABLE_LABELS  = {"not_found", "test_only"}


def _pack_fixture(fixture_dir: Path) -> bytes:
    """Zip the fixture's source tree (everything except meta.yaml) into bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(fixture_dir.rglob("*")):
            if p.is_dir() or p.name == "meta.yaml":
                continue
            arcname = str(p.relative_to(fixture_dir)).replace("\\", "/")
            zf.write(p, arcname=arcname)
    return buf.getvalue()


def _label_for_import_names(import_names: list[str], scan) -> str:
    """
    Re-derive the same label classify_vulns() would, but without DB models.
    Walks every import name (e.g. pyyaml exposes `yaml`, pillow exposes `PIL`)
    and returns the strongest verdict across them — function_reachable wins
    over reachable wins over test_only wins over not_found.
    """
    from app.services.reachability import _normalise
    best = "not_found"
    rank = {"function_reachable": 4, "reachable": 3, "test_only": 2, "not_found": 1}
    for name in import_names:
        pkg = _normalise(name)
        if pkg in scan.ast_reachable:
            cand = "function_reachable"
        else:
            info = scan.presence.get(pkg)
            if info is None:
                cand = "not_found"
            elif info["main"]:
                cand = "reachable"
            elif info["test"]:
                cand = "test_only"
            else:
                cand = "not_found"
        if rank[cand] > rank[best]:
            best = cand
    return best


def main() -> int:
    metas: list[tuple[Path, dict]] = []
    for d in LANG_DIRS:
        for m in sorted((ROOT / d).rglob("meta.yaml")):
            with m.open(encoding="utf-8") as f:
                metas.append((m, yaml.safe_load(f) or {}))

    if not metas:
        print("no fixtures found")
        return 0

    runs = {"pass": 0, "fp": 0, "fn": 0, "track_mismatch": 0, "skipped": 0}
    failures: list[str] = []
    by_lang: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for meta_path, meta in metas:
        lang = meta.get("language", "?")
        if lang not in SUPPORTED:
            runs["skipped"] += 1
            by_lang[lang]["skipped"] += 1
            continue

        fixture_dir = meta_path.parent
        zip_bytes   = _pack_fixture(fixture_dir)

        try:
            scan = scan_zip(zip_bytes)
        except Exception as exc:
            runs["fn"] += 1
            failures.append(f"{fixture_dir.name}: scan_zip raised {exc!r}")
            by_lang[lang]["error"] += 1
            continue

        import_names = meta.get("import_names")
        if not import_names:
            runs["track_mismatch"] += 1
            by_lang[lang]["no_pkg"] += 1
            continue

        actual    = _label_for_import_names(import_names, scan)
        expected  = meta.get("expected_label")

        # unknown_acceptable: any non-guessing analyzer behaviour passes
        # because today's Python analyzer never outputs `unknown` literally
        # — it forces a four-way decision.  Mark these as "skipped" until
        # the analyzer learns to emit `unknown`.
        if expected == "unknown_acceptable":
            runs["skipped"] += 1
            by_lang[lang]["unknown_skip"] += 1
            continue

        # Boil down to reach-or-not for the FP/FN counters; the exact
        # label match is a stricter overlay we report separately.
        actual_reach   = actual   in REACHABLE_LABELS
        expected_reach = meta.get("expected_reachable") is True

        if expected_reach == actual_reach:
            runs["pass"] += 1
            by_lang[lang]["pass"] += 1
        elif expected_reach and not actual_reach:
            runs["fn"] += 1
            by_lang[lang]["fn"] += 1
            failures.append(
                f"FN  {fixture_dir.name}: expected reachable ({expected}), "
                f"got {actual}"
            )
        else:
            runs["fp"] += 1
            by_lang[lang]["fp"] += 1
            failures.append(
                f"FP  {fixture_dir.name}: expected unreachable ({expected}), "
                f"got {actual}"
            )

    # ── report ────────────────────────────────────────────────────────────────
    print("Reachability corpus run")
    print("=" * 60)
    for lang in LANG_DIRS:
        if not by_lang.get(lang):
            continue
        cells = by_lang[lang]
        bits = " ".join(f"{k}={v}" for k, v in sorted(cells.items()))
        print(f"  {lang:<12} {bits}")
    print("-" * 60)
    print(f"  pass           {runs['pass']}")
    print(f"  false positive {runs['fp']}")
    print(f"  false negative {runs['fn']}")
    print(f"  skipped        {runs['skipped']}  (lang not yet supported / unknown_acceptable)")
    if runs["track_mismatch"]:
        print(f"  no-pkg         {runs['track_mismatch']}  (framework_mechanism, no package)")

    if failures:
        print()
        print("Failures:")
        for f in failures:
            print(f"  {f}")

    # Exit non-zero only if we actually saw FP or FN on the supported track —
    # skipped fixtures don't fail the run.
    return 0 if runs["fp"] == 0 and runs["fn"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
