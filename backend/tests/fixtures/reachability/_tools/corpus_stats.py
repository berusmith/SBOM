"""
Per-language / per-track counts for the reachability fixture corpus.
Validates schema first; refuses to print stats on a corpus that fails
validation (a meta.yaml with a typo'd label would silently distort the
numbers).

Run from repo root:
    python backend/tests/fixtures/reachability/_tools/corpus_stats.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LANG_DIRS = ("python", "javascript", "typescript", "java")
LABELS = ("function_reachable", "reachable", "test_only", "not_found", "unknown_acceptable")


def _load_metas() -> list[tuple[Path, dict]]:
    out: list[tuple[Path, dict]] = []
    for d in LANG_DIRS:
        for m in sorted((ROOT / d).rglob("meta.yaml")):
            try:
                with m.open(encoding="utf-8") as f:
                    out.append((m, yaml.safe_load(f) or {}))
            except yaml.YAMLError:
                pass
    return out


def main() -> int:
    sys.path.insert(0, str(Path(__file__).parent))
    from validate_meta import main as validate_main
    if validate_main() != 0:
        print("\nrefusing to print stats on a corpus that fails validation", file=sys.stderr)
        return 1
    print()  # blank line after validator output

    metas = _load_metas()
    if not metas:
        print("no fixtures found")
        return 0

    by_lang_label: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_track:      dict[str, int] = defaultdict(int)
    expected_reach_yes = 0
    expected_reach_no  = 0

    for _, meta in metas:
        lang  = meta.get("language", "?")
        label = meta.get("expected_label", "?")
        ftype = meta.get("fixture_type", "?")
        by_lang_label[lang][label] += 1
        by_track[ftype] += 1
        if meta.get("expected_reachable") is True:
            expected_reach_yes += 1
        elif meta.get("expected_reachable") is False:
            expected_reach_no += 1

    # Per-language breakdown
    print("=" * 78)
    print(f"{'language':<12} {'fnReach':>8} {'reach':>6} {'test':>6} "
          f"{'notFnd':>7} {'unkOK':>6} {'TOTAL':>6}")
    print("-" * 78)
    grand = {label: 0 for label in LABELS}
    for lang in LANG_DIRS:
        row = by_lang_label.get(lang, {})
        if not row:
            continue
        cells = [row.get(label, 0) for label in LABELS]
        for label, n in zip(LABELS, cells):
            grand[label] += n
        print(f"{lang:<12} "
              f"{cells[0]:>8} {cells[1]:>6} {cells[2]:>6} "
              f"{cells[3]:>7} {cells[4]:>6} {sum(cells):>6}")
    print("-" * 78)
    print(f"{'TOTAL':<12} "
          f"{grand['function_reachable']:>8} {grand['reachable']:>6} "
          f"{grand['test_only']:>6} {grand['not_found']:>7} "
          f"{grand['unknown_acceptable']:>6} {sum(grand.values()):>6}")
    print()

    # Two-track summary
    print("Tracks (fixture_type):")
    for k in ("cve_reachability", "framework_mechanism"):
        print(f"  {k:<22} {by_track.get(k, 0):>3}")
    print()

    # Reachability balance
    print(f"FP/FN baseline: {expected_reach_yes} reachable / "
          f"{expected_reach_no} unreachable "
          f"(non-binary: {len(metas) - expected_reach_yes - expected_reach_no})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
