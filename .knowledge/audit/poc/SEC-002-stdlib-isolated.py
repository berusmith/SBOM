"""
SEC-002 isolated test — DO NOT RUN against production.
============================================================
Direct test of Python 3.11 stdlib xml.etree.ElementTree against
classic billion-laughs payloads at 4/5/6/7-layer nesting.

Runs in isolated process (no FastAPI), so we can probe scaling
without OOM-ing the live backend.

Stops at any layer that takes > 10s OR allocates > 200MB so we
don't blow up the audit machine itself.
"""
from __future__ import annotations

import os
import sys
import time
import tracemalloc
import xml.etree.ElementTree as ET

# Cross-platform memory limit / measurement
try:
    import psutil
    _proc = psutil.Process(os.getpid())
    def _mem_mb(): return _proc.memory_info().rss / 1024 / 1024
except ImportError:
    def _mem_mb(): return -1.0  # unknown; rely on tracemalloc


def make_payload(depth: int, fanout: int = 10) -> bytes:
    """Build classic billion-laughs with given nesting depth and fanout."""
    lines = ['<?xml version="1.0"?>', '<!DOCTYPE lolz [', '  <!ENTITY lol "lol">']
    prev = "lol"
    for i in range(2, depth + 1):
        body = "".join(f"&{prev};" for _ in range(fanout))
        lines.append(f'  <!ENTITY lol{i} "{body}">')
        prev = f"lol{i}"
    lines.append("]>")
    lines.append('<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">')
    lines.append('  <components>')
    lines.append('    <component type="library">')
    lines.append(f'      <name>&{prev};</name>')
    lines.append('      <version>1.0.0</version>')
    lines.append('    </component>')
    lines.append('  </components>')
    lines.append('</bom>')
    return "\n".join(lines).encode()


def test_layer(depth: int, fanout: int = 10):
    payload = make_payload(depth, fanout)
    expansion = fanout ** (depth - 1)        # 10^(depth-1) expansions of "lol"
    expanded_size_est = expansion * 3        # "lol" = 3 bytes
    print(f"--- depth={depth} (fanout={fanout}) ---")
    print(f"  payload size:           {len(payload):>10} bytes")
    print(f"  if fully expanded:      ~{expanded_size_est:>9} bytes ({expanded_size_est/1024/1024:.1f} MB)")

    mem_before = _mem_mb()
    tracemalloc.start()
    t0 = time.perf_counter()
    error = None
    name_text = ""
    try:
        root = ET.fromstring(payload)
        # Walk to the <name> element to FORCE evaluation of the entity
        for el in root.iter():
            tag = el.tag.split("}", 1)[-1] if "}" in el.tag else el.tag
            if tag == "name" and el.text:
                name_text = el.text
                break
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    elapsed = time.perf_counter() - t0
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    mem_after = _mem_mb()

    print(f"  parse + walk time:      {elapsed:>10.3f}s")
    print(f"  tracemalloc peak:       {peak/1024/1024:>10.2f} MB")
    if mem_before >= 0:
        print(f"  RSS before/after:       {mem_before:>6.1f} / {mem_after:>6.1f} MB  (delta {mem_after-mem_before:+.1f})")
    if error:
        print(f"  RESULT: ERROR {error}")
        return None
    name_len = len(name_text)
    print(f"  <name> text length:     {name_len:>10}  (expected {expanded_size_est:>10} if fully expanded)")
    if name_len >= expanded_size_est * 0.9:
        print(f"  → entity FULLY expanded (no protection)")
    elif name_len == 0 or name_len < 100:
        print(f"  → entity NOT expanded — parser refused or kept as reference")
    else:
        print(f"  → entity PARTIALLY expanded (parser has some limit)")
    return {"depth": depth, "elapsed": elapsed, "peak_mb": peak/1024/1024, "name_len": name_len}


def main():
    print("SEC-002 — isolated test of stdlib xml.etree.ElementTree billion-laughs")
    print(f"Python: {sys.version.split()[0]}")
    print(f"PID: {os.getpid()}\n")

    results = []
    # Build up: 4 → 5 → 6.  Stop if any layer takes > 10s or allocates > 200MB.
    for depth in (4, 5, 6, 7):
        try:
            r = test_layer(depth, fanout=10)
            print()
            if r is None:
                print(f"  [STOP] depth {depth} errored — likely defense triggered")
                break
            results.append(r)
            if r["elapsed"] > 10:
                print(f"  [STOP] depth {depth} took {r['elapsed']:.1f}s — refusing higher to protect audit machine")
                break
            if r["peak_mb"] > 200:
                print(f"  [STOP] depth {depth} allocated {r['peak_mb']:.1f}MB peak — refusing higher")
                break
        except MemoryError:
            print(f"  [MEMORY ERROR] at depth {depth} — vulnerability confirmed at this size")
            break

    print("\n=== summary ===")
    for r in results:
        print(f"  depth={r['depth']}: {r['elapsed']:.3f}s, {r['peak_mb']:.1f} MB peak, name_len={r['name_len']}")

    # Verdict
    if results and any(r["name_len"] > 1000 for r in results):
        print("\n[VULNERABLE] stdlib expanded entities to large strings")
        print("  → SEC-002 confirmed: defusedxml NOT in use, fix required")
        return 1
    else:
        print("\n[INDETERMINATE] entities not fully expanded — investigate further")
        return 0


if __name__ == "__main__":
    sys.exit(main())
