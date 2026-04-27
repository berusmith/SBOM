"""
PoC for SEC-018 — DO NOT RUN against production without permission.
============================================================
Verifies that nginx returns the four security headers required by
SEC-018:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - Referrer-Policy: strict-origin-when-cross-origin
  - Permissions-Policy: geolocation=(), camera=(), microphone=()

Targets nginx (default :80).  Skip / report mismatch if no nginx is
running (e.g. dev mode where uvicorn is hit directly).

Pre-fix:  all four headers absent → MISSING
Post-fix: all four present       → PASS

Setup:
  POC_API_URL=http://<nginx-host>  python SEC-018-nginx-security-headers.py
  Defaults to http://127.0.0.1 (port 80).
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("POC_API_URL", "http://127.0.0.1")

EXPECTED = {
    "x-content-type-options": "nosniff",
    "x-frame-options":        "DENY",
    "referrer-policy":        "strict-origin-when-cross-origin",
    "permissions-policy":     "geolocation=(), camera=(), microphone=()",
}


def probe(path: str) -> dict[str, str]:
    req = urllib.request.Request(URL.rstrip("/") + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            # urllib lower-cases header keys
            return {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in e.headers.items()}
    except urllib.error.URLError as e:
        print(f"[skip] cannot reach {URL}: {e}")
        sys.exit(0)


def check(headers: dict[str, str], where: str) -> int:
    missing = []
    wrong = []
    for h, want in EXPECTED.items():
        got = headers.get(h)
        if got is None:
            missing.append(h)
        elif got.strip() != want:
            wrong.append(f"{h}: want={want!r} got={got!r}")

    print(f"--- {where} ---")
    if not missing and not wrong:
        print("  [PASS] all 4 security headers present and correct")
        return 0
    for h in missing:
        print(f"  [MISSING] {h}")
    for w in wrong:
        print(f"  [WRONG]   {w}")
    return 1


def main() -> int:
    print(f"PoC SEC-018 - nginx security headers ({URL})\n")
    fails = 0
    fails += check(probe("/"), "GET /")
    fails += check(probe("/index.html"), "GET /index.html")

    print()
    if fails == 0:
        print("=" * 60)
        print("[NO LEAK] all probed paths return the SEC-018 header set")
        print("=" * 60)
        return 0
    print("=" * 60)
    print(f"[GAP] {fails} probe(s) had missing or wrong headers")
    print("=" * 60)
    return 1


if __name__ == "__main__":
    sys.exit(main())
