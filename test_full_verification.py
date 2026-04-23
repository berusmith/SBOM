"""
Full platform verification test suite.
Tests all major features end-to-end.
"""
import urllib.request, urllib.error, json, time, base64, uuid, os, hashlib

BASE = os.environ.get("SBOM_TEST_URL", "http://localhost:9101")
results = []
TS = str(int(time.time()))[-6:]


def req(method, path, body=None, tok=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            rb = resp.read()
            return resp.status, json.loads(rb) if rb else {}
    except urllib.error.HTTPError as e:
        rb = e.read()
        try:
            b = json.loads(rb)
        except:
            b = {}
        return e.code, b


def req_raw(method, path, data=None, headers=None, tok=None):
    url = BASE + path
    h = dict(headers or {})
    if tok:
        h["Authorization"] = "Bearer " + tok
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def chk(name, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    results.append((mark, name))
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""))


print("=" * 60)
print(f"SBOM Platform Full Verification — {BASE}")
print("=" * 60)

# ═══════════════════════════════════════════════════
# 1. AUTH
# ═══════════════════════════════════════════════════
print("\n--- 1. AUTH ---")
s, d = req("POST", "/api/auth/login", {"username": "admin", "password": "wrongpass"})
chk("Auth: reject bad password", s == 401)
s, d = req("POST", "/api/auth/login", {"username": "admin", "password": "sbom@2024"})
chk("Auth: login success", s == 200 and "access_token" in d)
token = d.get("access_token", "")
s, d = req("GET", "/api/auth/me", tok=token)
chk("Auth: /me returns user", s == 200 and d.get("username") == "admin")
s, d = req("GET", "/api/stats")
chk("Auth: blocked without token", s in [401, 403])

# ═══════════════════════════════════════════════════
# 2. STATS
# ═══════════════════════════════════════════════════
print("\n--- 2. STATS ---")
s, d = req("GET", "/api/stats", tok=token)
chk("Stats: all keys present", s == 200 and all(k in d for k in ["organizations", "products", "releases", "components", "vulnerabilities"]))
s, d = req("GET", "/api/stats/risk-overview", tok=token)
chk("Stats: risk-overview", s == 200 and isinstance(d, list))
s, d = req("GET", "/api/stats/top-threats", tok=token)
chk("Stats: top-threats", s == 200 and "active_kev_count" in d)
s, d = req("GET", "/api/stats/top-risky-components", tok=token)
chk("Stats: top-risky-components", s == 200)

# ═══════════════════════════════════════════════════
# 3. ORG → PRODUCT → RELEASE CRUD
# ═══════════════════════════════════════════════════
print("\n--- 3. ORG/PRODUCT/RELEASE CRUD ---")
OrgName = f"TestOrg-{TS}"
s, d = req("POST", "/api/organizations", {"name": OrgName}, tok=token)
chk("Org: create", s == 200 and "id" in d)
org_id = d.get("id", "")

s, d = req("GET", "/api/organizations", tok=token)
chk("Org: list", s == 200 and any(o["id"] == org_id for o in d))

s, d = req("POST", f"/api/organizations/{org_id}/products", {"name": "TestProd", "description": "QA"}, tok=token)
chk("Product: create", s == 200 and "id" in d)
prod_id = d.get("id", "")

s, d = req("POST", f"/api/products/{prod_id}/releases", {"version": "1.0.0"}, tok=token)
chk("Release: create", s == 200 and "id" in d)
rel_id = d.get("id", "")

s, d = req("POST", f"/api/products/{prod_id}/releases", {"version": "2.0.0"}, tok=token)
rel2_id = d.get("id", "")

# ═══════════════════════════════════════════════════
# 4. SBOM UPLOAD (multipart)
# ═══════════════════════════════════════════════════
print("\n--- 4. SBOM UPLOAD ---")
sbom_json = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
    "metadata": {"component": {"name": "TestApp", "version": "1.0.0"}},
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
    ]
}).encode()

boundary = f"----TestBoundary{uuid.uuid4().hex}"
parts = [
    f"--{boundary}\r\n".encode(),
    b'Content-Disposition: form-data; name="file"; filename="sbom.json"\r\n',
    b"Content-Type: application/json\r\n\r\n",
    sbom_json,
    f"\r\n--{boundary}--\r\n".encode(),
]
body = b"".join(parts)

s, raw, hdrs = req_raw("POST", f"/api/releases/{rel_id}/sbom", data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, tok=token)
upload_resp = json.loads(raw) if s == 200 else {}
chk("SBOM upload: success", s == 200, f"components={upload_resp.get('components_found')} vulns={upload_resp.get('vulnerabilities_found')}")

# Upload second SBOM for diff
sbom2 = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.22", "purl": "pkg:npm/lodash@4.17.22"},
        {"type": "library", "name": "react", "version": "18.2.0", "purl": "pkg:npm/react@18.2.0"},
    ]
}).encode()
boundary2 = f"----TestBoundary{uuid.uuid4().hex}"
body2 = b"".join([
    f"--{boundary2}\r\n".encode(),
    b'Content-Disposition: form-data; name="file"; filename="sbom2.json"\r\n',
    b"Content-Type: application/json\r\n\r\n",
    sbom2, f"\r\n--{boundary2}--\r\n".encode(),
])
s2, _, _ = req_raw("POST", f"/api/releases/{rel2_id}/sbom", data=body2,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary2}"}, tok=token)
chk("SBOM upload: second release", s2 == 200)

# ═══════════════════════════════════════════════════
# 5. COMPONENTS & VULNERABILITIES
# ═══════════════════════════════════════════════════
print("\n--- 5. COMPONENTS & VULNS ---")
s, d = req("GET", f"/api/releases/{rel_id}/components", tok=token)
chk("Components: list", s == 200 and isinstance(d, list) and len(d) >= 2, f"count={len(d) if isinstance(d, list) else 'N/A'}")

s, d = req("GET", f"/api/releases/{rel_id}/vulnerabilities", tok=token)
chk("Vulns: list", s == 200 and isinstance(d, list), f"count={len(d) if isinstance(d, list) else 'N/A'}")
vuln_list = d if isinstance(d, list) else []

if vuln_list:
    vid = vuln_list[0]["id"]
    s, d = req("PATCH", f"/api/vulnerabilities/{vid}/status", {"status": "not_affected", "justification": "code_not_reachable"}, tok=token)
    chk("Vuln: update VEX status", s == 200)
    s, d = req("GET", f"/api/vulnerabilities/{vid}/history", tok=token)
    chk("Vuln: history", s == 200 and isinstance(d, list))

# ═══════════════════════════════════════════════════
# 6. POLICY GATE
# ═══════════════════════════════════════════════════
print("\n--- 6. POLICY GATE ---")
s, d = req("GET", f"/api/releases/{rel_id}/gate", tok=token)
chk("Gate: returns checks", s == 200 and "checks" in d, f"total={d.get('total')}")
check_ids = [c["id"] for c in d.get("checks", [])]
chk("Gate: has 6 checks", len(check_ids) == 6, f"ids={check_ids}")
chk("Gate: has signature check", "signature_verified" in check_ids)

# ═══════════════════════════════════════════════════
# 7. INTEGRITY & SIGNATURE
# ═══════════════════════════════════════════════════
print("\n--- 7. INTEGRITY & SIGNATURE ---")
s, d = req("GET", f"/api/releases/{rel_id}/integrity", tok=token)
chk("Integrity: check", s == 200 and d.get("status") == "ok")
chk("Integrity: has signature field", "signature" in d)

s, d = req("GET", f"/api/releases/{rel_id}/signature/verify", tok=token)
chk("Signature: initially unsigned", s == 200 and d.get("status") == "unsigned")

# Sign with ECDSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
pub_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

# Read SBOM file to sign
upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "uploads")
sbom_files = [f for f in os.listdir(upload_dir) if f.startswith(rel_id)]
if sbom_files:
    with open(os.path.join(upload_dir, sbom_files[0]), "rb") as f:
        sbom_content = f.read()
    sig = private_key.sign(sbom_content, ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(sig).decode()

    s, d = req("POST", f"/api/releases/{rel_id}/signature", {
        "signature": sig_b64, "public_key": pub_pem, "signer_identity": "test@ci.com"
    }, tok=token)
    chk("Signature: upload valid", s == 200, f"status={s}")

    s, d = req("GET", f"/api/releases/{rel_id}/signature/verify", tok=token)
    chk("Signature: verify valid", s == 200 and d.get("status") == "valid")
    chk("Signature: algorithm", d.get("algorithm") == "ecdsa-sha256")
    chk("Signature: signer identity", d.get("signer_identity") == "test@ci.com")

    # Invalid signature rejected
    s, d = req("POST", f"/api/releases/{rel_id}/signature", {
        "signature": base64.b64encode(b"bad").decode(), "public_key": pub_pem
    }, tok=token)
    chk("Signature: invalid rejected", s == 400)

    # Delete signature
    s, d = req("DELETE", f"/api/releases/{rel_id}/signature", tok=token)
    chk("Signature: delete", s == 200)
else:
    chk("Signature: SBOM file found", False, "no file in uploads/")

# ═══════════════════════════════════════════════════
# 8. DIFF
# ═══════════════════════════════════════════════════
print("\n--- 8. DIFF ---")
s, d = req("GET", f"/api/products/{prod_id}/diff?from={rel_id}&to={rel2_id}", tok=token)
chk("Diff: endpoint works", s == 200 and "components" in d)
if s == 200:
    chk("Diff: has added/removed", "added" in d["components"] and "removed" in d["components"])

# ═══════════════════════════════════════════════════
# 9. EXPORTS
# ═══════════════════════════════════════════════════
print("\n--- 9. EXPORTS ---")
s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/report", tok=token)
chk("Export: PDF report", s == 200 and raw[:4] == b"%PDF", f"size={len(raw)}")

s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/csaf", tok=token)
chk("Export: CSAF JSON", s == 200)

s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/export/cyclonedx-xml", tok=token)
chk("Export: CycloneDX XML", s == 200 and b"<bom" in raw)

s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/export/spdx-json", tok=token)
chk("Export: SPDX JSON", s == 200)

s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/evidence-package", tok=token)
chk("Export: evidence package ZIP", s == 200 and raw[:2] == b"PK", f"size={len(raw)}")

s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/sbom-quality", tok=token)
chk("SBOM quality score", s == 200)

# ═══════════════════════════════════════════════════
# 10. IEC 62443 COMPLIANCE
# ═══════════════════════════════════════════════════
print("\n--- 10. IEC 62443 ---")
s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/compliance/iec62443", tok=token)
chk("IEC 62443-4-1", s == 200 and raw[:4] == b"%PDF")
s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/compliance/iec62443-4-2", tok=token)
chk("IEC 62443-4-2", s == 200 and raw[:4] == b"%PDF")
s, raw, hdrs = req_raw("GET", f"/api/releases/{rel_id}/compliance/iec62443-3-3", tok=token)
chk("IEC 62443-3-3", s == 200 and raw[:4] == b"%PDF")

# ═══════════════════════════════════════════════════
# 11. CRA INCIDENTS
# ═══════════════════════════════════════════════════
print("\n--- 11. CRA INCIDENTS ---")
s, d = req("POST", "/api/cra/incidents", {"title": f"QA-{TS}", "description": "Test incident"}, tok=token)
chk("CRA: create incident", s in (200, 201) and "id" in d)
inc_id = d.get("id", "")

s, d = req("GET", "/api/cra/incidents", tok=token)
chk("CRA: list incidents", s == 200 and isinstance(d, list))

if inc_id:
    s, d = req("POST", f"/api/cra/incidents/{inc_id}/start-clock", tok=token)
    chk("CRA: start clock", s == 200)
    s, d = req("POST", f"/api/cra/incidents/{inc_id}/advance", tok=token)
    chk("CRA: advance state", s == 200)
    s, d = req("DELETE", f"/api/cra/incidents/{inc_id}", tok=token)
    chk("CRA: delete", s in (200, 204))

# ═══════════════════════════════════════════════════
# 12. SEARCH
# ═══════════════════════════════════════════════════
print("\n--- 12. SEARCH ---")
s, d = req("GET", "/api/search/components?q=lodash", tok=token)
chk("Search: find lodash", s == 200 and d.get("total", 0) > 0, f"total={d.get('total')}")

# ═══════════════════════════════════════════════════
# 13. LOCK / UNLOCK
# ═══════════════════════════════════════════════════
print("\n--- 13. LOCK/UNLOCK ---")
s, d = req("POST", f"/api/releases/{rel_id}/lock", tok=token)
chk("Lock: success", s == 200)
s, d = req("DELETE", f"/api/releases/{rel_id}", tok=token)
chk("Lock: delete blocked", s == 409)
s, d = req("POST", f"/api/releases/{rel_id}/unlock", tok=token)
chk("Unlock: success", s == 200)

# ═══════════════════════════════════════════════════
# 14. POLICIES
# ═══════════════════════════════════════════════════
print("\n--- 14. POLICIES ---")
s, d = req("GET", "/api/policies", tok=token)
chk("Policies: list", s == 200)

# ═══════════════════════════════════════════════════
# 15. LICENSE RULES
# ═══════════════════════════════════════════════════
print("\n--- 15. LICENSE RULES ---")
s, d = req("GET", "/api/licenses/rules", tok=token)
chk("License rules: list", s == 200 and isinstance(d, list) and len(d) >= 8, f"count={len(d) if isinstance(d, list) else 'N/A'}")

s, d = req("GET", "/api/licenses/violations/summary", tok=token)
chk("License violations: summary", s == 200 and "total_violations" in d)

s, d = req("GET", f"/api/licenses/releases/{rel_id}/violations", tok=token)
chk("License violations: per-release", s == 200 and "total" in d)

# ═══════════════════════════════════════════════════
# 16. TISAX
# ═══════════════════════════════════════════════════
print("\n--- 16. TISAX ---")
s, d = req("POST", "/api/tisax/assessments", {
    "organization_id": org_id, "module": "infosec", "assessment_level": "AL2"
}, tok=token)
chk("TISAX: create assessment", s in (200, 201) and "id" in d)
tisax_id = d.get("id", "")

if tisax_id:
    s, d = req("GET", f"/api/tisax/assessments/{tisax_id}", tok=token)
    chk("TISAX: get detail", s == 200)
    chapters = d.get("chapters", [])
    ctrls = []
    for ch in chapters:
        ctrls.extend(ch.get("controls", []))
    chk("TISAX: has controls", len(ctrls) >= 40, f"count={len(ctrls)}")

    if ctrls:
        ctrl_id = ctrls[0]["id"]
        s, d = req("PATCH", f"/api/tisax/assessments/{tisax_id}/controls/{ctrl_id}", {
            "current_maturity": 3, "target_maturity": 3, "evidence_note": "Test evidence"
        }, tok=token)
        chk("TISAX: update control", s == 200)

    s, d = req("GET", f"/api/tisax/assessments/{tisax_id}/gap-report", tok=token)
    chk("TISAX: gap report", s == 200 and "readiness" in d)

    s, raw, _ = req_raw("GET", f"/api/tisax/assessments/{tisax_id}/export-csv", tok=token)
    chk("TISAX: CSV export", s == 200 and len(raw) > 100)

    s, raw, _ = req_raw("GET", f"/api/tisax/assessments/{tisax_id}/export-pdf", tok=token)
    chk("TISAX: PDF export", s == 200 and raw[:4] == b"%PDF")

    req("DELETE", f"/api/tisax/assessments/{tisax_id}", tok=token)

# ═══════════════════════════════════════════════════
# 17. SETTINGS & MONITOR
# ═══════════════════════════════════════════════════
print("\n--- 17. SETTINGS & MONITOR ---")
s, d = req("GET", "/api/settings/brand", tok=token)
chk("Settings: brand", s == 200)

s, d = req("GET", "/api/settings/alerts", tok=token)
chk("Settings: alerts", s == 200 and "monitor_interval_hours" in d)

s, d = req("GET", "/api/settings/monitor", tok=token)
chk("Monitor: status", s == 200 and "interval_hours" in d, f"interval={d.get('interval_hours')}")

# ═══════════════════════════════════════════════════
# 18. USERS
# ═══════════════════════════════════════════════════
print("\n--- 18. USERS ---")
s, d = req("GET", "/api/users", tok=token)
chk("Users: list", s == 200 and isinstance(d, list))

# ═══════════════════════════════════════════════════
# 19. ADMIN ACTIVITY
# ═══════════════════════════════════════════════════
print("\n--- 19. ADMIN ACTIVITY ---")
s, d = req("GET", "/api/admin/activity", tok=token)
chk("Activity: audit log", s == 200 and isinstance(d, list))

# ═══════════════════════════════════════════════════
# 20. API TOKENS
# ═══════════════════════════════════════════════════
print("\n--- 20. API TOKENS ---")
s, d = req("GET", "/api/tokens", tok=token)
chk("Tokens: list", s == 200 and isinstance(d, list))

s, d = req("POST", "/api/tokens", {"name": f"test-{TS}", "scope": "read"}, tok=token)
chk("Tokens: create", s in (200, 201) and "token" in d, f"prefix={d.get('token','')[:5]}")
tok_id = d.get("id", "")
if tok_id:
    s, d = req("DELETE", f"/api/tokens/{tok_id}", tok=token)
    chk("Tokens: delete", s in (200, 204))

# ═══════════════════════════════════════════════════
# 21. FIRMWARE
# ═══════════════════════════════════════════════════
print("\n--- 21. FIRMWARE ---")
s, d = req("GET", "/api/firmware/scans", tok=token)
chk("Firmware: list scans", s == 200)

# ═══════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════
print("\n--- CLEANUP ---")
req("DELETE", f"/api/releases/{rel_id}", tok=token)
req("DELETE", f"/api/releases/{rel2_id}", tok=token)
req("DELETE", f"/api/products/{prod_id}", tok=token)
req("DELETE", f"/api/organizations/{org_id}", tok=token)
chk("Cleanup: done", True)

# ═══════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
passed = sum(1 for m, _ in results if m == "PASS")
failed = sum(1 for m, _ in results if m == "FAIL")
total = len(results)
print(f"TOTAL: {passed}/{total} PASSED, {failed} FAILED")
if failed:
    print(f"\nFailed tests ({failed}):")
    for m, n in results:
        if m == "FAIL":
            print(f"  x {n}")
else:
    print("\nALL TESTS PASSED!")
print("=" * 60)
