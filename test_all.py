import urllib.request, urllib.error, json, time

BASE = "http://localhost:9100"
results = []
TS = str(int(time.time()))[-6:]  # last 6 digits for unique names


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
        except Exception:
            b = {}
        return e.code, b


def chk(name, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    results.append((mark, name, str(detail)))
    print("[" + mark + "] " + name + (" -- " + str(detail) if detail else ""))


# --- Auth ---
s, d = req("POST", "/api/auth/login", {"username": "admin", "password": "wrongpass"})
chk("Auth: reject bad password", s == 401)
s, d = req("POST", "/api/auth/login", {"username": "admin", "password": "sbom@2024"})
chk("Auth: login success", s == 200 and "access_token" in d)
token = d.get("access_token")
s, d = req("GET", "/api/stats", tok=token)
chk("Auth: protected with token (200)", s == 200)
s, d = req("GET", "/api/stats")
chk("Auth: blocked without token (403)", s in [401, 403], "status=" + str(s))

# --- Stats ---
s, d = req("GET", "/api/stats", tok=token)
chk("Stats: /stats all keys", s == 200 and all(k in d for k in [
    "organizations", "products", "releases", "components",
    "vulnerabilities", "patch_tracking", "cra_incidents"
]))
s, d = req("GET", "/api/stats/risk-overview", tok=token)
chk("Stats: /risk-overview list", s == 200 and isinstance(d, list), "status=" + str(s) + " len=" + str(len(d) if isinstance(d, list) else "N/A"))
if isinstance(d, list) and d:
    chk("Stats: risk-overview row keys", all(k in d[0] for k in ["org_id", "org_name", "total_vulns", "unpatched_critical", "risk_score"]))
s, d = req("GET", "/api/stats/top-threats", tok=token)
chk("Stats: /top-threats shape", s == 200 and "active_kev_count" in d and "top_epss" in d)

# --- Organizations ---
OrgName = "TestOrg-" + TS
s, d = req("POST", "/api/organizations", {"name": OrgName}, tok=token)
chk("Org: create (200)", s == 200 and "id" in d, "status=" + str(s))
org_id = d.get("id", "MISSING")
s, d = req("GET", "/api/organizations", tok=token)
chk("Org: list includes new org", s == 200 and any(o["id"] == org_id for o in d))
s, d = req("PATCH", "/api/organizations/" + org_id, {"name": OrgName + "-Up"}, tok=token)
chk("Org: PATCH update (200)", s == 200 and d.get("name", "").endswith("-Up"), "status=" + str(s))

# --- Products ---
s, d = req("POST", "/api/organizations/" + org_id + "/products", {"name": "TestProd", "description": "QA"}, tok=token)
chk("Product: create (200)", s == 200 and "id" in d, "status=" + str(s))
prod_id = d.get("id", "MISSING")
s, d = req("GET", "/api/organizations/" + org_id + "/products", tok=token)
chk("Product: list", s == 200 and any(p["id"] == prod_id for p in d))

# --- Releases ---
s, d = req("POST", "/api/products/" + prod_id + "/releases", {"version": "1.0.0", "notes": "QA"}, tok=token)
chk("Release: create (200)", s == 200 and "id" in d, "status=" + str(s))
rel_id = d.get("id", "MISSING")
s, d = req("GET", "/api/products/" + prod_id + "/releases", tok=token)
rel_list = d.get("releases", d) if isinstance(d, dict) else d
chk("Release: list contains release", isinstance(rel_list, list) and any(r["id"] == rel_id for r in rel_list))
s, d = req("POST", "/api/releases/" + rel_id + "/lock", tok=token)
chk("Release: lock (200)", s == 200, "status=" + str(s))
s, d = req("DELETE", "/api/releases/" + rel_id, tok=token)
chk("Release: locked delete blocked (409)", s == 409, "status=" + str(s))
s, d = req("POST", "/api/releases/" + rel_id + "/unlock", tok=token)
chk("Release: unlock (200)", s == 200, "status=" + str(s))

# --- Vulnerabilities ---
s, d = req("GET", "/api/releases/" + rel_id + "/vulnerabilities", tok=token)
chk("Vuln: list (200)", s == 200 and isinstance(d, list), "status=" + str(s))
s, d = req("GET", "/api/releases/" + rel_id + "/vulnerabilities?skip=0&limit=10", tok=token)
chk("Vuln: pagination (200)", s == 200)

# --- Search ---
s, d = req("GET", "/api/search/components?q=test", tok=token)
chk("Search: /search/components (200)", s == 200, "status=" + str(s))

# --- CRA Incidents ---
s, d = req("POST", "/api/cra/incidents", {"title": "QA Incident", "description": "Test"}, tok=token)
chk("CRA: create (201)", s == 201 and "id" in d, "status=" + str(s))
inc_id = d.get("id", "MISSING")
s, d = req("GET", "/api/cra/incidents", tok=token)
chk("CRA: list (200)", s == 200 and isinstance(d, list))
s, d = req("GET", "/api/cra/incidents/" + inc_id, tok=token)
chk("CRA: get single (200)", s == 200 and d.get("id") == inc_id)
# advance: detected → pending_triage
s, d = req("POST", "/api/cra/incidents/" + inc_id + "/advance", {"note": "QA triage"}, tok=token)
chk("CRA: advance to pending_triage (200)", s == 200, "status=" + str(s))
# now close-not-affected is valid from pending_triage
s, d = req("POST", "/api/cra/incidents/" + inc_id + "/close-not-affected", {"note": "QA close"}, tok=token)
chk("CRA: close-not-affected (200)", s == 200, "status=" + str(s) + " " + str(d.get("detail", "")))
s, d = req("DELETE", "/api/cra/incidents/" + inc_id, tok=token)
chk("CRA: delete (204)", s == 204, "status=" + str(s))

# --- Users + RBAC ---
s, d = req("GET", "/api/users", tok=token)
chk("Users: list admin (200)", s == 200 and isinstance(d, list))
s, d = req("POST", "/api/users", {"username": "qaview" + TS, "password": "Qatest1234", "role": "viewer"}, tok=token)
chk("Users: create viewer (201)", s == 201 and "id" in d, "status=" + str(s) + " " + str(d.get("detail", "")))
uid = d.get("id")
if uid:
    s2, d2 = req("POST", "/api/auth/login", {"username": "qaview" + TS, "password": "Qatest1234"})
    vt = d2.get("access_token")
    chk("RBAC: viewer login (200)", s2 == 200 and bool(vt))
    s, d = req("POST", "/api/organizations", {"name": "ShouldFail"}, tok=vt)
    chk("RBAC: viewer blocked from create org (403)", s == 403, "status=" + str(s))
    s, d = req("GET", "/api/stats", tok=vt)
    chk("RBAC: viewer can read stats (200)", s == 200)
    s, d = req("DELETE", "/api/users/" + uid, tok=token)
    chk("Users: delete viewer (204)", s == 204, "status=" + str(s))

# --- Settings ---
s, d = req("GET", "/api/settings/brand", tok=token)
chk("Settings: brand config (200)", s == 200)

# --- Policies ---
s, d = req("GET", "/api/policies", tok=token)
chk("Policies: list (200)", s == 200 and isinstance(d, list))
s, d = req("POST", "/api/policies", {"name": "QA Policy", "severity": "critical", "action": "block"}, tok=token)
chk("Policies: create (201)", s == 201 and "id" in d, "status=" + str(s))
pol_id = d.get("id")
if pol_id:
    s, d = req("DELETE", "/api/policies/" + pol_id, tok=token)
    chk("Policies: delete (204)", s == 204, "status=" + str(s))

# --- NVD enrichment: no vulns → 400; endpoint exists and is protected ---
s, d = req("POST", "/api/releases/" + rel_id + "/enrich-nvd", tok=token)
chk("NVD: enrich endpoint exists (400 = no vulns)", s == 400, "status=" + str(s) + " " + str(d.get("detail", "")))
# viewer cannot trigger enrichment
if uid is None:  # uid was deleted above; re-check RBAC via a fresh viewer token attempt
    pass  # skip if viewer already deleted
s_v, _ = req("POST", "/api/releases/" + rel_id + "/enrich-nvd", tok=None)
chk("NVD: blocked without auth (403)", s_v in [401, 403], "status=" + str(s_v))

# --- Cleanup ---
req("DELETE", "/api/releases/" + rel_id, tok=token)
req("DELETE", "/api/products/" + prod_id, tok=token)
s, d = req("DELETE", "/api/organizations/" + org_id, tok=token)
chk("Cleanup: cascade org delete (204)", s == 204, "status=" + str(s))

# --- Summary ---
passed = sum(1 for r in results if r[0] == "PASS")
failed = sum(1 for r in results if r[0] == "FAIL")
print("")
print("=" * 55)
print("TOTAL: " + str(passed) + " PASS / " + str(failed) + " FAIL  (" + str(len(results)) + " tests)")
if failed:
    print("\nFailed:")
    for r in results:
        if r[0] == "FAIL":
            print("  FAIL: " + r[1] + " -- " + r[2])
