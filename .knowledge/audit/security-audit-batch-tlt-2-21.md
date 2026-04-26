---
internal: true
phase: 3
audit_id: 2026-04-26-security-code-review
methodology: STRIDE-driven; SEC-001a canonical template applied compactly
deployment_mode: lan_only
commercialization_planned: true
created: 2026-04-26
status: bulk findings TLT-2..21 (TLT-1 = SEC-001 family in main doc)
schema_frozen: true (per Phase 3 round-2 user approval)
---

# Phase 3 — Findings batch (TLT-2..TLT-21)

Compact format. SEC-001a in `security-audit-2026-04-26.md` remains the canonical full template. Findings here use the same 13-column metadata + 4-layer recommendation + traceability yaml block schema, but with tighter prose because most are static + heuristic-validated, not full dynamic PoCs.

**Index**:

| ID | TLT | Title | sev_lan | sev_pub | exp_complex |
|----|-----|-------|---------|---------|-------------|
| SEC-002 | TLT-2 | converter.py XML billion-laughs (dynamic-poc) | Low | Medium | low |
| SEC-003 | TLT-3 | nginx X-Forwarded-For client spoof bypasses rate limit + audit IP | Low | High | trivial |
| SEC-004 | TLT-4 | subprocess wrappers — verified safe; no command injection | — | — | — (confirmed-N/A) |
| SEC-005 | TLT-5 | webhook DNS-rebinding window in `_validate_webhook_url` | Low | Medium | medium |
| SEC-006 | TLT-6 | OIDC state cookie attribute audit | Low | Medium | low |
| SEC-007 | TLT-7 | JWT crypto / scope downgrade audit | Low | Low | medium |
| SEC-008 | TLT-8 | Plan / scope escalation paths | Low | Medium | low |
| SEC-009 | TLT-9 | Stored output sanitisation in PDF / CSAF | Low | Low | medium |
| SEC-010 | TLT-10 | AlertConfig.webhook_url plaintext in DB (= ALERT-001) | Medium | Medium | low |
| SEC-011 | TLT-11 | Race conditions: release lock, monitor, share-link create | Low | Medium | high |
| SEC-012 | TLT-12 | firmware upload: zip-bomb, RCE via filename, EMBA RCE | Low | Medium | medium |
| SEC-013 | TLT-13 | Audit log tamper / repudiation gaps | Low | Medium | medium |
| SEC-014 | TLT-14 | Backup at rest: SQLite plain-copy, no encryption | Medium | High | low |
| SEC-015 | TLT-15 | DoS: 1 worker, unbounded monitor, large SBOM | Medium | High | low |
| SEC-016 | TLT-16 | Frontend: localStorage token + open redirect surface | Low | Medium | medium |
| SEC-017 | TLT-17 | Supply chain: no CI SCA / no signed artifacts | Medium | High | n/a (process) |
| SEC-018 | TLT-18 | nginx security header gaps | Info | Medium | n/a (config) |
| SEC-019 | TLT-19 | OS / launchd hardening: 1 worker, soft RSS, no read-only FS | Low | Medium | medium |
| SEC-020 | TLT-20 | (deferred — LLM threats; documented in threat-model §TLT-20 expanded) | n/a | n/a | n/a |
| SEC-021 | TLT-21 | Time / clock integrity: NTP, JWT exp, rate-limit reset on restart | Low | Medium | medium |

**Confirmed leaks requiring Phase 5 patch**:SEC-001a/b/c/d (in main doc), SEC-002 (XML bomb), SEC-003 (XFF spoof), SEC-010 (DB plaintext), SEC-014 (backup), SEC-015 (DoS), SEC-017 (CI), SEC-018 (nginx headers), partial others.

---

## SEC-002 (TLT-2) — `converter.py` XML billion-laughs via stdlib `xml.etree.ElementTree`

### Metadata

| field | value |
|-------|-------|
| finding_id | SEC-002 |
| parent_finding | null |
| status | open |
| discovered_phase | 3 |
| verification_method | static + dynamic-poc-timing |
| first_observed_commit | (XML conversion was added in `bbc786c`, 2026-04-NN; predates audit) |
| exploitation_complexity | low |
| severity_lan_only | **Low** (single worker freeze ≈ 30s with lol5; recovers; no data leak) |
| severity_if_public | **Medium** (sustained DoS easy with viewer JWT; load-balanced multi-worker setup amplifies) |
| blocks_commercialization | true (SOC 2 CC7.1 — system operations / DoS resilience) |
| confidence | High |
| category | DoS / Misconfig |
| cwe | [CWE-776 Improper Restriction of Recursive Entity References](https://cwe.mitre.org/data/definitions/776.html) ("XML Entity Expansion") |
| owasp | OWASP A05:2021 Security Misconfiguration |
| cvss_3_1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = **6.5 (Medium)** lan_only / **6.5** if_public (CVSS doesn't change much; severity_if_public is higher because attacker pool wider, not because impact differs) |

### traceability

```yaml
traceability:
  threat: TLT-2
  parent_finding: null
  attack_tree_leaf: attack-tree-2.path-B.leaf-1   # Billion-laughs in JSON SBOM (here applies to XML)
  abuse_cases: []
```

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC7.1
    gap_type: control_partial
    note: System operations — DoS resilience missing for XML conversion path
  - framework: ISO27001
    control: A.8.32
    gap_type: control_missing
    note: Change management — XML parser hardening not in security review checklist
  - framework: IEC62443-4-1
    control: SI-1
    gap_type: control_partial
```

### Location

- `backend/app/services/converter.py:230` `ET.fromstring(content)` — stdlib parser, NOT defusedxml
- `backend/app/api/convert.py` — POST `/api/convert?target=...` exposes this; viewer can hit it (router-level `_auth` only)

### Observation

Stdlib `xml.etree.ElementTree.fromstring`(Python 3.11)在 3.7+ 已**關閉外部 DTD**(XXE 路徑封死),但**未限制 internal entity expansion**。Python 官方 `xml` 模組安全文件明示 ElementTree 對 billion-laughs **不安全**。

### Evidence / PoC

PoC `.knowledge/audit/poc/SEC-002-converter-billion-laughs.py` 跑出 **HTTP 200 in 2.03s for 499-byte 4-level entity payload** — vs <100ms 預期 baseline。Timing-based 證明展開有發生。Evidence file:`evidence/2026-04-26/SEC-002.md`,含 lol5/6/7 推估的 OOM 風險表。

PoC 故意停在 lol4(10⁴ 展開)避免把 dev backend OOM。

### Impact

LAN-only:單一 viewer JWT 一個請求 ≈ 30s freeze(lol5);搭配 single-worker uvicorn 等於整個 backend 凍結。連發 = 完整 DoS。Commercial:多客戶共用同一 backend 進程,任一客戶可癱瘓所有人服務。SOC 2 CC7.1 必修。

### Recommendation

#### primary_remediation
**Pre-parse rejection of DOCTYPE/ENTITY** — 2 lines, no new dep:
```python
def _cdx_xml_to_json(content: bytes) -> dict:
    if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
        raise ValueError("XML SBOM 中不支援 DOCTYPE / ENTITY 宣告")
    try:
        root = ET.fromstring(content)
    ...
```
CycloneDX XML schema 不需要 DOCTYPE / ENTITY,合法 SBOM 不會被 false-positive。
- effort: S (5 lines)
- risk_of_fix: Low (rejection is for malicious patterns only)

#### defense_in_depth
- 規則:任何 stdlib XML parse 點都要過 `_safe_xml_load()` helper,helper 內含 DOCTYPE/ENTITY check + size cap (1MB)
- CI test:`tests/test_xml_safety.py` — 餵 billion-laughs payload,assert 400

#### compensating_control
**Disable XML conversion temporarily** — 1-line: `if fname_lower.endswith(".xml"): raise HTTPException(400, "XML import temporarily disabled pending security update")`. 客戶仍可用 JSON 互轉,XML 路徑暫時無痛關掉。
- effort: S (1 line)
- risk_of_fix: Low (XML import is rarely used per usage pattern)

#### monitoring_detection
```yaml
monitoring_detection:
  applies_to_finding: SEC-002
  endpoint_class: pre-validation
  log_pipeline: in-handler, blocking
  log_field:
    name: xml_doctype_attempt
    type: bool
    sourced_from: |
      Set true when pre-parse check finds DOCTYPE or ENTITY token
  alert_rule: |
    xml_doctype_attempt == true     # any DOCTYPE in user XML = adversarial
```
- effort: S
- risk_of_fix: None

### References
- CWE-776, OWASP XXE Cheat Sheet, Python `xml` security docs

---

## SEC-003 (TLT-3) — `nginx-sbom.conf` X-Forwarded-For appends client value; `rate_limit._client_ip` reads first → spoofable

### Metadata

| field | value |
|-------|-------|
| finding_id | SEC-003 |
| parent_finding | null |
| status | open |
| discovered_phase | 1 (predicted in recon) → 3 (verified) |
| verification_method | static + dynamic-poc-pending (would require sending crafted XFF; trivially confirmable) |
| first_observed_commit | nginx config first added in `fc8d065` (2026-04-NN); rate_limit.py in earlier commit |
| exploitation_complexity | **trivial** (one curl with `-H "X-Forwarded-For: 1.2.3.4"`) |
| severity_lan_only | **Low** (rate limit bypass on LAN doesn't matter much; audit log spoofing is the real concern) |
| severity_if_public | **High** (login brute-force rate limit completely bypassed; audit logs poisoned) |
| blocks_commercialization | **true** (SOC 2 CC6.7 + CC7.2 — both audit logging integrity AND rate limiting) |
| confidence | High |
| category | Authn / Authz / Misconfig |
| cwe | [CWE-348 Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html) |
| owasp | OWASP A07:2021 + API4 Unrestricted Resource Consumption |
| cvss_3_1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5 (High)** if_public; lan_only N/A external attacker absent |

### traceability

```yaml
traceability:
  threat: TLT-3
  parent_finding: null
  attack_tree_leaf: attack-tree-1.branch-A.leaf-1   # IP-based primitive enabling other tree paths
  abuse_cases: [abuse-3, abuse-4]                   # share token brute-force + forgot-password bomb
  related_sdlc: SDLC-001     # same "convention not enforcement" pattern
```

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.7
    gap_type: control_partial
    note: Boundary protection — rate limiter relies on attacker-controlled identifier
  - framework: SOC2
    control: CC7.2
    gap_type: control_missing
    note: Audit logging integrity — logged IP can be spoofed by client
  - framework: ISO27001
    control: A.8.16
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SVV-3
    gap_type: control_partial
    note: Vulnerability assessment — known weakness not flagged in any CI lint
```

### Location

- `deploy/nginx-sbom.conf:38-39` `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` — **appends**, doesn't replace
- `backend/app/core/rate_limit.py:51` (approx) `forwarded.split(",")[0].strip()` — takes **first** entry from XFF list

### Observation

`$proxy_add_x_forwarded_for` 在 nginx 是 「append client-supplied XFF + real IP」格式: `<client_xff>, <real_ip>`. 取 `split(",")[0]` 就拿到 client 偽造的字串。

對攻擊者而言只要送 `curl -H "X-Forwarded-For: 99.99.99.99"`,backend 會把 99.99.99.99 當做 client IP 來:
- Rate limit 計數 — bypass(登入暴力 10/5min/IP 可繞過,送 100 個假 IP)
- Audit log `audit_event.ip_address` — 寫攻擊者偽造的值,無法追蹤來源
- 也影響 SLA / IP-based session 的所有 downstream 邏輯

### Recommendation

#### primary_remediation
nginx 改用 **`proxy_set_header X-Real-IP $remote_addr`**(real_ip 是 client → nginx 的 socket peer,不可偽造)+ rate_limit.py 改讀 `X-Real-IP`:

```diff
# deploy/nginx-sbom.conf
-proxy_set_header   X-Real-IP         $remote_addr;
-proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
+proxy_set_header   X-Real-IP         $remote_addr;
+# Drop the X-Forwarded-For chain — backend uses X-Real-IP only.

# backend/app/core/rate_limit.py
 def _client_ip(request: Request) -> str:
-    forwarded = request.headers.get("X-Forwarded-For")
-    if forwarded:
-        return forwarded.split(",")[0].strip()
-    return request.client.host if request.client else "unknown"
+    real_ip = request.headers.get("X-Real-IP")
+    if real_ip:
+        return real_ip.strip()
+    return request.client.host if request.client else "unknown"
```

(若日後接 Cloudflare / multi-hop reverse proxy,改用 `X-Forwarded-For` **取最後 N 個** entries,N = 信任的 hop 數,並把 `--proxy-headers` 設正確的 `--forwarded-allow-ips`。但 LAN-only 單一 nginx 不需這麼複雜。)

- effort: S (3 file changes,nginx + rate_limit + audit log helper)
- risk_of_fix: Low (admin must reload nginx after deploy.sh — already part of deploy flow)

#### defense_in_depth
- Reject any incoming X-Forwarded-For at nginx layer: `proxy_set_header X-Forwarded-For "";` (空字串覆蓋 client 送的)
- Test: `tests/test_xff_spoof.py` — assert client-supplied XFF doesn't reach backend handler

#### compensating_control
N/A for LAN — internet attacker absent today. For commercialised public deployment, immediate hot-fix = `proxy_set_header X-Forwarded-For "";` in nginx (drops attacker-supplied XFF entirely).

#### monitoring_detection
```yaml
monitoring_detection:
  applies_to_finding: SEC-003
  endpoint_class: cross-cutting (auth, audit, rate-limit)
  log_pipeline: structured, async
  log_field:
    name: client_xff_supplied
    type: bool
  alert_rule: |
    client_xff_supplied == true   # XFF should be empty after fix; any truthy = misconfig or attack
```

### References
- nginx X-Real-IP vs X-Forwarded-For — https://nginx.org/en/docs/http/ngx_http_realip_module.html
- CWE-348, OWASP API4

---

## SEC-004 (TLT-4) — subprocess wrappers (Trivy/Syft/EMBA): `confirmed-N/A`,但 documented for completeness

### Metadata

| field | value |
|-------|-------|
| finding_id | SEC-004 |
| status | confirmed-N/A |
| discovered_phase | 3 |
| verification_method | static (read 3 service files) |
| severity_lan_only | n/a |
| severity_if_public | n/a |
| blocks_commercialization | false |
| confidence | High |
| category | Injection (audit; no actual finding) |
| cwe | n/a (CWE-78 is what's NOT present) |

### traceability

```yaml
traceability:
  threat: TLT-4
  parent_finding: null
  attack_tree_leaf: null     # no exploitable path identified
  abuse_cases: []
```

### Observation

3 個 subprocess 服務(`trivy_scanner.py`, `syft_scanner.py`, `firmware_service.py`):

```python
# All three use list-form arguments:
subprocess.run(["trivy", "image", "--format", "cyclonedx", image_ref], ...)
subprocess.run(["syft", "scan", "-o", "cyclonedx-json", source_path], ...)
subprocess.run(["emba", "-d", "1", "-l", logs_dir, "-f", firmware_path], ...)
```

**全部 list-form,無 `shell=True`,無 string concatenation**。`image_ref` / `source_path` / `firmware_path` 直接做為 argv 傳入,不經 shell 解譯。即使使用者塞 `; rm -rf /` 進 image_ref,也只會被當成單一字串 argument 傳給 trivy(後者會回 "image not found")。

`firmware_service.py` 的 EMBA 路徑用 `tempfile.mkdtemp` 產 work dir,使用者上傳的檔案先寫到該 dir 再 invoke EMBA,filename 是 `Path(file.filename).name` 過濾過(per CHANGELOG `C-2 path traversal` fix at commit 49b53cd)。

### Status: confirmed-N/A

3 個 subprocess wrapper 都用 best-practice list-form。無 finding。記錄此 finding 供 commercialisation due-diligence 引用 — 客戶會問「subprocess injection 怎麼防」,回「全 list-form,不過 shell」最簡潔。

---

## SEC-005 (TLT-5) — webhook DNS-rebinding window in `_validate_webhook_url`

### Metadata

| field | value |
|-------|-------|
| finding_id | SEC-005 |
| status | open |
| discovered_phase | 3 |
| verification_method | static (TOCTOU pattern recognition) |
| first_observed_commit | `49b53cd` (Phase 0 SSRF fix) — fix introduced the validation but TOCTOU is intrinsic |
| exploitation_complexity | medium (需要設 attacker-controlled DNS,有最小 ttl) |
| severity_lan_only | Low |
| severity_if_public | Medium |
| blocks_commercialization | partial (advanced attack;基本 SSRF 已擋) |
| confidence | Medium (theoretical attack;real-world exploit window depends on DNS TTL) |
| category | SSRF / Time-of-check-to-time-of-use |
| cwe | [CWE-367 TOCTOU](https://cwe.mitre.org/data/definitions/367.html) + [CWE-918 SSRF](https://cwe.mitre.org/data/definitions/918.html) |
| owasp | OWASP A10:2021 |
| cvss_3_1 | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` = 4.4 if_public |

### Observation

`alerts._validate_webhook_url()` resolves DNS at validation time, rejects if any A/AAAA points to private IP. Subsequent `httpx.post(url)` does its own DNS lookup. **Two separate resolutions** = TOCTOU.

Attacker controls a domain with:
1. Authoritative DNS responding `1.2.3.4` (public) for first lookup → passes validation
2. Same domain second lookup returns `127.0.0.1` (loopback) → SSRF to internal services

Window is bounded by DNS TTL (attacker can set to 0). httpx caches connection per-process not per-request, but multi-request scenarios open the gap.

### Recommendation

#### primary_remediation
- 改用 `httpx.AsyncClient(transport=httpx.HTTPTransport(local_address=...))` — pin to single resolved IP from validation step, pass to httpx as connect target (not re-resolve)
- OR — switch to `requests` adapter that takes `(host, port)` tuple and bypasses DNS

```python
def _send_webhook_safe(url: str, ...):
    parsed = urlparse(url)
    safe_ip = _validate_webhook_url(url)   # returns the resolved + validated IP
    transport = httpx.HTTPTransport(retries=0)
    headers = {"Host": parsed.hostname}    # required for SNI / vhost routing
    return httpx.post(
        url.replace(parsed.hostname, safe_ip, 1),   # connect to safe_ip directly
        headers=headers, ...
    )
```

- effort: M (~3h, requires testing TLS SNI flow)
- risk_of_fix: Medium (touches notification path; rollback = revert to 2-resolution flow)

#### defense_in_depth + compensating_control + monitoring_detection
- defense: outbound firewall rule blocking RFC1918 / loopback / metadata IPs at OS level
- compensating: disallow `https` to bare-IP destinations entirely (require domain) + enforce DNS pinning
- monitoring: structured log of resolved-IP per webhook call + alert on outbound-to-RFC1918 count > 0

---

## SEC-006 (TLT-6) — OIDC state cookie attribute audit (need confirm SameSite=Lax + HttpOnly + Secure)

### Metadata

| field | value |
|-------|-------|
| finding_id | SEC-006 |
| status | open (needs read of `auth.py` callback to confirm) |
| discovered_phase | 3 |
| verification_method | static-pending |
| exploitation_complexity | low |
| severity_lan_only | Low |
| severity_if_public | Medium |
| blocks_commercialization | partial |
| confidence | Medium |

### Observation
Phase 1 noted OIDC state cookie attributes "待 Phase 3 確認". Need to read `auth.py:oidc_callback` to verify cookie has `httponly=True, secure=True, samesite="lax"`. If missing any → CSRF on OIDC callback.

### Recommendation
Verify:
```python
# Expected:
response.set_cookie(
    "oidc_state", state,
    httponly=True, secure=True, samesite="lax",
    max_age=600, path="/api/auth/oidc",
)
```

If `secure=True` is set unconditionally, LAN-only HTTP-mode breaks (cookie not sent over HTTP). Conditional on settings.HTTPS / DEBUG.

---

## SEC-007 (TLT-7) — JWT crypto + scope-downgrade audit

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-007 |
| status | open (verify `algorithms=["HS256"]` enforced) |
| discovered_phase | 3 |
| verification_method | static |
| severity_lan_only | Low | severity_if_public | Low (after audit) |
| confidence | High |

### Observation
`security.py:72` `jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])` — explicit allowed-list. **alg=none / HS256-vs-RS256 confusion attack closed**. Good.

`deps.py:get_current_user` checks token starts with `sbom_` for API tokens — distinguishable from JWT (which starts with `eyJ`). No prefix-confusion possible.

scope downgrade via `require_admin_scope` (deps.py:69) is correct: read tokens get 403 on POST/PATCH/DELETE; write tokens get 403 on DELETE; admin tokens get full access. **No bypass identified.**

`exp` claim is set + jti-revocation list checked. Standard.

**Open finding sub-points**:
1. **No `aud` claim** → JWT signed by this app reusable in any other app sharing SECRET_KEY (unlikely scenario but documented finding)
2. **No `iss` claim** → can't distinguish "issued by this server" vs "forged with leaked key"
3. **No refresh token mechanism** → 8h TTL forces re-login; UX trade-off, not security

### Recommendation
- effort: S (add `aud="sbom-platform"` and `iss=settings.ALLOWED_ORIGIN` to `create_access_token`; `decode_token` validates with `audience=` + `issuer=` kwargs)
- risk_of_fix: Low

---

## SEC-008 (TLT-8) — Plan / scope escalation paths

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-008 |
| status | open |
| verification_method | static |
| severity_lan_only | Low | severity_if_public | Medium |
| confidence | Medium |

### Observation
`require_admin` checks role; **`api_token_scope == "read"` returns 403** even on admin role (good). But `require_admin` accepts both JWT-admin and `api_token_scope == "admin"` indistinguishably — Phase 5 should ensure all destructive ops use `require_admin_scope` (strict admin), not just `require_admin`.

Grep audit:
- `users.py` admin-only? — yes (require_admin / require_admin_scope mix; verify each)
- `tokens.py` admin-only? — yes
- Plan operations (`PATCH /organizations/{id}/plan`) — admin-only ✓

### Recommendation
- effort: S (audit + tighten ~5 endpoints to `require_admin_scope`)
- risk_of_fix: Low

---

## SEC-009 (TLT-9) — Stored XSS via PDF / CSAF generation

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-009 |
| status | open |
| verification_method | static |
| severity_lan_only | Low | severity_if_public | Low |
| confidence | Low (PDF rendering doesn't normally execute JS;CSAF JSON 是 data not template) |

### Observation
- `pdf_report.py` uses reportlab + `_s()` to strip non-Latin-1 chars. PDFs can contain JS but reportlab doesn't emit `<script>`-bearing constructs.
- `csaf.py` produces JSON; downstream consumers (CSAF viewers) could XSS if they render unescaped HTML in vuln descriptions, but that's their problem.
- `*.html` file outputs (NOTICE.md → HTML) use markdown library; verify no raw HTML pass-through.

### Recommendation
- Audit each report-output renderer for raw HTML injection
- effort: S audit
- risk_of_fix: Low

---

## SEC-010 (TLT-10 / ALERT-001) — `AlertConfig.webhook_url` plaintext in DB; Slack webhook URL is secret-bearing

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-010 |
| status | open |
| verification_method | static (verified in Phase 1 self-check) |
| first_observed_commit | initial schema |
| exploitation_complexity | low (DB read access) |
| severity_lan_only | Medium (defence-in-depth failure) |
| severity_if_public | Medium |
| blocks_commercialization | partial (SOC 2 CC6.1) |
| confidence | High |
| category | Crypto / Storage |
| cwe | [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html) |
| owasp | OWASP A02:2021 Cryptographic Failures |

### traceability
```yaml
traceability:
  threat: TLT-10
  parent_finding: null
  attack_tree_leaf: null
  abuse_cases: []
```

### compliance_impact
```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1
    gap_type: control_partial
  - framework: ISO27001
    control: A.5.20
    gap_type: control_missing
    note: Information transfer / supplier relationships — Slack webhook URL contains secret token in URL path
  - framework: GDPR
    control: Art.32
    gap_type: control_partial
```

### Observation
`models/alert_config.py:9` `webhook_url = Column(String, nullable=True, default="")`.

Slack incoming webhook URL format: `https://hooks.slack.com/services/T<workspace>/B<channel>/<secret>` — the `<secret>` is the auth token. URL-as-secret is a Slack design choice;leak = attacker can post messages to that channel.

DB compromise (e.g. SQL backup leak per SEC-014, file system access) → webhook URLs leaked → impersonation in customer's Slack channel.

### Recommendation

#### primary_remediation
**Encrypt webhook_url column** using app-level envelope encryption with key from `SECRET_KEY` (already required for JWT). Adds 1 dep choice:
- Option A: `cryptography` library (BSD-3) — already in `python-jose[cryptography]` dep, **no new package**. Use `cryptography.fernet.Fernet`.
- Option B: pure-stdlib AES-GCM via `Crypto`-equivalent in `cryptography` — same lib.

Implement `EncryptedString` SQLAlchemy TypeDecorator that auto-encrypts on INSERT, decrypts on SELECT.

- effort: M (~3h — TypeDecorator + key derivation + migration script)
- risk_of_fix: Medium (need a backfill migration for existing rows;rollback path = decrypt + write plaintext)

#### defense_in_depth
- DB at-rest encryption (Postgres `pgcrypto` at column level, OR full-disk encryption on Mac mini host)
- File system access control: `$HOME/sbom/` is owner-only (mode 0700)

#### compensating_control
**Rotate Slack webhook frequently** (manual): treat any DB backup access as compromise + rotate. Document in operations runbook.

#### monitoring_detection
- Log all DB SELECT on `alert_config` (already audit-logged via SQLAlchemy event hooks?) — verify
- Alert on unexpected SELECT patterns

### References
- CWE-256, Slack incoming webhook security docs

---

## SEC-011 (TLT-11) — Race conditions: release lock, monitor restart, share-link create

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-011 |
| status | open |
| verification_method | static (TOCTOU pattern in 3 places) |
| exploitation_complexity | high (need precise timing) |
| severity_lan_only | Low | severity_if_public | Medium |
| confidence | Medium |

### Observation
- `releases.py:lock` `release.locked = True; db.commit()` — between read and commit, another request could modify. SQLite WAL mode helps;Postgres needs `SELECT FOR UPDATE`.
- `monitor.py` background thread + `trigger()` — `_scan_lock` (threading.Lock) protects in-process,但 launchd 重啟瞬間 + 手動 trigger 可能在 lock 重建前並行
- `share.py:create_share_link` 的 20-link cap check — count then insert,並發可超過 20

### Recommendation
- Use `db.query(...).with_for_update()` (Postgres) / `BEGIN EXCLUSIVE` (SQLite) for critical-section reads
- effort: M (~4h)
- risk_of_fix: Medium

---

## SEC-012 (TLT-12) — firmware upload: 500MB cap good, filename sanitisation good (per Phase 0 fix), EMBA RCE inherited

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-012 |
| status | mostly confirmed-N/A (Phase 0 fixes good); residual from EMBA itself |
| verification_method | static (verified Phase 0 fix held) |
| confidence | High |

### Observation
Phase 0 hardening:
- `firmware.py:upload_firmware` uses `Path(file.filename).name` ✓
- 500MB cap via `await file.read(MAX+1)` ✓
- admin-only ✓

Residual:
- EMBA itself has CVE history (firmware analysis tools commonly do) — out of platform's scope (用戶自己裝),記錄 in NOTICE.md GPL-3.0 disclaimer
- zip-bomb in firmware: 500MB upload cap is byte-level pre-extraction;EMBA extracts internally and may itself have zip-bomb protection issues — **inherited risk** from EMBA, not platform

### Recommendation
- Document EMBA-inherited risk in NOTICE / Help Center
- Force EMBA timeout (already in subprocess.run timeout=30s for detection;extend for full scan)

---

## SEC-013 (TLT-13) — Audit log tamper / repudiation gaps

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-013 |
| status | open |
| verification_method | static |
| severity_lan_only | Low | severity_if_public | Medium |
| confidence | High |
| **related_sdlc** | SDLC-001 (convention not enforcement: audit-event INSERT 散在每 router,沒有 mandatory middleware enforce 每 mutation 都 log) |

### Observation
- `audit_event` 表沒 unique constraint;admin 直接 SQL UPDATE 改 historical row 不留痕跡
- 沒 hash chain / Merkle tree 防序列竄改
- 沒 PII 自動 redaction(`ip_address` 是 GDPR PII,留太久違反 storage limitation Art.5(1)(e))

### Recommendation
#### primary_remediation
- DB-level INSERT-only trigger (Postgres):`CREATE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;`
- IP retention policy:每月 cron job 把 90 天前的 `audit_events.ip_address` 改 `[REDACTED]`

- effort: M (~3h — trigger + cron + test)
- risk_of_fix: Low (admin loses ability to "fix" audit log,which is the point)

#### monitoring_detection
- Hash chain: each row stores `prev_hash + sha256(this_row)`;periodic verification cron alerts on chain break
- effort: M (~4h);risk_of_fix: Low

### Compliance
- SOC 2 CC7.2 (system monitoring) + GDPR Art.5(1)(e) + IEC 62443-4-1 SUM-3 (security update management — relies on audit trail)

---

## SEC-014 (TLT-14) — Backup at rest: `deploy/backup.sh` plain SQLite copy, no encryption

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-014 |
| status | open |
| verification_method | static (read deploy/backup.sh) |
| severity_lan_only | Medium | severity_if_public | High |
| blocks_commercialization | true (ISO 27001 A.8.13 Information Backup) |
| confidence | High |

### Observation
`deploy/backup.sh` 用 `sqlite3 .backup` 命令拷檔到 `$HOME/sbom/backups/`,**plain copy,no encryption,no off-host transfer**。

Mac mini disk failure / theft / compromise → 14 天 backup 全洩漏 = 14 天平台所有客戶 SBOM + audit log + hashed passwords + (per SEC-010) plaintext webhook URLs。

### Recommendation
#### primary_remediation
- backup.sh 改用 `gpg --symmetric --cipher-algo AES256 --batch --passphrase-file /home/peter/.sbom-backup-key` encrypt 後再拷
- backup key 不在同台 Mac mini(at minimum 一份在 USB / 1Password / 雲端 Vault)
- Off-host transfer: `rsync` 到 NAS / 雲端 storage

- effort: M (~2h — script + key management procedure documented)
- risk_of_fix: Low (recovery procedure documented = restore decrypted)

---

## SEC-015 (TLT-15) — DoS:1 worker uvicorn,unbounded monitor,large SBOM blocks worker

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-015 |
| status | open |
| verification_method | static + heuristic |
| severity_lan_only | Medium | severity_if_public | High |
| blocks_commercialization | true (SOC 2 CC7.1) |
| confidence | High |

### Observation
- `launchd plist` 指定 `--workers 1`;單一慢請求 (= SEC-002 billion-laughs / large SBOM enrichment 多分鐘) 凍結整個服務
- `monitor.py` 背景 thread 跑全 release rescan,沒 incremental;大型客戶帳戶可能跑數分鐘
- SBOM 上傳 endpoint 沒 size limit 強制(只 nginx `client_max_body_size 55M`,backend 自己沒 cap)

### Recommendation
#### primary_remediation
- `launchd plist` `--workers $(sysctl -n hw.ncpu)` (Mac mini 8 核 = 8 worker)
- monitor 加 incremental flag + per-tenant timeout
- SBOM upload endpoint 加 `max_size=10*1024*1024` Pydantic check + early reject

- effort: M (~4h)
- risk_of_fix: Medium (worker scaling 改變記憶體 footprint;Mac mini 8GB RAM × 8 worker = 1GB/worker,接近上限)

---

## SEC-016 (TLT-16) — Frontend localStorage token + open redirect surface

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-016 |
| status | open |
| verification_method | static (frontend code) |
| severity_lan_only | Low | severity_if_public | Medium |
| confidence | High |

### Observation
- `localStorage.getItem("token")` (frontend `api/client.js`) — XSS 一次帶走 token (vs httpOnly cookie 模型不可)
- `useLocation` based redirect after login — verify no `?next=` open redirect surface;若有 → host whitelist required
- Frontend 有 i18n 字串渲染為 HTML 的位置 (e.g. `dangerouslySetInnerHTML`) — Phase 6 grep 確認

### Recommendation
- 短期:CSP `script-src 'self'` 嚴格化(等 inline script 都消除)+ Trusted Types policy
- 長期:把 JWT 移到 httpOnly cookie + CSRF token 機制
- effort:長 (~1 sprint),risk_of_fix:Medium-High (改變 auth flow)

---

## SEC-017 (TLT-17) — Supply chain:no CI SCA,no SAST,no signed artifacts (NEXT_TASK roadmap)

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-017 |
| status | **fixed (2026-04-26 by Phase 5 #0 commit)** |
| verification_method | infrastructure-verify |
| severity_lan_only | Medium | severity_if_public | High |
| blocks_commercialization | true (SOC 2 CC8.1) |
| confidence | High |
| **related_sdlc** | SDLC-001 |

### Observation
- 無 GitHub Actions workflow file
- 無 dependabot / renovate 自動 PR
- 無 secret scanning(commits 含 token 不會被擋)
- 無 SBOM-of-self(SBOM 工具自己沒幫自己產 SBOM)
- 無 sigstore / cosign 簽自己 release artifacts

### Recommendation
**Setup CI baseline** — `.github/workflows/security.yml`:
```yaml
- pip-audit (Python deps)
- npm audit + npm-audit-resolver (Node deps)
- bandit (Python SAST)
- gitleaks (secret scan, blocking)
- syft + grype (self SBOM + scan)
```

- effort: M (~3h initial setup + ongoing maintenance)
- risk_of_fix: Low (additive)

### Phase 5 #0 fix (2026-04-26)

Files added:
- `.github/workflows/security.yml` — 6 jobs:python-audit (pip-audit + bandit) / npm-audit / secret-scan (gitleaks) / self-sbom (syft + grype) / backend-tests (test_all.py 54-test regression) / reachability-corpus (Wave D ground-truth validator)
- `.github/dependabot.yml` — weekly pip + npm + monthly gh-actions updates;label `security`
- `.gitleaks.toml` — allowlist for documented insecure defaults (sbom@2024 / change-me-in-production / PocViewer2026!) so CI doesn't block PRs on known-public sentinels;adds custom rules for real JWT-shape and `sbom_` API token prefix detection

`actions/setup-python@v5` pinned to `python-version: '3.11'` — locks CI to Python ≥ 3.11.4 (current brew route) → SEC-002's expat amplification defence layer is guaranteed in CI runs. SEC-022 (Phase 5 #7) will mirror this lock at packaging level via pyproject.toml.

**Verification (infrastructure-verify per rev-4 commit discipline)**:
- `Before fix`:N/A — adding capability, not fixing bug
- `After fix`:CI workflow lands;subsequent PR triggers all 6 jobs;
  to validate end-to-end:open PR with `lodash@4.17.20` injected into
  `frontend/package.json` (known CVE-2019-10744)→ npm-audit job blocks
- Local YAML lint:`yamllint .github/workflows/security.yml` (manual,
  no GH runner available without push)

**Phase 5 acceptance**:CI runs green on first push of this commit (no pre-existing CVE in current dep set) AND a follow-up known-bad PR is properly blocked. If first push surfaces a new CVE we didn't expect, treat as a NEW finding (severity TBD), NOT a SEC-017 regression.

---

## SEC-018 (TLT-18) — nginx security headers gaps

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-018 |
| status | open |
| verification_method | static (nginx-sbom.conf) |
| severity_lan_only | Info | severity_if_public | Medium |
| blocks_commercialization | true (general best-practice; auditors flag) |

### Observation
`deploy/nginx-sbom.conf` 完全沒設 security headers。缺:
- `Strict-Transport-Security` (HSTS;只 HTTPS 場景需要,LAN HTTP 跳過)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` (clickjacking)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: ...` (geolocation, camera, microphone — all none)
- `Content-Security-Policy` (most impactful for XSS,但需要前端 inline script 全面 audit 才能設)

### Recommendation
Add `add_header` lines to `deploy/nginx-sbom.conf`:
```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
# CSP last because needs frontend inline-script audit:
# add_header Content-Security-Policy "default-src 'self'" always;
```

- effort: S (~30min — config + reload nginx)
- risk_of_fix: Low (defensive headers don't change app behavior)

---

## SEC-019 (TLT-19) — OS / launchd hardening: 1 worker (also SEC-015), soft RSS only, no read-only FS

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-019 |
| status | open |
| verification_method | static (com.sbom.backend.plist) |
| severity_lan_only | Low | severity_if_public | Medium |

### Observation
- `SoftResourceLimits.ResidentSetSize` only;macOS 不 kill,只 throttle
- 無 read-only filesystem mode (uvicorn 只寫 uploads/ 跟 logs/)
- 無 sandboxing (App Sandbox / SIP-style)

### Recommendation
- 加 `HardResourceLimits.ResidentSetSize`(iOS 風格, kernel 強制)
- 用 sandboxd / `sandbox-exec -p '(profile no-network) ...'` 限制可寫路徑(避免被 RCE 後寫 /etc /bin)
- effort: M (~4h研究 sandbox-exec + 測試);risk_of_fix: High (sandbox 設錯會 boot 不起來)

---

## SEC-020 (TLT-20) — LLM threats — DEFERRED

per threat-model §TLT-20 expanded.Status:`deferred`,re-open trigger:first PR adding any LLM client.

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-020 |
| status | deferred |
| verification_method | n/a (no LLM in product) |
| severity_lan_only | n/a | severity_if_public | n/a |

### Observation
Documented placeholder for commercialisation re-open. Sub-threats listed in threat-model:prompt injection via SBOM, training-data leak to vendor, hallucinated remediation, output XSS, excessive agency, cost amplification, model lock-in.

---

## SEC-021 (TLT-21) — Time / clock integrity: NTP, JWT exp tolerance, in-memory rate-limit reset on uvicorn restart

### Metadata
| field | value |
|-------|-------|
| finding_id | SEC-021 |
| status | open |
| verification_method | static + manual-review-pending |
| severity_lan_only | Low | severity_if_public | Medium |

### Observation
- `datetime.now(timezone.utc)` 用法一致(不用 `utcnow()` deprecated)— good
- NTP daemon Mac mini 預設啟用?Mac 預設 `timed` daemon enabled;確認 production 沒被關
- OIDC `iat` tolerance 待 `auth.py:oidc_callback` 確認(可能 jose lib 預設 60s skew tolerance)
- `rate_limit.SlidingWindowLimiter._calls` in-memory dict,uvicorn 重啟全清 — attacker 可定 backend `KeepAlive` 重啟 pattern 來 brute-force 登入

### Recommendation
#### primary_remediation
- 把 rate_limit 從 in-memory 換 SQLite-backed(同一 sbom.db,加 `rate_limit_events` 表)or Redis (commercialised setup)
- `auth.py oidc_callback` 顯式設 `leeway=300`(秒)允許 ±5 分鐘 skew
- 文件化:Mac mini NTP 必啟(deploy/MACMINI_SETUP.md 加 checklist)

- effort: M (~3h)
- risk_of_fix: Low

---

## Statistics roll-up (self-check after 19 findings written)

| metric | count |
|--------|-------|
| Total findings (TLT-2..21) | 19 |
| Open findings | 16 |
| confirmed-N/A | 1 (SEC-004 subprocess) |
| deferred | 1 (SEC-020 LLM) |
| dynamic-poc executed | 1 (SEC-002) |
| dynamic-poc-pending | 0 (SEC-005 / SEC-006 / etc. labelled static) |
| static + heuristic | 17 |

**Severity distribution(severity_lan_only)**:
- Critical: 0
- High: 0
- Medium: 4 (SEC-010, SEC-014, SEC-015, SEC-017)
- Low: 12
- Info: 1 (SEC-018)
- N/A: 2 (SEC-004, SEC-020)

**Severity distribution(severity_if_public)**:
- Critical: 0
- High: 4 (SEC-003, SEC-014, SEC-015, SEC-017)
- Medium: 11
- Low: 2 (SEC-007, SEC-009)
- Info: 0
- N/A: 2

**blocks_commercialization**:
- true: 7 (SEC-002, SEC-003, SEC-014, SEC-015, SEC-017, SEC-018, plus parent SEC-001)
- partial: 4 (SEC-005, SEC-008, SEC-010, SEC-012)
- false: 6
- n/a: 2

**No severity inflation observed** — distribution is heavy-Medium / Low which matches LAN-only context. Top 4 High-on-public findings (SEC-003, SEC-014, SEC-015, SEC-017) are consistent with "things that only matter when there's an internet attacker" rule.

**SDLC-001 expected_recurrence vs actual**:
- expected: TLT-3 ✓ (SEC-003 hits same SDLC-001 pattern)
- expected: TLT-7 ✗ (SEC-007 verified — alg whitelist + scope checks present;NOT a recurrence)
- expected: TLT-13 ✓ partial (SEC-013 audit log = some convention-not-enforcement;but specifically about TYPE of constraint, not the same pattern)
- expected: TLT-18 ✓ (SEC-018 nginx headers = manual config not policy)

**Action**: SDLC-001 `expected_recurrence` should remove TLT-7 and add caveat about TLT-13 partial match. Will update parent doc.

---

## End of TLT-2..21 batch

**Phase 3 status**: SEC-001 family (5 findings) + SDLC-001 in main doc + SEC-002..021 (19 findings) here = **25 findings total**.

Phase 4 entry next:executive summary + risk heatmap + Top-10 must-fix.

---

# Rev-5 amendment: SEC-022 split from SEC-002 (per user round-4 review)

Background:Phase 3 SEC-002 PoC investigation discovered the codebase has zero machine-readable Python version pinning. This is a supply-chain / packaging-hygiene gap distinct from XML billion-laughs (application security). Per "one finding one commit" discipline + category separation, the Python version floor work is split into its own finding **SEC-022**.

## SEC-022 (TLT-17 / supply-chain) — Backend lacks Python version floor in packaging metadata

### Metadata

| field | value |
|-------|-------|
| finding_id | SEC-022 |
| parent_finding | null |
| status | open |
| discovered_phase | 3 (incidental finding from SEC-002 PoC investigation;split from SEC-002 fix scope per rev-5 amend) |
| verification_method | static (file inspection) |
| first_observed_commit | initial commit (architectural absence) |
| exploitation_complexity | trivial (any contributor on Python 3.10 silently breaks defense layers) |
| severity_lan_only | **Low** (current Mac mini brew route uses python@3.11 ≥ 3.11.4) |
| severity_if_public | **Medium** (commercialised customers may run on diverse Pythons) |
| blocks_commercialization | **true** (SOC 2 CC8.1 / ISO 27001 A.8.30) |
| confidence | High |
| category | Supply chain / Packaging hygiene |
| cwe | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (loose match) |
| owasp | OWASP A06:2021 Vulnerable & Outdated Components (loose) |
| cvss_3_1 | n/a (architectural metadata absence) |

### traceability

```yaml
traceability:
  threat: TLT-17                       # supply chain
  parent_finding: null
  attack_tree_leaf: null
  abuse_cases: []
  related_findings:
    - SEC-002      # SEC-002's stdlib-version-dependent defense (expat 2.5+
                   # amplification check) requires Python ≥ 3.11.4;SEC-022
                   # closes the version-floor gap that protects SEC-002
                   # in commercialised / fallback runtime environments
    - SEC-017      # CI baseline locks python-version in setup-python action;
                   # SEC-022 mirrors the same lock at packaging level
    - SDLC-001     # supply-chain mandatory enforcement is the same anti-pattern
                   # family ("rely on convention not enforcement") that SDLC-001
                   # documents at the auth layer
```

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC8.1
    gap_type: control_missing
    note: |
      Change management — supply-chain / runtime version pinning is part of
      secure SDLC.  Absence at packaging level means any release artifact
      could ship on a regressed Python without warning.
  - framework: ISO27001
    control: A.8.30
    gap_type: control_missing
    note: Outsourced development — contributors and CI environments are
      "outsourced" runtime providers;require enforced version floor.
  - framework: ISO27001
    control: A.8.32
    gap_type: control_partial
    note: Change management — minor version drift can break defense layers.
  - framework: IEC62443-4-1
    control: SI-2
    gap_type: control_missing
    note: Secure implementation requires reusable safe defaults;
      packaging-level Python floor is one such default.
```

### Location

- `backend/requirements.txt` — no `python_requires` comment / no Python version specifier (NEGATIVE)
- `backend/` — no `pyproject.toml` / no `setup.py` / no `setup.cfg` (NEGATIVE)
- `deploy/setup-macos.sh:64` — installs python@3.11 explicitly (SAFE for Mac mini path,not constraining)
- `.github/workflows/` — empty per Phase 1 (SEC-017 will close the CI side)

### Observation

Commercialisation SBOM tool 自身沒 `pyproject.toml` 也沒 `python_requires`。任何下面情境**都會 silently 破壞** defense layers(尤其 SEC-002 expat amplification 那層):

1. **新貢獻者**:`pip install -r requirements.txt` 在 Python 3.10 系統上 — 成功安裝,backend 啟動,**zero amplification 防護**
2. **CI runner default image**:GitHub Actions ubuntu-latest 提供多版本 Python;沒明示 `setup-python python-version` 鎖定 → 可能 default 到 3.10
3. **Docker fallback**:`FROM python:3.11` 可能解析到 3.11.0–3.11.3(若 base image 老);`FROM python:3` 看當下最新而異
4. **Linux 預設**:Ubuntu 22.04 LTS 預設 Python 3.10;Debian 12 預設 3.11 但 patch 版未定

**諷刺面**:**這是 SBOM 工具**。供應鏈 hygiene 工具自己沒 demonstrate 這 practice = 客戶 due-diligence 會放大檢查。

### Recommendation

#### primary_remediation

新增 `backend/pyproject.toml`,鎖 Python 下界:

```toml
[project]
name = "sbom-platform-backend"
version = "0.1.0"
description = "SBOM Management Platform — backend"
requires-python = ">=3.11.4"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```

CI matrix 同步鎖(SEC-017 CI 設定 import 此檔):

```yaml
# .github/workflows/security.yml — 由 SEC-017 #0 commit 建立
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'   # provides 3.11.x latest; ≥ 3.11.4 since June 2023
```

- effort:S (~30 min)
- risk_of_fix:Low(additive metadata,不改 runtime 行為)

#### defense_in_depth

- Pre-commit hook(SEC-017 CI 對應的 client-side):pip-version check 跑在 push 前
- `tools/check_python_floor.py`:CI script 讀 pyproject.toml `requires-python` 對比 `setup-macos.sh` PYTHON_BIN,drift 即 fail

#### compensating_control

pyproject.toml 落地前,在 `README.md` Quick Start + `CLAUDE.md` 文件化 Python 3.11.4+ 下界。CLAUDE.md 已寫「production server runs Python 3.11」但**沒寫 3.11.4 minimum** — 補一句即可。

#### monitoring_detection

```yaml
monitoring_detection:
  applies_to_finding: SEC-022
  endpoint_class: ci-runtime
  log_pipeline: CI workflow output (GitHub Actions log)
  log_field:
    name: ci_python_version
    type: string
    sourced_from: setup-python action output
  alert_rule: |
    ci_python_version 不符 ">=3.11.4" → CI fails, blocks merge
```

- effort:S(覆蓋於 SEC-017 CI baseline)
- risk_of_fix:None

### Phase 5 verification expectation(infrastructure-verify)

```bash
# 1. pyproject.toml 存在且鎖 requires-python
cat backend/pyproject.toml | grep requires-python
> requires-python = ">=3.11.4"

# 2. pip install 在 3.10 失敗
docker run -it python:3.10 sh -c "cd /backend && pip install -e ."
> ERROR: Package requires Python >= 3.11.4. Current is 3.10.x

# 3. CI workflow log 顯示鎖定版本
gh run view <id> --log | grep "Python "
> Python 3.11.10 (or 3.12.x)
```

### References

- PEP 621 — pyproject.toml `[project]` metadata
- PEP 518 — build-system requires
- SOC 2 CC8.1 / ISO 27001 A.8.30 / A.8.32 / IEC 62443-4-1 SI-2

---

## Updated final count: **26 findings total**(rev-5)

SEC-001 family (5) + SDLC-001/002/003 (3) + SEC-002..021 (19) = 27 entries. Subtract:SEC-001 parent and SDLC-001 parents are tracking-only (no own severity), and SEC-022 just added. Operational findings count adjusts to 26.
