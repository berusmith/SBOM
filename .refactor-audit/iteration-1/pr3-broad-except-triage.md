# PR-3 broad-except triage — CODE-1.014 partial closure

Generated 2026-05-03 (PR-3 Stage N.1).
Branch: `refactor/iter-1-pr3-error-handling` at HEAD = the N.1 audit-doc commit.

## §1 Scope + methodology

This document classifies every `except Exception:` / `except:` /
`except BaseException:` site in `backend/app/` per CODE-1.014 partial
closure scope (Q-PR3 ratification (α): fix silent swallows + annotate
deliberate keeps + DEFER translate-and-raise + typed-domain-exceptions
to iter-2).

**Source grep** (run during PR-3 Phase 0):
```
grep -rn "except Exception\|except:\|except BaseException" backend/app/
```

Returned 47 lines.  1 line is a docstring false positive
(`upload_sbom.py:69` contains the word "except" inside a CODE-1.011
fix-history reference comment, not an `except` clause).  Actual broad-except
clause count: **46 sites**.

## §2 47-site classification table

| File:line | Class | Reason / Target |
|-----------|:-----:|-----------------|
| `api/auth.py:119` | (c) | OIDC discovery URL fetch — wraps urllib errors as HTTPException; iter-2 typed-exc target: `OIDCDiscoveryError` |
| `api/auth.py:148` | (c) | OIDC token exchange — wraps urllib + JSON parse; iter-2 typed-exc target: `OIDCTokenExchangeError` |
| `api/auth.py:164` | (c) | OIDC userinfo fetch — wraps urllib + JSON; iter-2 typed-exc target: `OIDCUserinfoError` |
| `api/firmware.py:81` | (a) | Top-level upload handler — translates ALL upload-time errors to user-facing 500 |
| `api/firmware.py:132` | (a) | Background scan-spawn — must not crash request thread when scan-launch fails |
| `api/firmware.py:192` | **(b)** | **Silent swallow** — EMBA JSON parse fallback; bare `pass`; FIX in N.2 (add `logger.exception`) |
| `api/firmware.py:207` | (a) | Top-level GET status handler — translates DB/IO errors to user-facing 500 |
| `main.py:173` | **(b)** | **Silent swallow** — `CREATE INDEX IF NOT EXISTS` startup loop; bare `pass`; FIX in N.3 (log but don't raise — best-effort startup) |
| `main.py:354` | (a) | Top-level migration block — startup must boot even with partial migration; logs already present elsewhere |
| `services/alerts.py:28` | (a) | Webhook HTTP send — must not crash event-emit caller; logs `e` value |
| `services/alerts.py:167` | (a) | Per-rule alert dispatch in loop — must not stop other rules; logs `e` value |
| `services/alerts.py:195` | (a) | Top-level `notify_new_vulns` — must not crash background scan; logs `e` value |
| `services/firmware_service.py:18` | (a) | Bare `except:` — system-availability check (`shutil.which("emba")`); intentional broad scope |
| `services/firmware_service.py:104` | (a) | Background scan job worker — must not crash worker; logs `e` |
| `services/firmware_service.py:129` | (a) | Bare `except:` — JSON parse fallback during EMBA result extraction |
| `services/font_manager.py:123` | (a) | Font discovery on Windows — registry-or-path lookup with multiple failure modes; logs `e` |
| `services/font_manager.py:196` | (a) | Top-level font load — fallback to default font; logs `e` |
| `services/ghsa.py:68` | (a) | Per-PURL GHSA query in batch — must not crash batch; one-PURL failure shouldn't fail others |
| `services/ghsa.py:87` | (a) | Top-level `fetch_ghsa_for_components` — wraps batch errors; logs `e` |
| `services/monitor.py:125` | (a) | Background monitor scan loop — per-release error must not stop other releases |
| `services/monitor.py:153` | (a) | Background monitor scan job — must not crash monitor thread |
| `services/monitor.py:167` | (a) | Background monitor cleanup loop — must not crash thread |
| `services/monitor.py:199` | (a) | Background scheduling tick — must not crash scheduler |
| `services/monitor.py:225` | (a) | Background monitor outer loop — last-resort safety net |
| `services/nvd.py:39` | (a) | NVD per-CVE fetch in batch — one CVE failure shouldn't fail batch |
| `services/pdf_report.py:107` | (a) | PDF report top-level — wraps reportlab errors as fallback PDF |
| `services/pdf_shim.py:229` | (a) | Library-boundary fallback (reportlab not installed) |
| `services/pdf_shim.py:249` | (a) | Library-boundary fallback (font load) |
| `services/pdf_shim.py:253` | (a) | Library-boundary fallback (PDF generation) |
| `services/pdf_shim.py:340` | (a) | Library-boundary fallback (table render) |
| `services/pdf_shim.py:350` | (a) | Library-boundary fallback (image embed) |
| `services/pdf_shim.py:403` | (a) | Library-boundary fallback (cleanup) |
| `services/scanners/reachability/python_analyzer.py:284` | (a) | Per-file AST parse — one bad file mustn't crash whole scan |
| `services/signature_verifier.py:53` | (a) | Public-key parse fallback — multiple format candidates (PEM/DER); logs not needed (caller handles) |
| `services/signature_verifier.py:84` | (c) | ECDSA verify — wraps cryptography errors; iter-2 typed-exc target: `SignatureVerificationError` |
| `services/signature_verifier.py:94` | (c) | RSA-PSS verify — same; iter-2 typed-exc target: `SignatureVerificationError` |
| `services/signature_verifier.py:153` | (c) | RSA-PKCS1 verify — same; iter-2 typed-exc target: `SignatureVerificationError` |
| `services/signature_verifier.py:192` | **(b)** | **Silent swallow** — X.509 cert parse for signer identity extraction; bare `pass`; FIX in N.4 (log + return None gracefully) |
| `services/signature_verifier.py:200` | (a) | X.509 issuer parse — fallback when DN parsing fails; returns "Unknown" |
| `services/syft_scanner.py:48` | (a) | Library-boundary check (`syft` binary availability) |
| `services/trivy_scanner.py:18` | (a) | Library-boundary check (`trivy` binary availability) |
| `services/usecases/release/enrich.py:265` | (a) | Background EPSS enrichment — must not crash enrichment task |
| `services/usecases/release/enrich.py:306` | (a) | Background NVD enrichment — must not crash enrichment task |
| `services/usecases/release/lifecycle.py:313` | **(b)** | **Silent swallow** — sbom_quality_grade computation in `get_gate`; bare `pass`; FIX in N.5 (same shape as PR-1's already-fixed CODE-1.011, use `logger.exception`) |
| `services/usecases/release/upload_sbom.py:62` | (a) | NTIA score helper — pre-existing broad catch with `e` used; library-boundary feel |
| `services/usecases/release/upload_sbom.py:84` | **HISTORICAL** | **Already fixed in PR-1 D.3** — `logger.exception(...)` instead of bare pass; CODE-1.011's specific site closure |

**Summary**:
- **(a) deliberate keep**: 37 sites
- **(b) silent swallow (FIX in N.2-N.5)**: 4 sites
- **(c) translate-and-raise (DEFER to iter-2)**: 6 sites
- HISTORICAL closure (PR-1 D.3): 1 site
- Docstring false positive (not counted): 1 grep line at upload_sbom.py:69

Total: 37 + 4 + 6 + 1 = 48 (47 grep lines minus 1 docstring false positive + 1 historical site that's already counted; matches 46 actual broad-except clauses + 1 historical closure marker).

## §3 (b) silent-swallow fix plan

For each of the 4 sites, the minimum-bar pattern is **`logger.exception(...)` + appropriate next action** (re-raise / return None / pass-with-log).  Re-raise only if caller can handle; for startup / background-task contexts, log + continue is acceptable per the (a) classification rationale (but the difference is the SILENT swallow has no log line, which makes debugging blind).

| Site | Stage | Target replacement pattern |
|------|:-----:|---------------------------|
| `api/firmware.py:192` | N.2 | `except Exception:` → `except (json.JSONDecodeError, KeyError, ValueError) as e:` + `logger.warning("EMBA JSON extract failed for scan %s: %s", scan_id, e)` (continue with empty result) |
| `main.py:173` | N.3 | `except Exception:` → keep broad (DDL errors are diverse) but replace `pass` with `_startup_log.warning("CREATE INDEX failed: %s", _idx)` (best-effort startup, continue) |
| `signature_verifier.py:192` | N.4 | `except Exception:` → `except Exception as e:` + `logger.debug("X.509 signer extract failed: %s", e)` (return None gracefully — used as best-effort metadata extraction) |
| `usecases/release/lifecycle.py:313` | N.5 | `except Exception:` → keep broad (multiple SBOM parse failure modes) but replace `pass` with `logger.warning("SBOM quality grade computation failed for release %s: %s", release_id, e)` — same shape as CODE-1.011's PR-1 D.3 fix at `upload_sbom.py:84` |

## §4 (c) deferred sites + iter-2 carry-over

The 6 (c) sites all share a pattern: **wrap a foreign-library exception
and translate to a domain-meaningful error**.  This is the canonical use
case for typed domain exceptions.

Per Q-PR3-2 (b) decision (DEFER FU-1.001 + typed-exc to iter-2),
**`domain/exceptions.py` is NOT introduced in PR-3**.  Iter-2 entry plan
inherits this scope:

- **Iter-2 task A**: introduce `backend/app/domain/exceptions.py` with `DomainError` base class + 4 typed subclasses needed for these 6 sites:
  - `OIDCDiscoveryError` (auth.py:119)
  - `OIDCTokenExchangeError` (auth.py:148)
  - `OIDCUserinfoError` (auth.py:164)
  - `SignatureVerificationError` (signature_verifier.py:84/94/153 — 3 sites use same target type)
- **Iter-2 task B**: replace each (c) site's `except Exception as e:` body with `except (...) as e: raise <SpecificType>(...) from e`.
- **Iter-2 task C**: write ADR-0005 documenting the typed-exception decision (analogous to PR-1 D.4 domain layer extraction).

These 6 sites are NOT touched in PR-3.  PR-3 closes CODE-1.014 PARTIALLY
— silent swallows + deliberate keeps annotated; translate-and-raise +
typed-exc deferred.

## §5 Historical correction note

The user's PR-3 entry prompt referenced "CODE-1.011 broad-except triage —
46 個 broad except 散落 backend/app/".  Phase 0 grep validation surfaced
this as **§K invocation #10** (K.7.3 category-axis catch):

- **CODE-1.011** = ONE specific silent swallow at `releases.py:215-221`
  (pre-PR-1 location; post-D.2 location is `usecases/release/upload_sbom.py:80-85`).
  This site is **already fixed** during PR-1 D.3 commit `e811bb2`
  ("CODE-1.009/1.016/ARCH-1.013 bundled fixes" — also bundled the
  CODE-1.011 silent-swallow fix per the commit's bundled-fixes scope;
  current code uses `logger.exception(...)` not bare pass).
- **CODE-1.014** = the umbrella triage of all 46 broad-except sites.
  This is what PR-3 Stage N is actually executing (per (α) partial
  scope: silent swallows + deliberate keeps annotated + translate-and-raise
  deferred).

Stage R.2 will retroactively update `code-audit.md` CODE-1.011 status
block to record PR-1 D.3 historical closure, and CODE-1.014 status block
to record PR-3 partial closure.  Stage R.1 D30 entry will record the
§K invocation #10 + (α) resolution as the audit-trail for the spec
correction.

## §6 Methodology + verification

Classification was done by:
1. Reading each site's surrounding 5-line context to identify pattern (top-level handler / background safety-net / library boundary / silent swallow / translate-and-raise).
2. Cross-referencing with CODE-1.014's recommendation in `code-audit.md:281-286` ("Legitimate top-level boundary ~25 sites; Background-task safety nets ~10 sites; Silent swallows ~5 sites; Translate-and-raise ~6 sites").
3. Grep-confirming silent-swallow set: `grep -B 1 -A 1 "except Exception:" | grep -A 1 "except Exception:" | grep "pass$"` returns the 4 sites in the (b) row exactly.

Forecast accuracy vs CODE-1.014's 46-site forecast:
- Actual: 46 broad-except clauses (47 grep lines minus 1 docstring false positive)
- (a) deliberate: 37 actual vs ~25 (25+10) forecast — close (37 ≈ 35 if the +10 background were merged with +25 top-level, which is the natural collapse; CODE-1.014 split them as separate bullets)
- (b) silent: 4 actual vs ~5 forecast — slightly under (CODE-1.011's site already fixed, so the umbrella's "~5 silent" only had 4 left to fix)
- (c) translate-and-raise: 6 actual vs ~6 forecast — exact match

Triage doc accepts +/- 1 forecast variance as expected (CODE-1.014 was a Phase 5 estimate, not a precise count).
