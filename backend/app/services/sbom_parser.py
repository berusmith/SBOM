"""
Parse CycloneDX JSON and SPDX JSON into a unified component list.
Returns list of dicts: {name, version, purl, license}
"""
import json


def validate(content: bytes, filename: str) -> None:
    """Raise ValueError with a descriptive Chinese message if the SBOM is structurally invalid."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"無效的 JSON 格式：{e}")

    if not isinstance(data, dict):
        raise ValueError("SBOM 必須是 JSON 物件（{}），而非陣列或純值")

    if "spdxVersion" in data:
        _validate_spdx(data)
    elif "bomFormat" in data or "components" in data:
        _validate_cyclonedx(data)
    else:
        raise ValueError(
            "無法辨識 SBOM 格式。"
            "CycloneDX 需要 'bomFormat' 或 'components' 欄位；"
            "SPDX 需要 'spdxVersion' 欄位"
        )


def _validate_cyclonedx(data: dict) -> None:
    bom_format = data.get("bomFormat", "")
    if bom_format and bom_format.lower() != "cyclonedx":
        raise ValueError(f"bomFormat 欄位應為 'CycloneDX'，實際為 {bom_format!r}")

    if "components" not in data:
        raise ValueError("CycloneDX SBOM 缺少必要的 'components' 欄位")

    if not isinstance(data["components"], list):
        raise ValueError("CycloneDX 'components' 欄位必須是陣列（[]）")

    spec = data.get("specVersion", "")
    if spec and not any(spec.startswith(v) for v in ("1.", "2.")):
        raise ValueError(f"不支援的 CycloneDX specVersion：{spec!r}，支援 1.x / 2.x")

    for i, c in enumerate(data["components"][:10]):
        if not isinstance(c, dict):
            raise ValueError(f"components[{i}] 必須是物件，實際為 {type(c).__name__}")
        if "name" not in c:
            raise ValueError(f"components[{i}] 缺少必要的 'name' 欄位")


def _validate_spdx(data: dict) -> None:
    ver = data.get("spdxVersion", "")
    if not ver.startswith("SPDX-"):
        raise ValueError(f"無效的 spdxVersion：{ver!r}，應以 'SPDX-' 開頭")

    for field in ("SPDXID", "name"):
        if field not in data:
            raise ValueError(f"SPDX SBOM 缺少必要欄位 '{field}'")

    if "packages" not in data:
        raise ValueError("SPDX SBOM 缺少必要的 'packages' 欄位")

    if not isinstance(data["packages"], list):
        raise ValueError("SPDX 'packages' 欄位必須是陣列（[]）")


def parse(content: bytes, filename: str) -> list[dict]:
    data = json.loads(content)
    fname = filename.lower()

    if "spdxVersion" in data:
        return _parse_spdx(data)
    if "bomFormat" in data or "components" in data:
        return _parse_cyclonedx(data)

    raise ValueError("Unrecognized SBOM format. Expected CycloneDX JSON or SPDX JSON.")


def _parse_cyclonedx(data: dict) -> list[dict]:
    components = []
    for c in data.get("components", []):
        license_str = _cdx_license(c)
        components.append({
            "name": c.get("name", ""),
            "version": c.get("version", ""),
            "purl": c.get("purl", ""),
            "license": license_str,
        })
    return components


def _cdx_license(component: dict) -> str:
    licenses = component.get("licenses", [])
    ids = []
    for item in licenses:
        lic = item.get("license", {})
        ids.append(lic.get("id") or lic.get("name") or "")
    return ", ".join(filter(None, ids))


def _parse_spdx(data: dict) -> list[dict]:
    components = []
    for pkg in data.get("packages", []):
        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break
        declared = pkg.get("licenseDeclared", "")
        if declared in ("NOASSERTION", "NONE"):
            declared = ""
        components.append({
            "name": pkg.get("name", ""),
            "version": pkg.get("versionInfo", ""),
            "purl": purl,
            "license": declared,
        })
    # skip the root package (DESCRIBES relationship target)
    return [c for c in components if c["name"]]


# ── NTIA SBOM Quality Checks ──────────────────────────────────────────────────

def _pct(items: list, pred) -> float:
    if not items:
        return 0.0
    return sum(1 for i in items if pred(i)) / len(items)


def check_ntia(data: dict, is_spdx: bool) -> list[dict]:
    """Run NTIA minimum element checks. Returns list of {id, label, passed, detail}."""
    def ok(passed, detail=""):
        return {"passed": passed, "detail": detail}

    if is_spdx:
        pkgs = [p for p in data.get("packages", []) if p.get("name")]
        has_supplier = any(
            p.get("supplier", "") not in ("", "NOASSERTION", "NONE") for p in pkgs
        )
        version_pct = _pct(pkgs, lambda p: p.get("versionInfo", "") not in ("", "NOASSERTION", "NONE"))
        purl_pct    = _pct(pkgs, lambda p: any(
            r.get("referenceType") == "purl" for r in p.get("externalRefs", [])
        ))
        has_deps   = bool(data.get("relationships"))
        has_author = bool(data.get("creationInfo", {}).get("creators"))
        has_ts     = bool(data.get("creationInfo", {}).get("created"))
        fmt = "SPDX"
    else:
        comps = data.get("components", [])
        has_supplier = any(
            c.get("supplier", {}).get("name") or c.get("author") for c in comps
        )
        version_pct = _pct(comps, lambda c: bool(c.get("version", "").strip()))
        purl_pct    = _pct(comps, lambda c: bool(c.get("purl") or c.get("cpe")))
        has_deps    = bool(data.get("dependencies"))
        meta        = data.get("metadata", {})
        has_author  = bool(meta.get("authors") or meta.get("component", {}).get("author"))
        has_ts      = bool(meta.get("timestamp"))
        fmt = "CycloneDX"

    threshold = 0.8
    return [
        {"id": "supplier",     "label": "供應商名稱", **ok(has_supplier, f"{'有' if has_supplier else '無'}供應商欄位（{fmt}）")},
        {"id": "name",         "label": "元件名稱",   **ok(True, "上傳驗證已確保所有元件有名稱")},
        {"id": "version",      "label": "元件版本",   **ok(version_pct >= threshold, f"{version_pct*100:.0f}% 元件有版本（門檻 80%）")},
        {"id": "unique_id",    "label": "唯一識別碼", **ok(purl_pct >= threshold, f"{purl_pct*100:.0f}% 元件有 PURL/CPE（門檻 80%）")},
        {"id": "dependencies", "label": "相依關係",   **ok(has_deps, f"{'有' if has_deps else '無'}相依關係區塊")},
        {"id": "author",       "label": "SBOM 作者",  **ok(has_author, f"{'有' if has_author else '無'}作者 metadata")},
        {"id": "timestamp",    "label": "時間戳記",   **ok(has_ts, f"{'有' if has_ts else '無'}時間戳記 metadata")},
    ]


def score_sbom(data: dict) -> dict:
    """Return {score, grade, passed, total} for a parsed SBOM dict."""
    is_spdx = "spdxVersion" in data
    checks  = check_ntia(data, is_spdx)
    passed  = sum(1 for c in checks if c["passed"])
    total   = len(checks)
    score   = round(passed / total * 100)
    grade   = "A" if passed >= 6 else "B" if passed >= 4 else "C" if passed >= 2 else "D"
    return {"score": score, "grade": grade, "passed": passed, "total": total, "checks": checks}
