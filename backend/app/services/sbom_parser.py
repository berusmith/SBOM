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
