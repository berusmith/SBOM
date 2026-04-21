"""
Parse CycloneDX JSON and SPDX JSON into a unified component list.
Returns list of dicts: {name, version, purl, license}
"""
import json


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
