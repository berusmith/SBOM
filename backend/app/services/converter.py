"""
SBOM format converter.
Supports:
  cyclonedx-json → spdx-json
  spdx-json      → cyclonedx-json
  cyclonedx-json → cyclonedx-xml
  cyclonedx-xml  → cyclonedx-json  (via xml.etree)

All conversions preserve as much metadata as possible from the source.
"""
from __future__ import annotations

import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

SUPPORTED_TARGETS = ("cyclonedx-json", "cyclonedx-xml", "spdx-json")


def detect_format(data: dict) -> str:
    """Return 'cyclonedx-json' or 'spdx-json'."""
    if "spdxVersion" in data:
        return "spdx-json"
    if "bomFormat" in data or "components" in data:
        return "cyclonedx-json"
    raise ValueError("無法辨識 SBOM 格式（需要 CycloneDX JSON 或 SPDX JSON）")


def convert(content: bytes, filename: str, target: str) -> tuple[bytes, str]:
    """
    Convert SBOM bytes to target format.
    Returns (output_bytes, suggested_filename).
    Raises ValueError on unsupported conversion or parse errors.
    """
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"不支援的目標格式 {target!r}，可選：{', '.join(SUPPORTED_TARGETS)}")

    fname_lower = filename.lower()

    # ── CycloneDX XML input ───────────────────────────────────────────────────
    if fname_lower.endswith(".xml"):
        data = _cdx_xml_to_json(content)
        source = "cyclonedx-json"
    else:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON 解析失敗：{e}")
        source = detect_format(data)

    if source == target or (source == "cyclonedx-json" and target == "cyclonedx-json"):
        raise ValueError(f"來源格式與目標格式相同（{source}），無需轉換")

    # ── Dispatch ───────────────────────────────────────────────────────────────
    if source == "cyclonedx-json" and target == "spdx-json":
        out = _cdx_to_spdx(data)
        return json.dumps(out, indent=2, ensure_ascii=False).encode(), "converted.spdx.json"

    if source == "spdx-json" and target == "cyclonedx-json":
        out = _spdx_to_cdx(data)
        return json.dumps(out, indent=2, ensure_ascii=False).encode(), "converted.cyclonedx.json"

    if source == "cyclonedx-json" and target == "cyclonedx-xml":
        out = _cdx_json_to_xml(data)
        return out, "converted.cyclonedx.xml"

    if source == "spdx-json" and target == "cyclonedx-xml":
        cdx = _spdx_to_cdx(data)
        out = _cdx_json_to_xml(cdx)
        return out, "converted.cyclonedx.xml"

    raise ValueError(f"不支援 {source} → {target} 轉換")


# ── CycloneDX JSON → SPDX JSON ────────────────────────────────────────────────

def _cdx_to_spdx(cdx: dict) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_name = cdx.get("metadata", {}).get("component", {}).get("name", "converted-sbom")

    packages = []
    rels = []
    doc_id = "SPDXRef-DOCUMENT"

    for comp in cdx.get("components", []):
        ref = "SPDXRef-" + re.sub(r"[^A-Za-z0-9\-.]", "-", f"{comp.get('name','pkg')}-{comp.get('version','')}")
        pkg: dict = {
            "SPDXID": ref,
            "name": comp.get("name", ""),
            "versionInfo": comp.get("version", ""),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        if comp.get("purl"):
            pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": comp["purl"]}]
        lic = _cdx_license_str(comp)
        pkg["licenseConcluded"] = lic or "NOASSERTION"
        pkg["licenseDeclared"] = lic or "NOASSERTION"
        pkg["copyrightText"] = "NOASSERTION"
        if comp.get("description"):
            pkg["comment"] = comp["description"]
        packages.append(pkg)
        rels.append({"spdxElementId": doc_id, "relationshipType": "DESCRIBES", "relatedSpdxElement": ref})

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": doc_name,
        "documentNamespace": f"https://sbom.example.com/{uuid.uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: SBOM Platform Converter"],
        },
        "packages": packages,
        "relationships": rels,
    }


def _cdx_license_str(comp: dict) -> str:
    licenses = comp.get("licenses", [])
    ids = []
    for item in licenses:
        lic = item.get("license", {})
        ids.append(lic.get("id") or lic.get("name") or "")
    return " AND ".join(filter(None, ids))


# ── SPDX JSON → CycloneDX JSON ────────────────────────────────────────────────

def _spdx_to_cdx(spdx: dict) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_name = spdx.get("name", "converted-sbom")

    components = []
    for pkg in spdx.get("packages", []):
        name = pkg.get("name", "")
        if not name:
            continue
        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break

        lic_raw = pkg.get("licenseDeclared") or pkg.get("licenseConcluded") or ""
        if lic_raw in ("NOASSERTION", "NONE", ""):
            lic_raw = ""

        comp: dict = {
            "type": "library",
            "name": name,
            "version": pkg.get("versionInfo", ""),
            "bom-ref": pkg.get("SPDXID", str(uuid.uuid4())),
        }
        if purl:
            comp["purl"] = purl
        if lic_raw:
            comp["licenses"] = [{"license": {"id": lic_raw} if _is_spdx_id(lic_raw) else {"name": lic_raw}}]
        if pkg.get("comment"):
            comp["description"] = pkg["comment"]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "SBOM Platform Converter", "version": "1.0"}],
            "component": {"type": "library", "name": doc_name, "version": ""},
        },
        "components": components,
    }


def _is_spdx_id(s: str) -> bool:
    return bool(re.match(r'^[A-Za-z0-9\-\+\.]+$', s))


# ── CycloneDX JSON → XML ──────────────────────────────────────────────────────

_CDX_NS = "http://cyclonedx.org/schema/bom/1.5"

def _cdx_json_to_xml(cdx: dict) -> bytes:
    ET.register_namespace("", _CDX_NS)
    bom = ET.Element(f"{{{_CDX_NS}}}bom")
    bom.set("version", str(cdx.get("version", 1)))
    if cdx.get("serialNumber"):
        bom.set("serialNumber", cdx["serialNumber"])

    # metadata
    meta = cdx.get("metadata", {})
    if meta:
        m_el = ET.SubElement(bom, f"{{{_CDX_NS}}}metadata")
        if meta.get("timestamp"):
            ET.SubElement(m_el, f"{{{_CDX_NS}}}timestamp").text = meta["timestamp"]

    # components
    comps_el = ET.SubElement(bom, f"{{{_CDX_NS}}}components")
    for comp in cdx.get("components", []):
        c_el = ET.SubElement(comps_el, f"{{{_CDX_NS}}}component")
        c_el.set("type", comp.get("type", "library"))
        if comp.get("bom-ref"):
            c_el.set("bom-ref", comp["bom-ref"])
        for field in ("name", "version", "purl", "description"):
            if comp.get(field):
                ET.SubElement(c_el, f"{{{_CDX_NS}}}{field}").text = comp[field]
        if comp.get("licenses"):
            lics_el = ET.SubElement(c_el, f"{{{_CDX_NS}}}licenses")
            for item in comp["licenses"]:
                lic = item.get("license", {})
                l_el = ET.SubElement(lics_el, f"{{{_CDX_NS}}}license")
                if lic.get("id"):
                    ET.SubElement(l_el, f"{{{_CDX_NS}}}id").text = lic["id"]
                elif lic.get("name"):
                    ET.SubElement(l_el, f"{{{_CDX_NS}}}name").text = lic["name"]

    ET.indent(bom, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(bom, encoding="unicode").encode("utf-8")


# ── CycloneDX XML → JSON ──────────────────────────────────────────────────────

def _cdx_xml_to_json(content: bytes) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"XML 解析失敗：{e}")

    ns = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
    def tag(name: str) -> str:
        return f"{{{ns}}}{name}" if ns else name

    def text(el, name: str) -> str:
        child = el.find(tag(name))
        return child.text.strip() if child is not None and child.text else ""

    components = []
    for comp_el in root.findall(f".//{tag('component')}"):
        comp: dict = {
            "type": comp_el.get("type", "library"),
            "bom-ref": comp_el.get("bom-ref", ""),
            "name": text(comp_el, "name"),
            "version": text(comp_el, "version"),
        }
        purl = text(comp_el, "purl")
        if purl:
            comp["purl"] = purl
        desc = text(comp_el, "description")
        if desc:
            comp["description"] = desc
        lics = []
        for lic_el in comp_el.findall(f".//{tag('license')}"):
            lic_id = text(lic_el, "id")
            lic_name = text(lic_el, "name")
            if lic_id:
                lics.append({"license": {"id": lic_id}})
            elif lic_name:
                lics.append({"license": {"name": lic_name}})
        if lics:
            comp["licenses"] = lics
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": int(root.get("version", 1)),
        "serialNumber": root.get("serialNumber", f"urn:uuid:{uuid.uuid4()}"),
        "components": components,
    }
