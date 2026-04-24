"""
Trivy wrapper: scan container images and IaC/filesystem archives.
Returns CycloneDX JSON which is then fed into the existing sbom_parser pipeline.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import zipfile
from pathlib import Path


def is_trivy_available() -> bool:
    try:
        r = subprocess.run(["trivy", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def scan_image(image_ref: str, timeout: int = 300) -> dict:
    """
    Run `trivy image --format cyclonedx <image_ref>`.
    Returns parsed CycloneDX dict, or raises RuntimeError with a user-facing message.
    """
    if not is_trivy_available():
        raise RuntimeError("Trivy 未安裝，請先執行：curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh")

    result = subprocess.run(
        ["trivy", "image", "--format", "cyclonedx", "--quiet", image_ref],
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")
        raise RuntimeError(f"Trivy 掃描失敗：{stderr[:500]}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Trivy 輸出解析失敗：{e}")


def scan_iac(zip_bytes: bytes, timeout: int = 180) -> dict:
    """
    Unzip the uploaded archive, run `trivy fs --format cyclonedx --scanners misconfig,vuln`.
    Returns parsed CycloneDX dict (components may be sparse for pure IaC).
    Raises RuntimeError on failure.
    """
    if not is_trivy_available():
        raise RuntimeError("Trivy 未安裝，請先執行：curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Unzip safely (no path traversal)
        with zipfile.ZipFile(__import__("io").BytesIO(zip_bytes)) as zf:
            for member in zf.infolist():
                name = Path(member.filename).as_posix()
                if ".." in name or name.startswith("/"):
                    continue
                dest = tmp / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not member.is_dir():
                    dest.write_bytes(zf.read(member.filename))

        result = subprocess.run(
            [
                "trivy", "fs",
                "--format", "cyclonedx",
                "--quiet",
                "--scanners", "misconfig,vuln",
                str(tmp),
            ],
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")
            raise RuntimeError(f"Trivy IaC 掃描失敗：{stderr[:500]}")

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Trivy 輸出解析失敗：{e}")


def extract_misconfigs(cyclonedx: dict) -> list[dict]:
    """
    Pull Trivy misconfig findings out of CycloneDX vulnerabilities section.
    Returns list of {id, title, severity, resource, resolution}.
    """
    findings = []
    for vuln in cyclonedx.get("vulnerabilities", []):
        vid = vuln.get("id", "")
        # Trivy misconfig IDs start with AVD- or DS-
        if not (vid.startswith("AVD-") or vid.startswith("DS-")):
            continue
        findings.append({
            "id": vid,
            "title": vuln.get("description", vid),
            "severity": (vuln.get("ratings") or [{}])[0].get("severity", "unknown").lower(),
            "resource": (vuln.get("affects") or [{}])[0].get("ref", ""),
            "resolution": vuln.get("recommendation", ""),
        })
    return findings
