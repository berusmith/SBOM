"""
Syft wrapper: produce CycloneDX SBOMs from source archives or single binaries.

Syft (Anchore, Apache-2.0) handles a much broader surface than the existing
`sbom_parser` (which only consumes user-provided SBOMs) or `trivy_scanner`
(which targets container images and IaC).  It's used for two distinct flows
on the platform:

  1. **Source-archive scan**  — user uploads a .zip / .tar.gz of their repo,
     Syft walks it and identifies declared dependencies (package.json,
     requirements.txt, go.mod, Cargo.toml, pom.xml, ...).  Output is a
     CycloneDX JSON which then feeds the existing `sbom_parser.parse()`
     pipeline so the rest of the system (vuln scanner, EPSS, GHSA, SBOM
     quality scorer) lights up automatically.

  2. **Binary scan**  — user uploads a single binary (.exe / .so / .dll /
     a stripped firmware image / a Java jar / a Python wheel).  Syft
     applies its binary cataloguers (Go binary, .NET, Java, Python, Rust,
     Linux kernel, etc.) to extract embedded version information.  Same
     CycloneDX → sbom_parser pipeline downstream.

Like trivy_scanner we shell out to the Syft CLI rather than embedding a
library, so:
  * Apache-2.0 license stays at arms length (it's an external tool the
    operator installs).
  * Syft can be upgraded independently of the platform.
  * On macOS Mac Mini deployments the user installs via `brew install syft`
    (or via the INSTALL_SYFT=1 flag in deploy/setup-macos.sh).
"""
from __future__ import annotations

import io
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path


# Filesystem cap to prevent zip-bomb / runaway disk use during a scan.
_MAX_UNCOMPRESSED = 500 * 1024 * 1024   # 500 MB across all extracted files


def is_syft_available() -> bool:
    try:
        r = subprocess.run(["syft", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _install_hint() -> str:
    return (
        "Syft 未安裝。安裝指令(macOS):brew install syft;"
        "(Linux):curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
    )


def _run_syft_on_path(target: Path, timeout: int) -> dict:
    """Invoke `syft <target> -o cyclonedx-json` and return the parsed dict."""
    result = subprocess.run(
        ["syft", str(target), "-o", "cyclonedx-json", "--quiet"],
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")
        raise RuntimeError(f"Syft 掃描失敗:{stderr[:500]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Syft 輸出解析失敗:{e}")


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract zip to dest, refusing path-traversal entries and bounding the
    total uncompressed size at _MAX_UNCOMPRESSED."""
    total = 0
    dest_resolved = dest.resolve()
    for member in zf.infolist():
        # Reject absolute paths and any '..' segment in the entry name.
        # Path() normalises slashes for us; we then check that the resolved
        # destination stays inside dest.
        if member.is_dir():
            continue
        rel = Path(member.filename).as_posix()
        if rel.startswith("/") or ".." in rel.split("/"):
            continue
        out = (dest / rel).resolve()
        try:
            out.relative_to(dest_resolved)
        except ValueError:
            continue   # outside the sandbox — skip silently

        size = member.file_size
        if size < 0:
            continue
        total += size
        if total > _MAX_UNCOMPRESSED:
            raise RuntimeError(
                f"原始碼壓縮檔解開後超過 {_MAX_UNCOMPRESSED // (1024*1024)}MB 上限,疑似 zip-bomb"
            )

        out.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, open(out, "wb") as dst:
            # Chunked copy so a single huge file can't blow memory either.
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                dst.write(chunk)


def scan_source(zip_bytes: bytes, timeout: int = 300) -> dict:
    """
    Unzip a source archive into a temp dir, run Syft on the directory, return
    the parsed CycloneDX dict.  Caller is expected to feed that dict (encoded
    as JSON bytes) into `sbom_parser.parse(...)` to obtain the component list.

    Raises RuntimeError on any failure — the caller maps that to HTTP 500/503.
    """
    if not is_syft_available():
        raise RuntimeError(_install_hint())

    with tempfile.TemporaryDirectory(prefix="syft-src-") as tmpdir:
        tmp = Path(tmpdir)
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                _safe_extract_zip(zf, tmp)
        except zipfile.BadZipFile:
            raise RuntimeError("無效的 zip 檔")

        return _run_syft_on_path(tmp, timeout)


def scan_binary(file_bytes: bytes, filename: str, timeout: int = 180) -> dict:
    """
    Write a single binary to a temp file, run Syft on it, return CycloneDX
    dict.  Used for .exe / .so / .dll / firmware images / language artefacts.
    Filename is preserved so Syft's per-format cataloguers (which dispatch on
    extension or magic bytes) get a useful hint.
    """
    if not is_syft_available():
        raise RuntimeError(_install_hint())

    # Reject obviously invalid filenames before touching the filesystem.
    safe_name = Path(filename or "binary.bin").name
    if not safe_name:
        raise RuntimeError("檔名無效")

    with tempfile.TemporaryDirectory(prefix="syft-bin-") as tmpdir:
        tmp_path = Path(tmpdir) / safe_name
        tmp_path.write_bytes(file_bytes)
        return _run_syft_on_path(tmp_path, timeout)
