#!/usr/bin/env python3
"""
SBOM CLI Tool - Integrate SBOM scanning into CI/CD pipelines

Usage:
  sbom upload <sbom.json> --release <id>
  sbom gate --release <id>
  sbom diff --v1 <id> --v2 <id>

Environment variables:
  SBOM_API_TOKEN - API token for authentication (required)
  SBOM_API_URL   - API server URL (default: http://localhost:9100)
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.error
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


class SBOMClient:
    """API client for SBOM service."""

    def __init__(self, api_url: str, api_token: str):
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to API."""
        url = f"{self.api_url}/api{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        body = None
        if data:
            body = json.dumps(data).encode('utf-8')

        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers=headers,
                method=method
            )
            with urllib.request.urlopen(req) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data) if response_data else {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            try:
                error_json = json.loads(error_body)
                error_msg = error_json.get('detail', error_body)
            except:
                error_msg = error_body
            raise RuntimeError(f"API Error {e.code}: {error_msg}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection Error: {e.reason}")

    def upload_sbom(self, release_id: str, sbom_file: str) -> Dict[str, Any]:
        """Upload SBOM file to a release via multipart/form-data."""
        with open(sbom_file, 'rb') as f:
            file_content = f.read()

        filename = os.path.basename(sbom_file)
        boundary = f'----SBOMCLIBoundary{uuid.uuid4().hex}'

        # RFC 2046 compliant multipart body
        parts = []
        parts.append(f'--{boundary}\r\n'.encode())
        parts.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode())
        parts.append(b'Content-Type: application/json\r\n')
        parts.append(b'\r\n')
        parts.append(file_content)
        parts.append(f'\r\n--{boundary}--\r\n'.encode())

        body = b''.join(parts)

        url = f"{self.api_url}/api/releases/{release_id}/sbom"

        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)),
                },
                method="POST"
            )
            with urllib.request.urlopen(req) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data) if response_data else {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            try:
                error_json = json.loads(error_body)
                error_msg = error_json.get('detail', error_body)
            except:
                error_msg = error_body
            raise RuntimeError(f"API Error {e.code}: {error_msg}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection Error: {e.reason}")

    def get_gate(self, release_id: str) -> Dict[str, Any]:
        """Get Policy Gate status for a release."""
        return self._make_request("GET", f"/releases/{release_id}/gate")

    def get_diff(self, v1_id: str, v2_id: str, product_id: Optional[str] = None) -> Dict[str, Any]:
        """Get diff between two release versions.

        If product_id is not provided, attempts to find it from the release.
        Note: The release endpoint may not include product_id, so providing it
        explicitly is recommended for better compatibility.
        """
        pid = product_id

        if not pid:
            # Try to get product_id from release, but this may not be available
            try:
                v1_data = self._make_request("GET", f"/releases/{v1_id}")
                pid = v1_data.get('product_id')
            except:
                pass

        if not pid:
            raise RuntimeError(
                f"Could not determine product ID for release {v1_id}. "
                "Please provide product ID via --product argument."
            )

        return self._make_request(
            "GET",
            f"/products/{pid}/diff?from={v1_id}&to={v2_id}"
        )


def cmd_upload(args, client: SBOMClient) -> int:
    """Handle 'upload' command."""
    if not args.release:
        print("Error: --release is required for upload command", file=sys.stderr)
        return 1

    if not os.path.isfile(args.sbom_file):
        print(f"Error: SBOM file not found: {args.sbom_file}", file=sys.stderr)
        return 1

    try:
        print(f"Uploading {args.sbom_file} to release {args.release}...")
        result = client.upload_sbom(args.release, args.sbom_file)
        print(f"[OK] Upload successful")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as e:
        print(f"[FAIL] Upload failed: {e}", file=sys.stderr)
        return 1


def cmd_gate(args, client: SBOMClient) -> int:
    """Handle 'gate' command."""
    if not args.release:
        print("Error: --release is required for gate command", file=sys.stderr)
        return 1

    try:
        print(f"Checking Policy Gate for release {args.release}...")
        result = client.get_gate(args.release)

        # Extract gate status
        overall = result.get('overall', 'unknown')
        passed_count = result.get('passed', 0)
        total_count = result.get('total', 0)
        checks = result.get('checks', [])

        status_icon = "[PASS]" if overall == "pass" else "[FAIL]"
        print(f"\nPolicy Gate Status: {status_icon} {overall.upper()} ({passed_count}/{total_count})")
        print(f"\nChecks:")
        for check in checks:
            status_icon = "[+]" if check.get('passed') else "[-]"
            label = check.get('label', 'Unknown')
            detail = check.get('detail', '')
            print(f"  {status_icon} {label}")
            if detail:
                print(f"     {detail}")

        # Return exit code based on gate status
        if overall != "pass":
            print(f"\n{json.dumps(result, indent=2, ensure_ascii=False)}")
            return 1

        print(f"\n[OK] All checks passed!")
        return 0
    except Exception as e:
        print(f"[ERROR] Gate check failed: {e}", file=sys.stderr)
        return 1


def cmd_diff(args, client: SBOMClient) -> int:
    """Handle 'diff' command."""
    if not args.v1 or not args.v2:
        print("Error: --v1 and --v2 are required for diff command", file=sys.stderr)
        return 1

    try:
        print(f"Comparing release {args.v1} with {args.v2}...")
        result = client.get_diff(args.v1, args.v2, getattr(args, 'product', None))

        print(f"\n=== Diff Report ===")
        print(f"Product: {result.get('product_name', 'N/A')}")
        print(f"From: {result.get('from_version', 'unknown')}")
        print(f"To:   {result.get('to_version', 'unknown')}")

        # Components
        comps = result.get('components', {})
        added = comps.get('added', [])
        removed = comps.get('removed', [])
        unchanged = comps.get('unchanged', 0)

        print(f"\nComponents:")
        print(f"  Added:     {len(added)}")
        print(f"  Removed:   {len(removed)}")
        print(f"  Unchanged: {unchanged}")

        if added:
            print(f"\nAdded Components:")
            for comp in added[:10]:
                print(f"  [+] {comp.get('name')} ({comp.get('version', 'unknown')})")
            if len(added) > 10:
                print(f"  ... and {len(added) - 10} more")

        if removed:
            print(f"\nRemoved Components:")
            for comp in removed[:10]:
                print(f"  [-] {comp.get('name')} ({comp.get('version', 'unknown')})")
            if len(removed) > 10:
                print(f"  ... and {len(removed) - 10} more")

        # Vulnerabilities
        vulns = result.get('vulnerabilities', {})
        vuln_added = vulns.get('added', [])
        vuln_removed = vulns.get('removed', [])
        vuln_unchanged = vulns.get('unchanged', 0)

        print(f"\nVulnerabilities:")
        print(f"  Added:     {len(vuln_added)}")
        print(f"  Removed:   {len(vuln_removed)}")
        print(f"  Unchanged: {vuln_unchanged}")

        if vuln_added:
            print(f"\nNew Vulnerabilities (by CVSS score):")
            for vuln in vuln_added[:5]:
                print(f"  {vuln.get('cve_id')} - {vuln.get('severity')} (CVSS: {vuln.get('cvss_score', 'N/A')})")
            if len(vuln_added) > 5:
                print(f"  ... and {len(vuln_added) - 5} more")

        if vuln_removed:
            print(f"\nFixed Vulnerabilities:")
            for vuln in vuln_removed[:5]:
                print(f"  {vuln.get('cve_id')} - {vuln.get('severity')} (CVSS: {vuln.get('cvss_score', 'N/A')})")
            if len(vuln_removed) > 5:
                print(f"  ... and {len(vuln_removed) - 5} more")

        print(f"\n{json.dumps(result, indent=2, ensure_ascii=False)}")
        return 0
    except Exception as e:
        print(f"[ERROR] Diff failed: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point."""
    # Force UTF-8 output encoding
    if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    if sys.stderr.encoding and sys.stderr.encoding.lower() != 'utf-8':
        import io
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

    parser = argparse.ArgumentParser(
        description="SBOM CLI - Integrate SBOM scanning into CI/CD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sbom upload sbom.json --release <release-id>
  sbom gate --release <release-id>
  sbom diff --v1 <release-id-1> --v2 <release-id-2>

Environment Variables:
  SBOM_API_TOKEN  API authentication token (required)
  SBOM_API_URL    API server URL (default: http://localhost:9100)
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload SBOM file')
    upload_parser.add_argument('sbom_file', help='Path to SBOM file (JSON)')
    upload_parser.add_argument('--release', required=True, help='Release ID')

    # Gate command
    gate_parser = subparsers.add_parser('gate', help='Check Policy Gate status')
    gate_parser.add_argument('--release', required=True, help='Release ID')

    # Diff command
    diff_parser = subparsers.add_parser('diff', help='Compare two release versions')
    diff_parser.add_argument('--v1', required=True, help='First release ID')
    diff_parser.add_argument('--v2', required=True, help='Second release ID')
    diff_parser.add_argument('--product', required=False, help='Product ID (optional if v1 includes product_id)')

    args = parser.parse_args()

    # Check required environment variables
    api_token = os.getenv('SBOM_API_TOKEN')
    if not api_token:
        print("Error: SBOM_API_TOKEN environment variable not set", file=sys.stderr)
        return 1

    api_url = os.getenv('SBOM_API_URL', 'http://localhost:9100')

    # Create client
    client = SBOMClient(api_url, api_token)

    # Dispatch to command handler
    if args.command == 'upload':
        return cmd_upload(args, client)
    elif args.command == 'gate':
        return cmd_gate(args, client)
    elif args.command == 'diff':
        return cmd_diff(args, client)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
