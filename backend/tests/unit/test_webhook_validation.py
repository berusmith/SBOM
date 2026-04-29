"""
Function-level characterization for `_validate_webhook_url` (in
backend/app/services/alerts.py:19).

This is a SECURITY-RELEVANT helper (SSRF guard).  Per invariants.md §II.4
data exposure rules, this contract MUST NOT regress.  The tests below pin
the rejection rules explicitly so any future change requires updating the
tests in the same commit (defense-in-depth).

This helper does NOT move during PR-1; tests guard against accidental
regression while alerts.py is touched (e.g. ARCH-1.005 `services/`
sub-folder reorganisation).
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.services.alerts import _validate_webhook_url


# ── Empty / non-http schemes ──────────────────────────────────────────────────

@pytest.mark.function_level
def test_empty_url_rejected():
    err = _validate_webhook_url("")
    assert err  # non-empty string = error
    assert "empty" in err.lower()


@pytest.mark.function_level
@pytest.mark.parametrize("url", [
    "ftp://example.com/hook",
    "file:///etc/passwd",
    "gopher://example.com",
    "ssh://example.com",
    "javascript:alert(1)",
])
def test_non_http_scheme_rejected(url):
    err = _validate_webhook_url(url)
    assert "http/https" in err.lower() or "scheme" in err.lower()


# ── Loopback / private / link-local — SSRF guard ──────────────────────────────

@pytest.mark.function_level
@pytest.mark.parametrize("hostname, ip", [
    ("localhost", "127.0.0.1"),
    ("private-host.lan", "10.0.0.1"),
    ("internal", "192.168.1.1"),
    ("aws-meta", "169.254.169.254"),  # AWS instance metadata
    ("link-local", "169.254.1.1"),
])
def test_private_ips_rejected_via_dns(hostname, ip):
    """Even when the hostname looks public, DNS resolving to a private IP must reject."""
    fake_addrinfo = [(2, 1, 6, "", (ip, 0))]
    with patch("app.services.alerts.socket.getaddrinfo", return_value=fake_addrinfo):
        err = _validate_webhook_url(f"https://{hostname}/hook")
        assert err  # non-empty = rejection
        assert "non-routable" in err.lower() or "private" in err.lower() or "loopback" in err.lower()


# ── Multi-IP DNS: any private answer rejects (defense-in-depth) ──────────────

@pytest.mark.function_level
def test_dns_returns_mixed_public_and_private_rejects():
    """Hostile DNS that returns one public IP + one private IP must still reject."""
    mixed = [
        (2, 1, 6, "", ("8.8.8.8", 0)),       # public
        (2, 1, 6, "", ("127.0.0.1", 0)),     # loopback
    ]
    with patch("app.services.alerts.socket.getaddrinfo", return_value=mixed):
        err = _validate_webhook_url("https://attacker.example.com/hook")
        assert err
        assert "non-routable" in err.lower()


# ── DNS failure rejects ───────────────────────────────────────────────────────

@pytest.mark.function_level
def test_dns_failure_rejected():
    import socket
    with patch("app.services.alerts.socket.getaddrinfo", side_effect=socket.gaierror("test")):
        err = _validate_webhook_url("https://does-not-exist.example.com/hook")
        assert "DNS" in err or "resolution" in err.lower()


# ── No host part rejected ─────────────────────────────────────────────────────

@pytest.mark.function_level
def test_url_without_host_rejected():
    err = _validate_webhook_url("https:///path-only")
    assert err
    assert "host" in err.lower()


# ── Public URL with public-resolved DNS passes ────────────────────────────────

@pytest.mark.function_level
def test_public_url_with_public_dns_passes():
    """Sanity: a clearly-public destination should validate successfully."""
    public_ips = [(2, 1, 6, "", ("8.8.8.8", 0))]
    with patch("app.services.alerts.socket.getaddrinfo", return_value=public_ips):
        err = _validate_webhook_url("https://hooks.example.com/notify")
        assert err == ""  # empty string = success per the contract
