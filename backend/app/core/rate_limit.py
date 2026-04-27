"""
Simple in-memory sliding-window rate limiter.
No external dependencies — uses stdlib only.
Thread-safe via threading.Lock.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    def __init__(self, max_calls: int, window_seconds: int):
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            dq = self._calls[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.max_calls:
                return False
            dq.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._calls.pop(key, None)


# Login brute-force: 10 attempts per 5 minutes per IP
login_limiter = SlidingWindowLimiter(max_calls=10, window_seconds=300)

# General API: 300 requests per minute per IP
api_limiter = SlidingWindowLimiter(max_calls=300, window_seconds=60)


def _client_ip(request: Request) -> str:
    """Resolve client IP for rate-limiting and audit logging.

    SEC-003 fix (2026-04-26): only trust X-Real-IP (set by nginx from
    $remote_addr — the socket peer, not client-controllable).  The old
    code read split(",")[0] of X-Forwarded-For, which an attacker could
    spoof with a single curl header (CWE-348 Use of Less Trusted Source)
    to bypass login brute-force rate limiting and poison audit logs.

    Required cooperation:
      • nginx (deploy/nginx-sbom.conf): `proxy_set_header X-Forwarded-For "";`
        — clears any client-supplied chain at the edge.
      • uvicorn must run with `--no-proxy-headers` (deploy/com.sbom.backend.plist,
        start_backend.bat, backend/Dockerfile) — otherwise its built-in
        ProxyHeadersMiddleware would silently rewrite request.client.host
        from X-Forwarded-For when the request originates on the trusted
        list (default: 127.0.0.1), defeating this fix.
    """
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def check_login_rate_limit(request: Request) -> None:
    """FastAPI dependency — call inside login endpoint."""
    ip = _client_ip(request)
    if not login_limiter.is_allowed(ip):
        raise HTTPException(
            status_code=429,
            detail="嘗試次數過多，請 5 分鐘後再試",
            headers={"Retry-After": "300"},
        )
