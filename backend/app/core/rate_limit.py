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
    # Respect X-Forwarded-For when behind nginx/proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
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
