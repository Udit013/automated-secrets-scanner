"""
Access control and abuse limits.

Two deployment modes, chosen by ACCESS_TOKEN:
- unset → demo mode: the API is public, protected by rate and capacity limits;
- set   → private workspace: every /api/v1 request must carry the token.
"""

import hmac
import time
from collections import deque

from fastapi import HTTPException, status
from starlette.requests import HTTPConnection

from .config import settings


WS_SUBPROTOCOL = "cipherwatch.v1"
WS_TOKEN_PREFIX = "bearer."


def auth_required() -> bool:
    return bool(settings.ACCESS_TOKEN)


def _presented_token(conn: HTTPConnection) -> str:
    header = conn.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # Browsers cannot set an Authorization header on a WebSocket handshake.
    # The one header they can set is Sec-WebSocket-Protocol, so the token
    # rides there as "bearer.<token>". A query parameter would also work,
    # but it would be written to every access log on the way.
    if conn.scope.get("type") == "websocket":
        for proto in conn.headers.get("sec-websocket-protocol", "").split(","):
            proto = proto.strip()
            if proto.startswith(WS_TOKEN_PREFIX):
                return proto[len(WS_TOKEN_PREFIX):]
    return ""


async def require_access(conn: HTTPConnection) -> None:
    if not settings.ACCESS_TOKEN:
        return
    presented = _presented_token(conn)
    # Constant-time comparison: don't leak the token through response timing.
    if not presented or not hmac.compare_digest(presented.encode(), settings.ACCESS_TOKEN.encode()):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "This workspace requires an access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def client_ip(conn: HTTPConnection) -> str:
    """
    The client address, read from X-Forwarded-For only as far as the number
    of trusted proxies allows. Each proxy appends the address it saw, so the
    entry `hops` from the right is the last one a trusted proxy added — any
    values a client prepends itself are ignored.
    """
    hops = settings.TRUSTED_PROXY_HOPS
    forwarded = conn.headers.get("x-forwarded-for", "")
    if hops > 0 and forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return conn.client.host if conn.client else "unknown"


class SlidingWindowLimiter:
    """In-process sliding-window limiter. Fine for one instance; see docs for scaling."""

    MAX_TRACKED_CLIENTS = 10_000

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str, now: float | None = None) -> int:
        """Record a hit. Returns 0 if allowed, else seconds until the next slot frees."""
        now = time.monotonic() if now is None else now
        hits = self._hits.setdefault(key, deque())
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return max(1, int(hits[0] + self.window - now) + 1)
        hits.append(now)
        if len(self._hits) > self.MAX_TRACKED_CLIENTS:
            self._evict(now)
        return 0

    def _evict(self, now: float) -> None:
        for k in [k for k, h in self._hits.items() if not h or h[-1] <= now - self.window]:
            del self._hits[k]

    def reset(self) -> None:
        self._hits.clear()


scan_limiter = SlidingWindowLimiter(settings.SCAN_RATE_LIMIT, settings.SCAN_RATE_WINDOW_SECONDS)


def _wait(seconds: int) -> str:
    return f"{seconds}s" if seconds < 90 else f"{-(-seconds // 60)} min"


async def limit_scan_creation(conn: HTTPConnection) -> None:
    retry_after = scan_limiter.check(client_ip(conn))
    if retry_after:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Scan limit reached ({settings.SCAN_RATE_LIMIT} per "
            f"{settings.SCAN_RATE_WINDOW_SECONDS // 60} minutes). Try again in {_wait(retry_after)}.",
            headers={"Retry-After": str(retry_after)},
        )
