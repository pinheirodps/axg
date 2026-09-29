"""Request size and rate limits for the AXG API (DoS protection).

``AXG_MAX_BODY_BYTES`` (default 256 KiB) caps request bodies, including chunked uploads.
``AXG_RATE_LIMIT_PER_MINUTE`` (default 600, 0 disables) caps decisions per caller.
The rate limiter is per process: behind several replicas, also limit at the proxy.
"""

from __future__ import annotations

import os
import threading
import time

DEFAULT_MAX_BODY_BYTES = 256 * 1024
DEFAULT_RATE_LIMIT_PER_MINUTE = 600


def max_body_bytes() -> int:
    return int(os.environ.get("AXG_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES))


def rate_limit_per_minute() -> int:
    return int(os.environ.get("AXG_RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT_PER_MINUTE))


async def _reject_too_large(send) -> None:
    body = b'{"detail":"Request body too large"}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """Pure ASGI middleware: rejects oversized bodies before the application parses them.

    The body is read here (at most ``limit`` bytes) and replayed to the app: raising from a
    wrapped ``receive`` would not work, because FastAPI turns body-read errors into a 400.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = max_body_bytes()
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await _reject_too_large(send)
            return

        buffered: list[dict] = []
        received = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request":
                break  # client disconnected: let the app see it
            received += len(message.get("body", b""))
            if received > limit:
                await _reject_too_large(send)
                return
            if not message.get("more_body", False):
                break

        async def replay():
            return buffered.pop(0) if buffered else await receive()

        await self.app(scope, replay, send)


class RateLimiter:
    """Fixed one-minute window per caller id."""

    def __init__(self) -> None:
        self._windows: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def check(self, caller_id: str) -> int | None:
        """Return None if allowed, else the seconds until the window resets."""
        limit = rate_limit_per_minute()
        if limit <= 0:
            return None
        now = time.time()
        window = int(now // 60)
        with self._lock:
            start, count = self._windows.get(caller_id, (window, 0))
            if start != window:
                start, count = window, 0
            if count >= limit:
                return max(1, int((window + 1) * 60 - now))
            self._windows[caller_id] = (start, count + 1)
        return None

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


rate_limiter = RateLimiter()
