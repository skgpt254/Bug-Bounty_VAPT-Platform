from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """A tiny async token-bucket limiter. CLI tools like nuclei/httpx enforce
    their own -rate-limit; this covers the phases we implement natively with
    aiohttp (CORS probing, cloud bucket checks, JS fetch) so they respect the
    same global RPS cap instead of hammering the target concurrently.
    """

    def __init__(self, rate_per_sec: float):
        self.rate = max(rate_per_sec, 0.1)
        self._lock = asyncio.Lock()
        self._next_slot = time.monotonic()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + (1.0 / self.rate)
        if wait > 0:
            await asyncio.sleep(wait)
