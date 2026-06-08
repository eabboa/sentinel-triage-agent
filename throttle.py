"""
This module contains a basic rate limiter for the Gemini API.
It is used to limit the number of requests to the Gemini API to be slightly under the 15 RPM Free Tier limit.
WARNING: It is only intended for development testing. Production should use the rate limiting provided by the API provider.
"""

import asyncio
import time


class APIRateLimiter:
    """Asynchronous rate limiter using a sliding window."""

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls: list[float] = []
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

    def reset(self) -> None:
        """
        Clears all recorded call timestamps. Intended for test isolation.

        Returns:
            None
        """
        self.calls.clear()

    async def acquire(self):
        """
        Acquires permission to make an API call, sleeping if the limit is reached.

        Returns:
            None
        """
        while True:
            async with self.lock:
                now = time.monotonic()
                # Clean up calls that are older than the period
                self.calls = [t for t in self.calls if now - t < self.period]

                if len(self.calls) < self.max_calls:
                    self.calls.append(now)
                    return

                # Calculate sleep time while still holding lock
                sleep_time = self.period - (now - self.calls[0])

            # Sleep OUTSIDE the lock so other coroutines can proceed
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)


# Limit to 14 requests per 60 seconds to be slightly under the 15 RPM Free Tier limit
gemini_rate_limiter = APIRateLimiter(max_calls=14, period=60.0)
