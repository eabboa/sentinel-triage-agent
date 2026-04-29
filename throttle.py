import asyncio
import time

class APIRateLimiter:
    """Asynchronous rate limiter using a sliding window."""
    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls = []
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            # Clean up calls that are older than the period
            self.calls = [t for t in self.calls if now - t < self.period]
            
            if len(self.calls) >= self.max_calls:
                # We reached the limit, need to wait until the oldest call expires
                sleep_time = self.period - (now - self.calls[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                # Advance time since we slept
                now = time.monotonic()
                self.calls = [t for t in self.calls if now - t < self.period]
                
            self.calls.append(now)

# Limit to 14 requests per 60 seconds to be slightly under the 15 RPM Free Tier limit
gemini_rate_limiter = APIRateLimiter(max_calls=14, period=60.0)
