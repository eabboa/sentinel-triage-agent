"""
Behavioral Contract for throttle.py

Asserts the APIRateLimiter correctly throttles when max_calls is reached.
"""

import asyncio
import time

import pytest

from throttle import APIRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_throttles():
    """Asserts acquire() blocks when max_calls is exhausted within the period."""
    # Tiny window: 2 calls per 0.5 seconds
    limiter = APIRateLimiter(max_calls=2, period=0.5)

    # First two calls should be instant
    await limiter.acquire()
    await limiter.acquire()

    # Third call should block until the window slides
    start = time.monotonic()
    await limiter.acquire()
    elapsed = time.monotonic() - start

    # Must have waited some time (the sleep_time > 0 branch)
    assert elapsed > 0.1


@pytest.mark.asyncio
async def test_rate_limiter_context_manager():
    """Asserts the async context manager protocol works."""
    limiter = APIRateLimiter(max_calls=5, period=60.0)

    async with limiter:
        pass  # Should not raise
