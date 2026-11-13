"""Rate-limited request queue implementation."""

import asyncio
from datetime import datetime
from typing import Any, Callable, Coroutine, Optional

from forensics_utils_mcp_server.config import (
    QUEUE_RATE_LIMIT,
    QUEUE_TIMEOUT_SECONDS,
    QUEUE_RETRY_ATTEMPTS,
    QUEUE_RETRY_DELAY_SECONDS,
)


class RateLimitedQueue:
    """Async queue with rate limiting."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(1)  # Only 1 concurrent request
        self._last_request_time: Optional[datetime] = None
        self._min_interval = 60.0 / QUEUE_RATE_LIMIT  # seconds between requests
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        """Start the queue worker."""
        if not self._running:
            self._running = True
            self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        """Stop the queue worker."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def _worker(self) -> None:
        """Worker that processes queued requests."""
        while self._running:
            try:
                # Get next request with timeout
                request = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._process_request(request)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def _process_request(self, request: dict) -> None:
        """Process a single request with rate limiting."""
        async with self._semaphore:
            # Wait for rate limit
            if self._last_request_time:
                elapsed = (datetime.now() - self._last_request_time).total_seconds()
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)

            # Execute request with retries
            for attempt in range(QUEUE_RETRY_ATTEMPTS):
                try:
                    result = await request["func"](
                        *request["args"], **request["kwargs"]
                    )
                    request["future"].set_result(result)
                    self._last_request_time = datetime.now()
                    return
                except Exception as e:
                    if attempt < QUEUE_RETRY_ATTEMPTS - 1:
                        await asyncio.sleep(QUEUE_RETRY_DELAY_SECONDS)
                    else:
                        request["future"].set_exception(e)

    async def submit(
        self, func: Callable[..., Coroutine[Any, Any, Any]], *args: Any, **kwargs: Any
    ) -> Any:
        """Submit a request to the queue and wait for result."""
        future = asyncio.get_event_loop().create_future()

        request = {
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "future": future,
        }

        await self._queue.put(request)

        # Wait for result with timeout
        try:
            return await asyncio.wait_for(future, timeout=QUEUE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Request timed out after {QUEUE_TIMEOUT_SECONDS}s")


# Global queue instance
queue = RateLimitedQueue()
