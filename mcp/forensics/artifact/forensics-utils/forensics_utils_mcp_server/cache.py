"""In-memory cache implementation with size limit."""

import json
import time
from collections import OrderedDict
from typing import Any, Optional

from forensics_utils_mcp_server.config import CACHE_MAX_SIZE_MB


class Cache:
    """In-memory cache with size limit and LRU eviction."""

    def __init__(self) -> None:
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._size_bytes = 0
        self._max_size_bytes = CACHE_MAX_SIZE_MB * 1024 * 1024

    def _calculate_size(self, value: Any) -> int:
        """Calculate size of value in bytes."""
        try:
            return len(json.dumps(value).encode("utf-8"))
        except (TypeError, ValueError):
            return 1024  # Default size estimate for non-serializable values

    def _evict_if_needed(self, new_size: int) -> None:
        """Evict oldest entries if cache would exceed limit."""
        while self._size_bytes + new_size > self._max_size_bytes and self._cache:
            # Remove oldest entry
            key, value = self._cache.popitem(last=False)
            self._size_bytes -= self._calculate_size(value)

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key in self._cache:
            # Move to end (most recently used)
            value = self._cache.pop(key)
            self._cache[key] = value
            return value
        return None

    async def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        # Calculate size
        size = self._calculate_size(value)

        # Evict if needed
        self._evict_if_needed(size)

        # Remove old value if exists
        if key in self._cache:
            old_value = self._cache.pop(key)
            self._size_bytes -= self._calculate_size(old_value)

        # Add new value
        self._cache[key] = value
        self._size_bytes += size

    async def delete(self, key: str) -> None:
        """Delete entry from cache."""
        if key in self._cache:
            value = self._cache.pop(key)
            self._size_bytes -= self._calculate_size(value)

    async def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._size_bytes = 0

    async def get_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "entries": len(self._cache),
            "size_mb": round(self._size_bytes / (1024 * 1024), 2),
            "max_size_mb": CACHE_MAX_SIZE_MB,
            "usage_percent": round((self._size_bytes / self._max_size_bytes) * 100, 2),
        }


# Global cache instance
cache = Cache()
