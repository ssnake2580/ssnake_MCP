"""Test suite for Forensics MCP Server."""

import os
import tempfile
import pytest
import pytest_asyncio
from unittest.mock import patch, MagicMock

from forensics_utils_mcp_server.cache import Cache
from forensics_utils_mcp_server.queue import RateLimitedQueue
from forensics_utils_mcp_server.tools.hash_tools import calculate_hashes
from forensics_utils_mcp_server.tools.string_tools import extract_strings


class TestCache:
    """Test cache functionality."""

    @pytest_asyncio.fixture
    async def cache(self):
        """Create a test cache instance."""
        cache = Cache()
        await cache.clear()
        yield cache
        await cache.clear()

    @pytest.mark.asyncio
    async def test_cache_set_and_get(self, cache):
        """Test setting and getting cache values."""
        await cache.set("test_key", {"data": "test_value"})
        result = await cache.get("test_key")
        assert result == {"data": "test_value"}

    @pytest.mark.asyncio
    async def test_cache_nonexistent_key(self, cache):
        """Test getting non-existent key returns None."""
        result = await cache.get("nonexistent_key")
        assert result is None


class TestHashTools:
    """Test hash calculation tools."""

    @pytest.fixture
    def temp_file(self):
        """Create a temporary test file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("Hello, World!")
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_calculate_hashes(self, temp_file):
        """Test hash calculation for a file."""
        result = await calculate_hashes(temp_file)

        assert result["status"] == "success"
        assert "hashes" in result
        assert "md5" in result["hashes"]
        assert "sha1" in result["hashes"]
        assert "sha256" in result["hashes"]
        assert "sha512" in result["hashes"]

        # Verify known hash values
        assert result["hashes"]["md5"] == "65a8e27d8879283831b664bd8b7f0ad4"

    @pytest.mark.asyncio
    async def test_calculate_hashes_file_not_found(self):
        """Test hash calculation for non-existent file (absolute path)."""
        import sys
        missing = "C:\\nonexistent\\file.txt" if sys.platform == "win32" else "/nonexistent/file.txt"
        result = await calculate_hashes(missing)

        assert result["status"] == "error"
        # path validation: absolute path that doesn't exist → file_not_found
        assert result["error_type"] == "file_not_found"

    @pytest.mark.asyncio
    async def test_calculate_hashes_relative_path_rejected(self):
        """Test that relative paths are rejected by validation."""
        result = await calculate_hashes("relative/path.bin")

        assert result["status"] == "error"
        assert result["error_type"] == "invalid_input"


class TestStringTools:
    """Test string extraction tools."""

    @pytest.fixture
    def temp_binary_file(self):
        """Create a temporary binary file with strings."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write some ASCII strings
            f.write(b"Hello World\x00")
            f.write(b"http://example.com\x00")
            f.write(b"192.168.1.1\x00")
            f.write(b"test@example.com\x00")
            # Write some Unicode strings
            f.write(
                b"U\x00n\x00i\x00c\x00o\x00d\x00e\x00 \x00S\x00t\x00r\x00i\x00n\x00g\x00\x00\x00"
            )
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_extract_strings(self, temp_binary_file):
        """Test string extraction from binary file."""
        result = await extract_strings(temp_binary_file)

        assert result["status"] == "success"
        assert "strings" in result
        assert "ascii" in result["strings"]
        assert "interesting" in result["strings"]

        # Check if interesting strings were found
        interesting = result["strings"]["interesting"]
        assert any("http://" in s for s in interesting)


class TestQueue:
    """Test rate-limited queue."""

    @pytest.mark.asyncio
    async def test_queue_initialization(self):
        """Test queue initialization."""
        q = RateLimitedQueue()
        assert q._running is False

    @pytest.mark.asyncio
    async def test_queue_start_stop(self):
        """Test queue start and stop."""
        q = RateLimitedQueue()
        await q.start()
        assert q._running is True

        await q.stop()
        assert q._running is False
