"""Test binwalk tools."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from forensics_utils_mcp_server.tools.binwalk_tools import binwalk_scan, binwalk_extract


@pytest.mark.asyncio
async def test_binwalk_validates_relative_path():
    """Relative paths should be rejected by the new validator."""
    result = await binwalk_scan("FirstHack.ad1")
    assert result["status"] == "error"
    assert result["error_type"] == "invalid_input"


@pytest.mark.asyncio
async def test_binwalk_absolute_missing_path():
    """Absolute path to a missing file should report file_not_found."""
    import sys
    missing = "C:\\nonexistent\\FirstHack.ad1" if sys.platform == "win32" else "/nonexistent/FirstHack.ad1"
    result = await binwalk_scan(missing)
    assert result["status"] == "error"
    assert result["error_type"] == "file_not_found"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
