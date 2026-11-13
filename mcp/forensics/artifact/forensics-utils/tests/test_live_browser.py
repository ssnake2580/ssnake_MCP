"""Optional live integration tests.

Default locations:
- Chromium: ``<repo>/chromium_live_test_data/Administrator_Default/Default``
- Firefox: ``<repo>/firefox_live_test_data/ts2fu2xj.default-release-5``

Override with ``CHROMIUM_LIVE_TEST_DIR`` / ``FIREFOX_LIVE_TEST_DIR`` env vars.
Skipped automatically when the default location does not exist on disk.
"""

import os
from pathlib import Path

import pytest

from forensics_utils_mcp_server.tools.chromium_tools import (
    chromium_profile_summary,
    chromium_parse_history,
    chromium_parse_cookies,
    chromium_parse_bookmarks,
)
from forensics_utils_mcp_server.tools.firefox_tools import (
    firefox_profile_summary,
    firefox_parse_history,
    firefox_parse_cookies,
)


_REPO = Path(__file__).parent.parent
DEFAULT_CHROMIUM = _REPO / "chromium_live_test_data" / "Administrator_Default" / "Default"
DEFAULT_FIREFOX = _REPO / "firefox_live_test_data" / "ts2fu2xj.default-release-5"


def _resolve_chromium() -> Path | None:
    candidate = Path(os.environ.get("CHROMIUM_LIVE_TEST_DIR", DEFAULT_CHROMIUM))
    return candidate if candidate.exists() else None


def _resolve_firefox() -> Path | None:
    candidate = Path(os.environ.get("FIREFOX_LIVE_TEST_DIR", DEFAULT_FIREFOX))
    return candidate if candidate.exists() else None


@pytest.fixture(scope="module")
def chromium_dir() -> Path:
    p = _resolve_chromium()
    if p is None:
        pytest.skip("Chromium live test data not available")
    return p


@pytest.fixture(scope="module")
def firefox_dir() -> Path:
    p = _resolve_firefox()
    if p is None:
        pytest.skip("Firefox live test data not available")
    return p


def test_chromium_live_profile_summary(chromium_dir):
    import asyncio
    r = asyncio.run(chromium_profile_summary(str(chromium_dir), sample_limit=2))
    assert r["status"] == "success", r
    arts = r["artifacts"]
    assert any(
        arts.get(a, {}).get("present") and not arts.get(a, {}).get("error")
        for a in ("history", "cookies", "logins", "bookmarks", "downloads")
    )


def test_chromium_live_history(chromium_dir):
    import asyncio
    r = asyncio.run(chromium_parse_history(str(chromium_dir), limit=5))
    assert r["status"] == "success", r
    assert isinstance(r["records"], list)


def test_chromium_live_cookies(chromium_dir):
    import asyncio
    r = asyncio.run(chromium_parse_cookies(str(chromium_dir), limit=5))
    assert r["status"] == "success", r
    assert isinstance(r["records"], list)


def test_chromium_live_bookmarks(chromium_dir):
    import asyncio
    r = asyncio.run(chromium_parse_bookmarks(str(chromium_dir), limit=5))
    assert r["status"] in ("success", "error")
    if r["status"] == "success":
        assert "records" in r


def test_firefox_live_profile_summary(firefox_dir):
    import asyncio
    r = asyncio.run(firefox_profile_summary(str(firefox_dir), sample_limit=2))
    assert r["status"] == "success", r


def test_firefox_live_history(firefox_dir):
    import asyncio
    r = asyncio.run(firefox_parse_history(str(firefox_dir), limit=5))
    assert r["status"] == "success", r


def test_firefox_live_cookies(firefox_dir):
    import asyncio
    r = asyncio.run(firefox_parse_cookies(str(firefox_dir), limit=5))
    assert r["status"] == "success", r
