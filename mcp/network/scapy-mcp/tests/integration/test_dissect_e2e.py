"""E2E smoke test for dissect_bytes — non-empty layer list."""
from __future__ import annotations

import base64

import pytest

from .conftest import call_tool


@pytest.mark.asyncio
async def test_dissect_handwritten_ether(settings) -> None:  # noqa: ANN001
    raw = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00"
    data = base64.b64encode(raw).decode()
    result = await call_tool("dissect_bytes", data=data, link_type="EN10MB")
    assert "Ether" in result["layers"]
