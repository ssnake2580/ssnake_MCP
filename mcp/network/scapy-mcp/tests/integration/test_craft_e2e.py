"""E2E smoke test for craft_packet — non-empty result via FastMCP."""
from __future__ import annotations

import pytest

from .conftest import call_tool


@pytest.mark.asyncio
async def test_craft_packet_registered(settings) -> None:  # noqa: ANN001
    result = await call_tool(
        "craft_packet",
        layers=[
            {"type": "Ether", "dst": "ff:ff:ff:ff:ff:ff", "src": "00:11:22:33:44:55"},
            {"type": "IP", "dst": "8.8.8.8", "src": "10.0.0.2"},
            {"type": "UDP", "dport": 53, "sport": 12345},
            {"type": "DNS", "rd": 1, "qname": "example.com"},
        ],
    )
    assert result["layer_count"] == 4
    assert "Ether" in result["summary"]
