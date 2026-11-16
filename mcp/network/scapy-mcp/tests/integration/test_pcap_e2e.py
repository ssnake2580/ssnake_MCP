"""E2E smoke tests for read_pcap — committed fixtures round-trip via FastMCP."""
from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import call_tool

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.mark.asyncio
async def test_read_http_get_pcap(settings) -> None:  # noqa: ANN001
    result = await call_tool(
        "read_pcap",
        path=str(FIXTURES / "http_get.pcap"),
    )
    assert result["count"] >= 5


@pytest.mark.asyncio
async def test_read_dns_query_pcap(settings) -> None:  # noqa: ANN001
    result = await call_tool(
        "read_pcap",
        path=str(FIXTURES / "dns_query.pcap"),
    )
    assert result["count"] == 2


@pytest.mark.asyncio
async def test_read_arp_request_pcap(settings) -> None:  # noqa: ANN001
    result = await call_tool(
        "read_pcap",
        path=str(FIXTURES / "arp_request.pcap"),
    )
    assert result["count"] == 2
