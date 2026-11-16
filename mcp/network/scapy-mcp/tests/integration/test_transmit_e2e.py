"""E2E smoke test for transmit — default settings refuse emission."""
from __future__ import annotations

import pytest

from scapy_mcp.utils.exceptions import EmissionRefusedError

from .conftest import call_tool


@pytest.mark.asyncio
async def test_transmit_refused_by_default(settings) -> None:  # noqa: ANN001
    """Default settings refuse all emission — the e2e observable success is denial."""
    with pytest.raises(EmissionRefusedError) as exc_info:
        await call_tool(
            "transmit_packet",
            packet={
                "layers": [
                    {"type": "Ether", "dst": "ff:ff:ff:ff:ff:ff", "src": "00:11:22:33:44:55"},
                    {"type": "IP", "dst": "10.0.0.1", "src": "10.0.0.2"},
                    {"type": "UDP", "dport": 53, "sport": 12345},
                ],
            },
            iface="lo0",
            count=1,
        )
    assert exc_info.value.control == "transmit_enabled"
