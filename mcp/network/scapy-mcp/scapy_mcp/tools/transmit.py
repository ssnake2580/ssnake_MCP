"""``transmit_packet`` / ``probe_packet`` — closed-by-default emission.

Both functions rebuild the packet from raw bytes, run the four-control
:func:`EmissionController.check` gate (refusal raises
:class:`EmissionRefusedError`), then dispatch the actual ``send`` / ``sendp``
/ ``srp`` call onto a dedicated :class:`ThreadPoolExecutor` so a slow
caller cannot starve the sniffer (spec §5.7).

The ``_executor`` singleton is sized from ``capture_executor_workers`` and
created lazily on the first call.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from scapy.layers.inet import IP, UDP  # noqa: F401  — registration side-effect
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendp, srp

from scapy_mcp.security.controller import EmissionController
from scapy_mcp.utils.exceptions import (
    ConfigurationError,
)

if TYPE_CHECKING:
    from scapy.packet import Packet

    from scapy_mcp.config.settings import ScapySettings

_EXECUTOR: ThreadPoolExecutor | None = None


def _executor(settings: ScapySettings) -> ThreadPoolExecutor:
    """Module-level singleton sized executor (spec §5.7)."""
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=settings.capture_executor_workers,
            thread_name_prefix="scapy-mcp-emit",
        )
    return _EXECUTOR


def _rebuild_packet(raw: bytes) -> Packet:
    return Ether(raw)


async def transmit_packet(
    *,
    settings: ScapySettings,
    packet_bytes: bytes,
    iface: str,
    count: int = 1,
) -> dict:
    """Send a single unidirectional frame after the four-control gate."""
    if count < 1:
        raise ConfigurationError("count must be >= 1", context={"count": count})

    pkt = _rebuild_packet(packet_bytes)
    EmissionController(settings=settings).check(pkt, is_probe=False)

    loop = asyncio.get_running_loop()

    def _emit() -> None:
        # L2-only dispatch uses sendp (which needs ``transmit_allow_l2``). L3
        # packets go via the kernel's routing table with ``send``.
        if pkt.haslayer(Ether) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            sendp(pkt, iface=iface, count=count, verbose=False)
        else:
            send(pkt, verbose=False)

    await loop.run_in_executor(_executor(settings), _emit)
    return {"sent": count, "iface": iface}


async def probe_packet(
    *,
    settings: ScapySettings,
    packet_bytes: bytes,
    iface: str,
    targets: list[str],
    timeout_seconds: float = 2.0,
) -> dict:
    """Send a request-response probe. Bounded by ``transmit_max_probe_targets``."""
    pkt = _rebuild_packet(packet_bytes)
    EmissionController(settings=settings).check(
        pkt,
        is_probe=True,
        target_count=len(targets),
    )

    loop = asyncio.get_running_loop()

    def _probe() -> None:
        # ``srp`` requires L2; the same packet is dispatched once. The
        # ``targets`` count is enforced by the controller before this runs.
        srp([pkt], timeout=timeout_seconds, iface=iface, verbose=False)

    await loop.run_in_executor(_executor(settings), _probe)
    return {"targets": len(targets), "iface": iface, "timeout": timeout_seconds}
