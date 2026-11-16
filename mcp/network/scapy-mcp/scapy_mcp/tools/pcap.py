"""``read_pcap`` / ``write_pcap`` — pcap staging primitives.

``write_pcap`` resolves the target against ``settings.pcap_write_dir`` and
refuses paths that escape the directory (mirrors archive-org-mcp's path
containment guard). When a packet would be refused by the transmit
controls, a structured ``scapy-write-would-refuse`` warning is logged but
the write still proceeds — pcap staging is an authoring tool, not emission.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from scapy.layers.l2 import Ether
from scapy.utils import rdpcap, wrpcap

from scapy_mcp.feeds import FEEDS
from scapy_mcp.security.controller import EmissionController
from scapy_mcp.utils.exceptions import (
    ConfigurationError,
    EmissionRefusedError,
)

if TYPE_CHECKING:
    from scapy_mcp.config.settings import ScapySettings

logger = logging.getLogger("scapy_mcp.tools.pcap")


def _resolve_path(settings: ScapySettings, filename: str) -> Path:
    base = settings.pcap_write_dir.resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ConfigurationError(
            "filename escapes pcap_write_dir",
            context={"filename": filename, "pcap_write_dir": str(base)},
        )
    return target


def _warn_if_untransmittable(
    *,
    settings: ScapySettings,
    packets: list[bytes],
    filename: str,
) -> None:
    """Spec §6.3 'observable authoring': if a packet would be refused by the
    emission controls, log a structured warning before staging it. The pcap is
    a staging primitive, so we PROCEED with the write — the warning is the
    signal.
    """
    controller = EmissionController(settings=settings)
    for raw in packets:
        try:
            pkt = Ether(raw)
        except Exception:  # noqa: BLE001 — bad bytes; pcap write proceeds
            continue
        try:
            controller.check(pkt, is_probe=False)
        except EmissionRefusedError as exc:
            # ``extra=`` reserves LogRecord attribute names like ``filename``,
            # which would raise KeyError. Embed the structured fields in the
            # message body instead — the warning text is grep-able for the
            # control name and the filename.
            logger.warning(
                "scapy-write-would-refuse control=%s reason=%s filename=%s",
                exc.control,
                exc.reason,
                filename,
            )


def write_pcap(
    *,
    settings: ScapySettings,
    filename: str,
    packets: list[bytes],
) -> dict:
    """Stage pcap to ``pcap_write_dir``. Refuses paths outside the dir."""
    target = _resolve_path(settings, filename)
    _warn_if_untransmittable(
        settings=settings,
        packets=packets,
        filename=filename,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target), packets)
    FEEDS["pcap"].record_cycle(entities=len(packets))
    return {"path": str(target), "count": len(packets)}


def read_pcap(
    *,
    settings: ScapySettings,
    path: str,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Read packet summaries from a pcap at ``path``.

    Enforces the ``pcap_read_max_bytes`` ceiling *before* invoking
    :func:`scapy.utils.rdpcap` so a multi-GB file cannot exhaust memory
    by being loaded whole. ``offset`` and ``limit`` window into the
    resulting packet list, which is then summarised and returned.

    The ``path`` is operator-provided (a file produced by ``write_pcap``
    or a pre-existing capture on disk); containment under
    ``pcap_write_dir`` is the *write* path's concern, not this one's.
    """
    p = Path(path)
    if not p.exists():
        FEEDS["pcap"].record_cycle(error=f"file not found: {path}")
        raise ConfigurationError(
            f"file not found: {path}",
            context={"path": path},
        )
    file_size = p.stat().st_size
    if file_size > settings.pcap_read_max_bytes:
        FEEDS["pcap"].record_cycle(
            error=f"file size {file_size} exceeds pcap_read_max_bytes {settings.pcap_read_max_bytes}",
        )
        raise ConfigurationError(
            f"pcap file size {file_size} exceeds pcap_read_max_bytes {settings.pcap_read_max_bytes}",
            context={
                "path": path,
                "size_bytes": file_size,
                "max_bytes": settings.pcap_read_max_bytes,
            },
        )
    packets = rdpcap(str(p))
    window = packets[offset : offset + limit]
    summaries = [pkt.summary() for pkt in window]
    FEEDS["pcap"].record_cycle(entities=len(summaries))
    return {"count": len(summaries), "offset": offset, "summaries": summaries}
