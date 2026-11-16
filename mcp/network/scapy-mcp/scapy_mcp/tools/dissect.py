"""``dissect_bytes`` — parse base64-encoded raw bytes into a layer summary.

Returns a dict with ``layers`` (list of layer names) and ``summary``. Malformed
input raises :class:`DissectionError` with a structured payload
(``{error, reason, offset, partial_layers}``) per spec §6.3.
"""

from __future__ import annotations

import base64
import binascii
import logging
import struct
from typing import TYPE_CHECKING

from scapy.error import Scapy_Exception
from scapy.layers.l2 import Ether

from scapy_mcp.feeds import FEEDS
from scapy_mcp.utils.exceptions import DissectionError

if TYPE_CHECKING:
    from scapy_mcp.config.settings import ScapySettings

logger = logging.getLogger("scapy_mcp.tools.dissect")


def dissect_bytes(
    *,
    settings: ScapySettings,
    data: str,
    link_type: str = "EN10MB",
) -> dict:
    """Dissect a base64-encoded frame.

    Malformed input raises :class:`DissectionError`; the feed's
    ``errors_total`` counter increments in that case so ``/readyz`` can
    report ``degraded`` when dissection is broken.
    """
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        FEEDS["dissect"].record_cycle(error=f"base64 decode failed: {exc}")
        raise DissectionError(
            "base64 decode failed",
            reason=str(exc),
            offset=0,
            partial_layers=[],
        ) from exc

    if link_type != "EN10MB":
        FEEDS["dissect"].record_cycle(error=f"unsupported link_type {link_type!r}")
        raise DissectionError(
            f"unsupported link_type {link_type!r}",
            reason="only EN10MB supported in v1",
            offset=0,
            partial_layers=[],
        )

    try:
        pkt = Ether(raw)
    except (Scapy_Exception, ValueError, IndexError, struct.error) as exc:
        partial: list[str] = []
        # Best-effort: try to slice into Ether layer for partial info.
        try:
            partial_pkt = Ether(raw[:14])
            partial = [p.__name__ for p in partial_pkt.layers()]
        except Scapy_Exception, ValueError, IndexError, struct.error:
            logger.debug("partial-dissect-fallback-failed", exc_info=True)
        FEEDS["dissect"].record_cycle(error=str(exc))
        raise DissectionError(
            "dissection failed",
            reason=str(exc),
            offset=14,
            partial_layers=partial,
        ) from exc

    layers = [layer.__name__ for layer in pkt.layers()]
    if not layers:
        FEEDS["dissect"].record_cycle(error="empty packet")
        raise DissectionError(
            "dissection produced empty layer list",
            reason="no parseable layers",
            offset=0,
            partial_layers=[],
        )

    FEEDS["dissect"].record_cycle(entities=len(layers))
    return {
        "summary": pkt.summary(),
        "layers": layers,
        "layer_count": len(layers),
    }
