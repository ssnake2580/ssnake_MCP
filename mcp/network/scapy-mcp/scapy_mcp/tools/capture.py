"""``capture_start`` / ``capture_stop`` / ``capture_read`` — live BPF capture.

Capture is OPTIONAL: when ``/dev/bpf*`` is missing the function refuses with
:class:`CapabilityUnavailableError` and the ``capture`` feed is marked
unavailable. ``/readyz`` is unaffected because capture is not a required
feed.

Two backend paths:

- ``AsyncSniffer`` — preferred when scapy exposes it (>=2.5).
- ``sniff(stop_filter=...)`` — synchronous fallback executed in the
  module-level worker pool when AsyncSniffer is unavailable (older
  scapy, or a build without the async surface). ``capture_stop``
  sets a per-session cancel event the stop_filter checks.

If scapy exposes neither, capture refuses with
:class:`CapabilityUnavailableError` (reason = "no sniffer backend").

Session storage: ``_SESSIONS[session_id]`` is the sniffer object
itself (AsyncSniffer or :class:`_SyncCaptureSession`). Both expose
``.stop()`` and ``.results``, so callers and tests can treat them
uniformly.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scapy_mcp.feeds import FEEDS
from scapy_mcp.utils.exceptions import (
    CapabilityUnavailableError,
    ConfigurationError,
)

if TYPE_CHECKING:
    from scapy_mcp.config.settings import ScapySettings

logger = logging.getLogger("scapy_mcp.tools.capture")

# Lazy imports — capture.py is imported unconditionally by server.py even on
# hosts where scapy's async surface is unavailable (e.g. minimal build).
# A missing AsyncSniffer must NOT cascade into a server-import failure.
try:
    from scapy.sendrecv import AsyncSniffer  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — depends on scapy build
    AsyncSniffer = None  # type: ignore[assignment,misc]

try:
    from scapy.sendrecv import sniff  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    sniff = None  # type: ignore[assignment,misc]


_SESSIONS: dict[str, Any] = {}
_EXECUTOR: ThreadPoolExecutor | None = None


class _SyncCaptureSession:
    """Sync-fallback stand-in for an AsyncSniffer.

    Holds the executor ``Future`` for the blocking ``sniff()`` call,
    a cancel event the stop_filter observes, and a list the on-packet
    callback populates (exposed as ``.results`` so :func:`capture_read`
    and tests can treat sync and async sessions uniformly).
    """

    def __init__(
        self,
        future: Future,
        cancel_event: threading.Event,
        pkt_holder: list,
    ) -> None:
        self._future = future
        self._cancel = cancel_event
        self.results = pkt_holder

    def stop(self) -> None:
        self._cancel.set()


def _executor(settings: ScapySettings) -> ThreadPoolExecutor:
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=settings.capture_executor_workers,
            thread_name_prefix="scapy-mcp-capture",
        )
    return _EXECUTOR


def _probe_bpf() -> bool:
    """Return True iff /dev/bpf* is reachable."""
    bpf_dir = Path("/dev")
    if not bpf_dir.exists():
        return False
    return any(p.name.startswith("bpf") for p in bpf_dir.iterdir())


def capture_start(
    *,
    settings: ScapySettings,
    iface: str | None = None,
    bpf_filter: str | None = None,
    packet_cap: int | None = None,
    duration_cap: int | None = None,
) -> dict:
    if not _probe_bpf():
        FEEDS["capture"].mark_capability_unavailable("/dev/bpf* not reachable")
        raise CapabilityUnavailableError(
            "capture unavailable",
            capability="capture",
            reason="/dev/bpf* not reachable",
        )

    if iface is None:
        iface = settings.default_iface
    if iface is None:
        raise ConfigurationError("iface required (no default_iface in settings)")

    cap = packet_cap or settings.capture_packet_cap
    duration = duration_cap or settings.capture_duration_cap_seconds
    flt = bpf_filter or settings.capture_default_bpf_filter

    session_id = uuid.uuid4().hex
    backend = "async"

    if AsyncSniffer is not None:
        sniffer = AsyncSniffer(
            iface=iface,
            filter=flt,
            count=cap,
            timeout=duration,
        )
        sniffer.start()
        _SESSIONS[session_id] = sniffer
    elif sniff is not None:
        backend = "sync"
        cancel_event = threading.Event()
        pkt_holder: list = []

        def _on_packet(pkt: Any) -> None:
            pkt_holder.append(pkt)

        def _stop_filter(_pkt: Any) -> bool:
            return cancel_event.is_set()

        future: Future = _executor(settings).submit(
            sniff,
            iface=iface,
            filter=flt,
            timeout=duration,
            stop_filter=_stop_filter,
            prn=_on_packet,
        )
        _SESSIONS[session_id] = _SyncCaptureSession(
            future=future,
            cancel_event=cancel_event,
            pkt_holder=pkt_holder,
        )
    else:
        FEEDS["capture"].mark_capability_unavailable("no sniffer backend available")
        raise CapabilityUnavailableError(
            "capture unavailable",
            capability="capture",
            reason="scapy exposes neither AsyncSniffer nor sniff()",
        )

    return {
        "session_id": session_id,
        "iface": iface,
        "packet_cap": cap,
        "duration_cap": duration,
        "backend": backend,
    }


def capture_stop(*, session_id: str) -> dict:
    session = _SESSIONS.pop(session_id, None)
    if session is None:
        raise ConfigurationError(f"unknown session: {session_id}")
    session.stop()
    return {"session_id": session_id, "stopped": True}


def capture_read(*, session_id: str) -> dict:
    session = _SESSIONS.get(session_id)
    if session is None:
        raise ConfigurationError(f"unknown session: {session_id}")
    packets = session.results
    summaries = [pkt.summary() for pkt in (packets or [])]
    FEEDS["capture"].record_cycle(entities=len(summaries))
    return {"count": len(summaries), "summaries": summaries}
