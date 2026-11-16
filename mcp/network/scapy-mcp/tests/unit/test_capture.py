"""Capture tool tests.

Capture is BPF-aware: when ``/dev/bpf*`` is unreachable the session refuses
with ``CapabilityUnavailableError`` and marks the capture feed unavailable.
Capture is OPTIONAL — when degraded, ``/readyz`` still returns 200.
"""
from __future__ import annotations

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.feeds import FEEDS
from scapy_mcp.tools import capture as cap_mod
from scapy_mcp.tools.capture import capture_start
from scapy_mcp.utils.exceptions import CapabilityUnavailableError


def test_capture_unavailable_when_no_bpf(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = ScapySettings(_env_file=None)
    # Force the BPF probe to fail.
    monkeypatch.setattr(cap_mod, "_probe_bpf", lambda: False)
    with pytest.raises(CapabilityUnavailableError) as exc_info:
        capture_start(settings=settings, iface="lo0")
    assert exc_info.value.capability == "capture"
    # Feed marked unavailable; /readyz should still be 200 (capture is optional).
    assert FEEDS["capture"].errors_total >= 1
