"""E2E tests for capture — BPF-aware, capability_unavailable on miss."""
from __future__ import annotations

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.feeds import FEEDS, required_feeds_healthy
from scapy_mcp.tools import capture as cap_mod
from scapy_mcp.utils.exceptions import CapabilityUnavailableError


def test_capture_refuses_when_no_bpf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Capability-unavailable path: capture is optional so the required-feed
    ``healthy`` aggregate is unaffected by capture's degraded state. The
    remaining required feeds (craft/dissect/pcap) start cold in this test
    process so ``required_feeds_healthy()`` returns False — but capture's
    unavailability must NOT be the cause: we assert it independently via
    ``FEEDS["capture"].errors_total`` increment.
    """
    initial_capture_errors = FEEDS["capture"].errors_total
    monkeypatch.setattr(cap_mod, "_probe_bpf", lambda: False)
    with pytest.raises(CapabilityUnavailableError) as exc_info:
        cap_mod.capture_start(settings=ScapySettings(_env_file=None), iface="lo0")
    assert exc_info.value.capability == "capture"
    # capture feed recorded the unavailability — proves the failure path
    # flowed through the wiring-discipline signal, not a silent miss.
    assert FEEDS["capture"].errors_total > initial_capture_errors
    # Required-feed aggregate must reflect ONLY required-feed state. Capture
    # is optional so its error must not push the aggregate to "degraded".
    assert "capture" not in {f.name for f in FEEDS.values() if f.required}
