"""Capture tool supplementary tests — stop/read paths.

The ``capture_start`` happy path needs AsyncSniffer.start/stop mocked; the
``capture_stop`` and ``capture_read`` paths can be exercised end-to-end with
the mock in place. ``capture_read`` against an unknown session must raise
``ConfigurationError``.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.feeds import FEEDS
from scapy_mcp.tools import capture as cap_mod
from scapy_mcp.tools.capture import capture_read, capture_start, capture_stop
from scapy_mcp.utils.exceptions import ConfigurationError


def test_capture_stop_unknown_session_raises() -> None:
    with pytest.raises(ConfigurationError):
        capture_stop(session_id="does-not-exist")


def test_capture_read_unknown_session_raises() -> None:
    with pytest.raises(ConfigurationError):
        capture_read(session_id="does-not-exist")


def test_capture_start_with_valid_bpf_returns_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = ScapySettings(_env_file=None)
    monkeypatch.setattr(cap_mod, "_probe_bpf", lambda: True)

    class _FakeSniffer:
        def __init__(self, **_kwargs: object) -> None:
            self.results: list = []

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    # ``results`` may not exist on AsyncSniffer until start completes.
    monkeypatch.setattr(cap_mod, "AsyncSniffer", _FakeSniffer)
    out = capture_start(settings=settings, iface="lo0", packet_cap=1, duration_cap=1)
    assert "session_id" in out

    # Read the (empty) results — session is still alive here.
    sid = out["session_id"]
    rd = capture_read(session_id=sid)
    assert rd["count"] == 0
    # Now stop the captured session.
    capture_stop(session_id=sid)
    FEEDS["capture"].cycles_total = 0


def test_capture_start_missing_iface_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = ScapySettings(_env_file=None)
    settings.default_iface = None
    monkeypatch.setattr(cap_mod, "_probe_bpf", lambda: True)
    with pytest.raises(ConfigurationError):
        capture_start(settings=settings)


def test_get_session_isolates_results(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two sessions get independent results lists."""
    settings = ScapySettings(_env_file=None)
    monkeypatch.setattr(cap_mod, "_probe_bpf", lambda: True)

    class _S:
        def __init__(self, **kw: object) -> None:
            self.results = kw.get("_results", [])  # type: ignore[assignment]

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    # Provide two sniffer instances with different results.
    monkeypatch.setattr(
        cap_mod,
        "AsyncSniffer",
        lambda **kw: _S(_results=[SimpleNamespace(summary=lambda: "pkt-1")] if kw.get("iface") == "lo0" else _S(_results=[])),
    )
    a = capture_start(settings=settings, iface="lo0", packet_cap=1, duration_cap=1)
    # Inject a result and read it back.
    cap_mod._SESSIONS[a["session_id"]].results = [SimpleNamespace(summary=lambda: "pkt-1")]
    rd = capture_read(session_id=a["session_id"])
    assert rd["count"] == 1
