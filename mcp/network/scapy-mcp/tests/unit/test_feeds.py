"""Feed registry tests — five feeds, two optional, four mandatory signals.

The wiring-discipline contract (mcp-common §7) requires every tool to expose
``feed.entities_count``, ``feed.last_updated_timestamp``, ``feed.errors_total``,
and ``cycles_total``. These tests pin the FeedState Pydantic model that backs
``/health`` and ``/readyz``.
"""
from __future__ import annotations

import pytest

from scapy_mcp.feeds import FEEDS, FeedState, required_feeds_healthy


def test_required_feeds_are_required() -> None:
    for name in ("craft", "dissect", "pcap"):
        assert FEEDS[name].required is True


def test_optional_feeds_can_be_marked_unavailable() -> None:
    for name in ("capture", "transmit"):
        assert FEEDS[name].required is False
        # Should not raise.
        FEEDS[name].mark_capability_unavailable("BPF missing")


def test_required_feeds_cannot_be_marked_unavailable() -> None:
    for name in ("craft", "dissect", "pcap"):
        feed = FEEDS[name]
        feed.cycles_total = 1  # simulate working
        with pytest.raises(ValueError):
            feed.mark_capability_unavailable("oops")


def test_feed_healthy_after_one_successful_cycle() -> None:
    feed = FeedState(name="x", required=True)
    feed.record_cycle(entities=10)
    assert feed.healthy is True
    assert feed.entities_count == 10


def test_feed_unhealthy_after_only_error_cycles() -> None:
    feed = FeedState(name="x", required=True)
    feed.record_cycle(error="boom")
    assert feed.healthy is False


def test_optional_feed_unhealthy_when_only_errors() -> None:
    feed = FeedState(name="capture", required=False)
    feed.record_cycle(error="no bpf")
    assert feed.healthy is False


def test_required_feeds_healthy_returns_false_when_one_required_is_unhealthy() -> None:
    FEEDS["dissect"].cycles_total = 1
    FEEDS["dissect"].record_cycle(error="bad input")
    assert required_feeds_healthy() is False
