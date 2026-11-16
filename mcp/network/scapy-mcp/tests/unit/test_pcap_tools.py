"""PCAP read/write tool tests.

The path-containment guard rejects ``filename="../escape.pcap"``-style escapes.
``read_pcap`` returns summaries with offset/limit windowing.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.feeds import FEEDS
from scapy_mcp.models.layers import EtherSpec, IPSpec, TCPSpec
from scapy_mcp.models.packet import PacketSpec
from scapy_mcp.tools.craft import craft_packet
from scapy_mcp.tools.pcap import read_pcap, write_pcap
from scapy_mcp.utils.exceptions import ConfigurationError


@pytest.fixture
def settings(tmp_path: Path) -> ScapySettings:
    s = ScapySettings(_env_file=None)
    s.pcap_write_dir = tmp_path / "pcap-staging"
    s.pcap_write_dir.mkdir(parents=True, exist_ok=True)
    return s


def test_write_then_read_round_trip(settings: ScapySettings) -> None:
    FEEDS["pcap"].cycles_total = 0
    FEEDS["pcap"].entities_count = 0
    spec = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPSpec(dst="10.0.0.1", src="10.0.0.2"),
        TCPSpec(dport=80, sport=12345),
    ])
    crafted = craft_packet(settings=settings, spec=spec)
    write_pcap(settings=settings, filename="out.pcap", packets=[crafted["bytes"]])
    out = settings.pcap_write_dir / "out.pcap"
    assert out.exists()
    result = read_pcap(settings=settings, path=str(out))
    assert result["count"] == 1


def test_read_with_limit_and_offset(settings: ScapySettings) -> None:
    FEEDS["pcap"].cycles_total = 0
    FEEDS["pcap"].entities_count = 0
    pkts = [
        craft_packet(settings=settings, spec=PacketSpec(layers=[
            EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
            IPSpec(dst="10.0.0.1", src="10.0.0.2"),
        ]))["bytes"]
        for _ in range(5)
    ]
    write_pcap(settings=settings, filename="five.pcap", packets=pkts)
    result = read_pcap(
        settings=settings,
        path=str(settings.pcap_write_dir / "five.pcap"),
        limit=2,
        offset=1,
    )
    assert result["count"] == 2
    assert result["offset"] == 1


def test_write_rejects_path_outside_pcap_write_dir(settings: ScapySettings) -> None:
    """``../escape.pcap`` is portable across macOS (``/private/tmp``) and Linux."""
    with pytest.raises(Exception):
        write_pcap(settings=settings, filename="../escape.pcap", packets=[b"\x00"])
