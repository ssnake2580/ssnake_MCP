"""Craft and dissect tool tests.

``craft_packet`` builds a PacketSpec into a real scapy packet; ``dissect_bytes``
parses base64-encoded raw bytes back into a layer list. Both increment their
respective feed cycles (wiring-discipline §1).
"""
from __future__ import annotations

import base64

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.feeds import FEEDS
from scapy_mcp.models.layers import (
    ARPSpec,
    DNSLayerSpec,
    EtherSpec,
    ICSpec,
    IPSpec,
    IPv6Spec,
    RawSpec,
    TCPSpec,
    UDPSpec,
)
from scapy_mcp.models.packet import PacketSpec
from scapy_mcp.tools.craft import craft_packet
from scapy_mcp.tools.dissect import dissect_bytes
from scapy_mcp.utils.exceptions import DissectionError


@pytest.fixture(autouse=True)
def _reset_feed() -> None:
    FEEDS["craft"].cycles_total = 0
    FEEDS["craft"].entities_count = 0
    FEEDS["dissect"].cycles_total = 0
    FEEDS["dissect"].entities_count = 0


def test_craft_packet_builds_full_stack() -> None:
    settings = ScapySettings(_env_file=None)
    pkt = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPSpec(dst="8.8.8.8", src="10.0.0.2"),
        UDPSpec(dport=53, sport=12345),
        DNSLayerSpec(rd=1, qname="example.com"),
    ])
    result = craft_packet(settings=settings, spec=pkt)
    assert result["layer_count"] == 4
    assert "Ether" in result["summary"]
    assert FEEDS["craft"].cycles_total == 1


def test_dissect_bytes_returns_layers() -> None:
    settings = ScapySettings(_env_file=None)
    pkt = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPSpec(dst="8.8.8.8", src="10.0.0.2"),
        UDPSpec(dport=53, sport=12345),
    ])
    crafted = craft_packet(settings=settings, spec=pkt)
    data_b64 = base64.b64encode(crafted["bytes"]).decode()
    result = dissect_bytes(settings=settings, data=data_b64, link_type="EN10MB")
    assert "Ether" in result["layers"]
    assert "IP" in result["layers"]
    assert "UDP" in result["layers"]


def test_dissect_bytes_handles_malformed() -> None:
    settings = ScapySettings(_env_file=None)
    # 2 bytes is too short for an Ether header (Ether wants >=14); scapy raises
    # ``struct.error: unpack requires a buffer of 6 bytes`` which we surface as
    # ``DissectionError``. Plan literal used 24 bytes; scapy 2.7 is more lenient
    # with truncated IP and would not raise — 2 bytes is the minimal reproducer.
    bad = base64.b64encode(b"\x00\x00").decode()
    with pytest.raises(DissectionError) as exc_info:
        dissect_bytes(settings=settings, data=bad, link_type="EN10MB")
    payload = exc_info.value.to_payload()
    assert payload["error"] == "dissection_failed"
    assert "offset" in payload


def test_dissect_bytes_rejects_invalid_base64() -> None:
    from scapy_mcp.utils.exceptions import DissectionError

    settings = ScapySettings(_env_file=None)
    with pytest.raises(DissectionError) as exc_info:
        dissect_bytes(settings=settings, data="not-base64!@#", link_type="EN10MB")
    assert "base64" in str(exc_info.value)


def test_dissect_bytes_rejects_unsupported_link_type() -> None:
    from scapy_mcp.utils.exceptions import DissectionError

    settings = ScapySettings(_env_file=None)
    good = base64.b64encode(b"\x00" * 14).decode()
    with pytest.raises(DissectionError) as exc_info:
        dissect_bytes(settings=settings, data=good, link_type="LINUX_SLL")
    assert exc_info.value.offset == 0


def test_craft_packet_supports_each_layer_type() -> None:
    """Every LayerSpec discriminator constructs without raising."""
    settings = ScapySettings(_env_file=None)
    # ARPSpec
    arp = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        ARPSpec(op="who-has", pdst="10.0.0.1", psrc="10.0.0.2"),
    ])
    r = craft_packet(settings=settings, spec=arp)
    assert r["layer_count"] == 2

    # IPv6 + TCP
    ipv6 = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPv6Spec(dst="2001:db8::1"),
        TCPSpec(dport=443),
    ])
    r = craft_packet(settings=settings, spec=ipv6)
    assert r["layer_count"] == 3

    # ICMP
    icmp = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPSpec(dst="10.0.0.1"),
        ICSpec(icmp_type=8, icmp_code=0),
    ])
    r = craft_packet(settings=settings, spec=icmp)
    assert r["layer_count"] == 3


def test_craft_packet_rejects_empty_layers() -> None:
    from scapy_mcp.utils.exceptions import ConfigurationError

    settings = ScapySettings(_env_file=None)
    with pytest.raises(ConfigurationError):
        craft_packet(settings=settings, spec=PacketSpec(layers=[]))


def test_craft_packet_supports_raw_layer() -> None:
    """RawSpec loads hex bytes into the Raw layer."""
    settings = ScapySettings(_env_file=None)
    pkt = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        RawSpec(load="deadbeef"),
    ])
    r = craft_packet(settings=settings, spec=pkt)
    assert r["layer_count"] == 2
    assert b"\xde\xad\xbe\xef" in r["bytes"]
