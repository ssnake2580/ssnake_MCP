"""Transmit tool tests — refusal-by-default, four-control gate.

The transmit tools must REFUSE every frame when the master switch is off;
when on, the L3 CIDR allowlist / L2 flag / broadcast flag / probe-target cap
each gate emission. The unit tests assert refusal paths; live emission is
covered by e2e tests gated on the broadcast opt-in (which is off by default).
"""
from __future__ import annotations

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.models.layers import EtherSpec, IPSpec, UDPSpec
from scapy_mcp.models.packet import PacketSpec
from scapy_mcp.security.controller import EmissionController
from scapy_mcp.tools.craft import craft_packet
from scapy_mcp.tools.transmit import probe_packet, transmit_packet
from scapy_mcp.utils.exceptions import EmissionRefusedError


def test_transmit_refused_when_master_switch_off() -> None:
    import asyncio

    settings = ScapySettings(_env_file=None)
    spec = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPSpec(dst="10.0.0.1", src="10.0.0.2"),
        UDPSpec(dport=53, sport=12345),
    ])
    crafted = craft_packet(settings=settings, spec=spec)
    with pytest.raises(EmissionRefusedError) as exc_info:
        asyncio.run(
            transmit_packet(
                settings=settings,
                packet_bytes=crafted["bytes"],
                iface="lo0",
                count=1,
            ),
        )
    assert exc_info.value.control == "transmit_enabled"


def test_probe_refused_when_targets_exceed_cap() -> None:
    import asyncio

    settings = ScapySettings(_env_file=None)
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    settings.transmit_max_probe_targets = 2
    spec = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
        IPSpec(dst="10.0.0.1", src="10.0.0.2"),
        UDPSpec(dport=53),
    ])
    crafted = craft_packet(settings=settings, spec=spec)
    with pytest.raises(EmissionRefusedError) as exc_info:
        asyncio.run(
            probe_packet(
                settings=settings,
                packet_bytes=crafted["bytes"],
                iface="lo0",
                targets=["10.0.0.3", "10.0.0.4", "10.0.0.5"],
                timeout_seconds=0.5,
            ),
        )
    assert exc_info.value.control == "transmit_max_probe_targets"


def test_transmit_refused_for_l2_without_flag() -> None:
    """Pure ARP must be refused unless transmit_allow_l2 — spec §6.3."""
    import asyncio

    settings = ScapySettings(_env_file=None)
    settings.transmit_enabled = True
    spec = PacketSpec(layers=[
        EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
    ])
    crafted = craft_packet(settings=settings, spec=spec)
    with pytest.raises(EmissionRefusedError) as exc_info:
        asyncio.run(
            transmit_packet(
                settings=settings,
                packet_bytes=crafted["bytes"],
                iface="lo0",
                count=1,
            ),
        )
    assert exc_info.value.control == "transmit_allow_l2"


def test_controller_returns_none_on_full_allow() -> None:
    settings = ScapySettings(_env_file=None)
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP, UDP

    pkt = IP(dst="10.5.5.5") / UDP(dport=53)
    ctrl.check(pkt, is_probe=False)  # no raise


def test_transmit_count_must_be_positive() -> None:
    import asyncio

    settings = ScapySettings(_env_file=None)
    from scapy_mcp.utils.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError):
        asyncio.run(
            transmit_packet(
                settings=settings,
                packet_bytes=b"\x00",
                iface="lo0",
                count=0,
            ),
        )


def test_transmit_ipv6_in_allowlist_passes() -> None:
    """L3 allow-list miss on IPv6 family — refused per-family."""
    settings = ScapySettings(_env_file=None)
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet6 import IPv6

    ipv6_pkt = IPv6(dst="2001:db8::1")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(ipv6_pkt, is_probe=False)
    assert exc_info.value.control == "transmit_allow_l3_cidrs"


def test_transmit_broadcast_dst_refused() -> None:
    """Broadcast destination refused when transmit_allow_broadcast is off."""
    settings = ScapySettings(_env_file=None)
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP

    pkt = IP(dst="255.255.255.255")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=False)
    assert exc_info.value.control == "transmit_allow_broadcast"
