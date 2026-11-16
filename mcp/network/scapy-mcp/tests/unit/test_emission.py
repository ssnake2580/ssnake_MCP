from __future__ import annotations

import pytest

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.security.controller import EmissionController
from scapy_mcp.utils.exceptions import EmissionRefusedError


@pytest.fixture
def settings() -> ScapySettings:
    return ScapySettings(_env_file=None)


def test_master_switch_off_refuses(settings: ScapySettings) -> None:
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP, UDP

    pkt = IP(dst="10.0.0.1") / UDP(dport=53)
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=False)
    assert exc_info.value.control == "transmit_enabled"


def test_l3_allowlist_miss_refuses(settings: ScapySettings) -> None:
    """Allowing 10.0.0.0/8 but not 192.168.0.0/16: 192.168 packet refused."""
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP

    pkt = IP(dst="192.168.1.1")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=False)
    assert exc_info.value.control == "transmit_allow_l3_cidrs"


def test_l3_allowlist_match_passes(settings: ScapySettings) -> None:
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP

    pkt = IP(dst="10.5.5.5")
    ctrl.check(pkt, is_probe=False)  # no raise


def test_ipv6_family_without_allowlist_entry_refuses(settings: ScapySettings) -> None:
    """An IPv6 destination is denied when only an IPv4 CIDR is allowlisted."""
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet6 import IPv6

    pkt = IPv6(dst="2001:db8::1")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=False)
    assert exc_info.value.control == "transmit_allow_l3_cidrs"


def test_l2_packet_without_explicit_allow_refuses(settings: ScapySettings) -> None:
    """Pure ARP — no IP layer — must be refused unless transmit_allow_l2."""
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.l2 import ARP, Ether

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=False)
    assert exc_info.value.control == "transmit_allow_l2"


def test_l2_packet_with_explicit_allow_passes(settings: ScapySettings) -> None:
    settings.transmit_enabled = True
    settings.transmit_allow_l2 = True
    settings.transmit_allow_broadcast = True
    ctrl = EmissionController(settings=settings)
    from scapy.layers.l2 import ARP, Ether

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1")
    ctrl.check(pkt, is_probe=False)


def test_broadcast_dst_refused_without_flag(settings: ScapySettings) -> None:
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP

    pkt = IP(dst="255.255.255.255")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=False)
    assert exc_info.value.control == "transmit_allow_broadcast"


def test_probe_with_too_many_targets_refused(settings: ScapySettings) -> None:
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    settings.transmit_max_probe_targets = 2
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP

    pkt = IP(dst="10.0.0.1")
    with pytest.raises(EmissionRefusedError) as exc_info:
        ctrl.check(pkt, is_probe=True, target_count=10)
    assert exc_info.value.control == "transmit_max_probe_targets"


def test_probe_within_cap_passes(settings: ScapySettings) -> None:
    settings.transmit_enabled = True
    settings.transmit_allow_l3_cidrs = ["10.0.0.0/8"]
    settings.transmit_max_probe_targets = 4
    ctrl = EmissionController(settings=settings)
    from scapy.layers.inet import IP

    ctrl.check(IP(dst="10.0.0.1"), is_probe=True, target_count=4)
