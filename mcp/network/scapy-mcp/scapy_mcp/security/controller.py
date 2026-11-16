"""Emission controls — the gate every frame must clear before it leaves the process."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

# IP/IPv6/ARP/Ether are used at runtime by `haslayer`, so they stay imported.
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from scapy_mcp.utils.exceptions import EmissionRefusedError

if TYPE_CHECKING:
    # Annotation-only: `EmissionController` is a plain class, not a pydantic
    # model, so these are never resolved at runtime.
    from scapy.packet import Packet

    from scapy_mcp.config.settings import ScapySettings

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class EmissionController:
    """Four controls (master, L3 CIDR, L2 flag, broadcast flag) plus a fifth for
    request-response probes (target-count cap). All five must pass before a frame
    leaves the process.

    A packet whose destination family has no allowlist entry is DENIED, never
    skipped. A destination that has a same-family entry but falls outside every
    allowlisted network is likewise DENIED — presence of a CIDR for the family
    is necessary but not sufficient.
    """

    def __init__(self, settings: ScapySettings) -> None:
        self.settings = settings
        self._cidrs: list[tuple[int, _IPNetwork]] = []
        for cidr in settings.transmit_allow_l3_cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            self._cidrs.append((net.version, net))

    def _destination_address(self, packet: Packet) -> _IPAddress | None:
        """Return the parsed L3 destination address, or None if there is no L3 layer."""
        raw: str | None = None
        if packet.haslayer(IP):
            raw = packet[IP].dst
        elif packet.haslayer(IPv6):
            raw = packet[IPv6].dst
        if raw is None:
            return None
        try:
            return ipaddress.ip_address(raw)
        except ValueError:
            return None

    def _has_l2_only(self, packet: Packet) -> bool:
        """True if the packet has Ether/ARP but no IP/IPv6 — requires transmit_allow_l2."""
        return not (packet.haslayer(IP) or packet.haslayer(IPv6))

    def _is_broadcast(self, packet: Packet) -> bool:
        if packet.haslayer(ARP):
            return bool(packet[ARP].op == 1 and packet[ARP].pdst == "255.255.255.255")
        if packet.haslayer(Ether):
            dst = packet[Ether].dst.lower()
            if dst in {"ff:ff:ff:ff:ff:ff", "33:33:00:00:00:00"}:
                return True
        if packet.haslayer(IP):
            dst = packet[IP].dst
            try:
                ip = ipaddress.ip_address(dst)
            except ValueError:
                return False
            return ip.is_multicast or dst == "255.255.255.255"
        return False

    def _check_l3_allowlist(self, packet: Packet) -> None:
        """Deny unless the L3 destination sits inside an allowlisted same-family CIDR."""
        dst = self._destination_address(packet)
        if dst is None:
            raise EmissionRefusedError(
                "L3 destination could not be parsed",
                control="transmit_allow_l3_cidrs",
                reason="unparsable destination address",
            )

        family_nets = [net for version, net in self._cidrs if version == dst.version]
        if not family_nets:
            raise EmissionRefusedError(
                f"no allowlist entry for family IPv{dst.version}",
                control="transmit_allow_l3_cidrs",
                reason=f"add a CIDR to transmit_allow_l3_cidrs for IPv{dst.version}",
            )

        if not any(dst in net for net in family_nets):
            raise EmissionRefusedError(
                f"destination {dst} is outside every allowlisted CIDR",
                control="transmit_allow_l3_cidrs",
                reason=f"add a CIDR covering {dst} to transmit_allow_l3_cidrs",
            )

    def check(self, packet: Packet, *, is_probe: bool, target_count: int = 1) -> None:
        """Run all five controls, most-specific refusal first.

        Order matters, and is chosen so the caller always gets the most
        informative control name:

        1. ``transmit_enabled`` — nothing else is meaningful while the master
           switch is off.
        2. ``transmit_max_probe_targets`` — a fan-out breach is about the
           request shape, independent of any single destination.
        3. ``transmit_allow_l2`` — an L2-only frame has no L3 destination to
           evaluate, so this must resolve before any address checks.
        4. ``transmit_allow_broadcast`` — broadcast/multicast is a coarser
           property than CIDR membership. A broadcast address will essentially
           never fall inside a unicast allowlist, so checking containment first
           would mask the real problem ("you tried to broadcast") behind a
           generic allowlist miss.
        5. ``transmit_allow_l3_cidrs`` — the narrowest check runs last.
        """
        s = self.settings

        if not s.transmit_enabled:
            raise EmissionRefusedError(
                "transmit is disabled",
                control="transmit_enabled",
                reason="master switch off",
            )

        if is_probe and target_count > s.transmit_max_probe_targets:
            raise EmissionRefusedError(
                f"probe target count {target_count} exceeds cap",
                control="transmit_max_probe_targets",
                reason=f"max {s.transmit_max_probe_targets}",
            )

        l2_only = self._has_l2_only(packet)
        if l2_only and not s.transmit_allow_l2:
            raise EmissionRefusedError(
                "L2-only packet and transmit_allow_l2 is off",
                control="transmit_allow_l2",
                reason="enable transmit_allow_l2 to send ARP/ND/RAW frames",
            )

        if self._is_broadcast(packet) and not s.transmit_allow_broadcast:
            raise EmissionRefusedError(
                "destination is broadcast/multicast",
                control="transmit_allow_broadcast",
                reason="enable transmit_allow_broadcast to send broadcast frames",
            )

        if not l2_only:
            self._check_l3_allowlist(packet)
