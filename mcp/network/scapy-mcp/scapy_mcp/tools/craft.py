"""``craft_packet`` — build a scapy Packet from a LayerSpec stack.

The function walks the ``PacketSpec.layers`` list bottom-up: ``layers[0]``
becomes the wire-most layer and ``layers[-1]`` becomes the payload. Every
call increments the ``craft`` feed cycle counter.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from scapy_mcp.feeds import FEEDS
from scapy_mcp.models.layers import (
    ARPSpec,
    DNSLayerSpec,
    EtherSpec,
    ICSpec,
    IPSpec,
    IPv6Spec,
    LayerSpec,
    RawSpec,
    TCPSpec,
    UDPSpec,
)
from scapy_mcp.utils.exceptions import ConfigurationError

if TYPE_CHECKING:
    from scapy_mcp.config.settings import ScapySettings
    from scapy_mcp.models.packet import PacketSpec


def _build_layer(spec: LayerSpec) -> Packet:
    if isinstance(spec, EtherSpec):
        return Ether(dst=spec.dst, src=spec.src)
    if isinstance(spec, ARPSpec):
        return ARP(
            op=spec.op,
            pdst=spec.pdst,
            psrc=spec.psrc or "0.0.0.0",
            hwdst=spec.hwdst,
            hwsrc=spec.hwsrc or "00:00:00:00:00:00",
        )
    if isinstance(spec, IPSpec):
        return IP(dst=spec.dst, src=spec.src or "0.0.0.0", ttl=spec.ttl or 64)
    if isinstance(spec, IPv6Spec):
        return IPv6(dst=spec.dst, src=spec.src or "::", hlim=spec.hlim or 64)
    if isinstance(spec, TCPSpec):
        return TCP(dport=spec.dport, sport=spec.sport or 0, flags=spec.flags or "")
    if isinstance(spec, UDPSpec):
        return UDP(dport=spec.dport, sport=spec.sport or 0)
    if isinstance(spec, ICSpec):
        return ICMP(type=spec.icmp_type, code=spec.icmp_code or 0)
    if isinstance(spec, DNSLayerSpec):
        return DNS(rd=spec.rd, qd=DNSQR(qname=spec.qname) if spec.qname else None)
    if isinstance(spec, RawSpec):
        return Raw(load=bytes.fromhex(spec.load))
    raise TypeError(f"unknown layer spec: {spec!r}")


def craft_packet(*, settings: ScapySettings, spec: PacketSpec) -> dict:
    if not spec.layers:
        raise ConfigurationError(
            "at least one layer required",
            context={"spec": spec.model_dump()},
        )
    # First layer is the wire-most (layers[0] in spec = outermost on the wire);
    # subsequent layers stack on top. Initialising ``pkt`` with the first
    # build keeps the type narrowed to ``Packet`` (no ``Packet | None`` carrier),
    # which is what the type checker needs at ``bytes(pkt)`` / ``pkt.summary()``.
    pkt = _build_layer(spec.layers[0])
    for layer in spec.layers[1:]:
        pkt = pkt / _build_layer(layer)
    raw_bytes = bytes(pkt)
    summary = pkt.summary()
    FEEDS["craft"].record_cycle(entities=1)
    return {
        "summary": summary,
        "layer_count": len(spec.layers),
        "bytes_b64": base64.b64encode(raw_bytes).decode(),
        "bytes": raw_bytes,
    }
