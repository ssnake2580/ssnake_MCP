"""Layer specifications — a discriminated union over the supported scapy layers.

Every layer spec is ``extra="forbid"``: an unrecognized field is a caller
error, not something to silently drop. A typo such as ``dest`` for ``dst``
would otherwise yield a packet that looks valid but is addressed wrongly.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    type: str  # discriminator


class EtherSpec(_Base):
    type: Literal["Ether"] = "Ether"
    dst: str
    src: str
    ether_type: int | None = None  # EtherType; not the discriminator


class ARPSpec(_Base):
    type: Literal["ARP"] = "ARP"
    op: Literal["who-has", "is-at"] = "who-has"
    pdst: str
    psrc: str | None = None
    hwdst: str = "ff:ff:ff:ff:ff:ff"
    hwsrc: str | None = None


class IPSpec(_Base):
    type: Literal["IP"] = "IP"
    dst: str
    src: str | None = None
    ttl: int | None = 64
    proto: Literal["tcp", "udp", "icmp"] | None = None


class IPv6Spec(_Base):
    type: Literal["IPv6"] = "IPv6"
    dst: str
    src: str | None = None
    hlim: int | None = 64


class TCPSpec(_Base):
    type: Literal["TCP"] = "TCP"
    dport: int
    sport: int | None = None
    flags: str | None = None  # "S", "SA", etc.


class UDPSpec(_Base):
    type: Literal["UDP"] = "UDP"
    dport: int
    sport: int | None = None


class ICSpec(_Base):
    type: Literal["ICMP"] = "ICMP"
    icmp_type: int
    icmp_code: int | None = 0


class DNSLayerSpec(_Base):
    type: Literal["DNS"] = "DNS"
    qname: str | None = None
    qtype: str | None = None
    rd: int = 0


class RawSpec(_Base):
    type: Literal["Raw"] = "Raw"
    load: str  # hex


LayerSpec = Annotated[
    EtherSpec | ARPSpec | IPSpec | IPv6Spec | TCPSpec | UDPSpec | ICSpec | DNSLayerSpec | RawSpec,
    Field(discriminator="type"),
]
