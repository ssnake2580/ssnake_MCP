"""Generate deterministic PCAP fixtures for scapy-mcp tests.

All timestamps fixed to epoch 1700000000.000000. No randomness. The fixtures
round-trip through ``rdpcap`` / ``wrpcap`` and exercise every layer the
Phase 1 tools support (Ether, IP, IPv6, TCP, UDP, ICMP, DNS, ARP).

Run from repo root: ``python -m scripts.gen_pcap_fixtures``
"""

from __future__ import annotations

import json
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

FIXTURE_TS = 1700000000.0  # 2023-11-14 22:13:20 UTC
PROVENANCE = {
    "generator": "scripts.gen_pcap_fixtures",
    "fixed_epoch_seconds": FIXTURE_TS,
    "deterministic": True,
}

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _write(name: str, packets: list) -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    wrpcap(str(FIXTURES_DIR / f"{name}.pcap"), packets)
    (FIXTURES_DIR / f"{name}.provenance.json").write_text(
        json.dumps(PROVENANCE, indent=2),
    )


def _stamp(pkt: object, ts: float = FIXTURE_TS) -> None:
    """Set packet time without using a non-existent constructor kwarg.

    Scapy exposes the timestamp on the packet object (``pkt.time``), not as
    a constructor field for ``Ether``/``IP``/``TCP``/etc. The plan's literal
    script would raise ``TypeError`` because those classes do not accept a
    ``timestamp`` keyword.
    """
    pkt.time = ts  # type: ignore[attr-defined]


def http_get() -> None:
    eth = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
    _stamp(eth)

    packets = []

    # SYN
    pkt = (
        eth
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(
            sport=12345,
            dport=80,
            flags="S",
            seq=1000,
        )
    )
    _stamp(pkt)
    packets.append(pkt)

    # SYN-ACK
    pkt = (
        Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    )
    _stamp(pkt)
    packets.append(pkt)

    # ACK
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
    )
    _stamp(pkt)
    packets.append(pkt)

    # GET
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    )
    _stamp(pkt)
    packets.append(pkt)

    # 200 OK
    pkt = (
        Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345, flags="PA", seq=2001, ack=1066)
        / Raw(load=b"HTTP/1.1 200 OK\r\n\r\nHi")
    )
    _stamp(pkt)
    packets.append(pkt)

    _write("http_get", packets)


def dns_query() -> None:
    # Query
    q = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    _stamp(q)

    # Response
    r = (
        Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa")
        / IP(src="8.8.8.8", dst="10.0.0.1")
        / UDP(sport=53, dport=12345)
        / DNS(qr=1, qd=DNSQR(qname="example.com"))
    )
    _stamp(r)

    _write("dns_query", [q, r])


def arp_request() -> None:
    who_has = Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op="who-has",
        pdst="10.0.0.1",
        psrc="10.0.0.2",
        hwsrc="aa:aa:aa:aa:aa:aa",
        hwdst="ff:ff:ff:ff:ff:ff",
    )
    _stamp(who_has)

    is_at = Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa") / ARP(
        op="is-at",
        pdst="10.0.0.2",
        psrc="10.0.0.1",
        hwsrc="bb:bb:bb:bb:bb:bb",
        hwdst="aa:aa:aa:aa:aa:aa",
    )
    _stamp(is_at)

    _write("arp_request", [who_has, is_at])


def icmp_echo() -> None:
    req = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / ICMP(type=8)
    )
    _stamp(req)

    reply = (
        Ether(src="bb:bb:bb:bb:bb:bb", dst="aa:aa:aa:aa:aa:aa")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / ICMP(type=0)
    )
    _stamp(reply)

    _write("icmp_echo", [req, reply])


def ipv6_tcp() -> None:
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=12345, dport=443, flags="S")
    )
    _stamp(pkt)
    _write("ipv6_tcp", [pkt])


def malformed() -> None:
    """Truncated IP header — 14 bytes of Ether + only 10 bytes of IP.

    Hand-craft a 24-byte pcap record so ``dissect_bytes`` raises
    ``DissectionError`` with the expected ``offset`` / ``partial_layers``.
    """
    raw = b"\x00" * 14 + b"\x45" + b"\x00" * 9  # 14 + 10 bytes
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    (FIXTURES_DIR / "malformed.pcap").write_bytes(
        # PCAP global header + 1 record header + 24 bytes payload.
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xff\xff\x00\x00\x01\x00\x00\x00" + b"\x18\x00\x00\x00" + raw,
    )
    (FIXTURES_DIR / "malformed.provenance.json").write_text(
        json.dumps(PROVENANCE, indent=2),
    )


GENERATORS = [http_get, dns_query, arp_request, icmp_echo, ipv6_tcp, malformed]


if __name__ == "__main__":
    for gen in GENERATORS:
        gen()
    print(f"Wrote {len(GENERATORS)} fixtures to {FIXTURES_DIR}")
