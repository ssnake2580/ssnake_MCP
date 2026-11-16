from __future__ import annotations

import pytest
from pydantic import ValidationError

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


def test_ether_spec_requires_dst_and_src() -> None:
    s = EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    assert s.dst == "ff:ff:ff:ff:ff:ff"


def test_ip_spec_carries_ttl_and_proto() -> None:
    s = IPSpec(dst="10.0.0.1", src="10.0.0.2", ttl=64, proto="tcp")
    assert s.proto == "tcp"


def test_packet_spec_builds_bottom_up() -> None:
    p = PacketSpec(
        layers=[
            EtherSpec(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"),
            IPSpec(dst="8.8.8.8", src="10.0.0.2"),
            UDPSpec(dport=53, sport=12345),
            DNSLayerSpec(rd=1),
        ],
    )
    assert len(p.layers) == 4
    assert p.layers[0].type == "Ether"
    assert p.layers[-1].type == "DNS"


def test_packet_spec_rejects_unknown_layer_field() -> None:
    """An unrecognized field on a layer must be rejected, not silently dropped.

    A typo like ``dest`` for ``dst`` would otherwise produce a packet that is
    valid-looking but addressed wrongly, so layer specs are ``extra="forbid"``.
    """
    with pytest.raises(ValidationError):
        PacketSpec.model_validate(
            {
                "layers": [
                    {
                        "type": "Ether",
                        "dst": "ff:ff:ff:ff:ff:ff",
                        "src": "00:11:22:33:44:55",
                        "not_a_real_field": "boom",
                    },
                ],
            },
        )


def test_packet_spec_rejects_unknown_layer_type() -> None:
    with pytest.raises(ValidationError):
        PacketSpec.model_validate({"layers": [{"type": "NotALayer"}]})


def test_packet_spec_accepts_valid_dict_payload() -> None:
    p = PacketSpec.model_validate(
        {
            "layers": [
                {"type": "Ether", "dst": "ff:ff:ff:ff:ff:ff", "src": "00:11:22:33:44:55"},
                {"type": "IP", "dst": "10.0.0.1"},
            ],
        },
    )
    assert [layer.type for layer in p.layers] == ["Ether", "IP"]


def test_arp_spec_carries_op_and_targets() -> None:
    s = ARPSpec(
        op="who-has",
        pdst="10.0.0.1",
        psrc="10.0.0.2",
        hwdst="ff:ff:ff:ff:ff:ff",
        hwsrc="00:11:22:33:44:55",
    )
    assert s.op == "who-has"


def test_remaining_layer_specs_construct() -> None:
    assert IPv6Spec(dst="2001:db8::1").hlim == 64
    assert TCPSpec(dport=80).dport == 80
    assert ICSpec(icmp_type=8).icmp_code == 0
    assert RawSpec(load="deadbeef").load == "deadbeef"
