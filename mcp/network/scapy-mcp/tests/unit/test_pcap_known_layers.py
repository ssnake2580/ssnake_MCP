"""Phase 0b gate: open the committed ``http_get.pcap`` fixture, dissect every
packet, and assert the layer order matches the spec's documented exchange:

    TCP/80 three-way handshake + GET + 200, with TCP flags
    "S", "SA", "A", "PA", "PA" in order.
"""
from __future__ import annotations

import base64
from pathlib import Path

# Scapy 2.7 requires layers to be explicitly imported for the dissect engine
# to bind them by EtherType. Without these imports, the IP/TCP layers fall
# back to ``Raw`` even though the bytes are well-formed.
from scapy.layers.inet import IP, TCP  # noqa: F401  — registration side-effect
from scapy.utils import rdpcap

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.tools.dissect import dissect_bytes

REPO = Path(__file__).resolve().parent.parent.parent
FIXTURE = REPO / "tests" / "fixtures" / "http_get.pcap"
EXPECTED_FLAGS = ["S", "SA", "A", "PA", "PA"]


def test_http_get_pcap_dissects_to_expected_layer_shape() -> None:
    settings = ScapySettings(_env_file=None)
    observed_flags: list[str] = []
    for pkt in rdpcap(str(FIXTURE)):
        data_b64 = base64.b64encode(bytes(pkt)).decode()
        result = dissect_bytes(settings=settings, data=data_b64, link_type="EN10MB")
        layers = result["layers"]
        assert "Ether" in layers, layers
        assert "IP" in layers, layers
        assert "TCP" in layers, layers
        # scapy FlagValue.__str__ matches the canonical flag strings.
        observed_flags.append(str(pkt["TCP"].flags))

    assert observed_flags == EXPECTED_FLAGS
