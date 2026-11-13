"""Tests for CapInfos module."""

import tempfile
from unittest.mock import Mock

from scapy.all import IP, TCP, Raw, wrpcap

from mcpcap.core.config import Config
from mcpcap.modules.capinfos import CapInfosModule


class TestCapInfosModule:
    """Test CapInfos module functionality."""

    def test_protocol_name(self):
        """Test protocol name property."""
        config = Mock()
        module = CapInfosModule(config)
        assert module.protocol_name == "CapInfos"

    def test_analyze_capinfos_file_not_found(self):
        """Test capinfos when file doesn't exist."""
        config = Config()
        module = CapInfosModule(config)

        result = module.analyze_capinfos("/nonexistent/file.pcap")

        assert "error" in result
        assert "not found" in result["error"]
        assert result["pcap_file"] == "/nonexistent/file.pcap"

    def test_analyze_capinfos(self):
        """Test capinfos with no packets."""

        # Write some packets to the temp file
        packets = [
            IP(src="192.168.0.1", dst="192.168.0.2")
            / TCP(sport=1234, dport=80)
            / Raw(load=b"GET / HTTP/1.1"),
            IP(src="192.168.0.2", dst="192.168.0.1")
            / TCP(sport=80, dport=1234)
            / Raw(load=b"HTTP/1.1 200 OK"),
        ]

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            wrpcap(tmp_file.name, packets)
            temp_path = tmp_file.name

        try:
            config = Config()
            module = CapInfosModule(config)
            result = module.analyze_capinfos(temp_path)

            # Verify results from _generate_statistics
            assert "packet_count" in result
            assert "data_size_bytes" in result
            assert "capture_duration_seconds" in result
            assert "first_packet_time" in result
            assert "last_packet_time" in result
            assert "data_rate_bytes" in result
            assert "data_rate_bits" in result
            assert "average_packet_size_bytes" in result
            assert "average_packet_rate" in result

            # Verify file-only details
            assert "file_size_bytes" in result
            assert "filename" in result
            assert "file_encapsulation" in result

            # verify actual file + packet details
            assert result["file_encapsulation"] == "Raw IPv4"
            assert result["packet_count"] == 2
            assert result["average_packet_size_bytes"] == 54.50

        finally:
            import os

            os.unlink(temp_path)

    def test_analyze_capinfos_unknown_linktype(self):
        """Test capinfos with no packets."""

        # Write some packets to the temp file
        packets = [
            IP(src="192.168.0.1", dst="192.168.0.2")
            / TCP(sport=1234, dport=80)
            / Raw(load=b"GET / HTTP/1.1"),
        ]

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            wrpcap(tmp_file.name, packets, linktype=1024)
            temp_path = tmp_file.name

        try:
            config = Config()
            module = CapInfosModule(config)
            result = module.analyze_capinfos(temp_path)

            # Verify file-only details
            assert "file_encapsulation" in result

            # verify actual file + packet details
            assert result["file_encapsulation"] == "Unknown (1024)"

        finally:
            import os

            os.unlink(temp_path)
