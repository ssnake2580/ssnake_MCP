"""CapInfos analysis module."""

import os
from typing import Any

from fastmcp import FastMCP
from scapy.all import PcapReader, rdpcap

from .base import BaseModule


class CapInfosModule(BaseModule):
    """Module for gathering metadata about capture files."""

    @property
    def protocol_name(self) -> str:
        """Return the name of the protocol this module analyzes."""
        return "CapInfos"

    def analyze_capinfos(self, pcap_file: str) -> dict[str, Any]:
        """
        Return metadata from a PCAP file, similar to Wireshark's capinfos utility.

        IMPORTANT: This tool expects a FILE PATH or URL, not file content.
        - For local files: "/path/to/capture.pcap"
        - For remote files: "https://example.com/capture.pcap"
        - File uploads are NOT supported - save the file locally first

        Args:
            pcap_file: Path to local PCAP file or HTTP URL to remote PCAP file
                      (NOT file content - must be a path or URL)

        Returns:
            A structured dictionary containing PCAP metadata including:
            - File information (size, name, encapsulation type)
            - Packet statistics (count, data size, average sizes)
            - Temporal data (duration, timestamps, rates)
        """
        return self.analyze_packets(pcap_file)

    def _analyze_protocol_file(self, pcap_file: str) -> dict[str, Any]:
        """Perform the actual information gathering on a local PCAP file."""
        try:
            packets = rdpcap(pcap_file)

            # Generate statistics
            stats = self._generate_statistics(packets)

            results = {
                "file_size_bytes": os.path.getsize(pcap_file),
                "filename": os.path.basename(pcap_file),
                "file_encapsulation": self._detect_linktype(pcap_file),
            }

            return results | stats

        except Exception as e:
            return {
                "error": f"Error reading PCAP file '{pcap_file}': {str(e)}",
                "file": pcap_file,
            }

    def _detect_linktype(self, path: str) -> str:
        """Detect the linktype and try to map it to a human-readable encapsulation type.

        Args:
            path: Path to the packet capture

        Returns:
            Detected link-layer header (linktype)

        """
        # mapping based on pcap-linktype(7) and https://github.com/wireshark/wireshark/blob/master/wiretap/wtap.c#L656
        LINKTYPE_MAP = {
            1: "Ethernet",
            101: "Raw IP",
            105: "IEEE 802.11 Wireless LAN",
            113: "Linux cooked-mode capture v1",
            228: "Raw IPv4",
            229: "Raw IPv6",
            276: "Linux cooked-mode capture v2",
        }
        try:
            with PcapReader(path) as reader:
                linktype = getattr(reader, "linktype", None)
        except Exception:
            linktype = None

        return LINKTYPE_MAP.get(
            linktype, f"Unknown ({linktype})" if linktype else "Unknown"
        )

    def _generate_statistics(self, packet_details: list) -> dict[str, Any]:
        """Return metadata about the capture file, similar to capinfos(1) utility."""
        if not packet_details:
            return {"error": "No packets found"}

        packet_count = len(packet_details)
        data_size = sum(len(pkt) for pkt in packet_details)
        first_time = float(packet_details[0].time)
        last_time = float(packet_details[-1].time)
        duration = max(last_time - first_time, 0.000001)
        data_byte_rate = data_size / duration if duration > 0 else 0
        data_bit_rate = (data_size * 8) / duration if duration > 0 else 0
        avg_packet_size = data_size / packet_count if packet_count > 0 else 0
        avg_packet_rate = packet_count / duration if duration > 0 else 0

        return {
            "packet_count": packet_count,
            "data_size_bytes": data_size,
            "capture_duration_seconds": duration,
            "first_packet_time": first_time,
            "last_packet_time": last_time,
            "data_rate_bytes": data_byte_rate,
            "data_rate_bits": data_bit_rate,
            "average_packet_size_bytes": avg_packet_size,
            "average_packet_rate": avg_packet_rate,
        }

    def setup_prompts(self, mcp: FastMCP) -> None:
        """Set up prompts for the MCP server.

        Args:
            mcp: FastMCP server instance
        """
        pass
