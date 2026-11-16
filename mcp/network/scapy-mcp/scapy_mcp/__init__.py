"""scapy_mcp — MCP server for scapy packet crafting, dissection, capture, and PCAP I/O."""

from __future__ import annotations

from oneiric.core.logging import LoggingConfig, configure_logging

from scapy_mcp.config.settings import get_settings

__version__ = "0.1.1"

# Configure logging once at import time. ``configure_logging`` is idempotent.
configure_logging(
    LoggingConfig(level=get_settings().log_level, service_name="scapy-mcp"),
)
