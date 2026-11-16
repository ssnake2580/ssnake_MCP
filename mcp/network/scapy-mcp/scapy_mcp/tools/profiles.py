"""Tool profile registration for scapy-mcp.

Three profiles: ``full`` (default — includes transmit), ``standard`` (no
transmit), ``minimal`` (health only). The ``register_all_tool_groups`` helper
unconditionally attaches every tool; ``apply_tool_profile`` from mcp-common
then prunes groups whose profile does not include them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from fastmcp import FastMCP

    from scapy_mcp.config.settings import ScapySettings

from mcp_common.tools.dispatch import ALL_TOOLS, ToolProfile
from pydantic import TypeAdapter

from scapy_mcp.models.layers import LayerSpec

# `LayerSpec` is the documented runtime import; LayerAdapter keeps the
# discriminated-union construction explicit so TypeAdapter stays out of the
# per-call site. Defined at module load time (not inside the registration
# closures) so every caller observes the same singleton and the E402 trip-wire
# stays clean.
LayerAdapter: TypeAdapter[LayerSpec] = TypeAdapter(LayerSpec)

SCAPY_MANDATORY_GROUPS: set[str] = {"health_tools"}
TRANSMIT_GROUPS: set[str] = {"transmit_tools"}

# Tools that must always be registered regardless of profile. Mirrors the
# mcp-common EXPECTED_BASELINE pattern.
EXPECTED_BASELINE: set[str] = {
    "discover_tools",
    "get_liveness",
    "get_readiness",
    "health_check_all",
}


@dataclass
class ServerBundle:
    settings: ScapySettings


# Stable profile -> group-name list consumed by ``apply_tool_profile``.
# ``_select_profile_groups`` returns ``registrations[profile]`` directly; the
# dispatch then looks up each name in ``registration_map`` and invokes the
# corresponding registration function. Keys must be ``ToolProfile`` enum
# values (NOT strings) so the dispatch's ``registrations.get(ToolProfile.X)``
# lookup is type-correct. Value type mirrors mcp-common's
# ``_apply_tool_profile_async`` parameter signature exactly — ``dict`` is
# invariant in V, so a narrower value type (just ``list[...]``) fails the
# assignability check.
PROFILE_REGISTRATIONS: dict[
    ToolProfile,
    list[str | Callable[[FastMCP], Awaitable[None] | None]] | type[ALL_TOOLS],
] = {
    ToolProfile.FULL: [
        "craft_tools",
        "dissect_tools",
        "pcap_tools",
        "capture_tools",
        "transmit_tools",
        "health_tools",
    ],
    ToolProfile.STANDARD: [
        "craft_tools",
        "dissect_tools",
        "pcap_tools",
        "capture_tools",
        # transmit_tools intentionally omitted — closed-by-default in standard.
        "health_tools",
    ],
    ToolProfile.MINIMAL: [
        "health_tools",
    ],
}


def _build_registration_map(
    bundle: ServerBundle,
) -> dict[str, Callable[[FastMCP], Awaitable[None] | None]]:
    """Each entry is a Callable[[FastMCP], None] bound to the supplied bundle.

    ``_apply_tool_profile_async`` invokes each entry as ``fn(server)``;
    therefore the registration functions MUST take only the server.

    Return type is widened to ``Awaitable[None] | None`` so the dict satisfies
    mcp-common's ``Callable[[FastMCP], Awaitable[None] | None]`` parameter
    exactly — ``dict`` is invariant in V, so ``Callable[..., None]`` alone
    won't be accepted as ``Callable[..., Awaitable[None] | None]``.
    """

    def _register_craft(app: FastMCP) -> None:
        from scapy_mcp.models.packet import PacketSpec
        from scapy_mcp.tools.craft import craft_packet

        @app.tool(name="craft_packet")
        async def _craft_packet(layers: list[dict]) -> dict:
            spec = PacketSpec(layers=[LayerAdapter.validate_python(layer) for layer in layers])
            result = craft_packet(settings=bundle.settings, spec=spec)
            return {
                "summary": result["summary"],
                "layer_count": result["layer_count"],
                "bytes_b64": result["bytes_b64"],
            }

    def _register_dissect(app: FastMCP) -> None:
        from scapy_mcp.tools.dissect import dissect_bytes

        @app.tool(name="dissect_bytes")
        async def _dissect_bytes(data: str, link_type: str = "EN10MB") -> dict:
            return dissect_bytes(settings=bundle.settings, data=data, link_type=link_type)

    def _register_pcap(app: FastMCP) -> None:
        import base64

        from scapy_mcp.tools.pcap import read_pcap, write_pcap

        @app.tool(name="read_pcap")
        async def _read_pcap(path: str, limit: int = 100, offset: int = 0) -> dict:
            return read_pcap(settings=bundle.settings, path=path, limit=limit, offset=offset)

        @app.tool(name="write_pcap")
        async def _write_pcap(filename: str, packets: list[str]) -> dict:
            raw = [base64.b64decode(p) for p in packets]
            return write_pcap(settings=bundle.settings, filename=filename, packets=raw)

    def _register_capture(app: FastMCP) -> None:
        from scapy_mcp.tools.capture import capture_read, capture_start, capture_stop

        @app.tool(name="capture_start")
        async def _capture_start(
            iface: str | None = None,
            bpf_filter: str | None = None,
            packet_cap: int | None = None,
            duration_cap: int | None = None,
        ) -> dict:
            return capture_start(
                settings=bundle.settings,
                iface=iface,
                bpf_filter=bpf_filter,
                packet_cap=packet_cap,
                duration_cap=duration_cap,
            )

        @app.tool(name="capture_stop")
        async def _capture_stop(session_id: str) -> dict:
            return capture_stop(session_id=session_id)

        @app.tool(name="capture_read")
        async def _capture_read(session_id: str) -> dict:
            return capture_read(session_id=session_id)

    def _register_transmit(app: FastMCP) -> None:
        from scapy_mcp.models.packet import PacketSpec
        from scapy_mcp.tools.craft import craft_packet
        from scapy_mcp.tools.transmit import probe_packet, transmit_packet

        @app.tool(name="transmit_packet")
        async def _transmit_packet(packet: dict, iface: str, count: int = 1) -> dict:
            spec = PacketSpec(
                layers=[LayerAdapter.validate_python(layer) for layer in packet["layers"]],
            )
            crafted = craft_packet(settings=bundle.settings, spec=spec)
            return await transmit_packet(
                settings=bundle.settings,
                packet_bytes=crafted["bytes"],
                iface=iface,
                count=count,
            )

        @app.tool(name="probe_packet")
        async def _probe_packet(
            packet: dict,
            iface: str,
            targets: list[str],
            timeout_seconds: float = 2.0,
        ) -> dict:
            spec = PacketSpec(
                layers=[LayerAdapter.validate_python(layer) for layer in packet["layers"]],
            )
            crafted = craft_packet(settings=bundle.settings, spec=spec)
            return await probe_packet(
                settings=bundle.settings,
                packet_bytes=crafted["bytes"],
                iface=iface,
                targets=targets,
                timeout_seconds=timeout_seconds,
            )

    def _register_health(app: FastMCP) -> None:
        from scapy_mcp.feeds import as_components, required_feeds_healthy

        @app.tool(name="health")
        async def _health() -> dict:
            components = as_components()
            return {
                "status": "ok" if required_feeds_healthy() else "degraded",
                "components": components,
            }

    return {
        "craft_tools": _register_craft,
        "dissect_tools": _register_dissect,
        "pcap_tools": _register_pcap,
        "capture_tools": _register_capture,
        "transmit_tools": _register_transmit,
        "health_tools": _register_health,
    }


def register_all_tool_groups(
    app: FastMCP, bundle: ServerBundle
) -> dict[str, Callable[[FastMCP], Awaitable[None] | None]]:
    """Attach every tool group to ``app``; profile gating happens after this."""
    mapping = _build_registration_map(bundle)
    for fn in mapping.values():
        fn(app)
    return mapping
