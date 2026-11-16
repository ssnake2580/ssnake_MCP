"""Server smoke tests — FastMCP wiring, baseline tools, profile gating.

These tests construct the FastMCP app via ``asyncio.run`` because
``apply_tool_profile`` reaches into a running event loop. They do not bind
a transport.
"""
from __future__ import annotations

import asyncio

import pytest
from fastmcp import FastMCP

from scapy_mcp.config.settings import ScapySettings
from scapy_mcp.server import build_runtime
from scapy_mcp.tools.profiles import EXPECTED_BASELINE


def _build(settings: ScapySettings) -> FastMCP:
    """Construct the FastMCP app from a sync test."""
    return asyncio.run(build_runtime(settings=settings).build_mcp_app_async())


def _tool_names(app: FastMCP) -> set[str]:
    """FastMCP 3.x ``list_tools`` is async; bridge from sync tests."""
    return {t.name for t in asyncio.run(app.list_tools())}


@pytest.fixture
def settings() -> ScapySettings:
    return ScapySettings(_env_file=None)


def test_app_is_fastmcp_instance() -> None:
    from scapy_mcp.server import get_app

    assert isinstance(_build(ScapySettings(_env_file=None)), FastMCP)


def test_all_four_baseline_tools_registered(settings: ScapySettings) -> None:
    app = _build(settings)
    registered = _tool_names(app)
    assert EXPECTED_BASELINE.issubset(registered), (
        f"missing baseline tools: {EXPECTED_BASELINE - registered}"
    )


def test_standard_profile_unregisters_transmit_tools() -> None:
    """Spec §6.3: transmit is ``full``-only. The decorators always attach
    transmit_packet / probe_packet; the profile gate must explicitly remove
    them when profile != "full".
    """
    settings = ScapySettings(_env_file=None, tool_profile="standard")
    app = _build(settings)
    tools = _tool_names(app)
    assert "transmit_packet" not in tools
    assert "probe_packet" not in tools


def test_build_runtime_returns_runtime(settings: ScapySettings) -> None:
    runtime = build_runtime(settings=settings)
    assert runtime.settings == settings


def test_build_asgi_app_exposes_readyz(settings: ScapySettings) -> None:
    """``build_asgi_app`` registers a ``/readyz`` route. Before any required
    feed cycles succeed it returns 503; after at least one successful
    cycle per required feed it returns 200. This is the wiring-discipline
    ``/readyz`` 503 contract from spec §5.5.
    """
    from scapy_mcp.feeds import FEEDS, required_feeds_healthy

    # Reset required feeds so we are guaranteed a 503.
    for name in ("craft", "dissect", "pcap"):
        FEEDS[name].cycles_total = 0
        FEEDS[name].entities_count = 0
        FEEDS[name].errors_total = 0

    # Cold start: /readyz must report degraded.
    assert required_feeds_healthy() is False

    runtime = build_runtime(settings=settings)
    asgi = runtime.build_asgi_app()
    # The /readyz route is registered via Starlette's ``add_route``.
    assert any(
        getattr(r, "path", None) == "/readyz"
        for r in getattr(asgi, "routes", [])
    )

    # After at least one successful cycle per required feed, /readyz returns 200.
    for name in ("craft", "dissect", "pcap"):
        FEEDS[name].record_cycle(entities=1)
    assert required_feeds_healthy() is True


def test_full_profile_includes_transmit_tools(settings: ScapySettings) -> None:
    """Sanity: ``full`` profile (the default) MUST include transmit tools."""
    settings.tool_profile = "full"
    app = _build(settings)
    names = _tool_names(app)
    assert "transmit_packet" in names
    assert "probe_packet" in names


def test_minimal_profile_only_exposes_health(settings: ScapySettings) -> None:
    settings.tool_profile = "minimal"
    app = _build(settings)
    names = _tool_names(app)
    # Baseline tools survive every profile.
    assert "discover_tools" in names
    assert "get_liveness" in names
    # Domain tools are absent in minimal.
    assert "craft_packet" not in names
    assert "transmit_packet" not in names
