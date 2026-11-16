# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Smoke tests for the FastMCP server bootstrap."""

from __future__ import annotations

from snmp_mcp.server import build_app


async def test_build_app_registers_all_nine_tools(test_config) -> None:
    mcp, ctx = build_app(config=test_config)
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    expected = {
        # generic primitives
        "snmp_get",
        "snmp_walk",
        "snmp_bulk_walk",
        "snmp_table",
        # MIB-specific wrappers
        "system_info",
        "interfaces_list",
        "host_resources",
        "printer_status",
        "device_detect",
    }
    assert expected.issubset(names), f"missing: {expected - names}"
    # AppContext carries the config and a fresh cache.
    assert ctx.config is test_config
    assert len(ctx.cache.sessions) == 0
