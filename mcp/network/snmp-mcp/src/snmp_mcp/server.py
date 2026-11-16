# Copyright 2026 snmp-mcp contributors
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""MCP server entrypoint.

Wires up the MCP stdio server, registers the 4 generic SNMP primitives +
5 MIB-specific wrappers, and owns the per-host session cache + config
loader.

See DESIGN.md §2 (Architecture) and §5 (Tool Surface).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import oids
from .config import Config, load_config
from .errors import SnmpError
from .mibs.detect import device_detect as _device_detect
from .mibs.host_resources import host_resources as _host_resources
from .mibs.interfaces import interfaces_list as _interfaces_list
from .mibs.printer import printer_status as _printer_status
from .mibs.system import system_info as _system_info
from .session import SessionCache
from .transport import snmp_bulk_walk as _bulk_walk
from .transport import snmp_get as _generic_get
from .transport import snmp_table as _generic_table
from .transport import snmp_walk as _generic_walk

logger = logging.getLogger("snmp_mcp")


@dataclass
class AppContext:
    """Per-process app state passed implicitly to every tool via closure."""

    config: Config
    cache: SessionCache = field(default_factory=SessionCache)


def build_app(config: Config | None = None) -> tuple[FastMCP, AppContext]:
    """Construct the FastMCP server with all 9 tools registered.

    Returns the server + the AppContext so tests can introspect cache state.
    """
    if config is None:
        config = load_config()
    ctx = AppContext(config=config)
    mcp = FastMCP(
        "snmp-mcp",
        instructions=(
            "Vendor-neutral SNMP polling. All tools take a `host` parameter "
            "matching a host defined in `~/.config/snmp-mcp/config.toml` or "
            "via `SNMP_MCP_<HOST>_*` environment variables. v0 exposes 4 "
            "generic SNMP primitives (snmp_get, snmp_walk, snmp_bulk_walk, "
            "snmp_table) and 5 MIB-specific convenience wrappers "
            "(system_info, interfaces_list, host_resources, printer_status, "
            "device_detect). All tools are READ-ONLY: no SET operations."
        ),
    )

    # --- Generic primitives ----------------------------------------------

    @mcp.tool(
        description="Fetch one or more OIDs in a single SNMP GET-Request. "
        "Accepts numeric (e.g. 1.3.6.1.2.1.1.5.0) and a small set of "
        "symbolic forms (e.g. SNMPv2-MIB::sysName.0). Returns a dict "
        "keyed by OID with {value, type} per varbind."
    )
    async def snmp_get(host: str, oids_in: list[str]) -> dict:
        async def run() -> dict:
            resolved = [oids.resolve_oid(o) for o in oids_in]
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _generic_get(session, resolved)
            return {
                "ok": True,
                "host": host,
                "data": result["varbinds"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="Walk an OID subtree via GETNEXT chain. Terminates on "
        "endOfMibView or when the next OID leaves the subtree. Returns a "
        "list of {oid, value, type} rows."
    )
    async def snmp_walk(host: str, root_oid: str) -> dict:
        async def run() -> dict:
            resolved = oids.resolve_oid(root_oid)
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _generic_walk(session, resolved, use_bulk=False)
            return {
                "ok": True,
                "host": host,
                "data": result["rows"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="Walk an OID subtree via GETBULK (SNMPv2c+). Faster than "
        "snmp_walk for large tables; falls back to GETNEXT with a warning "
        "on v1 hosts. max_repetitions defaults to 25."
    )
    async def snmp_bulk_walk(host: str, root_oid: str, max_repetitions: int = 25) -> dict:
        async def run() -> dict:
            resolved = oids.resolve_oid(root_oid)
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _bulk_walk(session, resolved, max_repetitions=max_repetitions)
            return {
                "ok": True,
                "host": host,
                "data": result["rows"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="Walk and tabularize an SNMP table. Returns {table_oid, "
        "rows: [{index, <col_name>: value, ...}, ...]}. Column-name "
        "mapping is best-effort: unknown columns are keyed by numeric OID."
    )
    async def snmp_table(host: str, table_oid: str) -> dict:
        async def run() -> dict:
            resolved = oids.resolve_oid(table_oid)
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _generic_table(session, resolved)
            return {
                "ok": True,
                "host": host,
                "data": {"table_oid": result["table_oid"], "rows": result["rows"]},
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    # --- MIB-specific wrappers -------------------------------------------

    @mcp.tool(
        description="Fetch the SNMPv2-MIB::system group (RFC 3418): "
        "sysDescr, sysObjectID, sysUpTime (centiseconds and seconds), "
        "sysContact, sysName, sysLocation, sysServices."
    )
    async def system_info(host: str) -> dict:
        async def run() -> dict:
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _system_info(session)
            return {
                "ok": True,
                "host": host,
                "data": result["data"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="List network interfaces via IF-MIB (RFC 2863). Merges "
        "ifTable + ifXTable per ifIndex. HC counters (ifHCInOctets / "
        "ifHCOutOctets) are returned alongside 32-bit counters. ifSpeed "
        "saturation at ~4.29 Gbps is handled automatically — ifSpeed_bps "
        "falls back to ifHighSpeed*1e6 with ifSpeed_source='ifHighSpeed' "
        "and a warning."
    )
    async def interfaces_list(host: str) -> dict:
        async def run() -> dict:
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _interfaces_list(session)
            return {
                "ok": True,
                "host": host,
                "data": result["data"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="HOST-RESOURCES-MIB (RFC 2790) summary: CPU load per "
        "core (hrProcessorLoad), memory (hrMemorySize + derived swap), "
        "uptime, process count, and storage table (filesystems + RAM + "
        "swap). Raises 'unsupported' if the agent does not implement the "
        "MIB at all (typical on bare network switches)."
    )
    async def host_resources(host: str) -> dict:
        async def run() -> dict:
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _host_resources(session)
            return {
                "ok": True,
                "host": host,
                "data": result["data"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="PRINTER-MIB (RFC 3805) status: supplies (toner / ink / "
        "drum levels with percent computed when capacity is known), input "
        "trays, output bins, and active alerts. Works across HP, Brother, "
        "Canon, OKI, Epson, Lexmark. Sentinel values (-2 unknown, -3 not "
        "measured) are handled per RFC 3805."
    )
    async def printer_status(host: str) -> dict:
        async def run() -> dict:
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _printer_status(session)
            return {
                "ok": True,
                "host": host,
                "data": result["data"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    @mcp.tool(
        description="Probe which standard MIBs a device implements. Issues "
        "5 GETs (sysObjectID, sysDescr, ifNumber, hrSystemUptime, "
        "prtGeneralPrinterStatus.1.1) and reports a vendor hint (decoded "
        "from the sysObjectID enterprise number) plus a list of "
        "supported_mibs. Useful as a smoke test before calling heavier "
        "tools."
    )
    async def device_detect(host: str) -> dict:
        async def run() -> dict:
            session = ctx.cache.get(ctx.config.get_host(host))
            result = await _device_detect(session)
            return {
                "ok": True,
                "host": host,
                "data": result["data"],
                "warnings": result["warnings"],
            }

        return await _safe(run(), host=host)

    return mcp, ctx


async def _safe(coro: Any, *, host: str) -> dict:
    """Wrap a tool coroutine to convert SnmpError into a structured failure dict."""
    try:
        return await coro
    except SnmpError as exc:
        logger.warning(
            "tool failed: host=%s category=%s msg=%s",
            exc.host,
            exc.category,
            exc.message,
        )
        return {
            "ok": False,
            "host": exc.host or host,
            "data": None,
            "warnings": [],
            "error": exc.to_dict(),
        }


def _configure_logging() -> None:
    level_name = os.environ.get("SNMP_MCP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    # MCP stdio reserves stdout for the JSON-RPC stream — log to stderr only.
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=__import__("sys").stderr,
    )


def main() -> None:
    """Console entrypoint declared in pyproject.toml `[project.scripts]`.

    Starts the MCP stdio server. The MCP client (Claude Code, Claude
    Desktop) spawns this process and speaks JSON-RPC over stdin/stdout.
    """
    _configure_logging()
    mcp, _ctx = build_app()
    mcp.run()


__all__ = ["AppContext", "build_app", "main"]


if __name__ == "__main__":
    main()


def _list_tools() -> str:  # pragma: no cover - debug helper
    import asyncio

    mcp, _ = build_app()
    tools = asyncio.run(mcp.list_tools())
    return json.dumps([t.name for t in tools], indent=2)
