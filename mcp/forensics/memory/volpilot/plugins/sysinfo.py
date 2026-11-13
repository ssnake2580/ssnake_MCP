"""System information plugin wrappers (info, statistics, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import crashinfo, info, statistics

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_info(session: Session) -> dict:
    """Run windows.info and return system information."""
    treegrid = run_plugin(session, info.Info)
    results = {}
    for row in parse_treegrid(treegrid):
        results[row["Variable"]] = row["Value"]
    return {"plugin": "info", "results": results}


def run_statistics(session: Session) -> dict:
    """Run windows.statistics and return memory space statistics."""
    treegrid = run_plugin(session, statistics.Statistics)
    return {"plugin": "statistics", "results": parse_treegrid(treegrid)}


def run_crashinfo(session: Session) -> dict:
    """Run windows.crashinfo and return crash dump header information.

    Only produces data when the image is an actual Windows crash dump
    (.dmp), not a raw/VM memory snapshot. volatility3's own plugin has a
    bug on that path: it logs "This plugin requires a Windows crash
    dump" and then executes a bare ``raise`` outside any except block,
    which Python turns into ``RuntimeError("No active exception to
    reraise")`` instead of returning cleanly. Caught here and translated
    into an empty result, matching how sibling tools (svclist, consoles,
    truecrypt, ...) report "not applicable to this image" without
    crashing the MCP call.
    """
    try:
        treegrid = run_plugin(session, crashinfo.Crashinfo)
    except RuntimeError as e:
        if "No active exception to reraise" in str(e):
            return {"plugin": "crashinfo", "results": []}
        raise
    return {"plugin": "crashinfo", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "crashinfo": run_crashinfo,
    "info": run_info,
    "statistics": run_statistics,
}
