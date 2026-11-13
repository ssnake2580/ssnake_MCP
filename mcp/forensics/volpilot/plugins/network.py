"""Network analysis plugin wrappers (netscan, netstat)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import netscan, netstat

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_netscan(session: Session) -> dict:
    """Run windows.netscan and return network connections by pool scanning."""
    treegrid = run_plugin(session, netscan.NetScan)
    return {"plugin": "netscan", "results": parse_treegrid(treegrid)}


def run_netstat(session: Session) -> dict:
    """Run windows.netstat and return network connections via kernel structures."""
    treegrid = run_plugin(session, netstat.NetStat)
    return {"plugin": "netstat", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "netscan": run_netscan,
    "netstat": run_netstat,
}
