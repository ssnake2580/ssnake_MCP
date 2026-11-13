"""Service analysis plugin wrappers (svcscan, svclist)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import svclist, svcscan

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_svcscan(session: Session) -> dict:
    """Run windows.svcscan and return Windows services enumerated from services.exe."""
    treegrid = run_plugin(session, svcscan.SvcScan)
    return {"plugin": "svcscan", "results": parse_treegrid(treegrid)}


def run_svclist(session: Session) -> dict:
    """Run windows.svclist and return services walked from the services.exe linked list."""
    treegrid = run_plugin(session, svclist.SvcList)
    return {"plugin": "svclist", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "svcscan": run_svcscan,
    "svclist": run_svclist,
}
