"""Console / ConHost artifact plugin wrappers (consoles, cmdscan).

Both plugins extract forensic data from the Console Host (conhost.exe /
csrss.exe legacy) — the OS subsystem that backs interactive command
shells. ``consoles`` recovers the full screen buffer plus history;
``cmdscan`` is the focused command-history subset.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import cmdscan, consoles

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_consoles(session: Session, no_registry: bool = False) -> dict:
    """Run windows.consoles and return console host buffers / command history.

    no_registry: skip registry-based console signature lookup if True
        (faster, but may miss some console types on newer Windows).
    """
    extra: dict = {}
    if no_registry:
        extra["no_registry"] = True
    treegrid = run_plugin(
        session,
        consoles.Consoles,
        extra_config=extra or None,
    )
    return {"plugin": "consoles", "results": parse_treegrid(treegrid)}


def run_cmdscan(session: Session, no_registry: bool = False) -> dict:
    """Run windows.cmdscan and return command history from console hosts.

    no_registry: skip registry-based console signature lookup if True.
    """
    extra: dict = {}
    if no_registry:
        extra["no_registry"] = True
    treegrid = run_plugin(
        session,
        cmdscan.CmdScan,
        extra_config=extra or None,
    )
    return {"plugin": "cmdscan", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "cmdscan": run_cmdscan,
    "consoles": run_consoles,
}
