"""Registry analysis plugin wrappers (hivelist, hivescan, printkey, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows.registry import amcache, certificates, getcellroutine, hivelist, hivescan, printkey, scheduled_tasks, userassist

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session

# hashdump/lsadump/cachedump hard-import pycryptodome (Crypto/Cryptodome) at
# module load time with no further fallback, so importing them without the
# `full` extra installed raises ModuleNotFoundError. Guard it so the rest of
# the registry tools stay available on a minimal install.
try:
    from volatility3.plugins.windows.registry import cachedump, hashdump, lsadump

    _HAS_PYCRYPTODOME = True
except ImportError:
    _HAS_PYCRYPTODOME = False


def run_hivelist(session: Session) -> dict:
    """Run windows.registry.hivelist and return loaded registry hives."""
    treegrid = run_plugin(session, hivelist.HiveList)
    return {"plugin": "registry.hivelist", "results": parse_treegrid(treegrid)}


def run_hivescan(session: Session) -> dict:
    """Run windows.registry.hivescan and return hives found by pool scanning."""
    treegrid = run_plugin(session, hivescan.HiveScan)
    return {"plugin": "registry.hivescan", "results": parse_treegrid(treegrid)}


def run_userassist(session: Session) -> dict:
    """Run windows.registry.userassist and return UserAssist data."""
    treegrid = run_plugin(session, userassist.UserAssist)
    return {"plugin": "registry.userassist", "results": parse_treegrid(treegrid)}


def run_printkey(session: Session) -> dict:
    """Run windows.registry.printkey and return registry keys and values."""
    treegrid = run_plugin(session, printkey.PrintKey)
    return {"plugin": "registry.printkey", "results": parse_treegrid(treegrid)}


def run_certificates(session: Session) -> dict:
    """Run windows.registry.certificates and return certificate store entries."""
    treegrid = run_plugin(session, certificates.Certificates)
    return {"plugin": "registry.certificates", "results": parse_treegrid(treegrid)}


def run_scheduled_tasks(session: Session) -> dict:
    """Run windows.registry.scheduled_tasks and return scheduled task entries."""
    treegrid = run_plugin(session, scheduled_tasks.ScheduledTasks)
    return {"plugin": "registry.scheduled_tasks", "results": parse_treegrid(treegrid)}


def run_getcellroutine(session: Session) -> dict:
    """Run windows.registry.getcellroutine and return hives with hooked GetCellRoutine handlers."""
    treegrid = run_plugin(session, getcellroutine.GetCellRoutine)
    return {"plugin": "registry.getcellroutine", "results": parse_treegrid(treegrid)}


def run_amcache(session: Session) -> dict:
    """Run windows.registry.amcache and return AmCache application execution records."""
    treegrid = run_plugin(session, amcache.Amcache)
    return {"plugin": "registry.amcache", "results": parse_treegrid(treegrid)}


if _HAS_PYCRYPTODOME:

    def run_hashdump(session: Session) -> dict:
        """Run windows.registry.hashdump and return LM/NT password hashes.

        Requires the optional `pycryptodome` dependency (install with the
        `full` extra: `uv pip install -e .[full]`).
        """
        treegrid = run_plugin(session, hashdump.Hashdump)
        return {"plugin": "registry.hashdump", "results": parse_treegrid(treegrid)}

    def run_lsadump(session: Session) -> dict:
        """Run windows.registry.lsadump and return decrypted LSA secrets.

        Requires the optional `pycryptodome` dependency.
        """
        treegrid = run_plugin(session, lsadump.Lsadump)
        return {"plugin": "registry.lsadump", "results": parse_treegrid(treegrid)}

    def run_cachedump(session: Session) -> dict:
        """Run windows.registry.cachedump and return cached domain credentials.

        Requires the optional `pycryptodome` dependency.
        """
        treegrid = run_plugin(session, cachedump.Cachedump)
        return {"plugin": "registry.cachedump", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "registry.amcache": run_amcache,
    "registry.certificates": run_certificates,
    "registry.getcellroutine": run_getcellroutine,
    "registry.hivelist": run_hivelist,
    "registry.hivescan": run_hivescan,
    "registry.printkey": run_printkey,
    "registry.scheduled_tasks": run_scheduled_tasks,
    "registry.userassist": run_userassist,
}

if _HAS_PYCRYPTODOME:
    PLUGIN_MAP.update(
        {
            "registry.cachedump": run_cachedump,
            "registry.hashdump": run_hashdump,
            "registry.lsadump": run_lsadump,
        }
    )
