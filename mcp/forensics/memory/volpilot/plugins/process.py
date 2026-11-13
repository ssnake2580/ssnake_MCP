"""Process analysis plugin wrappers (pslist, psscan, pstree, ...)."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from volatility3.plugins.windows import cmdline, envars, getsids, handles, joblinks, orphan_kernel_threads, privileges, pslist, psscan, pstree, sessions, suspended_threads, thrdscan, threads

from plugins._common import _serialize_value, parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_pslist(session: Session) -> dict:
    """Run windows.pslist and return structured process list."""
    treegrid = run_plugin(session, pslist.PsList)
    return {"plugin": "pslist", "results": parse_treegrid(treegrid)}


def run_psscan(session: Session) -> dict:
    """Run windows.psscan and return process list found by pool scanning."""
    treegrid = run_plugin(session, psscan.PsScan)
    return {"plugin": "psscan", "results": parse_treegrid(treegrid)}


def run_pstree(session: Session) -> dict:
    """Run windows.pstree and return process tree with depth info."""
    treegrid = run_plugin(session, pstree.PsTree)
    col_names = [col.name for col in treegrid.columns]
    rows: list[dict[str, Any]] = []

    def visitor(node, accumulator):
        row = {
            name: _serialize_value(node.values[i])
            for i, name in enumerate(col_names)
        }
        row["depth"] = node.path_depth
        accumulator.append(row)
        return accumulator

    treegrid.populate(visitor, rows)
    return {"plugin": "pstree", "results": rows}


def run_cmdline(session: Session) -> dict:
    """Run windows.cmdline and return process command line arguments."""
    treegrid = run_plugin(session, cmdline.CmdLine)
    return {"plugin": "cmdline", "results": parse_treegrid(treegrid)}


def run_envars(session: Session) -> dict:
    """Run windows.envars and return process environment variables."""
    treegrid = run_plugin(session, envars.Envars)
    return {"plugin": "envars", "results": parse_treegrid(treegrid)}


def run_getsids(session: Session) -> dict:
    """Run windows.getsids and return SIDs for each process."""
    treegrid = run_plugin(session, getsids.GetSIDs)
    return {"plugin": "getsids", "results": parse_treegrid(treegrid)}


def run_handles(session: Session) -> dict:
    """Run windows.handles and return process open handles."""
    treegrid = run_plugin(session, handles.Handles)
    return {"plugin": "handles", "results": parse_treegrid(treegrid)}


def run_joblinks(session: Session) -> dict:
    """Run windows.joblinks and return process job link information."""
    treegrid = run_plugin(session, joblinks.JobLinks)
    return {"plugin": "joblinks", "results": parse_treegrid(treegrid)}


def run_privileges(session: Session) -> dict:
    """Run windows.privileges and return process token privileges."""
    treegrid = run_plugin(session, privileges.Privs)
    return {"plugin": "privileges", "results": parse_treegrid(treegrid)}


def run_thrdscan(session: Session) -> dict:
    """Run windows.thrdscan and return thread scan results."""
    treegrid = run_plugin(session, thrdscan.ThrdScan)
    return {"plugin": "thrdscan", "results": parse_treegrid(treegrid)}


def run_threads(session: Session) -> dict:
    """Run windows.threads and return threads walked from process thread lists."""
    treegrid = run_plugin(session, threads.Threads)
    return {"plugin": "threads", "results": parse_treegrid(treegrid)}


def run_orphan_kernel_threads(session: Session) -> dict:
    """Run windows.orphan_kernel_threads and return kernel threads not mapped to any module."""
    treegrid = run_plugin(session, orphan_kernel_threads.Threads)
    return {"plugin": "orphan_kernel_threads", "results": parse_treegrid(treegrid)}


def run_suspended_threads(session: Session) -> dict:
    """Run windows.suspended_threads and return userland threads left in a suspended state."""
    treegrid = run_plugin(session, suspended_threads.SuspendedThreads)
    return {"plugin": "suspended_threads", "results": parse_treegrid(treegrid)}


def run_sessions(session: Session) -> dict:
    """Run windows.sessions and return processes with session information."""
    treegrid = run_plugin(session, sessions.Sessions)
    return {"plugin": "sessions", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "cmdline": run_cmdline,
    "envars": run_envars,
    "getsids": run_getsids,
    "handles": run_handles,
    "joblinks": run_joblinks,
    "privileges": run_privileges,
    "sessions": run_sessions,
    "thrdscan": run_thrdscan,
    "threads": run_threads,
    "orphan_kernel_threads": run_orphan_kernel_threads,
    "suspended_threads": run_suspended_threads,
    "pslist": run_pslist,
    "psscan": run_psscan,
    "pstree": run_pstree,
}
