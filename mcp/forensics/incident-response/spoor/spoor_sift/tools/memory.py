"""Memory-forensics tools (Volatility 3), returning structured JSON.

Volatility is invoked with its JSON renderer (``-r json``, before the plugin name)
so output is parsed objects, not a wall of stdout. Each tool normalizes Volatility's
verbose column names into a stable schema the agent reasons over. All tools share
``_run_vol_plugin`` so the path-jail + audit guarantees can't be forgotten.
"""

from __future__ import annotations

from pathlib import Path

from spoor_sift.audit import AuditLog, AuditRecord
from spoor_sift.guardrails import resolve_in_root
from spoor_sift.runner import ToolRunner
from spoor_sift.tools.base import audited_run, parse_json_output


def _run_vol_plugin(
    memory_image: str,
    *,
    plugin: str,
    tool: str,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
) -> tuple[list[dict], AuditRecord]:
    """Path-jail the image, run a Volatility plugin (JSON renderer), audit, parse.

    Rows are flattened: real plugin output (notably ``windows.pstree``) nests
    child processes under ``__children`` — every row must surface.
    """
    image = resolve_in_root(evidence_root, memory_image)
    args = ["-f", str(image), "-r", "json", plugin]
    result, record = audited_run(
        runner=runner,
        audit=audit,
        binary="vol",
        args=args,
        tool=tool,
        audit_args={"memory_image": str(image)},
    )
    rows = parse_json_output(result.stdout, tool=tool, tool_call_id=record.tool_call_id)
    return _flatten(rows), record


def _flatten(rows: list[dict]) -> list[dict]:
    flat: list[dict] = []
    stack = list(reversed(rows))
    while stack:
        row = stack.pop()
        flat.append(row)
        stack.extend(reversed(row.get("__children") or []))
    return flat


def _cap(items: list, max_rows: int) -> dict:
    """Server-side row cap (risk R6): bounded BEFORE output reaches the model."""
    return {
        "total_scanned": len(items),
        "truncated": len(items) > max_rows,
        "items": items[:max_rows],
    }


def _normalize_process(row: dict) -> dict:
    return {
        "pid": row.get("PID"),
        "ppid": row.get("PPID"),
        "name": row.get("ImageFileName"),
        "threads": row.get("Threads"),
        "handles": row.get("Handles"),
        "session_id": row.get("SessionId"),
        "wow64": row.get("Wow64"),
        "offset": row.get("Offset(V)"),
        "create_time": row.get("CreateTime"),
        "exit_time": row.get("ExitTime"),
    }


def _normalize_connection(row: dict) -> dict:
    return {
        "proto": row.get("Proto"),
        "local_addr": row.get("LocalAddr"),
        "local_port": row.get("LocalPort"),
        "foreign_addr": row.get("ForeignAddr"),
        "foreign_port": row.get("ForeignPort"),
        "state": row.get("State"),
        "pid": row.get("PID"),
        "owner": row.get("Owner"),
        "created": row.get("Created"),
    }


def _normalize_injection(row: dict) -> dict:
    return {
        "pid": row.get("PID"),
        "process": row.get("Process"),
        "start": row.get("Start VPN") or row.get("Start"),
        "end": row.get("End VPN") or row.get("End"),
        "protection": row.get("Protection"),
        "tag": row.get("Tag"),
    }


def _normalize_cmdline(row: dict) -> dict:
    return {"pid": row.get("PID"), "process": row.get("Process"), "args": row.get("Args")}


def vol_pslist(
    memory_image: str, *, max_rows: int = 500,
    runner: ToolRunner, audit: AuditLog, evidence_root: Path | str,
) -> dict:
    """List processes from a Windows memory image (Volatility 3 ``windows.pslist``)."""
    rows, record = _run_vol_plugin(
        memory_image, plugin="windows.pslist", tool="vol_pslist",
        runner=runner, audit=audit, evidence_root=evidence_root,
    )
    capped = _cap([_normalize_process(r) for r in rows], max_rows)
    return {
        "tool": "vol_pslist",
        "tool_call_id": record.tool_call_id,
        "process_count": len(capped["items"]),
        "total_scanned": capped["total_scanned"],
        "truncated": capped["truncated"],
        "processes": capped["items"],
    }


def vol_pstree(
    memory_image: str, *, max_rows: int = 500,
    runner: ToolRunner, audit: AuditLog, evidence_root: Path | str,
) -> dict:
    """Process tree with parent/child links (Volatility 3 ``windows.pstree``)."""
    rows, record = _run_vol_plugin(
        memory_image, plugin="windows.pstree", tool="vol_pstree",
        runner=runner, audit=audit, evidence_root=evidence_root,
    )
    capped = _cap([_normalize_process(r) for r in rows], max_rows)
    return {
        "tool": "vol_pstree",
        "tool_call_id": record.tool_call_id,
        "process_count": len(capped["items"]),
        "total_scanned": capped["total_scanned"],
        "truncated": capped["truncated"],
        "processes": capped["items"],
    }


def vol_netscan(
    memory_image: str, *, state: str | None = None, max_rows: int = 300,
    runner: ToolRunner, audit: AuditLog, evidence_root: Path | str,
) -> dict:
    """Network connections/sockets from memory (Volatility 3 ``windows.netscan``).

    Pool scanning surfaces the same socket many times and stale sockets by the
    thousand — duplicates collapse, an optional ``state`` filter (e.g.
    ESTABLISHED) applies server-side, and rows are capped before output.
    """
    rows, record = _run_vol_plugin(
        memory_image, plugin="windows.netscan", tool="vol_netscan",
        runner=runner, audit=audit, evidence_root=evidence_root,
    )
    normalized = [_normalize_connection(r) for r in rows]
    seen: set[tuple] = set()
    unique: list[dict] = []
    for conn in normalized:
        key = (conn["proto"], conn["local_addr"], conn["local_port"],
               conn["foreign_addr"], conn["foreign_port"], conn["state"], conn["pid"])
        if key not in seen:
            seen.add(key)
            unique.append(conn)
    if state is not None:
        unique = [c for c in unique if c["state"] == state]
    capped = _cap(unique, max_rows)
    return {
        "tool": "vol_netscan",
        "tool_call_id": record.tool_call_id,
        "connection_count": len(capped["items"]),
        "total_scanned": len(rows),
        "truncated": capped["truncated"],
        "state_filter": state,
        "connections": capped["items"],
    }


def vol_malfind(
    memory_image: str, *, max_rows: int = 200,
    runner: ToolRunner, audit: AuditLog, evidence_root: Path | str,
) -> dict:
    """Injected / hidden code regions (Volatility 3 ``windows.malfind``)."""
    rows, record = _run_vol_plugin(
        memory_image, plugin="windows.malfind", tool="vol_malfind",
        runner=runner, audit=audit, evidence_root=evidence_root,
    )
    capped = _cap([_normalize_injection(r) for r in rows], max_rows)
    return {
        "tool": "vol_malfind",
        "tool_call_id": record.tool_call_id,
        "injection_count": len(capped["items"]),
        "total_scanned": capped["total_scanned"],
        "truncated": capped["truncated"],
        "injections": capped["items"],
    }


def vol_cmdline(
    memory_image: str, *, max_rows: int = 500,
    runner: ToolRunner, audit: AuditLog, evidence_root: Path | str,
) -> dict:
    """Process command-line arguments (Volatility 3 ``windows.cmdline``)."""
    rows, record = _run_vol_plugin(
        memory_image, plugin="windows.cmdline", tool="vol_cmdline",
        runner=runner, audit=audit, evidence_root=evidence_root,
    )
    capped = _cap([_normalize_cmdline(r) for r in rows], max_rows)
    return {
        "tool": "vol_cmdline",
        "tool_call_id": record.tool_call_id,
        "total_scanned": capped["total_scanned"],
        "truncated": capped["truncated"],
        "entries": capped["items"],
    }
