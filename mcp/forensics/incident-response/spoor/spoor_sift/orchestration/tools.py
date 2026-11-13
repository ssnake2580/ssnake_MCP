"""Adapt the tested SIFT core tools into LangChain tools for the agents.

Dependencies (runner / audit / evidence root / workspace root) are bound at
build time, so the agent calls a plain ``tool(arg=...)`` while every call still
flows through the path-jailed, audited core. Failures — tool errors, jail
escapes, malformed arguments — RETURN as readable error dicts (the failed call
is already on the audit log where it executed), which is what lets the agent
self-correct instead of crashing the graph.

Tools that produce artifacts (extractions, timelines) or read analyst-supplied
rules require a writable workspace; without ``workspace_root`` only the
evidence-only toolset is built.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from langchain_core.tools import BaseTool, StructuredTool

from spoor_sift.audit import AuditLog
from spoor_sift.runner import ToolRunner
from spoor_sift.tools import disk, indicators, memory, registry, timeline
from spoor_sift.tools.base import ToolExecutionError, ToolOutputError

_MEMORY_TOOLS: dict[str, tuple] = {
    "vol_pslist": (memory.vol_pslist, "List processes from a Windows memory image (Volatility 3 windows.pslist)."),
    "vol_pstree": (memory.vol_pstree, "Process tree with parent/child links — spot anomalous parents (windows.pstree)."),
    "vol_malfind": (memory.vol_malfind, "Injected / hidden executable code regions (windows.malfind)."),
    "vol_cmdline": (memory.vol_cmdline, "Process command-line arguments — inspect launch args (windows.cmdline)."),
}

# Bad args and jail escapes come back as data so the agent can reason and retry.
# (PathJailError is a ValueError; plugin/name validation raises ValueError too.)
_SELF_CORRECTABLE = (ToolExecutionError, ToolOutputError, ValueError)


def _call(core: Callable, /, **kwargs) -> dict:
    try:
        return core(**kwargs)
    except _SELF_CORRECTABLE as exc:
        return {
            "error": str(exc),
            "tool_call_id": getattr(exc, "tool_call_id", None),
            "hint": "The call failed (recorded in the audit log where it executed). "
                    "Reason about the cause, adjust arguments, and retry — or use a related tool.",
        }


def build_tools(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str | None = None,
) -> list[BaseTool]:
    """Build the LangChain tool set, each bound to the injected dependencies."""

    # ── memory (evidence only) ──
    def _make_memory_tool(core_fn, name, description) -> BaseTool:
        def mem_fn(memory_image: str) -> dict:
            return _call(core_fn, memory_image=memory_image,
                         runner=runner, audit=audit, evidence_root=evidence_root)

        return StructuredTool.from_function(func=mem_fn, name=name, description=description)

    tools = [
        _make_memory_tool(core_fn, name, description)
        for name, (core_fn, description) in _MEMORY_TOOLS.items()
    ]

    def netscan_fn(memory_image: str, state: str | None = None, max_rows: int = 300) -> dict:
        return _call(memory.vol_netscan, memory_image=memory_image, state=state,
                     max_rows=max_rows, runner=runner, audit=audit,
                     evidence_root=evidence_root)

    tools.append(StructuredTool.from_function(
        func=netscan_fn, name="vol_netscan",
        description="Network connections/sockets from memory — find C2 (windows.netscan). "
                    "Pool scans surface thousands of stale rows: pass state='ESTABLISHED' "
                    "to see live connections first; duplicates are collapsed and rows "
                    "capped server-side.",
    ))

    # ── disk / registry / hashing (evidence only) ──
    def fls_fn(image: str, offset: int | None = None, inode: str | None = None,
               recursive: bool = True) -> dict:
        return _call(disk.tsk_fls, image=image, offset=offset, inode=inode,
                     recursive=recursive, runner=runner, audit=audit,
                     evidence_root=evidence_root)

    tools.append(StructuredTool.from_function(
        func=fls_fn, name="tsk_fls",
        description="List filesystem entries from a disk image, deleted files included "
                    "(Sleuth Kit fls). Use offset for a partition's sector offset; "
                    "inode to list one directory.",
    ))

    def rip_fn(hive: str, plugin: str) -> dict:
        return _call(registry.regripper_run, hive=hive, plugin=plugin,
                     runner=runner, audit=audit, evidence_root=evidence_root,
                     workspace_root=workspace_root)

    tools.append(StructuredTool.from_function(
        func=rip_fn, name="regripper_run",
        description="Run a RegRipper plugin against a registry hive — in evidence or "
                    "extracted into the workspace (e.g. plugin 'run' for autostart "
                    "persistence, 'userassist' for execution history).",
    ))

    def hash_fn(path: str) -> dict:
        return _call(indicators.hash_file, path=path, audit=audit,
                     evidence_root=evidence_root, workspace_root=workspace_root)

    tools.append(StructuredTool.from_function(
        func=hash_fn, name="hash_file",
        description="MD5 + SHA-256 of an evidence file or extracted artifact (computed "
                    "in-process, audited) — fingerprint suspected binaries for IOC lists.",
    ))

    if workspace_root is None:
        return tools

    # ── workspace-dependent: extraction, scanning, timelines ──
    def icat_fn(image: str, inode: str, output_name: str, offset: int | None = None) -> dict:
        return _call(disk.tsk_icat, image=image, inode=inode, output_name=output_name,
                     offset=offset, runner=runner, audit=audit,
                     evidence_root=evidence_root, workspace_root=workspace_root)

    tools.append(StructuredTool.from_function(
        func=icat_fn, name="tsk_icat",
        description="Extract a file from a disk image by inode into the analyst workspace "
                    "(Sleuth Kit icat); returns its SHA-256 — custody sealed at extraction.",
    ))

    def yara_fn(rules_path: str, target: str) -> dict:
        return _call(indicators.yara_scan, rules_path=rules_path, target=target,
                     runner=runner, audit=audit,
                     evidence_root=evidence_root, workspace_root=workspace_root)

    tools.append(StructuredTool.from_function(
        func=yara_fn, name="yara_scan",
        description="Scan an evidence file/dir — or an artifact extracted into the "
                    "workspace (e.g. tsk_icat's extracted_to path) — with YARA rules "
                    "from the workspace; returns matching rule names per path.",
    ))

    def l2t_fn(source: str, plaso_name: str) -> dict:
        return _call(timeline.log2timeline_run, source=source, plaso_name=plaso_name,
                     runner=runner, audit=audit,
                     evidence_root=evidence_root, workspace_root=workspace_root)

    tools.append(StructuredTool.from_function(
        func=l2t_fn, name="log2timeline_run",
        description="Build a plaso super-timeline from an evidence source into the "
                    "workspace (name must end .plaso). Run ONCE per source, then slice "
                    "with psort_query.",
    ))

    def psort_fn(plaso_name: str, filter_expr: str | None = None, max_events: int = 200) -> dict:
        return _call(timeline.psort_query, plaso_name=plaso_name, filter_expr=filter_expr,
                     max_events=max_events, runner=runner, audit=audit,
                     workspace_root=workspace_root)

    tools.append(StructuredTool.from_function(
        func=psort_fn, name="psort_query",
        description="Slice a built .plaso super-timeline (optional plaso filter "
                    "expression, e.g. \"date > '2020-09-19 02:00:00'\"); events are "
                    "capped server-side.",
    ))

    return tools
