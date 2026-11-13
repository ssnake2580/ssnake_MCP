"""Registry tool: RegRipper plugins against a hive file.

RegRipper output is human-oriented text by design (every plugin formats its own
report), so the envelope is structured but the body is verbatim text the agent
reads — persistence keys, autostarts, recent activity. The hive is path-jailed;
the plugin name is validated for fail-fast errors (argv-list execution already
makes injection impossible by construction).
"""

from __future__ import annotations

import re
from pathlib import Path

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import resolve_readable
from spoor_sift.runner import ToolRunner
from spoor_sift.tools.base import audited_run

_PLUGIN_NAME = re.compile(r"^[a-z0-9_]{1,64}$")


def regripper_run(
    hive: str,
    plugin: str,
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str | None = None,
) -> dict:
    """Run a RegRipper plugin (e.g. ``run``, ``userassist``) against a hive.

    The hive may sit in the evidence tree (mounted/logical evidence) or be an
    artifact extracted into the workspace (icat'd from a disk image).
    """
    if not _PLUGIN_NAME.match(plugin):
        raise ValueError(
            f"invalid RegRipper plugin name {plugin!r}: expected lowercase letters, "
            "digits, or underscores (e.g. 'run', 'userassist')"
        )
    hive_path = resolve_readable(hive, evidence_root=evidence_root, workspace_root=workspace_root)
    result, record = audited_run(
        runner=runner,
        audit=audit,
        binary="rip.pl",
        args=["-r", str(hive_path), "-p", plugin],
        tool="regripper_run",
        audit_args={"hive": str(hive_path), "plugin": plugin},
    )
    return {
        "tool": "regripper_run",
        "tool_call_id": record.tool_call_id,
        "hive": str(hive_path),
        "plugin": plugin,
        "text": result.stdout,
    }
