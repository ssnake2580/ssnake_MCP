"""Timeline tools (plaso): build the super-timeline, slice it server-side.

The senior-analyst progression is build-once, pivot-many: ``log2timeline_run``
produces the ``.plaso`` store in the writable workspace (evidence stays
read-only), then ``psort_query`` slices it with a filter and a hard event cap —
the slice is bounded BEFORE it reaches the model, so a million-event timeline
cannot blow the context window (risk R6).
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from spoor_sift.audit import AuditLog
from spoor_sift.guardrails import resolve_in_root
from spoor_sift.runner import ToolRunner
from spoor_sift.tools.base import audited_run

_EVENT_FIELDS = ("datetime", "timestamp_desc", "source", "message", "parser", "display_name", "tag")


def log2timeline_run(
    source: str,
    plaso_name: str,
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str,
) -> dict:
    """Build a plaso super-timeline from an evidence source into the workspace."""
    if not plaso_name.endswith(".plaso"):
        raise ValueError(
            f"plaso_name must end with .plaso, got {plaso_name!r} — e.g. 'case001.plaso'"
        )
    source_path = resolve_in_root(evidence_root, source)
    storage = resolve_in_root(workspace_root, plaso_name)
    result, record = audited_run(
        runner=runner,
        audit=audit,
        binary="log2timeline.py",
        args=["--storage-file", str(storage), str(source_path)],
        tool="log2timeline_run",
        audit_args={"source": str(source_path), "plaso_file": str(storage)},
    )
    return {
        "tool": "log2timeline_run",
        "tool_call_id": record.tool_call_id,
        "plaso_file": str(storage),
        "source": str(source_path),
        "status": "built",
    }


def psort_query(
    plaso_name: str,
    *,
    filter_expr: str | None = None,
    max_events: int = 200,
    runner: ToolRunner,
    audit: AuditLog,
    workspace_root: Path | str,
) -> dict:
    """Slice a .plaso store (``psort`` dynamic output) into normalized events."""
    storage = resolve_in_root(workspace_root, plaso_name)
    args = ["-q", "-o", "dynamic", str(storage)]
    if filter_expr:
        args.append(filter_expr)
    result, record = audited_run(
        runner=runner,
        audit=audit,
        binary="psort.py",
        args=args,
        tool="psort_query",
        audit_args={"plaso_file": str(storage), "filter": filter_expr, "max_events": max_events},
    )
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    events = [
        {field: row.get(field) for field in _EVENT_FIELDS} for row in rows[:max_events]
    ]
    return {
        "tool": "psort_query",
        "tool_call_id": record.tool_call_id,
        "event_count": len(events),
        "total_parsed": len(rows),
        "truncated": len(rows) > len(events),
        "events": events,
    }
