"""Shared scaffolding for SIFT tool wrappers: audited execution + JSON parsing.

Every tool follows the same spine — validate inputs (guardrails) -> run an
allow-listed binary (runner) -> append a chained audit record (audit) -> parse
structured output. This module factors out that spine so each tool stays small,
and so the audit/guardrail guarantees can't be forgotten by an individual tool.
"""

from __future__ import annotations

import json
from typing import Any

from spoor_sift.audit import AuditLog, AuditRecord
from spoor_sift.runner import RawToolResult, ToolResult, ToolRunner


class ToolExecutionError(RuntimeError):
    """An allow-listed binary ran but exited non-zero. The call was still audited."""

    def __init__(self, tool: str, exit_code: int, stderr: str, *, tool_call_id: str):
        super().__init__(f"{tool} failed (exit {exit_code}): {stderr.strip()[:500]}")
        self.tool = tool
        self.exit_code = exit_code
        self.stderr = stderr
        self.tool_call_id = tool_call_id


class ToolOutputError(RuntimeError):
    """A tool succeeded but its output could not be parsed as expected."""

    def __init__(self, tool: str, message: str, *, tool_call_id: str):
        super().__init__(f"{tool}: {message}")
        self.tool = tool
        self.tool_call_id = tool_call_id


def audited_run(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    binary: str,
    args: list[str],
    tool: str,
    audit_args: dict,
) -> tuple[ToolResult, AuditRecord]:
    """Run an allow-listed binary, record it, and raise on failure.

    The call is *always* audited — successes and failures alike — so the trail is
    complete and the supervisor can see (and self-correct from) a failure.
    """
    result = runner.run(binary, args)
    record = audit.append(
        tool=tool, args=audit_args, exit_code=result.exit_code, stdout=result.stdout
    )
    if result.exit_code != 0:
        raise ToolExecutionError(
            tool, result.exit_code, result.stderr, tool_call_id=record.tool_call_id
        )
    return result, record


def audited_run_raw(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    binary: str,
    args: list[str],
    tool: str,
    audit_args: dict,
) -> tuple[RawToolResult, AuditRecord]:
    """``audited_run`` for tools whose stdout is bytes (file content, not text)."""
    result = runner.run_raw(binary, args)
    record = audit.append(
        tool=tool, args=audit_args, exit_code=result.exit_code, stdout=result.stdout
    )
    if result.exit_code != 0:
        raise ToolExecutionError(
            tool, result.exit_code, result.stderr, tool_call_id=record.tool_call_id
        )
    return result, record


def parse_json_output(text: str, *, tool: str, tool_call_id: str) -> Any:
    """Parse a tool's stdout as JSON, or raise a traceable ``ToolOutputError``."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ToolOutputError(
            tool,
            f"expected JSON output, got {len(text)} bytes that did not parse",
            tool_call_id=tool_call_id,
        ) from exc
