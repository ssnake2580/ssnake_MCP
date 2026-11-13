"""The ``spoor-sift`` MCP server.

Exposes the SIFT forensic toolset over stdio — the *same* audited, path-jailed
tool layer the LangGraph agents use (``orchestration.tools.build_tools``), so an
MCP client (Claude Code, an IDE, another agent) gets identical semantics:
structured JSON out, failures returned as readable error dicts, every call on
the hash-chained audit log. Blocking subprocess work is offloaded with
``asyncio.to_thread`` so the event loop stays responsive.

Run:    uv run spoor-sift          (or)   python -m spoor_sift.server
Config: EVIDENCE_ROOT (required), SPOOR_WORKSPACE (optional — enables the
        artifact-producing tools), SPOOR_AUDIT_PATH, SPOOR_TOOL_TIMEOUT (env).
"""

from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path

from langchain_core.tools import BaseTool
from mcp.server.fastmcp import FastMCP

from spoor_sift.audit import AuditLog
from spoor_sift.orchestration.tools import build_tools
from spoor_sift.runner import SubprocessRunner, ToolRunner


def _register(mcp: FastMCP, lc_tool: BaseTool) -> None:
    """Register a StructuredTool's typed function as an async MCP tool.

    The wrapper inherits the original signature (``__signature__`` is honored by
    FastMCP's schema generation), so the MCP input schema carries the same typed,
    optional parameters the LangChain agents see.
    """
    func = lc_tool.func

    async def wrapper(**kwargs):
        return await asyncio.to_thread(func, **kwargs)

    wrapper.__name__ = lc_tool.name
    wrapper.__doc__ = lc_tool.description
    wrapper.__signature__ = inspect.signature(func)
    wrapper.__annotations__ = dict(getattr(func, "__annotations__", {}))
    mcp.tool(name=lc_tool.name, description=lc_tool.description)(wrapper)


def build_server(
    *,
    runner: ToolRunner,
    audit: AuditLog,
    evidence_root: Path | str,
    workspace_root: Path | str | None = None,
) -> FastMCP:
    """Build the MCP server with its dependencies injected (testable + embeddable)."""
    mcp = FastMCP("spoor-sift")
    for tool in build_tools(
        runner=runner, audit=audit,
        evidence_root=Path(evidence_root), workspace_root=workspace_root,
    ):
        _register(mcp, tool)
    return mcp


def build_server_from_env() -> FastMCP:
    """Build the server from environment configuration (the production path)."""
    root = os.environ.get("EVIDENCE_ROOT")
    if not root:
        raise RuntimeError(
            "EVIDENCE_ROOT is not set; point it at the read-only evidence directory"
        )
    workspace = os.environ.get("SPOOR_WORKSPACE")
    if workspace:
        Path(workspace).mkdir(parents=True, exist_ok=True)
    audit_path = os.environ.get("SPOOR_AUDIT_PATH", "runs/audit.jsonl")
    timeout = float(os.environ.get("SPOOR_TOOL_TIMEOUT", "300"))
    return build_server(
        runner=SubprocessRunner(timeout=timeout),
        audit=AuditLog(audit_path),
        evidence_root=Path(root),
        workspace_root=Path(workspace) if workspace else None,
    )


def main() -> None:
    build_server_from_env().run(transport="stdio")


if __name__ == "__main__":
    main()
