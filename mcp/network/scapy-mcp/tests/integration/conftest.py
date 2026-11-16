"""Shared fixtures for the integration suite.

Drives registered tools directly via FastMCP's async dispatch without
spinning up a real transport. Mirrors archive-org-mcp's pattern.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from scapy_mcp.server import build_runtime
from scapy_mcp.config.settings import ScapySettings


async def call_tool(name: str, **kwargs: Any) -> Any:
    """Resolve a registered tool, run it, and unwrap ``ToolResult``.

    FastMCP 3.x wraps tool return values in ``ToolResult`` carrying both
    ``content`` (textual) and ``structured_content`` (typed dict). Tests want
    the structured dict directly; fall back to ``content`` when no
    structured content is present.
    """
    runtime = build_runtime()
    app = await runtime.build_mcp_app_async()
    tools = {t.name: t for t in await app.list_tools()}
    tool = tools[name]
    result = await tool.run(kwargs)
    if getattr(result, "structured_content", None) is not None:
        return result.structured_content
    return result.content


@pytest.fixture
def settings() -> ScapySettings:
    return ScapySettings(_env_file=None)
