"""scapy-mcp CLI entry point.

Builds the FastMCP ASGI app via :class:`scapy_mcp.server.Runtime` and
serves it on uvicorn (so the custom ``/readyz`` route is mounted).
Delegates to :func:`scapy_mcp.cli.main`.
"""

from __future__ import annotations

import sys

from scapy_mcp.cli import main as _cli_main


def main() -> int:
    """Entry point declared in pyproject ``[project.scripts]``."""
    _cli_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
