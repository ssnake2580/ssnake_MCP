"""scapy-mcp CLI entry point.

Runs the FastMCP ASGI app (built by ``Runtime.build_asgi_app``) on the
configured HTTP port via uvicorn so the custom ``/readyz`` route is mounted.
"""

from __future__ import annotations

import uvicorn

from scapy_mcp.config.settings import get_settings
from scapy_mcp.server import build_runtime


def main() -> None:
    settings = get_settings()
    asgi = build_runtime(settings=settings).build_asgi_app()
    port = settings.http_port or 3056
    uvicorn.run(asgi, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
