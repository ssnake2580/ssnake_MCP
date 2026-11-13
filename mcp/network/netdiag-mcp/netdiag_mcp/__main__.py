"""Entry point for netdiag-mcp."""

import argparse
import asyncio
import os
import sys

from netdiag_mcp import __version__


def main():
    parser = argparse.ArgumentParser(
        description="On-demand network diagnostics MCP Server (dig, ping, mtr, whois, TLS/HTTP checks)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
No required environment variables. Wrapped binaries (dig, ping, mtr, whois)
must be on PATH; missing ones degrade health_check but do not stop the
server, since the other tools (tcp_port_check, http_check, tls_cert_check)
use Python's own socket/ssl/httpx stack and need no external binary.

Optional: NETDIAG_HTTP_AUTH, a JSON object mapping an https URL prefix to the
Authorization header http_get sends under it, e.g.
  NETDIAG_HTTP_AUTH='{"https://reports.example.ac.jp/daily/": "Bearer <token>"}'
""",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--check", action="store_true", help="Verify wrapped binaries are present, then exit")
    args = parser.parse_args()

    if args.version:
        print(f"netdiag-mcp {__version__}")
        sys.exit(0)

    if args.check:
        from netdiag_mcp.server import health_check

        result = health_check()
        print(f"{result['status']} — {result['service']} {result['version']}")
        if result["missing"]:
            print(f"missing binaries: {', '.join(result['missing'])}", file=sys.stderr)
        if result["http_auth"]["error"]:
            print(result["http_auth"]["error"], file=sys.stderr)
        sys.exit(0 if result["status"] == "healthy" else 2)

    from netdiag_mcp.server import mcp

    try:
        mcp.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        os._exit(0)


if __name__ == "__main__":
    main()
