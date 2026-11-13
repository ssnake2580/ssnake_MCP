# CLAUDE.md

## Overview

MCP server wrapping `dig`/`ping`/`mtr`/`whois` and Python's own
`socket`/`ssl`/`httpx` stack for on-demand, single-target network
diagnostics (DNS, ping, traceroute, TCP port checks, HTTP, TLS certs,
WHOIS, ASN/GeoIP lookups). Transport is stdio only. All 9 tools are
read-only — there is no write/mutating tool, no config file, and no
environment variable required (`NETDIAG_HTTP_AUTH` is optional).

## Commands

```bash
uv sync --dev
uv run pytest -v                  # all tests
uv run ruff check .               # lint (gated in CI)
uv run ruff format --check .      # format (gated in CI)
```

## Architecture

- `netdiag_mcp/server.py` — `MCPServer("netdiag-mcp")` with 9 tools plus
  `health_check`. Every tool wraps its call in `try/except (ValueError,
  ToolError)` and returns `f"error: {e}"` instead of raising.
  `_REQUIRED_BINARIES = ("dig", "ping", "mtr", "whois")` — `health_check`
  reports `"degraded"` (not a hard failure) when any is missing from PATH.
- `netdiag_mcp/tools.py` — the actual implementations. `_run(binary, args)`
  is the shared subprocess wrapper (always an argv list, `SUBPROCESS_TIMEOUT
  = 15.0`, raises `ToolError` on missing binary/timeout/nonzero exit with no
  stdout). `tcp_port_check`/`http_check`/`tls_cert_check` don't shell out at
  all — they use `socket`/`ssl`/`httpx` directly, so those three work even
  with none of the four binaries installed. `ping_host` dispatches to
  `ping6` for an IPv6 literal on non-Linux (macOS's `ping` rejects IPv6
  outright; `ping6` has no deadline flag, unlike `ping`'s `-w`/`-t`, so the
  IPv6-on-macOS path relies on `SUBPROCESS_TIMEOUT` alone as a backstop).
  `dns_lookup`/`dnssec_check` map `transport` to dig's `+tls`/`+https` via
  `_DNS_TRANSPORT_FLAGS` — requires BIND 9.18+, an older `dig` rejects the
  flag outright rather than silently falling back to plain DNS.
- `netdiag_mcp/validate.py` — `validate_target()` (hostname/IP shape,
  rejects empty/whitespace/oversized), `validate_port()` (1-65535),
  `clamp()` (bounds a count/cycles argument). Every tool runs its
  target/port/count through one of these before it reaches a subprocess or
  socket call — inputs are LLM-driven and treated as adversarial.
- `netdiag_mcp/__main__.py` — argparse CLI: `--version`, `--check` (reports
  missing binaries, exits non-zero if any are absent), then
  `mcp.run(transport="stdio")`.

## Conventions

- No credential store and no config file. The only environment variable is
  the optional `NETDIAG_HTTP_AUTH` (`netdiag_mcp/http_auth.py`): an https URL
  prefix → `Authorization` value map that `http_get` applies per redirect hop
  after comparing parsed scheme/host/port/path. Never return, log or put the
  value into an error; `health_check` lists prefixes only. Environment only (no
  file), because several instances may run as one user with different access.
- Tests use `mcp.client.stdio.stdio_client` + `mcp.ClientSession` to
  exercise the real MCP protocol (spawns the actual binary, calls
  `list_tools()`/`call_tool()`) in addition to plain unit tests that call
  `netdiag_mcp.tools`/`netdiag_mcp.server` functions directly — the two are
  not redundant, since a protocol-level test catches issues a direct
  function call bypasses entirely (schema mismatches, serialization).
- `nmap`-style multi-host/multi-port scanning is intentionally out of
  scope — every tool takes exactly one target. Don't add a batch/sweep
  parameter to an existing tool as a "convenience"; that's a scope change.
