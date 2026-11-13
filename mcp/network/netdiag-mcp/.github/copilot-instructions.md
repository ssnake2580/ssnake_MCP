# Copilot review instructions — netdiag-mcp

This repo is a stdio MCP server ([MCPServer](https://github.com/modelcontextprotocol/python-sdk))
wrapping `dig`/`ping`/`mtr`/`whois` and Python's own `socket`/`ssl`/`httpx`
stack for on-demand, single-target network diagnostics. All 9 tools are
read-only — there is no write/mutating tool in this server, and no
approval-gate or write-tool allowlist to worry about.

## What to flag

- **Any `subprocess` call that isn't an argv list.** `netdiag_mcp/tools.py`'s
  `_run()` always calls `subprocess.run([binary, *args], ...)` — never
  `shell=True`, never a formatted/interpolated shell string. Tool arguments
  are LLM-driven and must be treated as adversarial; a new tool that shells
  out any other way is a command-injection risk regardless of how the
  argument looks "safe" at a glance.
- **Missing input validation on a new tool.** Every tool validates its
  target through `validate.py`'s `validate_target()` (hostname/IP shape
  check, rejects whitespace/empty/oversized input), `validate_port()`
  (1-65535), or `clamp()` (bounds a count/cycles argument) before it
  reaches a subprocess or socket call. A new tool that accepts a
  host/port/count argument without running it through one of these is a
  gap — the validation exists specifically because size/count bounds
  matter (e.g. an unbounded ping count) even though escaping is already
  handled by the argv-list discipline above.
- **A new tool that isn't single-target.** This server is deliberately
  scoped to one host/port/domain per call — no batch, sweep, or range
  argument (see `tcp_port_check`'s single `host, port` signature as the
  pattern). A PR adding multi-target or scan-style behavior (nmap-style
  sweeping) is a scope change that needs explicit sign-off, not something
  to wave through as a normal feature addition.
- **Silent behavior differences across dig versions.** `dns_lookup`'s
  `transport="dot"/"doh"` relies on an older `dig` rejecting `+tls`/`+https`
  outright (exit 1) rather than silently falling back to plain DNS. Don't
  suggest "gracefully falling back" here — that would turn a loud, correct
  failure into a tool that claims to have checked over an encrypted
  transport when it didn't.
- **`server.py` tool wrappers that don't catch `(ValueError, ToolError)`.**
  Every `@mcp.tool()` function in `server.py` catches these two and returns
  an `"error: ..."` string instead of raising, so a caller always gets a
  string back rather than an MCP-level exception. A new tool that lets one
  of these propagate uncaught is inconsistent with the rest of the file.
- **New system dependencies not reflected in `health_check`/README.** If a
  new tool shells out to a binary other than `dig`/`ping`/`mtr`/`whois`,
  `_REQUIRED_BINARIES` in `server.py` (and the setup section of both
  READMEs) needs updating, or `health_check` will misreport server health.

- The optional `NETDIAG_HTTP_AUTH` (`netdiag_mcp/http_auth.py`) carries
  credentials. Flag any change that could return, log or put a header value
  into an error or `health_check`; that attaches it by raw string prefix
  instead of parsed scheme/host/port/path; that sends it over plain http; or
  that sets it on the `httpx.Client` instead of per redirect hop.

## Not a concern here

- No config files or local credential store; the only environment variable is
  the optional `NETDIAG_HTTP_AUTH` above.
- No write/mutating tools, so there is no approval-gate or write-tool
  allowlist pattern (unlike some other servers in this fleet) to check.
