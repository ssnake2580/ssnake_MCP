<!-- mcp-name: io.github.shigechika/netdiag-mcp -->

# netdiag-mcp

English | [日本語](README.ja.md)

MCP server for on-demand network diagnostics — DNS lookups (with a DNSSEC AD-bit check), ping, an `mtr`-based path report, TCP port checks, HTTP status/redirect checks, TLS certificate inspection, and WHOIS, all from one server.

Built for triaging "can't reach X" / "is DNS propagated yet" reports without shelling into a jump host for each one-off `dig`/`ping`/`curl`.

## Tools

| Tool | Purpose |
|---|---|
| `dns_lookup` | Resolve a DNS record via `dig` (A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA), optionally against a specific resolver and over plain DNS/DoT/DoH |
| `dnssec_check` | Query a known-validating resolver and report whether the AD bit is set (plain/DoT/DoH) — the only reliable way to confirm DNSSEC validation, since an RRSIG being present in a plain `dig` reply does not by itself prove anything validated it |
| `ping_host` | ICMP ping (count clamped to 1-10) |
| `traceroute_path` | Hop-by-hop path/loss report via `mtr --report` (fixed cycles, not a live/continuous run) |
| `tcp_port_check` | Is a TCP port open — a plain socket connect, not a port scan |
| `http_check` | HEAD/GET a URL and report status, redirect chain, and latency |
| `http_get` | GET a URL and return the body. Textual types only (`text/*`, JSON, XML, JavaScript, YAML, `+json`/`+xml`), capped at 1 MiB. Refuses loopback, link-local and cloud-metadata destinations, including via redirect |
| `tls_cert_check` | Fetch the certificate a host presents and report subject/issuer/validity/SANs |
| `whois_lookup` | WHOIS lookup for a domain |
| `asn_lookup` | ASN + country-code lookup for an IP, or org info for an AS number, via Team Cymru's whois service — no API key or GeoIP database needed |
| `current_time` | Current date, time and weekday in an IANA timezone — the weekday is returned as data because deriving it from a date is arithmetic that fails silently. Also reports UTC and epoch, so it doubles as a clock check |
| `health_check` | Version and which wrapped binaries (`dig`/`ping`/`mtr`/`whois`) are present on PATH |

All tools are read-only and single-target (no batch/sweep mode) — this is a
convenience wrapper around checks an operator would run by hand, not a
scanning tool. `nmap`-style multi-host/multi-port scanning is intentionally
out of scope; deliberately probing many hosts or ports is a different,
higher-blast-radius action that deserves its own tooling and approval flow.

`tcp_port_check`, `http_check`, `http_get` and `tls_cert_check` use Python's
own socket/ssl/httpx stack rather than shelling out to `nc`/`curl`/`openssl`,
so those four tools work even on a host with only the `dig`/`ping`/`mtr`/`whois`
binaries installed (or none of them — `health_check` reports which are
missing without failing the whole server).

`dns_lookup`/`dnssec_check` support DNS-over-TLS and DNS-over-HTTPS via
`transport="dot"`/`"doh"` (dig's `+tls`/`+https`). This needs `dig` from
BIND 9.18+ — an older `dig` rejects the flag outright rather than silently
falling back to plain DNS, so a stale binary fails loudly instead of giving
a false sense of having checked over an encrypted transport.

`tls_cert_check`/`http_check` against a bare IP address can fail TLS
handshake with a "handshake failure" or similar error on SNI-hosted /
CDN-fronted origins (e.g. behind Cloudflare) — TLS's SNI extension only
carries hostnames, so an IP literal can't route to the right certificate on
a shared edge. This is normal TLS behavior, not a tool bug; check by
hostname when the target is CDN-fronted.

## Setup

### 1. System dependencies

`dns_lookup`, `dnssec_check`, `ping_host`, `traceroute_path` and
`whois_lookup` shell out to `dig`, `ping`, `mtr` and `whois` respectively.
Install whichever of these you want available:

```bash
# Debian/Ubuntu
sudo apt install dnsutils iputils-ping mtr-tiny whois
```

`mtr` needs raw-socket access. Debian/Ubuntu's `mtr-tiny` package grants
`cap_net_raw` to the `mtr-packet` helper at install time, so it normally
works for an unprivileged service user without further setup — verify with
`getcap "$(command -v mtr-packet)"` if `traceroute_path` reports a socket
permission error. Without that capability, `traceroute_path` fails cleanly
with a `ToolError` rather than crashing the server.

### 2. Install

```bash
pip install netdiag-mcp
# or
uv tool install netdiag-mcp
```

### 3. Claude Code (plugin)

This repository doubles as a single-plugin marketplace, so Claude Code can install
the server for you:

```
/plugin marketplace add shigechika/netdiag-mcp
/plugin install netdiag-mcp@netdiag-mcp
```

The plugin launches `uvx netdiag-mcp`. No environment variables are required — the
only prerequisite is the system dependencies above, and the TCP, HTTP and TLS
checks work even without them.

`uvx` must be on the `PATH` of the process that runs Claude Code — a login
shell usually has it, but a GUI-launched app may not; install
[uv](https://docs.astral.sh/uv/) system-wide if the plugin fails to start.

### 4. Claude Code (manual)

```bash
claude mcp add netdiag -- netdiag-mcp
```

No environment variables are required.

### 5. Codex

```bash
codex mcp add netdiag -- netdiag-mcp
```

Any other MCP client that launches stdio servers works the same way: give it
`netdiag-mcp` as the command.

## Optional: credentials for `http_get`

`http_get` can send an `Authorization` header to URLs under a configured https
prefix, for reading a protected JSON endpoint without handing the credential to
the model. Set `NETDIAG_HTTP_AUTH` to a JSON object mapping prefix to header
value:

```bash
NETDIAG_HTTP_AUTH='{"https://reports.example.ac.jp/daily/": "Bearer <token>"}'
```

- The header is chosen per request and per redirect hop by comparing the parsed
  URL (https only, exact host and port, path prefix on a `/` boundary). A
  redirect to anywhere else drops it, along with any cookie set while it was
  attached.
  `user@host` URLs never match, and neither does a path with anything beyond
  letters, digits, `.`, `_`, `~`, `-` and `/` (no `%`, `;` or `.`/`..`
  segments), so a server cannot normalise a matched URL out of the prefix. The
  longest matching prefix wins; two prefixes that differ only in case, `:443` or
  a trailing dot are rejected as duplicates. Values must be printable ASCII.
- netdiag-mcp never puts the value into its own output, errors or
  `health_check`; the result's status line says `auth=applied` when the final
  hop carried it, and `health_check` lists the configured prefixes in canonical
  form (not the values). Errors name a bad prefix by position, not by text. A
  response body under the prefix has the value (and its token part) masked as
  `[redacted]`, but an endpoint that transforms it (for example base64) would
  still reveal it, so point a prefix only at endpoints you control.
- A malformed value fails loudly: `http_get` returns an error and
  `health_check` reports `degraded`.
- It is read from the environment only. If several instances run as the same
  user (for example one open to many users and one restricted), set it only in
  the environment of the instance that should send it — a file would be shared
  by all of them.

## CLI

```bash
netdiag-mcp --version   # print version
netdiag-mcp --check     # report missing binaries and a malformed NETDIAG_HTTP_AUTH (exit 0 when all binaries are present and the setting, if any, parses)
```

## Security notes

- Every external-binary call passes an argv list (never a shell string), so
  no tool argument can break out into shell syntax.
- Hostname/IP and port arguments are validated and size/range-clamped before
  use — tool input is model-driven and treated as untrusted, the same as any
  other tool-calling surface.
- `tcp_port_check` connects to exactly one host:port per call; there is no
  loop or range argument, by design.
- The optional `http_get` credential never leaves the configured https prefix
  and netdiag-mcp never prints it; a response body that echoes it is the
  server's doing (see above).

## Development

### Live smoke test

Unit tests check logic against fixtures; they cannot tell you that a tool has
stopped returning real data (a dead `dig`/`ping`/`mtr`/`whois` binary, a
broken TLS trust store, a network that blocks outbound ICMP). `scripts/
smoke_test.py` runs **every registered tool** against real public endpoints
and fails on empty, malformed or error answers:

```bash
uv run python scripts/smoke_test.py
uv run python scripts/smoke_test.py --only ping --traceback
```

- **No inventory, so every target is a fixed public endpoint** — Cloudflare's
  `1.1.1.1` and IANA's `example.com` (reserved for documentation/testing use,
  RFC 2606). This server takes no config and has nothing to discover a
  target from, unlike a device-fleet MCP server in this family.
- `tests/test_smoke_probes.py` is the offline half: it only checks that
  every registered tool has a probe spec (and vice versa), so CI catches a
  tool added without deciding how anyone would know it works, without
  needing network access.

## License

MIT
