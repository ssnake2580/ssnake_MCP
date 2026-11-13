# Reference

## Tools

### `health_check`

No parameters. Returns `{status, service, version, binaries, missing, http_auth}`.
`status` is `"healthy"` when `dig`/`ping`/`mtr`/`whois` are all on PATH and
`NETDIAG_HTTP_AUTH` (if set) parses, `"degraded"` otherwise — the affected
tools fail at call time, but the server itself keeps running. `http_auth` is
`{prefixes, error}`: the configured URL prefixes (never the header values) and
the parse error, if any.

### `dns_lookup(hostname, record_type="A", resolver=None, transport="plain")`

Resolve a DNS record via `dig`. `record_type`: `A`/`AAAA`/`MX`/`TXT`/`NS`/
`CNAME`/`SOA`/`PTR`/`CAA`. Pass `resolver` to query a specific nameserver
instead of the host default (e.g. to check propagation to a given
resolver). `transport`: `"plain"` (UDP/TCP 53, default), `"dot"`
(DNS-over-TLS, 853) or `"doh"` (DNS-over-HTTPS, 443) — requires `dig` from
BIND 9.18+; an older `dig` rejects `dot`/`doh` outright instead of silently
falling back to plain DNS.

### `dnssec_check(hostname, resolver="1.1.1.1", transport="plain")`

Query a known-validating resolver and report whether the AD bit is set.
`transport` as above — useful to compare validation over plain DNS vs. an
encrypted transport when port 53 may be intercepted.

### `ping_host(host, count=4)`

ICMP ping. `count` is clamped to 1-10. On macOS, IPv6 literals are
dispatched to `ping6` (macOS's `ping` rejects them outright); on Linux,
`ping` handles both families and `ping6` is never used.

### `traceroute_path(host, cycles=3)`

Hop-by-hop path/loss report via `mtr --report` (fixed cycles, not a
live/continuous run). `cycles` clamped to 1-10. Needs `mtr-packet`'s
`cap_net_raw` capability; without it, fails cleanly with a `ToolError`
rather than crashing the server.

### `tcp_port_check(host, port, timeout=5.0)`

Is a TCP port open — a plain socket connect to exactly one `host:port`, not
a port scan. No loop or range argument, by design.

### `http_check(url, timeout=5.0)`

HEAD/GET a URL and report status, redirect chain, and latency.

### `http_get(url, timeout=5.0, max_bytes=262144)`

GET a URL and return the decoded body. Only textual content types are
returned (`text/*`, JSON, XML, JavaScript, YAML and `+json`/`+xml` suffixes);
anything else yields the status line only. The body is capped at `max_bytes`
(hard ceiling 1 MiB) and marked `truncated` when cut. Redirects are followed one
hop at a time (at most 5) and every hop, like the initial URL, is refused if it
resolves to loopback, link-local, an unspecified address or a cloud metadata
endpoint. The whole call is bounded by `timeout * 3` of wall clock.

With `NETDIAG_HTTP_AUTH` set, each hop under a configured https prefix is sent
with that prefix's `Authorization` header, decided per hop (see the README).
The status line then ends with `auth=applied`; the value is never returned.

### `tls_cert_check(host, port=443)`

Fetch the certificate a host presents and report subject/issuer/validity/
SANs. Against a bare IP on an SNI-hosted/CDN-fronted origin this can fail
the handshake — normal TLS behavior, not a tool bug (see
[index](index.md#design-notes)).

### `whois_lookup(domain)`

WHOIS lookup for a domain.

### `asn_lookup(target)`

ASN + country-code lookup for an IP, or org info for an AS number (e.g.
`AS15169` or `15169`), via Team Cymru's whois service — no API key or
GeoIP database needed. Takes an IP literal or AS number, not a hostname;
resolve first with `dns_lookup` if you only have a name.

### `current_time(timezone="UTC")`

Current date, time and weekday in the given IANA timezone (e.g.
`Asia/Tokyo`). Returns `date`, `time`, `weekday` (`Mon`..`Sun`),
`weekday_ja` (`月`..`日`), `weekday_index` (0 = Monday), `iso`,
`utc_offset`, `utc` and `epoch`.

Call this rather than working the weekday out from a date: that is calendar
arithmetic, and a caller that gets it wrong gets it wrong silently. Touches
no network — it reports this server's own clock, which also makes it a check
on whether that clock has drifted.

## Errors

Every tool catches `ValueError` (bad input) and `ToolError` (the wrapped
command failed) and returns them rather than raising, so a caller always
gets an answer back. Tools that answer with text return the string
`"error: ..."`; `current_time` and `health_check` answer with a dict, so
their failure carries an `"error"` key instead.

## CLI

```bash
netdiag-mcp --version   # print version
netdiag-mcp --check     # report missing binaries and a malformed NETDIAG_HTTP_AUTH (exit 0 when neither)
```

`--check` exits non-zero if any of `dig`/`ping`/`mtr`/`whois` is missing or
`NETDIAG_HTTP_AUTH` is set but malformed —
useful in a deploy script to fail fast before the server would otherwise
degrade silently.

## Security notes

- Every external-binary call passes an argv list (never a shell string), so
  no tool argument can break out into shell syntax.
- Hostname/IP and port arguments are validated and size/range-clamped
  before use — tool input is model-driven and treated as untrusted, the
  same as any other tool-calling surface.
- All tools are read-only; there is no write/mutating tool in this server.
