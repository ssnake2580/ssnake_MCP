# netdiag-mcp

MCP server for on-demand network diagnostics — DNS lookups (with a DNSSEC
AD-bit check), ping, an `mtr`-based path report, TCP port checks, HTTP
status/redirect checks, TLS certificate inspection, WHOIS, and ASN/GeoIP
lookups, all from one server.

Built for triaging "can't reach X" / "is DNS propagated yet" reports
without shelling into a jump host for each one-off `dig`/`ping`/`curl`.

## Tools

| Tool | Purpose |
|---|---|
| `dns_lookup` | Resolve a DNS record via `dig` (A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA), optionally against a specific resolver and over plain DNS/DoT/DoH |
| `dnssec_check` | Query a known-validating resolver and report whether the AD bit is set (plain/DoT/DoH) |
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

## Design notes

**Four tools don't shell out at all.** `tcp_port_check`, `http_check`,
`http_get` and `tls_cert_check` use Python's own socket/ssl/httpx stack rather
than `nc`/`curl`/`openssl`, so those four work even on a host with only
`dig`/`ping`/`mtr`/`whois` installed (or none of them — `health_check`
reports which are missing without failing the whole server).

**DNS-over-TLS/HTTPS needs a modern `dig`.** `dns_lookup`/`dnssec_check`
support `transport="dot"`/`"doh"` (dig's `+tls`/`+https`), which requires
BIND 9.18+. An older `dig` rejects the flag outright rather than silently
falling back to plain DNS, so a stale binary fails loudly instead of giving
a false sense of having checked over an encrypted transport.

**TLS by IP can fail even against a healthy target.** `tls_cert_check`/
`http_check` against a bare IP address can fail the TLS handshake on
SNI-hosted/CDN-fronted origins (e.g. behind Cloudflare) — SNI only carries
hostnames, so an IP literal can't route to the right certificate on a
shared edge. This is normal TLS behavior, not a tool bug; check by hostname
when the target is CDN-fronted.

## Next steps

- [Reference](reference.md) — every tool's parameters, CLI, exit codes
