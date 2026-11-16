# securitytrails-mcp

[![npm](https://img.shields.io/npm/v/securitytrails-mcp.svg)](https://www.npmjs.com/package/securitytrails-mcp)
[![CI](https://github.com/aqhmal/securitytrails-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/aqhmal/securitytrails-mcp/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/securitytrails-mcp.svg)](./LICENSE)

An [MCP](https://modelcontextprotocol.io) server that gives an LLM agent the
[SecurityTrails](https://securitytrails.com) API: DNS history, subdomain enumeration, WHOIS
(current and historical), SSL certificates, and IPv4 intelligence — 17 read-only tools.

Built for reconnaissance work where the interesting question is usually _"what did this look like
before the CDN went up?"_ rather than _"what does it resolve to now?"_.

> **Unofficial project.** Not affiliated with, endorsed by, or sponsored by SecurityTrails or
> Recorded Future, Inc. You bring your own SecurityTrails API key and use it under your own
> agreement with them. See [Legal](#legal).

## Quickstart

You need a SecurityTrails API key — the free tier is enough to try it.
Get one at [securitytrails.com/app/account/credentials](https://securitytrails.com/app/account/credentials).

### Claude Code

```sh
claude mcp add securitytrails --env SECURITYTRAILS_API_KEY=your_key -- npx -y securitytrails-mcp
```

### Claude Desktop, Cursor, VS Code, and other MCP hosts

```json
{
  "mcpServers": {
    "securitytrails": {
      "command": "npx",
      "args": ["-y", "securitytrails-mcp"],
      "env": {
        "SECURITYTRAILS_API_KEY": "your_key"
      }
    }
  }
}
```

Config file locations: Claude Desktop uses `claude_desktop_config.json`
(`~/Library/Application Support/Claude/` on macOS, `%APPDATA%\Claude\` on Windows);
Cursor uses `~/.cursor/mcp.json`; VS Code uses `.vscode/mcp.json` in the workspace.

## Tools

Every tool is read-only, accepts `response_format`, and costs **one SecurityTrails API query per
call** — including per page when paging.

| Tool                                    | What it does                                                   | Plan     |
| --------------------------------------- | -------------------------------------------------------------- | -------- |
| `securitytrails_ping`                   | Check the API key is accepted                                  | Free     |
| `securitytrails_usage`                  | Month-to-date consumption, allowance, remaining quota          | Free     |
| `securitytrails_domain_details`         | Current DNS records, hostname counts, registrar metadata       | Free     |
| `securitytrails_subdomains`             | Known subdomains as fully-qualified hostnames                  | Free     |
| `securitytrails_associated`             | Domains sharing registrant details or infrastructure           | Free     |
| `securitytrails_dns_history`            | Historical A/AAAA/MX/NS/SOA/TXT records with observation dates | Free     |
| `securitytrails_whois_current`          | Current WHOIS record                                           | Free     |
| `securitytrails_whois_history`          | Past WHOIS records — often pre-redaction                       | Free     |
| `securitytrails_ssl`                    | Certificates issued for a hostname, including SAN entries      | Free     |
| `securitytrails_tags`                   | SecurityTrails classification tags                             | Free     |
| `securitytrails_ip_neighbors`           | Adjacent IPv4 blocks, site counts, sample hostnames            | Free     |
| `securitytrails_ip_whois`               | Network block registration, owner, abuse contacts              | Free     |
| `securitytrails_search_domains`         | Search the domain dataset by filter object or DSL query        | Free     |
| `securitytrails_search_ips`             | Search the IP dataset by filter object or DSL query            | Free     |
| `securitytrails_scroll`                 | Continue a search via its `meta.scroll_id`, when offered       | Varies   |
| `securitytrails_ip_useragents`          | User agents observed originating from an IPv4 address          | **Paid** |
| `securitytrails_company_associated_ips` | IP ranges attributed to a domain's owning organisation         | **Paid** |

Plan column reflects what a free-tier key could reach at the time of writing; SecurityTrails may
move endpoints between tiers. The two paid endpoints return a clear plan error rather than a
generic failure, so an agent knows to stop retrying:

```
Your SecurityTrails plan does not permit this endpoint (HTTP 403): This feature is not
available for your subscription package.
```

### Response format

Every tool takes `response_format`:

- **`markdown`** (default) — a compact summary. Converts the API's raw Unix timestamps to dates,
  drops null-filled privacy contacts, and appends a pagination footer saying whether more data
  exists. Typically a fraction of the tokens of the equivalent JSON.
- **`json`** — the untouched upstream payload, for when you need a field the summary omits.

If a payload does not match the shape a renderer expects, the server returns the raw JSON rather
than a partial summary. A rendering gap will cost you tokens, never data.

## Examples

### Finding an origin IP behind a CDN

The current A record is a CDN edge, so ask what it used to be:

```
> Has example.com always been behind Cloudflare? Check its A record history.
```

```jsonc
// securitytrails_domain_details  { "domain": "example.com" }
// securitytrails_dns_history     { "domain": "example.com", "type": "a" }
```

The history table shows each IP with the window it was observed in and the hosting organisation —
an address that predates the CDN cutover is a candidate origin.

### Expanding scope from one domain

```
> I only know example.com. What else does this organisation own?
```

```jsonc
// securitytrails_whois_current { "domain": "example.com" }
// securitytrails_associated    { "domain": "example.com" }
// securitytrails_search_domains { "query": "whois_email = 'admin@example.com'" }
```

WHOIS gives the registrant email; searching the dataset by that email finds every other domain
registered with it. `securitytrails_whois_history` is often more productive than the current
record, because older entries predate privacy redaction.

### Mining certificates for hostnames

```
> Find hostnames for example.com that subdomain enumeration might have missed.
```

```jsonc
// securitytrails_subdomains { "domain": "example.com", "limit": 1000 }
// securitytrails_ssl        { "domain": "example.com", "status": "all", "include_subdomains": true }
```

SAN entries on expired certificates frequently name internal or staging hosts that no longer
resolve. Use `status: "all"` — the default `valid` filter hides exactly the interesting ones.

### Profiling an IP

```
> Who owns 8.8.8.8 and what else is in that block?
```

```jsonc
// securitytrails_ip_whois     { "ip": "8.8.8.8" }
// securitytrails_ip_neighbors { "ip": "8.8.8.8" }
```

## Quota and performance

SecurityTrails bills per API query against a monthly allowance. `securitytrails_usage` reports
where you stand. Things worth knowing before pointing an agent at a large target:

- **`securitytrails_subdomains` costs one query regardless of result size.** It returns the whole
  set in a single call, so prefer one call with a high `limit` over paging with `offset` — paging
  re-fetches and is billed again. Results default to 100 hostnames with `total_count` and
  `has_more` always reported, so a truncated result is never mistaken for a complete one.
- **Paged endpoints cost one query per page.** `securitytrails_associated`, `_dns_history`,
  `_ssl`, `_search_domains` and `_search_ips` all bill per page.
- **The domain and IP datasets accept different DSL fields.** `ptr_part` and `open_port_80` are
  IP-dataset fields; using them against `securitytrails_search_domains` is a syntax error, not an
  empty result.

Each request has a 30-second timeout and retries twice on `429`/`5xx`/network errors with
exponential backoff (500ms, then 1000ms). Non-transient failures — `400`, `401`, `403`, `404` —
are never retried, so a bad argument costs one query rather than three.

## Configuration

| Variable                     | Default      | Purpose                           |
| ---------------------------- | ------------ | --------------------------------- |
| `SECURITYTRAILS_API_KEY`     | _(required)_ | Your API key                      |
| `SECURITYTRAILS_TIMEOUT_MS`  | `30000`      | Per-attempt request timeout       |
| `SECURITYTRAILS_MAX_RETRIES` | `2`          | Retries on 429/5xx/network errors |

If the key is missing the server still starts and still lists its tools, so the host shows it as
healthy; each tool call then returns an error naming the variable to set. This is deliberate — a
server that exits on startup shows up in most hosts as an unexplained crash. The key is validated
by use rather than by a startup `ping`, so that restarting your editor does not spend quota.

## Development

```sh
git clone https://github.com/aqhmal/securitytrails-mcp.git
cd securitytrails-mcp
npm install
npm test          # 85 tests, no API key needed — the HTTP layer is stubbed
npm run build
npm run format    # Prettier, in place
npm run inspect   # build, then open the MCP Inspector against the server
```

The suite drives a real MCP `Client` against the server in-process, so tool schemas, argument
validation, rendering and error handling are exercised through the actual protocol rather than by
calling handlers directly. See [CONTRIBUTING.md](./CONTRIBUTING.md).

Release history is in [CHANGELOG.md](./CHANGELOG.md).

`evals/` holds a ten-question evaluation set for checking whether a model can actually accomplish
realistic lookups with these tools.

## Security

This is a reconnaissance tool. Only use it against infrastructure you are authorised to
investigate.

The API key is read from the environment, sent only to `api.securitytrails.com` over HTTPS as a
header, and never logged, written to disk, or included in a tool result. Tool arguments are
validated with Zod before any request is made: hostnames must be bare hostnames, IPs must be
IPv4, and identifiers interpolated into request paths are percent-encoded, so a traversal
sequence cannot escape its endpoint.

To report a vulnerability, see [SECURITY.md](./SECURITY.md).

## Legal

This is an unofficial, community-maintained client. It is **not** affiliated with, endorsed by, or
sponsored by SecurityTrails, Recorded Future, Inc., or Mastercard.

SecurityTrails is a trademark of Recorded Future, Inc. (officially styled _SecurityTrails, a
Recorded Future Company_). The name is used here only to identify the API this software talks to —
nominative use — and no claim to the mark, and no sponsorship or endorsement, is made or implied.
No SecurityTrails logos or brand assets are included or distributed with this project.

This project is a client. It ships no SecurityTrails data, and it grants you no rights to any. Your
use of the API is governed entirely by your own agreement with SecurityTrails / Recorded Future,
including their [terms of service](https://securitytrails.com/corp/terms-of-service), your plan's
query limits, and any restrictions on storing or redistributing what you retrieve. You are
responsible for complying with those terms, and for only running reconnaissance against
infrastructure you are authorised to investigate.

The MIT licence below covers this client's own source code and nothing else.

## License

MIT © [aqhmal](https://github.com/aqhmal)
