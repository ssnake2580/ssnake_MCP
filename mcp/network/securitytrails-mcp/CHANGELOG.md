# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-09-18

### Changed

- Documented the project's legal position explicitly: an unofficial notice at the top of the
  README, a Legal section recording that SecurityTrails is a trademark of Recorded Future, Inc.
  and used here only nominatively to identify the API, and a statement that use of the API is
  governed by the user's own agreement with SecurityTrails rather than by this project's licence.
- Package description now leads with "Unofficial" so the distinction is visible on the npm
  listing itself, not only in the README.

## [1.0.0] - 2026-09-18

Initial release: 17 read-only tools over the SecurityTrails v1 API, built on
`@modelcontextprotocol/server` v2.

### Added

- Domain tools: details, subdomains, associated domains, DNS history, current and historical
  WHOIS, SSL certificates, tags.
- IP tools: neighbouring blocks, IP WHOIS, observed user agents, company-associated ranges.
- Search tools: domain and IP dataset search by structured filter or DSL query, plus scroll.
- Account tools: key check and monthly quota reporting with remaining allowance.
- `response_format` on every tool — a compact Markdown summary by default, or the raw upstream
  JSON payload. Unrecognised payloads fall back to JSON rather than rendering partially.
- Pagination metadata on `securitytrails_subdomains` (`total_count`, `has_more`, `next_offset`)
  and a pagination footer on paged endpoints naming the cost of the next page.
- Zod validation on every tool argument, rejecting malformed hostnames, IPv6 on IPv4-only
  endpoints, and out-of-range values before a query is spent.
- Request timeout (30s default) and bounded retry with exponential backoff on 429/5xx/network
  errors. Non-transient failures are never retried.
- Error messages that name the fix: which environment variable, which plan tier, which tool
  reports remaining quota.

### Notes

- `securitytrails_ip_useragents` and `securitytrails_company_associated_ips` require a paid
  SecurityTrails plan and return a plan error on the free tier.
- SecurityTrails returns Unix timestamps in mixed units within a single record; Markdown
  rendering infers the unit rather than assuming milliseconds or seconds.

[Unreleased]: https://github.com/aqhmal/securitytrails-mcp/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/aqhmal/securitytrails-mcp/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/aqhmal/securitytrails-mcp/releases/tag/v1.0.0
