# Changelog

## Unreleased

### Changed
- Each release now also publishes `server.json` to the MCP Registry, so the listing stays at the npm version.

## 1.0.34

### Added
- `shodan_count`: total matches and facet breakdowns for a query without fetching results. Free.
- `domain_info`: subdomains and DNS records for a domain, with `history`, `type` and `page` options. Costs 1 query credit.
- `search_filters`: lists valid search filter and facet names. Free.
- `api_info`: plan, query and scan credits, and usage limits. Free.
- `ip_lookup`: OS, host CVEs, and per-service product, version, CPEs and CVEs. New `history` option adds a banner history (one row per port and version with first/last seen, so hundreds of scans stay compact); new `minify` option skips banners.
- `shodan_search`: `page` and `facets` parameters; OS and CVEs per match.
- `cve_lookup` and `cves_by_product` show CVSS v4 scores when CVEDB has them.

### Fixed
- `cves_by_product` never showed "Total CVEs Found": CVEDB only returns a total for `count=true`, so the tool now makes a second, free count request.
- EPSS ranking was shown as "Top N%" but CVEDB's `ranking_epss` is a percentile, so the most exploitable CVEs read as "Top 100%". It is now reported as a percentile in `cve_lookup` and `cves_by_product`.

### Changed
- `ip_lookup` shows the newest banner for each port when several exist.
- `cve_lookup` lists at most 50 affected CPEs, with the total and a note when there are more. CVE-2021-44228 has 1,593, which made one lookup about 95,000 characters.
- `shodan_search` returns breakdowns for all requested facets under `Facets`. `Country Distribution` is kept when the country facet is requested, which is the default.

## 1.0.33

### Fixed
- `shodan_search`: `max_results` was ignored and a full page of up to 100 matches came back, because the server sent a `limit` parameter Shodan's search API doesn't accept. Results are now trimmed to `max_results` (1-100).
- `shodan_search`: "Country Distribution" was always empty because facets were never requested. The server now asks for `facets=country`.
- `ip_lookup` no longer crashes on host responses without `ports` or `data`.
- CVEDB requests now time out after 10 seconds instead of hanging.
- The server reports its real version to clients instead of `1.0.0`.
- `server.json` version was out of step with `package.json`; the publish workflow now keeps them in sync.

### Added
- HTTP streaming transport: `MCP_TRANSPORT=httpStream` with `MCP_HOST`, `MCP_PORT` and `MCP_ENDPOINT`, and a `/health` endpoint.
- Unit tests for all seven tools with a mocked Shodan API, and an HTTP transport test.
- CI workflow (Node 20/22/24 tests, package check, dependency audit, Docker build), Dependabot, issue and pull request templates, security policy, contributing guide, code of conduct, citation file, and a documentation site at <https://w0h1v.github.io/mcp-shodan/>.

### Changed
- Stricter input validation: `ip_lookup` accepts only IPv4/IPv6 addresses; `max_results`, `skip` and `limit` must be integers within documented bounds.
- Dependencies: fastmcp 3 → 4.22, axios 1.20.0, dotenv 18. Lockfile refreshed, clearing high-severity advisories in transitive `hono` and `undici`.
- `package.json` declares `engines.node >=20`.
- Dockerfile uses Node 24 LTS, `npm ci --omit=dev`, and runs as a non-root user. The placeholder API key is no longer baked into the image.
- The npm publish workflow runs tests first and skips docs-, workflow- and config-only changes.

## 1.0.30

- Fixed `reverse_dns_lookup` crash on IPs without PTR records, added SSL/TLS certificate details to `ip_lookup` output, pinned axios below 1.14.1.

## 1.0.22

- Published to the [official MCP Registry](https://registry.modelcontextprotocol.io) with a `server.json` manifest; CLI install instructions for Claude Code, Codex and Gemini CLI.

## 1.0.17

- Migrated from the raw MCP SDK to [FastMCP](https://github.com/punkpeye/fastmcp), with one module per tool.

## Earlier

- 1.0.12: reverse DNS lookup and improved output formatting.
- 1.0.7: `cves_by_product`; vulnerabilities tool renamed to `cve_lookup`.
- 1.0.6: CVEDB integration for CVE and CPE lookups.
- 1.0.0: initial release.
