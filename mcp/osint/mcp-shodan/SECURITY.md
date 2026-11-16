# Security policy

mcp-shodan is an independent project and is not affiliated with Shodan.

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a suspected vulnerability.

Include:

- The mcp-shodan version or commit, and your Node version.
- Steps to reproduce, and the expected and actual results.
- The impact you believe the issue has.

Do not include API keys or indicators from private investigations in a report.

## Scope

In scope:

- **API key leakage** in logs, error messages or tool output.
- **Request forgery**: tool input that changes the host, path or method of the request sent to Shodan or CVEDB, or reaches any other host.
- **Validation bypass** of the IP, domain, CVE ID, facet and numeric bounds checks in the tool schemas under `src/tools/` and `src/helpers.ts`.
- **Unauthenticated access** to the HTTP streaming transport beyond what is documented.

Out of scope:

- **Shodan's API and data.** Report these to Shodan.
- **Misuse of the tool.** What you look up is up to the operator.
- **Local attackers with the same OS user**, who can already read the environment.
- **Automated scanner findings** without a working reproduction.

## Trust model

The server runs with your Shodan API key on behalf of an MCP client you configured. It treats tool arguments as untrusted and validates them with zod schemas before building a request. Over stdio it does not authenticate the client, which runs as the same OS user.

The HTTP streaming transport (`MCP_TRANSPORT=httpStream`) has **no authentication**. Do not expose the port beyond localhost; put an authenticating reverse proxy in front of it if other machines need access. Anyone who can reach the port can spend your query credits.

Shodan's API takes the key as a `key` query parameter, so it appears in request URLs sent to `api.shodan.io` over HTTPS. The server does not log request URLs. CVEDB (`cvedb.shodan.io`) calls are unauthenticated and never carry the key.

IPs, hostnames, queries and products you look up are sent to Shodan.
