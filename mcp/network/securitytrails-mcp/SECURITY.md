# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/aqhmal/securitytrails-mcp/security/advisories/new)
rather than opening a public issue.

Please include the version, a description of the issue, and steps to reproduce. You can expect an
initial response within seven days.

## Scope

In scope: anything in this repository — credential handling, input validation on tool arguments,
command or path injection through tool inputs, dependency vulnerabilities.

Out of scope: vulnerabilities in the SecurityTrails API itself (report those to SecurityTrails),
and vulnerabilities in the MCP host application (report those to the host's maintainers).

## Handling your API key

This server reads `SECURITYTRAILS_API_KEY` from the environment and sends it only to
`api.securitytrails.com` over HTTPS. It is never logged, never written to disk, and never
included in a tool result. If you believe a key has been exposed, rotate it at
[securitytrails.com/app/account/credentials](https://securitytrails.com/app/account/credentials).
