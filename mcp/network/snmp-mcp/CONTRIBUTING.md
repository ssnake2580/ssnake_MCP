# Contributing to snmp-mcp

Thanks for your interest! This project is in alpha and contributions of any
size are welcome.

## Ground rules

- **Read [DESIGN.md](DESIGN.md) first.** The v0 scope, tool signatures, and
  MIB-to-tool mapping are documented there. If your change diverges from
  the design, propose the design change in an issue or PR first.
- **No vendor-specific defaults.** This codebase must work for any
  SNMP-speaking device. No hardcoded IPs, hostnames, communities, or OIDs
  outside the standard IETF MIBs covered by the v0 wrappers.
- **No secrets in code, tests, or fixtures.** Communities, auth
  passphrases, and priv keys come from config files or environment
  variables. PRs that hardcode credentials will be rejected.
- **Read-only by design (v0).** SNMP SET operations are explicitly out of
  scope. A future major version may add a writes module; please open an
  issue to discuss before contributing one.

## Development setup

```bash
git clone https://github.com/acato/snmp-mcp
cd snmp-mcp
uv sync --all-extras
uv run pytest
uv run ruff check
uv run ruff format --check
```

Python 3.11+ required. Dependencies are managed by
[uv](https://docs.astral.sh/uv/).

## Testing

- **Unit tests** (`tests/unit/`) — fast, no network, run on every CI build.
  Use pysnmp's async harness or in-process fakes to stand in for a real
  agent. Fixtures live in `tests/fixtures/`.
- **Live integration tests** (`tests/integration/`) — gated behind the
  `SNMP_MCP_LIVE_HOST` env var. Skipped by default. CI never runs these.
- New MIB wrappers must come with at least unit-test coverage of the happy
  path plus one error case (timeout, no-such-name, no-such-instance, or
  end-of-MIB-view). Use `pytest -k` to scope while iterating.

For live tests against your own device:

```bash
export SNMP_MCP_LIVE_HOST=switch.example.com
export SNMP_MCP_LIVE_COMMUNITY='public'  # or set SNMP_MCP_LIVE_AUTH_PASS etc. for v3
uv run pytest tests/integration
```

Never commit a real config file or `.env` containing credentials.
`.gitignore` excludes `*.env` and `config.local.*`.

## Code style

- `ruff check` and `ruff format` are CI-enforced.
- Type hints are required on public functions (the MCP tool surface).
  Internal helpers may omit them but they're encouraged.
- Docstrings on every public function. Use the Google docstring style.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`. Scope is optional
(`feat(printer): ...`).

## Reporting device quirks

If you discover a device-specific behavior that the MCP should handle
(e.g., a switch that returns `ifSpeed` saturated at 4.29 Gbps even on a
10 Gbps link), open an issue with:

1. Device model and firmware version.
2. The exact tool call that misbehaves.
3. The observed output vs. expected.
4. A `snmpwalk` or `snmpget` reproduction if possible.

These are gold — they're exactly the kind of knowledge this project exists
to capture.
