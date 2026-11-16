# snmp-mcp

An [MCP](https://modelcontextprotocol.io/) server that wraps the IETF SNMP
standard so AI agents (Claude Code, Claude Desktop, IDE assistants) can poll
any SNMP-speaking device on the network without rediscovering each MIB's
quirks on every task.

**Status:** beta. Feature-complete v0 — 9 tools (4 generic primitives, 5
MIB-specific convenience wrappers) covering read-only inspection across
switches, routers, printers, and host-resources targets. 66 unit tests +
9 live integration tests passing against two device classes (a managed
RouterOS switch and an Epson print server with full PRINTER-MIB support).
API is stable.
See [DESIGN.md](DESIGN.md) for the full architecture, tool surface, and
MIB-to-tool mapping.

## Why

Mixed-vendor networks need a vendor-neutral read-side abstraction:

- A managed switch (MikroTik, Cisco, Aruba, Omada) exposes interface
  counters via `IF-MIB`. Use HC counters (`ifHCInOctets`/`ifHCOutOctets`)
  on any link >=1 Gbps — the 32-bit `ifInOctets`/`ifOutOctets` saturate at
  ~4.29 Gbps.
- A network printer (HP, Brother, Canon, OKI, Epson) exposes toner / ink
  / drum levels via `PRINTER-MIB` (RFC 3805). The MIB is identical across
  vendors; the wrapper returns one schema for all of them.
- A Linux host running `net-snmp` exposes CPU, memory, and disk via
  `HOST-RESOURCES-MIB` (RFC 2790). Same wrapper, same schema.
- Generic SNMP get/walk/bulkwalk/table primitives are also exposed so you
  can talk to anything else without writing vendor-specific code paths.

`snmp-mcp` is the read-side counterpart to vendor-specific MCPs that
already handle writes for one device (e.g., `synology-mcp` for DSM).

## Scope

### MVP (v0)

**Generic primitives** (4):

1. `snmp_get` — fetch one or more OIDs (numeric or symbolic).
2. `snmp_walk` — walk a subtree via GETNEXT.
3. `snmp_bulk_walk` — walk a subtree via GETBULK (faster for large tables).
4. `snmp_table` — fetch and tabularize an SNMP table.

**MIB-specific convenience wrappers** (5):

5. `system_info` — `SNMPv2-MIB::system` group (sysDescr / sysName /
   sysLocation / sysUpTime / ...).
6. `interfaces_list` — `IF-MIB::ifTable` + `IF-MIB::ifXTable`, with HC
   counters preferred where exposed.
7. `host_resources` — `HOST-RESOURCES-MIB` (CPU load, memory, storage).
8. `printer_status` — `PRINTER-MIB` (supplies, trays, alerts, status).
9. `device_detect` — probe `sysObjectID` + a handful of well-known root
   OIDs to report which standard MIBs the device supports.

### Out of scope (v0)

- SNMP SET (writes). Read-only by design.
- SNMP trap receiver (long-running daemon, different process model).
- Loading random vendor MIBs at runtime — standard IETF MIBs only.
- MIB browser GUI. Stick to the programmatic tool surface.
- Custom polling schedules or time-series storage. That belongs in Home
  Assistant, Prometheus, or similar.

See [DESIGN.md §11](DESIGN.md#11-out-of-scope-for-v0) for rationale.

## Multi-host

Every tool accepts a `host` parameter. Credentials and connection settings
come from a config file or environment variables — there are **no
hardcoded hosts** in this codebase. See
[`examples/config.toml`](examples/config.toml).

## Quickstart

```bash
# Install from PyPI (when published)
uv tool install snmp-mcp

# Or run from source
git clone https://github.com/acato/snmp-mcp
cd snmp-mcp
uv sync
uv run snmp-mcp
```

### Windows: avoid Microsoft Store Python

If `uv` picks Microsoft Store Python (path under `\WindowsApps\PythonSoftwareFoundation...`) when creating the venv, the MCP runs fine from a terminal but fails to launch from GUI hosts like the Claude desktop app, IDE extensions, or scheduled tasks. You will see:

```
Unable to create process using "...\WindowsApps\PythonSoftwareFoundation.Python.3.12_...\python.exe"
```

The Store-Python app-execution alias requires an interactive user context that GUI-spawned children do not get. Pin `uv` to a non-Store interpreter — uv's managed Python is easiest:

```powershell
uv python install 3.12
uv venv --python 3.12 --python-preference only-managed --clear
uv sync
```

Verify: `Get-Content .venv\pyvenv.cfg` — the `home =` line should point under `AppData\Roaming\uv\python\...`, **not** `\WindowsApps\`. A python.org installer or `winget install Python.Python.3.12` also works.

### Wire into Claude Code

```bash
claude mcp add snmp-mcp -- uv run --directory /path/to/snmp-mcp snmp-mcp
```

### Configuration

Copy `examples/config.toml` to `~/.config/snmp-mcp/config.toml` and fill in
your hosts. Or set per-host env vars (see
[DESIGN.md §6](DESIGN.md#6-configuration)).

## Compatibility

- **SNMPv1** — supported (legacy devices).
- **SNMPv2c** — first-class target (community-based; most common).
- **SNMPv3** — supported with auth (MD5/SHA/SHA2-family) and priv
  (DES/3DES/AES128/192/256).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks

This project is not affiliated with, endorsed by, or sponsored by any
vendor whose devices it polls.
