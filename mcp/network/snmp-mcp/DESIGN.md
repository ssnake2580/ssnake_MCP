# snmp-mcp — Design

> **Status:** alpha. This document is the source of truth for what the v0
> looks like. Implementation has landed for all 9 tools; live integration
> against multiple device classes is still in progress.

## Table of contents

1. [Goals](#1-goals)
2. [Architecture](#2-architecture)
3. [Auth and credential handling](#3-auth-and-credential-handling)
4. [Error handling and retry policy](#4-error-handling-and-retry-policy)
5. [Tool surface](#5-tool-surface)
   1. [Generic primitives](#51-generic-primitives)
   2. [MIB-specific wrappers](#52-mib-specific-wrappers)
6. [Configuration](#6-configuration)
7. [MIB-to-tool mapping](#7-mib-to-tool-mapping)
8. [Testing strategy](#8-testing-strategy)
9. [Versioning and SNMP compatibility](#9-versioning-and-snmp-compatibility)
10. [Security](#10-security)
11. [Out of scope for v0](#11-out-of-scope-for-v0)

---

## 1. Goals

### What this MCP exists to do

- **Encapsulate the SNMP protocol once.** Every agent currently rediscovers
  the v1/v2c/v3 differences, the HC-counter-vs-32-bit-counter trap, the
  table-walk-vs-bulk-walk performance gap. This MCP turns each of those
  into one tool call.
- **Make read-only device introspection trivial.** "What's the ink level
  on the lobby printer?" or "What's the current bandwidth on switch port
  4?" should be one tool call returning structured data, not a chain of
  `snmpwalk | grep | awk`.
- **Be vendor-neutral by construction.** A `printer_status` call should
  work the same against an OKI, an Epson, a Brother, and an HP, because
  they all implement the same IETF `PRINTER-MIB`. The MCP exists to make
  that uniformity actually accessible.
- **Be multi-host from day 1.** Tools take a `host` parameter; the server
  holds one connection per host. No "primary device" concept.

### Non-goals

- A replacement for a full NMS (Zabbix, Observium, LibreNMS). Those are
  built around long-running pollers + time-series storage; this is a
  request/response surface for AI agents to read current state.
- A trap receiver. That's a long-running listener daemon and a different
  process model.
- A MIB browser GUI. The tool surface is the API.
- Vendor-specific MIB compilation at runtime. Standard IETF MIBs only in
  v0.
- SNMP SET (writes). Read-only by design; a future major version may add
  a writes module behind a separate feature flag.

---

## 2. Architecture

### Process model

One long-lived MCP stdio process. Spawned by the MCP client (Claude Code,
Claude Desktop) on startup; speaks JSON-RPC over stdin/stdout per the MCP
spec.

Future: optional HTTP/SSE transport for multi-client scenarios (e.g.,
Open-WebUI). Not in v0.

### Module layout

```
src/snmp_mcp/
├── __init__.py
├── server.py              # MCP server bootstrap; tool registry
├── config.py              # TOML config + env-var overlay
├── errors.py              # SNMP error type → exception mapping
├── session.py             # per-host engine + credentials cache
├── transport.py           # pysnmp async wrapper (get/walk/bulk/table)
├── oids.py                # IANA + IETF OID constants used by wrappers
└── mibs/
    ├── __init__.py
    ├── system.py          # SNMPv2-MIB::system → system_info
    ├── interfaces.py      # IF-MIB → interfaces_list
    ├── host_resources.py  # HOST-RESOURCES-MIB → host_resources
    ├── printer.py         # PRINTER-MIB → printer_status
    └── detect.py          # heuristic device_detect
```

Each MIB-specific wrapper imports the generic primitives from
`transport.py` plus a small dictionary of OID constants from `oids.py`. No
runtime MIB compilation — the IETF MIBs we care about are small enough to
hand-lift the leaf OIDs.

### Per-host state

State lives in `session.py`'s `SessionCache`:

- One `pysnmp` `SnmpEngine` per host, cached for the process lifetime.
- One `CommunityData` (v1/v2c) or `UsmUserData` (v3) per host, derived
  from config + env vars on first use.
- One `UdpTransportTarget` per host, carrying address + port + timeout +
  retries.
- One `ContextData` per host (default context, but configurable for v3).

The cache is keyed by the config `host` name (not the IP). On config
reload, the cache is fully invalidated.

### Lifecycle

- Process start → load config → empty session cache → register tools →
  start MCP transport.
- First tool call against host X → cache miss → build engine + creds →
  run SNMP op → cache stays warm.
- Subsequent calls for X reuse cached engine/creds.
- Process shutdown → engines are GC'd; no explicit unbind required.

---

## 3. Auth and credential handling

### SNMPv1 / SNMPv2c

Community string only. Resolved from (priority order):

1. Env var `SNMP_MCP_<HOST>_COMMUNITY` (host-name uppercased,
   non-alphanumeric → `_`).
2. `community` field in `[hosts.<name>]` TOML table.

If neither is present and `version` is v1 or v2c, `auth_login`-equivalent
calls raise `ConfigError`.

### SNMPv3 (User-based Security Model, USM)

USM credentials are resolved from (priority order):

1. Env vars per field:
   - `SNMP_MCP_<HOST>_USER`
   - `SNMP_MCP_<HOST>_AUTH_PROTO` (`MD5` / `SHA` / `SHA224` / `SHA256` /
     `SHA384` / `SHA512`)
   - `SNMP_MCP_<HOST>_AUTH_PASS`
   - `SNMP_MCP_<HOST>_PRIV_PROTO` (`DES` / `3DES` / `AES128` / `AES192` /
     `AES256`)
   - `SNMP_MCP_<HOST>_PRIV_PASS`
   - `SNMP_MCP_<HOST>_CONTEXT`
2. Matching fields in `[hosts.<name>]`.

Security levels (derived implicitly, not configured directly):

- `noAuthNoPriv` — no `auth_pass` and no `priv_pass`. Discouraged; warned
  about on cache build.
- `authNoPriv` — `auth_pass` set, no `priv_pass`. Acceptable for trusted
  networks.
- `authPriv` — both set. Recommended.

`verify_engine_id` (default `true`): set to `false` for embedded devices
whose engine ID changes across reboots without re-keying — disables the
authoritative-engine-ID check on response.

---

## 4. Error handling and retry policy

### SNMP error categories

| Category                | Source                                  | Tool surface                                                  |
| ----------------------- | --------------------------------------- | ------------------------------------------------------------- |
| Timeout                 | pysnmp `RequestTimeoutError`            | `SnmpTimeout` (retry per `retries` config, then surface)      |
| No such name (v1)       | `errorStatus=2 (noSuchName)`            | `SnmpNoSuchName` (one varbind missing → partial result)       |
| No such instance (v2c+) | varbind tag `noSuchInstance`            | per-varbind `None` value + warning                            |
| No such object (v2c+)   | varbind tag `noSuchObject`              | per-varbind `None` value + warning                            |
| End of MIB view (walk)  | varbind tag `endOfMibView`              | terminates walk cleanly (not an error)                        |
| Bad value / wrong type  | `errorStatus=3` / `errorStatus=10`      | `SnmpBadValue`                                                |
| Auth failure (v3)       | USM `unknownUserName` / `wrongDigests`  | `SnmpAuthFailed` (no retry)                                   |
| Engine ID mismatch (v3) | USM `unknownEngineIDs`                  | `SnmpEngineMismatch` (optionally re-discover, then retry once) |
| Network error           | OS socket error                         | `SnmpTransportError` (retry per `retries`, then surface)      |
| Misconfiguration        | unknown host / missing community / etc. | `ConfigError` (no retry)                                      |

### Retry policy

- Transport errors and timeouts: retry up to `retries` times (default 2)
  with exponential backoff.
- v3 engine-ID mismatch: re-discover engine ID once, then retry once.
- All other errors: surface immediately.

---

## 5. Tool surface

Every tool name is **flat snake_case** with a module prefix where
appropriate. MCP clients see one flat namespace. All tools are async. All
take `host: str` as the first positional argument. All return a `dict`
with at minimum:

```python
{
    "ok": bool,         # True on success
    "host": str,        # echo of host
    "data": Any,        # the actual payload; schema per tool below
    "warnings": list[str],  # optional, e.g., "ifSpeed saturated, used ifHighSpeed"
}
```

On failure, tools return:

```python
{
    "ok": False,
    "host": str,
    "data": None,
    "warnings": [],
    "error": {
        "category": "timeout" | "auth" | "network" | "validation" | "unsupported" | "internal",
        "message": str,
        "host": str,
        "details": dict | None,
    },
}
```

### 5.1 Generic primitives

#### `snmp_get(host, oids)`

Fetch one or more OIDs in a single GET-Request PDU. Accepts both numeric
(`1.3.6.1.2.1.1.5.0`) and symbolic (`SNMPv2-MIB::sysName.0`) forms.
Symbolic forms are resolved against the small built-in OID table in
`oids.py`; arbitrary MIB compilation is not supported in v0.

Returns:

```python
{"ok": True, "host": "switch", "data": {
    "1.3.6.1.2.1.1.5.0": {"value": "crs312", "type": "OctetString"},
    "1.3.6.1.2.1.1.3.0": {"value": 1234567, "type": "TimeTicks"},
}, "warnings": []}
```

If a varbind comes back with `noSuchInstance` / `noSuchObject`, the
corresponding entry has `"value": None` and a warning is appended.

#### `snmp_walk(host, root_oid)`

Walk an OID subtree via GETNEXT chain. Terminates on `endOfMibView` or
when the returned OID is no longer a descendant of `root_oid`.

Returns:

```python
{"ok": True, "host": "switch", "data": [
    {"oid": "1.3.6.1.2.1.2.2.1.2.1", "value": "lo", "type": "OctetString"},
    {"oid": "1.3.6.1.2.1.2.2.1.2.2", "value": "ether1", "type": "OctetString"},
    ...
], "warnings": []}
```

#### `snmp_bulk_walk(host, root_oid, max_repetitions=25)`

Same as `snmp_walk` but uses GETBULK (SNMPv2c+). On a v1 host this falls
back to `snmp_walk` with a warning. `max_repetitions` controls how many
varbinds the agent returns per request; higher is faster on large tables
but risks IP fragmentation on links with small MTUs.

#### `snmp_table(host, table_oid)`

Fetch and tabularize an SNMP table. Walks the table, parses each row's
index out of the trailing OID suffix, and returns a list of dicts keyed
by column name where the column-name → column-OID mapping is known (from
`oids.py`). Unknown columns are keyed by their numeric OID.

Returns:

```python
{"ok": True, "host": "switch", "data": {
    "table_oid": "1.3.6.1.2.1.2.2",
    "rows": [
        {"index": "1", "ifIndex": 1, "ifDescr": "lo", "ifType": 24, ...},
        {"index": "2", "ifIndex": 2, "ifDescr": "ether1", "ifType": 6, ...},
        ...
    ],
}, "warnings": []}
```

### 5.2 MIB-specific wrappers

#### `system_info(host)`

Fetch the `SNMPv2-MIB::system` group (RFC 3418). Always implemented by
every SNMPv2c+ agent.

```python
{"ok": True, "host": "switch", "data": {
    "sysDescr": "RouterOS CRS312-4C+8XG",
    "sysObjectID": "1.3.6.1.4.1.14988.1",
    "sysUpTime": 12345678,   # in centiseconds
    "sysUpTime_seconds": 123456.78,
    "sysContact": "...",
    "sysName": "crs312",
    "sysLocation": "...",
    "sysServices": 78,
}, "warnings": []}
```

#### `interfaces_list(host)`

Walk `IF-MIB::ifTable` (RFC 2863) + `IF-MIB::ifXTable` and merge per
`ifIndex`. Returns per-interface state plus counters.

```python
{"ok": True, "host": "switch", "data": [
    {
        "ifIndex": 1, "ifName": "lo", "ifAlias": "",
        "ifType": 24, "ifMtu": 65536,
        "ifAdminStatus": "up", "ifOperStatus": "up",
        "ifSpeed_bps": 10000000000,   # ifHighSpeed * 1e6 when available
        "ifSpeed_source": "ifHighSpeed",  # or "ifSpeed" or "unknown"
        "ifPhysAddress": "",
        "counters": {
            "ifInOctets": 12345, "ifOutOctets": 67890,
            "ifHCInOctets": 12345, "ifHCOutOctets": 67890,
            "ifInErrors": 0, "ifOutErrors": 0,
            "ifInDiscards": 0, "ifOutDiscards": 0,
        },
    },
    ...
], "warnings": []}
```

**HC-counter handling**: when `ifHCInOctets` / `ifHCOutOctets` are present
(64-bit counters from `ifXTable`), they are returned alongside the
32-bit `ifInOctets` / `ifOutOctets`. Consumers should prefer HC on links
>=1 Gbps because the 32-bit counter wraps in seconds at multi-gigabit
rates. `ifSpeed_source = "ifHighSpeed"` signals that `ifSpeed` was
saturated (the well-known 4.29 Gbps cap) and `ifHighSpeed` is the true
link speed.

#### `host_resources(host)`

Walk `HOST-RESOURCES-MIB` (RFC 2790). Supported by `net-snmp` on every
modern Linux/BSD host and by many appliances. Returns:

```python
{"ok": True, "host": "linuxbox", "data": {
    "hrSystemUptime_centiseconds": 12345678,
    "hrSystemUptime_seconds": 123456.78,
    "hrSystemDate": "2026-05-26T20:00:00",
    "hrSystemProcesses": 142,
    "hrSystemNumUsers": 1,
    "memory": {
        "physical_kb": 16777216,
        "real_kb": 16777216,
        "swap_kb": 4194304,
    },
    "cpu_load_pct": [12, 8, 6, 4],   # per hrProcessorLoad row
    "storage": [
        {
            "index": 1, "descr": "/", "type": "fixed_disk",
            "alloc_units_bytes": 4096,
            "size_units": 25000000, "used_units": 12500000,
            "size_bytes": 102400000000, "used_bytes": 51200000000,
        },
        ...
    ],
}, "warnings": []}
```

If the agent does not register `HOST-RESOURCES-MIB`, the tool returns
`ok=False` with `category="unsupported"` and a hint pointing the user at
`device_detect`.

#### `printer_status(host)`

Walk the relevant subtrees of `PRINTER-MIB` (RFC 3805). Works across
vendors (HP, Brother, Canon, OKI, Epson, Lexmark) because the MIB
standardizes the data model. Returns:

```python
{"ok": True, "host": "printer-lobby", "data": {
    "device_status": "running",  # from hrDeviceStatus when present
    "printer_status": "idle",     # prtGeneralPrinterStatus
    "supplies": [
        {
            "index": "1.1", "descr": "Black Toner",
            "type": "toner", "unit": "percent",
            "max_capacity": 100, "current_level": 65,
            "level_pct": 65,
        },
        {
            "index": "1.2", "descr": "Drum",
            "type": "opc", "unit": "percent",
            "max_capacity": 100, "current_level": 87,
            "level_pct": 87,
        },
        ...
    ],
    "input_trays": [
        {"index": "1.1", "name": "Tray 1", "capacity": 250,
         "current_level": 200, "media_type": "plain", "status": "ok"},
        ...
    ],
    "output_bins": [
        {"index": "1.1", "name": "Top", "capacity": 100,
         "current_level": 0, "status": "ok"},
    ],
    "alerts": [
        # prtAlertTable entries, if any
        {"index": "1.1", "severity": "warning", "training_level": "untrainedTechnical",
         "group": "supplies", "description": "Black Toner low"},
    ],
}, "warnings": []}
```

`current_level` of `-2` (the PRINTER-MIB sentinel for "unknown") is
normalized to `None` and `level_pct` is computed only when both
`max_capacity` and `current_level` are non-negative. `current_level` of
`-3` ("we know it's there but can't measure") is preserved as `-3` for
caller inspection.

#### `device_detect(host)`

Quick probe to report which standard MIBs the device supports. Issues a
small fixed set of GETs:

- `SNMPv2-MIB::sysObjectID.0` (always — used as vendor hint).
- `SNMPv2-MIB::sysDescr.0` (always).
- `IF-MIB::ifNumber.0` (probe `IF-MIB`).
- `HOST-RESOURCES-MIB::hrSystemUptime.0` (probe `HOST-RESOURCES-MIB`).
- `PRINTER-MIB::prtGeneralPrinterStatus.1.1` (probe `PRINTER-MIB`).

Returns:

```python
{"ok": True, "host": "printer-lobby", "data": {
    "sys_object_id": "1.3.6.1.4.1.1248.1.2.2",
    "vendor_hint": "Seiko Epson",         # decoded from enterprise OID
    "sys_descr": "EPSON Built-in 11.42 ...",
    "supported_mibs": ["SNMPv2-MIB", "IF-MIB", "HOST-RESOURCES-MIB", "PRINTER-MIB"],
}, "warnings": []}
```

The `vendor_hint` is looked up against a small built-in table of
well-known enterprise OIDs (IANA-assigned numbers under
`1.3.6.1.4.1`). Unknown enterprises fall through to
`vendor_hint = "unknown"`.

---

## 6. Configuration

### File format

TOML, default location `~/.config/snmp-mcp/config.toml`. Honours
`$XDG_CONFIG_HOME` and `SNMP_MCP_CONFIG` (absolute path override).

```toml
[defaults]
port = 161
timeout = 3.0
retries = 2
verify_engine_id = true

[hosts.switch-core]
address = "10.0.0.10"
version = "v2c"
community = "..."        # or SNMP_MCP_SWITCH_CORE_COMMUNITY env var

[hosts.secure-router]
address = "10.0.0.1"
version = "v3"
user = "monitor"
auth_proto = "SHA"
auth_pass = "..."        # prefer env var
priv_proto = "AES128"
priv_pass = "..."        # prefer env var
context = ""
```

### Env-var override schema

Host names are normalized for env-var prefixing: lowercased letters,
digits unchanged, non-alphanumerics → `_`, the whole prefix is
uppercased. So:

- `switch-core` → `SNMP_MCP_SWITCH_CORE_*`
- `printer.example.com` → `SNMP_MCP_PRINTER_EXAMPLE_COM_*`

Recognized field suffixes:

| Field              | Env-var suffix(es)                |
| ------------------ | --------------------------------- |
| `address`          | `IP`, `HOST`, `ADDRESS`           |
| `version`          | `VERSION`                         |
| `port`             | `PORT`                            |
| `timeout`          | `TIMEOUT`                         |
| `retries`          | `RETRIES`                         |
| `community`        | `COMMUNITY`                       |
| `user`             | `USER`                            |
| `auth_proto`       | `AUTH_PROTO`                      |
| `auth_pass`        | `AUTH_PASS`, `AUTH_PASSWORD`      |
| `priv_proto`       | `PRIV_PROTO`                      |
| `priv_pass`        | `PRIV_PASS`, `PRIV_PASSWORD`      |
| `context`          | `CONTEXT`                         |
| `verify_engine_id` | `VERIFY_ENGINE_ID`                |

Env-var values override file values.

---

## 7. MIB-to-tool mapping

| Tool                | MIB(s) consulted                                         | RFC      | Notes                                                                 |
| ------------------- | -------------------------------------------------------- | -------- | --------------------------------------------------------------------- |
| `snmp_get`          | (any)                                                    | n/a      | Pass-through GET.                                                     |
| `snmp_walk`         | (any)                                                    | n/a      | GETNEXT chain.                                                        |
| `snmp_bulk_walk`    | (any)                                                    | n/a      | GETBULK; falls back to walk on v1.                                    |
| `snmp_table`        | (any conformant table)                                   | n/a      | Tabularizes via index suffix parsing.                                 |
| `system_info`       | `SNMPv2-MIB::system`                                     | RFC 3418 | Always implemented by SNMPv2c+ agents.                                |
| `interfaces_list`   | `IF-MIB::ifTable` + `IF-MIB::ifXTable`                   | RFC 2863 | HC counters from `ifXTable` preferred where present.                  |
| `host_resources`    | `HOST-RESOURCES-MIB`                                     | RFC 2790 | Linux `net-snmp` and many appliances; unsupported on bare switches.   |
| `printer_status`    | `PRINTER-MIB` (Printer Working Group)                    | RFC 3805 | Vendor-neutral. Sentinel values (-2, -3) handled per RFC.             |
| `device_detect`     | `SNMPv2-MIB::system` + first OIDs of `IF-MIB`, `HOST-RESOURCES-MIB`, `PRINTER-MIB` | n/a      | Heuristic probe. Reports which MIBs respond, plus a vendor hint.      |

---

## 8. Testing strategy

### Unit tests

- Located in `tests/unit/`.
- Use a small in-process fake `SnmpEngine` (or pysnmp's testing harness)
  to stand in for a real agent.
- Fixtures live in `tests/fixtures/` — canonical varbind dumps per MIB
  scenario, plus expected-output dumps for happy/error paths.
- Coverage targets: each tool's happy path + at least one error case
  (timeout, no-such-name, no-such-instance, end-of-MIB-view, malformed
  varbind, transport error).
- Auth: SNMPv2c happy path + SNMPv3 authPriv happy path + SNMPv3
  authFailed.

### Live integration tests

- Located in `tests/integration/`.
- Gated behind the `SNMP_MCP_LIVE_HOST` env var. Skipped by default. CI
  never runs these.
- Strictly **read-only**: no SET, no walks of unbounded subtrees, no
  writes to any configuration mechanism.
- Cover: all 4 generic primitives + all 5 MIB wrappers, against a real
  network device. CRS312 (the reference target) supports `SNMPv2-MIB`,
  `IF-MIB`, and `HOST-RESOURCES-MIB` (for the RouterOS host). It does NOT
  support `PRINTER-MIB` — that case is exercised against a separate
  printer target (`SNMP_MCP_LIVE_PRINTER_HOST`).

### CI

- `.github/workflows/test.yml`: matrix on Python 3.11 / 3.12.
- `ruff check` + `ruff format --check` enforced.
- `pytest --cov` on unit tests only (live integration gated).

---

## 9. Versioning and SNMP compatibility

### Protocol support

- **SNMPv1** — supported. `snmp_bulk_walk` falls back to `snmp_walk` with
  a warning. `noSuchInstance`/`noSuchObject` varbind tags don't exist;
  missing OIDs surface as `errorStatus=2 noSuchName`.
- **SNMPv2c** — first-class.
- **SNMPv3** — first-class with USM (auth + priv).

### Counter-width handling

- 32-bit `Counter32` (`ifInOctets`, `ifOutOctets`): wraps in seconds at
  multi-gigabit rates. v0 returns them verbatim but always also returns
  the 64-bit `Counter64` HC equivalents (`ifHCInOctets`, `ifHCOutOctets`)
  when the agent exposes `ifXTable`.
- 32-bit `Gauge32` `ifSpeed`: saturates at 4,294,967,295 bps ≈ 4.29 Gbps.
  v0 detects saturation (`ifSpeed == 4294967295`) and substitutes
  `ifHighSpeed * 1e6` when available, emitting a warning and setting
  `ifSpeed_source = "ifHighSpeed"`.

### Index parsing for tables

SNMP table indices are encoded in the OID suffix. v0 returns the index as
a string (the raw suffix), and additionally splits multi-component
indices on `.` for callers who want per-component access. Index columns
are also re-emitted as named columns when their column-OID mapping is
known.

---

## 10. Security

### Credentials at rest

- Community strings and SNMPv3 passphrases are loaded from config files
  or env vars. The config file is expected to be `0600`-permissioned by
  the operator; the loader does not enforce that but the `examples/`
  README does.
- v3 passphrases are passed straight through to pysnmp's `UsmUserData`,
  which derives the per-engine localized keys. v0 does not implement key
  rotation or pre-localized-key support.

### Credentials in logs

- `__repr__` on credential-bearing dataclasses masks community and
  passphrase fields (`***` for non-empty values).
- No tool surface returns the community or passphrase in any response
  payload.

### Network

- All polling happens over UDP/161 by default. No TLS / DTLS support in
  v0 (SNMP-over-TLS is rare in the wild).
- The MCP host's source IP matters: if a device's SNMP community is
  source-restricted (a common practice on managed switches), the MCP
  process must run on a host whose IP is in the device's ACL.

### Read-only by design

v0 implements no SET operations of any kind. There is no codepath in
this codebase that issues a SET PDU. A future writes module would live
in a separate `mibs/writes/` subtree behind an explicit feature flag.

---

## 11. Out of scope for v0

The following are intentionally excluded from v0. Each is either a
substantially different design (trap receiver, time-series) or large
enough to warrant its own track:

- **SNMP SET (writes).** Read-only by design. Future major version.
- **Trap / inform receiver.** Long-running listener daemon. Different
  process model from a request/response MCP stdio server.
- **Custom MIB compilation at runtime.** Standard IETF MIBs only in v0.
  If a vendor-specific MIB is needed (e.g., MikroTik enterprise wireless
  counters), the workaround is to call `snmp_walk` with the raw OID and
  parse the response in the caller.
- **MIB browser GUI.** The tool surface is the API.
- **Time-series storage or polling schedules.** That's a job for HA,
  Prometheus, Telegraf, etc. This MCP returns the current value on
  request.
- **`SNMP-NOTIFICATION-MIB` / `SNMP-USER-BASED-SM-MIB` writes.**
  Configuring SNMPv3 users on the agent side. Out of scope for v0.
- **SNMP-over-TLS / DTLS (RFC 6353).** Rare in the wild; v0 is UDP-only.
