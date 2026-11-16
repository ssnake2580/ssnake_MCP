# scapy-mcp

[![Code style: crackerjack](https://img.shields.io/badge/code%20style-crackerjack-000042)](https://github.com/lesleslie/crackerjack)
[![Runtime: oneiric](https://img.shields.io/badge/runtime-oneiric-6e5494)](https://github.com/lesleslie/oneiric)
[![Framework: FastMCP](https://img.shields.io/badge/framework-FastMCP-0ea5e9)](https://github.com/PrefectHQ/fastmcp)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Python: 3.14+](https://img.shields.io/badge/python-3.14%2B-green)](https://www.python.org/downloads/)

MCP server wrapping [scapy](https://scapy.net) for packet crafting, dissection,
pcap staging, and live BPF capture. Tools operate on a worker that holds a
`scapy_mcp.config.settings.ScapySettings` instance and respect a four-stage
transmit policy before any frame leaves the host.

**Version:** 0.1.1 — BSD-3-Clause — Python ≥ 3.14 — alpha status

## Install

```bash
uv pip install scapy-mcp
scapy-mcp
```

The console script `scapy-mcp` resolves to `scapy_mcp.__main__:main`, which
builds the FastMCP ASGI app and serves it on uvicorn (so the custom
`/readyz` route is mounted). Set `SCAPY_MCP_HTTP_PORT` to override the
default port 3056.

For local development:

```bash
uv sync --group dev
uv run scapy-mcp
```

## Configure

Settings layer: defaults → `settings/scapy-mcp.yaml` → `settings/local.yaml`
→ `SCAPY_MCP_*` environment variables (pydantic-settings nested delimiter
is `__`). Nested config (e.g. `auth`) uses `SCAPY_MCP_AUTH__ENABLED=true`.

| Setting | Default | Purpose |
|---|---|---|
| `http_port` | `3056` | MCP HTTP listener port |
| `tool_profile` | `full` | `MINIMAL`, `STANDARD`, or `FULL` profile |
| `log_level` | `INFO` | oneiric LoggingConfig level |
| `default_iface` | `None` | capture iface when caller omits one |
| `capture_packet_cap` | `10000` | per-session packet ceiling |
| `capture_duration_cap_seconds` | `60` | per-session wall-clock ceiling |
| `capture_default_bpf_filter` | `None` | global BPF filter applied when caller omits one |
| `capture_executor_workers` | `2` | ThreadPoolExecutor size for the sync sniff fallback |
| `pcap_write_dir` | `<tmpdir>/scapy_mcp/pcap-staging` | write-side staging root (path-containment enforced) |
| `pcap_read_max_bytes` | `52428800` | read-side ceiling; `read_pcap` refuses larger files *before* parsing |
| `transmit_enabled` | `false` | **master kill-switch** — must be `true` to emit any frame |
| `transmit_allow_l3_cidrs` | `[]` | L3 CIDR allow-list |
| `transmit_allow_l2` | `false` | allow L2 (ARP / ND / RAW) emission |
| `transmit_allow_broadcast` | `false` | allow broadcast destination |
| `transmit_max_pps` | `10` | per-session packets-per-second cap |
| `transmit_max_per_session` | `100` | per-session total packet cap |
| `transmit_max_probe_targets` | `16` | per-call probe-target count cap |

## Tools

The server registers 9 domain tools + the mcp-common baseline tools.

| Group | Tool | Purpose |
|----------|------------------|---------|
| craft | `craft_packet` | Build a `Packet` from a `LayerSpec` discriminated union |
| dissect | `dissect_bytes` | Parse raw bytes into layers + summary text |
| pcap | `read_pcap` | Read packet summaries from a pcap at `path`, with `offset`/`limit` windowing |
| pcap | `write_pcap` | Stage a pcap into `pcap_write_dir` (paths outside the dir refused) |
| capture | `capture_start` | Start a BPF-filtered capture (optional feed) |
| capture | `capture_stop` | Stop an in-progress capture session |
| capture | `capture_read` | Read summaries from an active capture session |
| transmit | `transmit_packet` | Send a single packet after every transmit control passes |
| transmit | `probe_packet` | One-shot emit at a small BPF, used to confirm the surface works |
| health | `health` | Per-feed aggregate status (counts + last error) |

Plus the four mcp-common baseline tools — `discover_tools`,
`get_liveness`, `get_readiness`, `health_check_all` — registered
unconditionally via `bootstrap_baseline_tools`.

### `read_pcap` contract

`read_pcap` accepts an **arbitrary path** (a file produced by
`write_pcap`, a pre-existing capture, or a fixture) and returns
summaries. Before parsing, the file size is checked against
`pcap_read_max_bytes`; oversize files are refused with
`ConfigurationError` so multi-GB captures cannot exhaust memory by
being loaded whole. Path containment under `pcap_write_dir` is the
*write* path's concern, not read's.

## Health

Two routes, answering different questions:

- **`/health`** — always HTTP 200. Reports per-feed detail in `components`.
  For orchestrators and `curl` smoke probes.
- **`/readyz`** — HTTP 503 when a required feed has not yet returned data,
  200 otherwise. For readiness probes.

The `capture` feed is **optional**: its absence never flips `/readyz`
to 503. All other registered feeds are required.

## Four transmit controls

Every `transmit_packet` call is checked against:

1. **Master kill-switch** (`transmit_enabled: bool`, default `false`). The default
   refuses every frame — set `SCAPY_MCP_TRANSMIT_ENABLED=true` to permit
   emission at all.
1. **L3 CIDR allow-list** (`transmit_allow_l3_cidrs: list[str]`). Set to
   `["0.0.0.0/0"]` for unrestricted L3; production deployments pin the
   specific CIDRs the worker is allowed to reach.
1. **L2 destination allow-flag** (`transmit_allow_l2: bool`, default `false`).
   Pure ARP / ND / RAW frames require this flag; L3 packets do not.
1. **Broadcast opt-in** (`transmit_allow_broadcast: bool`, default `false`).
   Even after the L2/L3 allow-list, broadcasts refuse unless this is `true`.

A refusal emits an `EmissionRefusedError` with the failing `control` name and a
human-readable reason. The wrapper logs a `scapy-write-would-refuse` /
`scapy-transmit-refused` warning so the refusal is visible without polluting
the caller's error stream.

## BPF probe (`capture`)

Capture is OPTIONAL. When `/dev/bpf*` is missing `capture_start` refuses
with `CapabilityUnavailableError` and the `capture` feed is marked
unavailable. `/readyz` stays 200 because capture is not a required feed.

### Backend selection

The capture worker picks one of two backends at session start:

- **`AsyncSniffer`** — preferred when scapy exposes it (≥ 2.5). Each
  session owns a sniffer; `capture_stop` calls `.stop()` and
  `capture_read` reads `.results`.
- **`sniff(stop_filter=...)`** — synchronous fallback executed in the
  module-level worker pool. `stop_filter` checks a per-session cancel
  event so `capture_stop` works; `packet_cap` and `duration_cap` are
  enforced via `count` and `timeout` on the underlying sniff call.

If scapy exposes neither backend, `capture_start` refuses with
`CapabilityUnavailableError` (reason = "no sniffer backend").

## Deterministic fixtures

Tests do **not** open raw sockets. All packet construction is exercised
against in-memory fixtures under `tests/fixtures/`. Each fixture includes a
hand-crafted `bytes()` body that round-trips through `craft_packet` →
`rdpcap`/`wrpcap` → `dissect_bytes`. No real network frames in the suite.

Regenerate via:

```bash
python -m scripts.gen_pcap_fixtures
```

## Default = closed-by-default transmit

The shipped defaults cannot emit a frame:

```
transmit_enabled = false
transmit_allow_l3_cidrs = []
transmit_allow_l2 = false
transmit_allow_broadcast = false
```

A worker installs only what its operator explicitly approves. See
`scapy_mcp/config/settings.py` for the full settings surface.

## License

BSD-3-Clause.

Built on [Oneiric](https://github.com/lesleslie/oneiric) for runtime configuration
and [mcp-common](https://github.com/lesleslie/mcp-common) for the FastMCP
baseline. [Crackerjack](https://github.com/lesleslie/crackerjack) gates every commit.
