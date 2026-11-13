# Baseline MCP server patches (RQ1)

RQ1 compares our implementation against three existing subprocess-based
Volatility 3 MCP servers. To keep the comparison reproducible we pin each
baseline to an exact upstream commit and apply a small, enumerated set of
patches on top. The patches do three things only: make the server start on
a clean host, pin Volatility 3 to a common version, and let `malfind`
target a single PID so the chain benchmark is feasible at scale. No patch
changes how the server parses or renders plugin output.

## Pinned upstream versions

| Baseline | Upstream repository | Pinned commit |
|---|---|---|
| bornpresident | <https://github.com/bornpresident/Volatility-MCP-Server> | `ee33d4f9a9141706367c7ea9abd94b6c929db0fc` (2025-07-07) |
| gaffx | <https://github.com/Gaffx/volatility-mcp> | `8c9aafcf530f73834ff014e36df09996f97688ef` (2025-07-09) |
| omghozlan | <https://github.com/OMGhozlan/Volatility-MCP-Server> | `af006de10b7db17483d8af166fc3edd6ccbe0b08` (2025-10-07) |

## Reproduce a baseline

Clone upstream, check out the pinned commit, and apply our patch. The patch
files are complete: they include both the edits to tracked files and the
new helper files we added (`vol_wrapper.py`, `run_stdio.py`).

```bash
# bornpresident
git clone https://github.com/bornpresident/Volatility-MCP-Server.git bornpresident
git -C bornpresident checkout ee33d4f9a9141706367c7ea9abd94b6c929db0fc
git -C bornpresident apply ../bornpresident.patch

# gaffx
git clone https://github.com/Gaffx/volatility-mcp.git gaffx
git -C gaffx checkout 8c9aafcf530f73834ff014e36df09996f97688ef
git -C gaffx apply ../gaffx.patch

# omghozlan
git clone https://github.com/OMGhozlan/Volatility-MCP-Server.git omghozlan
git -C omghozlan checkout af006de10b7db17483d8af166fc3edd6ccbe0b08
git -C omghozlan apply ../omghozlan.patch
```

Each baseline runs in its own isolated virtual environment with
`volatility3==2.28.0` (and `pycryptodome` for gaffx's registry plugins) so
the table compares MCP wrappers, not Volatility 3 versions.

## What each patch contains

### `bornpresident.patch`
- **vol_wrapper.py** (new): a `volatility3.cli.main()` shim, since the pip
  package ships no standalone `vol.py`. Preserves the upstream
  "subprocess of vol.py" architecture.
- **volatility_mcp_server.py**: fix an upstream syntax error; honour
  `VOLATILITY_DIR` / `VOLATILITY_SCRIPT` env vars instead of a hardcoded
  path; let `run_malfind` accept an optional `--pid`; return stdout when
  `vol.py` exits `rc!=0` but stdout is non-empty (dlllist emits `rc=1` as
  a warning while the payload is complete).

### `gaffx.patch`
- **http_client.py**: raise `DEFAULT_TIMEOUT` from 30 s to 600 s. Cold ISF
  resolution and large-image chain plugins exceed 30 s and otherwise
  surface as a read timeout. No other change; gaffx exposes only three
  tools and does not support the five-plugin chain (W2).

### `omghozlan.patch`
- **vol_wrapper.py** (new): same `vol.py` shim as bornpresident.
- **run_stdio.py** (new): an stdio-transport entry point that runs the same
  FastMCP object via `mcp.run()` instead of upstream's SSE-over-HTTP, so
  all systems are measured over the same transport. No upstream code is
  edited to switch transports.
- **volatility_mcp_server.py**: add `stdin=DEVNULL` to the async subprocess
  call (avoids a Windows/Python 3.13 deadlock); return stdout on `rc!=0`
  when non-empty (same fix as bornpresident).
- **plugins/windows/memory_plugins.py**: let `Malfind.run` accept `--pid`.

## Note on the bornpresident W2 byte count

The `rc!=0` stdout fix for bornpresident landed after its W2 (chain)
production run. Rather than re-measure, the bornpresident W2 byte count in
the paper's Table 4 carries a synthetic correction (measured latency
unchanged; bytes adjusted to the per-plugin total expected under the
patch), flagged in the table. The omghozlan fix landed before its run, so
its bytes are a direct measurement.
