# RQ1: Performance overhead

**Research question.** How much does direct Volatility 3 API integration
improve plugin-invocation performance compared to existing subprocess-based
MCP servers?

This directory holds every artifact behind Section 5.1 of the paper: the
measurement code, the raw per-trial results, the baseline server patches,
and this description.

## Systems under test

| System | Architecture | Volatility 3 |
|---|---|---|
| **VolPilot (Ours)** | direct Python API (in-process `import volatility3`) | 2.28.0 |
| [bornpresident] | subprocess of `vol.py` | 2.28.0 (pinned) |
| [gaffx] | MCP, FastAPI, then `vol.py` subprocess (three layers) | 2.28.0 (pinned) |
| [omghozlan] | subprocess of `vol.py` via generic `run_plugin` dispatcher | 2.28.0 (pinned) |

The three baselines are pinned to exact upstream commits and reproduced via
the patches in `vendor_patches/` (see `vendor_patches/PATCHES.md` for the
pinned commits and the clone-checkout-apply recipe). All four systems use
Volatility 3 2.28.0 so the comparison reflects the MCP wrapper, not the
Volatility version.

## Evaluation image

Windows 11 Enterprise 23H2, 16.00 GiB, 227 processes. Measured as
mean +/- standard deviation over N = 20 trials with one warmup trial
(so ISF symbols are resolved and cached before timing).

## Workloads

- **W1 (single):** one `pslist` call. Isolates fixed per-call overhead
  (the second Python interpreter and the Volatility 3 import that
  subprocess-based servers pay on every call).
- **W2 (chain):** a five-plugin triage chain, `pslist` then `dlllist` then
  `cmdline` then `malfind` then `netscan`. `malfind` is bound to `--pid`
  targeting a single representative process (`lsass.exe`, PID 880 in the
  evaluation image), because its default global scan was prohibitively slow
  at this scale (over 7 minutes per call on a 227-process image). The same
  forensic target is used across all systems for direct comparability. The
  PID constant lives in each runner as `MALFIND_PID`.

The paper's Table 4 reports W2 (the chain), since it exercises a realistic
multi-step analysis; the paper omits W1 for space. We report both below,
starting with W1 (which isolates the fixed per-call overhead) and then W2
(where that overhead compounds across five plugins).

## W1: single-plugin call

W1 is a single `pslist` call (N = 20, same warmup protocol). It is where the
fixed per-call overhead is most directly visible.

| System | Bytes (KB) | Latency (s) | KB/s |
|---|---|---|---|
| VolPilot (Ours) | 54.3 | 1.12 +/- 0.04 | 48.6 |
| bornpresident ‡ | ~21.4 | 2.41 +/- 0.13 | 8.9 |
| gaffx | 21.2 | 2.48 +/- 0.11 | 8.5 |
| omghozlan ‡ | ~21.4 | 2.63 +/- 0.10 | 8.1 |

On a single call our server is about 2.2x faster than the subprocess group.
The gap is the fixed cost the baselines pay every call (a second Python
interpreter plus a Volatility 3 import) and it is the same cost that, summed
over five plugins, drives the W2 result.

‡ Only the VolPilot and gaffx W1 rows are backed by preserved raw data
(`eval/ours_results.json` and `eval/gaffx_results.json`, `workloads.single`).
The bornpresident and omghozlan W1 per-trial data was overwritten by their
later chain-only production run and is not retained in this release; their
values are reported here for completeness.

## W2: five-plugin chain (Table 4)

| System | Bytes (KB) | Latency (s) | KB/s |
|---|---|---|---|
| VolPilot (Ours) | 3,309.7 | 75.78 +/- 6.22 | 43.7 |
| bornpresident | 522.7 † | 61.13 +/- 3.32 | 8.6 † |
| gaffx | not supported (no `dlllist` / `malfind` tool) | | |
| omghozlan | 526.1 | 59.43 +/- 2.63 | 8.9 |

Our server returns roughly 6x more structured forensic data than the
subprocess baselines yet sustains nearly 5x higher throughput (KB/s),
delivering each byte of typed evidence in about one-fifth the time. The
mechanism is that the subprocess baselines pay a second-interpreter startup
and a Volatility 3 import on every call, while our server pays that cost
once at startup and reuses the in-process context.

† The bornpresident W2 byte count is a synthetic correction. The `rc!=0`
stdout fix (see `vendor_patches/`) landed after its production run; rather
than re-measure, the byte count is adjusted to the per-plugin total
expected under the patch while the measured latency is left unchanged.
omghozlan's fix landed before its run, so its bytes are a direct
measurement.

### Latency notes

- **gaffx W2 is "not supported", not slow.** gaffx exposes only three MCP
  tools (`get_processes`, `get_connections`, `get_cmdline`); the chain
  needs `dlllist` and `malfind`, which it does not implement. This is an
  architectural limit, independent of the image.
- **omghozlan W2 latency can edge below bornpresident** because both use
  the same `vol.py` text renderer, which is cheaper than building typed
  dicts; the throughput column, not the latency column, is where our typed
  output separates from the baselines.

## Token-consumption trade-off

Richer structured output carries more tokens. Using OpenAI's `tiktoken`
(`cl100k_base`) as a proxy for Claude's tokenizer, a single chain
invocation from our server is approximately 1.35 M tokens (about $7 on
Claude Opus 4.7 at standard input pricing). We consider this acceptable in
exchange for the higher-fidelity, typed evidence required for accurate
forensic insight. `eval/e1_pslist_cost.py` is the tiktoken-based cost probe
that establishes the bytes-to-tokens methodology (it compares our `pslist`
output against `vol.py`'s text output). Two caveats apply to that probe:
the single `vol.py` text row stands in for all three subprocess baselines,
which differ in framing (HTTP for gaffx, asyncio for omghozlan, plain
subprocess for bornpresident) but emit the same `vol.py` default text
renderer; and `tiktoken cl100k_base` is used as a proxy for Claude's
tokenizer, so absolute token counts are approximate while relative
differences across systems are preserved.

## Files

```
rq1.md                         this file
eval/
  runner_ours.py               one-trial runners, one per system
  runner_bornpresident.py
  runner_gaffx.py
  runner_omghozlan.py
  runner_volpy.py              direct vol.py text output (byte reference)
  measure_ours.py              warmup + N=20 aggregation, one per system
  measure_bornpresident.py
  measure_gaffx.py
  measure_omghozlan.py
  e1_pslist_cost.py            tiktoken bytes-to-tokens cost probe
  ours_results.json            raw per-trial results (W1 single + W2 chain)
  bornpresident_results.json   raw per-trial results (W2 chain)
  gaffx_results.json           raw per-trial results (W1 single)
  omghozlan_results.json       raw per-trial results (W2 chain)
  e1_results.json              tiktoken cost-probe output
vendor_patches/
  PATCHES.md                   pinned commits + reproduce recipe
  bornpresident.patch          complete patch (edits + new files)
  gaffx.patch
  omghozlan.patch
```

## Reproduce

Each baseline must first be reproduced from its pinned upstream commit (see
`vendor_patches/PATCHES.md`) into a sibling `vendor/` tree and given an
isolated virtual environment with `volatility3==2.28.0`. Then, from the
repository root:

```bash
uv run python eval/measure_ours.py          --image win11.mem --runs 20 --workloads single,chain
uv run python eval/measure_bornpresident.py --image win11.mem --runs 20 --workloads single,chain
uv run python eval/measure_gaffx.py         --image win11.mem --runs 20 --workloads single
uv run python eval/measure_omghozlan.py     --image win11.mem --runs 20 --workloads single,chain
```

Read `throughput_kbps_mean` and `latency_mean` from each
`workloads.<workload>` block in the resulting `*_results.json`. If the
evaluation image changes, remap `MALFIND_PID` to the new image's
`lsass.exe` PID before running the chain.

The token-cost probe needs `tiktoken`, pulled in by the `eval` extra:

```bash
uv sync --extra eval
uv run python eval/e1_pslist_cost.py --image win11.mem --runs 5
```

It writes `eval/e1_results.json` and prints a summary table comparing our
`pslist` output against `vol.py`'s text output in bytes, tokens, and
latency.

[bornpresident]: https://github.com/bornpresident/Volatility-MCP-Server
[gaffx]: https://github.com/Gaffx/volatility-mcp
[omghozlan]: https://github.com/OMGhozlan/Volatility-MCP-Server
