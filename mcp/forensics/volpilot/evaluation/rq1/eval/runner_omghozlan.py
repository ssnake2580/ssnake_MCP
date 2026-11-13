"""Single-shot W1 / W2 measurement via OMGhozlan's MCP server.

Per-trial sequence: spawn vendor/omghozlan/run_stdio.py as a stdio
subprocess in its own isolated venv, open an MCP client session, and
call one or five tools. Times only the tool calls themselves; session
handshake and server-process spawn are one-time setup costs and are
excluded.

Workloads:
  - single: one run_plugin(plugin_name='windows.PsList') call.
  - chain:  five plugins back-to-back via the generic run_plugin
            dispatcher: windows.PsList, windows.DllList, windows.CmdLine,
            windows.Malfind (kw_args={"pid": MALFIND_PID}), windows.NetScan.
            All five share one MCP session, but each call still spawns
            a fresh vol.py subprocess inside the server, so the
            subprocess startup cost is paid once per plugin (in
            contrast to ours' single Context).

Transport substitution
----------------------
Upstream omghozlan defaults to SSE (`mcp.run_sse_async`) in its
``__main__`` block. The eval runner imports the same FastMCP object and
runs it under stdio instead (FastMCP's other supported transport, used
by bornpresident and gaffx). This isolates MCP-wrapper cost from
transport-specific overhead and keeps the per-call timing apples-to-
apples across the four systems in Table 4 (\S5.1). See
``vendor/PATCHES.md``.

Volatility version: 2.28.0 (pinned in vendor venv to match ours,
bornpresident, and gaffx).

Output JSON:
  single: {system, workload, latency_s, n_processes, output_bytes, is_error}
  chain:  {system, workload, latency_s, per_plugin_s, chain, n_processes,
           output_bytes_per_plugin, output_bytes_total}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT = Path(__file__).resolve().parents[3]
VENDOR = PROJECT / "vendor" / "omghozlan"
SERVER_VENV_PY = VENDOR / ".venv" / "Scripts" / "python.exe"
STDIO_ENTRY = VENDOR / "run_stdio.py"

W1_PLUGIN = "windows.PsList"

# Bind malfind to a single representative PID for the W2 chain. 880 is
# lsass.exe in win11.mem; remap if the image is swapped. Must match the
# MALFIND_PID in runner_ours.py and runner_bornpresident.py so all systems
# scan the same address range.
MALFIND_PID = 880

# Chain composition: same five plugins as the other systems' W2 chain.
# Malfind is targeted at a single PID via kw_args.
CHAIN_PLUGINS = [
    ("windows.PsList", None),
    ("windows.DllList", None),
    ("windows.CmdLine", None),
    ("windows.Malfind", {"pid": MALFIND_PID}),
    ("windows.NetScan", None),
]


def count_processes(text: str) -> int:
    count = 0
    for line in text.splitlines():
        first = line.split(None, 1)
        if first and first[0].isdigit():
            count += 1
    return count


def result_to_text(result) -> str:
    parts: list[str] = []
    for c in result.content:
        text = getattr(c, "text", None)
        parts.append(text if text is not None else str(c))
    return "".join(parts)


async def measure(image: str, output_path: str, workload: str) -> None:
    image = str(Path(image).resolve())

    env = os.environ.copy()
    server = StdioServerParameters(
        command=str(SERVER_VENV_PY),
        args=[str(STDIO_ENTRY)],
        env=env,
        cwd=str(VENDOR),
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            if workload == "single":
                t0 = time.perf_counter()
                result = await session.call_tool(
                    "run_plugin",
                    {
                        "memory_dump_path": image,
                        "plugin_name": W1_PLUGIN,
                        "os_type": "windows",
                    },
                )
                t1 = time.perf_counter()
                output_str = result_to_text(result)
                record = {
                    "system": "omghozlan",
                    "workload": "single",
                    "latency_s": t1 - t0,
                    "n_processes": count_processes(output_str),
                    "output_bytes": len(output_str.encode("utf-8")),
                    "is_error": bool(getattr(result, "isError", False)),
                }
            else:
                per_plugin_s: dict[str, float] = {}
                per_plugin_bytes: dict[str, int] = {}
                pslist_text = ""
                t0 = time.perf_counter()
                for plugin_name, kw_args in CHAIN_PLUGINS:
                    pt0 = time.perf_counter()
                    tool_args = {
                        "memory_dump_path": image,
                        "plugin_name": plugin_name,
                        "os_type": "windows",
                    }
                    if kw_args:
                        tool_args["kw_args"] = kw_args
                    result = await session.call_tool("run_plugin", tool_args)
                    per_plugin_s[plugin_name] = time.perf_counter() - pt0
                    plugin_text = result_to_text(result)
                    per_plugin_bytes[plugin_name] = len(plugin_text.encode("utf-8"))
                    if plugin_name == "windows.PsList":
                        pslist_text = plugin_text
                t1 = time.perf_counter()
                record = {
                    "system": "omghozlan",
                    "workload": "chain",
                    "latency_s": t1 - t0,
                    "per_plugin_s": per_plugin_s,
                    "chain": [name for name, _ in CHAIN_PLUGINS],
                    "n_processes": count_processes(pslist_text),
                    "output_bytes_per_plugin": per_plugin_bytes,
                    "output_bytes_total": sum(per_plugin_bytes.values()),
                }

    Path(output_path).write_text(json.dumps(record), encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--output", required=True)
    p.add_argument(
        "--workload",
        choices=["single", "chain"],
        default="single",
        help=(
            "single = run_pslist only; chain = 5-plugin triage sequence "
            "(pslist, dlllist, cmdline, malfind --pid <MALFIND_PID>, netscan), "
            "all via the generic run_plugin dispatcher in a single MCP session."
        ),
    )
    args = p.parse_args()
    asyncio.run(measure(args.image, args.output, args.workload))


if __name__ == "__main__":
    main()
