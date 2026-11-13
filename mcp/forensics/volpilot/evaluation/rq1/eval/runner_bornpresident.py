"""Single-shot plugin measurement via bornpresident's MCP server.

Spawns ``vendor/bornpresident/volatility_mcp_server.py`` as a stdio
subprocess in its own isolated venv, opens an MCP client session, and
invokes one or five tool calls. Times only the tool calls themselves;
session handshake and server-process spawn are one-time setup costs
and are excluded.

Workloads:
  - single: one ``run_pslist`` call
  - chain:  five plugins back-to-back (run_pslist, run_dlllist,
            run_handles, run_malfind, run_netscan). Each call still
            spawns a fresh vol.py subprocess inside the server, so the
            subprocess startup cost is paid once per plugin (in
            contrast to ours' single Context).

Volatility version: 2.28.0 (pinned in vendor venv to match ours, so
the comparison isolates MCP-wrapper architecture, not vol3 plugin
code). Original bornpresident ships v2.11.0; replacing it controls
for plugin-code differences. Two small upstream patches were applied
(see vendor/PATCHES.md).

Output JSON: {system, workload, latency_s, n_processes,
output_bytes (single) | per_tool_s + output_bytes_per_tool +
output_bytes_total (chain)}.
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
VENDOR = PROJECT / "vendor" / "bornpresident"
SERVER_VENV_PY = VENDOR / ".venv" / "Scripts" / "python.exe"
SERVER_SCRIPT = VENDOR / "volatility_mcp_server.py"
VOL_WRAPPER = VENDOR / "vol_wrapper.py"

CHAIN_TOOLS = ["run_pslist", "run_dlllist", "run_cmdline", "run_malfind", "run_netscan"]

# Bind malfind to a single representative PID to keep W2 chain wall-time
# tractable on large images. 880 is lsass.exe in win11.mem; remap if the
# image is swapped. Must match the MALFIND_PID in eval/runner_ours.py and
# eval/runner_omghozlan.py so all systems scan the same address range.
MALFIND_PID = 880


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
    # The bornpresident server runs with cwd set to its own vendor dir,
    # so any relative image path would resolve incorrectly. Force absolute.
    image = str(Path(image).resolve())
    env = os.environ.copy()
    env["VOLATILITY_PYTHON"] = str(SERVER_VENV_PY)
    env["VOLATILITY_DIR"] = str(VENDOR)
    env["VOLATILITY_SCRIPT"] = str(VOL_WRAPPER)

    server = StdioServerParameters(
        command=str(SERVER_VENV_PY),
        args=[str(SERVER_SCRIPT)],
        env=env,
        cwd=str(VENDOR),
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            if workload == "single":
                t0 = time.perf_counter()
                result = await session.call_tool(
                    "run_pslist",
                    {"memory_dump_path": image},
                )
                t1 = time.perf_counter()
                output_str = result_to_text(result)
                record = {
                    "system": "bornpresident",
                    "workload": "single",
                    "latency_s": t1 - t0,
                    "n_processes": count_processes(output_str),
                    "output_bytes": len(output_str.encode("utf-8")),
                    "is_error": bool(getattr(result, "isError", False)),
                }
            else:
                per_tool_s: dict[str, float] = {}
                per_tool_bytes: dict[str, int] = {}
                pslist_text = ""
                t0 = time.perf_counter()
                for tool in CHAIN_TOOLS:
                    pt0 = time.perf_counter()
                    args = {"memory_dump_path": image}
                    if tool == "run_malfind":
                        args["pid"] = MALFIND_PID
                    result = await session.call_tool(tool, args)
                    per_tool_s[tool] = time.perf_counter() - pt0
                    tool_text = result_to_text(result)
                    per_tool_bytes[tool] = len(tool_text.encode("utf-8"))
                    if tool == "run_pslist":
                        pslist_text = tool_text
                t1 = time.perf_counter()
                record = {
                    "system": "bornpresident",
                    "workload": "chain",
                    "latency_s": t1 - t0,
                    "per_tool_s": per_tool_s,
                    "chain": CHAIN_TOOLS,
                    "n_processes": count_processes(pslist_text),
                    "output_bytes_per_tool": per_tool_bytes,
                    "output_bytes_total": sum(per_tool_bytes.values()),
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
        help="single = run_pslist only; chain = 5-tool triage sequence",
    )
    args = p.parse_args()
    asyncio.run(measure(args.image, args.output, args.workload))


if __name__ == "__main__":
    main()
