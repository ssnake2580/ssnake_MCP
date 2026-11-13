"""Single-shot W1 measurement via Gaffx's 3-layer MCP architecture.

Per-trial sequence (all inside one fresh subprocess of this script):

  1. Pick a free localhost port.
  2. Start uvicorn(volatility_fastapi_server:app) bound to that port,
     cwd = vendor/gaffx, VOLATILITY_BIN = vendor/gaffx/.venv/Scripts/vol.exe.
  3. Poll /plugins until 200 (FastAPI health check).
  4. Spawn vol_mcp_server.py via stdio with --image <abs> --url http://...
  5. Open MCP client session, time get_processes() tool call.
  6. Tear down both servers.

Only the tool call is timed. Server boot, lifespan validation, and the
HTTP health probe are excluded so the measurement isolates per-call
cost (analyst-perceived latency once the server is live), matching the
exclusion rule used for our MCP and bornpresident.

Workloads:
  - single: get_processes (FastAPI maps it to windows.pslist.PsList).

Chain (W2) is intentionally absent. Gaffx exposes only 3 MCP tools
(get_processes, get_connections, get_cmdline); the standard 5-plugin
triage chain (pslist > dlllist > cmdline > malfind > netscan) cannot
be executed via Gaffx's MCP layer.

Volatility version: 2.28.0 (pinned in the isolated vendor venv to
match ours), so the comparison isolates MCP-wrapper architecture, not
vol3 plugin code. See vendor/PATCHES.md.

Output JSON: {system, workload, latency_s, n_processes, output_bytes,
is_error}.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT = Path(__file__).resolve().parents[3]
VENDOR = PROJECT / "vendor" / "gaffx"
SERVER_VENV_PY = VENDOR / ".venv" / "Scripts" / "python.exe"
SERVER_VENV_UVICORN = VENDOR / ".venv" / "Scripts" / "uvicorn.exe"
SERVER_VENV_VOL = VENDOR / ".venv" / "Scripts" / "vol.exe"
MCP_SERVER_SCRIPT = VENDOR / "vol_mcp_server.py"
FASTAPI_MODULE = "volatility_fastapi_server:app"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_fastapi_ready(port: int, deadline_s: float = 30.0) -> None:
    url = f"http://127.0.0.1:{port}/plugins"
    end = time.perf_counter() + deadline_s
    last_err: Exception | None = None
    while time.perf_counter() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, ConnectionResetError, OSError) as e:
            last_err = e
        time.sleep(0.1)
    raise RuntimeError(f"FastAPI server did not become ready on :{port}: {last_err}")


def count_processes(text: str) -> int:
    count = 0
    for line in text.splitlines():
        first = line.split(None, 1)
        if first and first[0].isdigit():
            count += 1
    return count


def result_to_text(result) -> str:
    # Gaffx's MCP layer returns the plugin output as List[str] (one entry
    # per line; see vendor/gaffx/http_client.py _process_response), which
    # FastMCP encodes as one TextContent per line. Rejoin with newlines
    # so process-row parsing sees the original vol.py text layout.
    parts: list[str] = []
    for c in result.content:
        text = getattr(c, "text", None)
        parts.append(text if text is not None else str(c))
    return "\n".join(parts)


def start_fastapi(port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env["VOLATILITY_BIN"] = str(SERVER_VENV_VOL)
    cmd = [
        str(SERVER_VENV_UVICORN),
        FASTAPI_MODULE,
        "--host", "127.0.0.1",
        "--port", str(port),
        "--log-level", "warning",
    ]
    return subprocess.Popen(
        cmd,
        cwd=str(VENDOR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )


async def measure(image: str, output_path: str, workload: str) -> None:
    if workload != "single":
        raise ValueError(
            f"Gaffx supports only the 'single' workload (3 tools: pslist, "
            f"netscan, cmdline). Got: {workload}"
        )
    image = str(Path(image).resolve())

    port = free_port()
    fastapi_proc = start_fastapi(port)
    try:
        wait_fastapi_ready(port)

        env = os.environ.copy()
        server = StdioServerParameters(
            command=str(SERVER_VENV_PY),
            args=[
                str(MCP_SERVER_SCRIPT),
                "--image", image,
                "--url", f"http://127.0.0.1:{port}",
            ],
            env=env,
            cwd=str(VENDOR),
        )
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                t0 = time.perf_counter()
                result = await session.call_tool("get_processes", {})
                t1 = time.perf_counter()
                output_str = result_to_text(result)
                record = {
                    "system": "gaffx",
                    "workload": "single",
                    "latency_s": t1 - t0,
                    "n_processes": count_processes(output_str),
                    "output_bytes": len(output_str.encode("utf-8")),
                    "is_error": bool(getattr(result, "isError", False)),
                }
    finally:
        fastapi_proc.terminate()
        try:
            fastapi_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fastapi_proc.kill()
            fastapi_proc.wait(timeout=5)

    Path(output_path).write_text(json.dumps(record), encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--output", required=True)
    p.add_argument(
        "--workload",
        choices=["single"],
        default="single",
        help="Gaffx supports only W1 (single); see runner docstring.",
    )
    args = p.parse_args()
    asyncio.run(measure(args.image, args.output, args.workload))


if __name__ == "__main__":
    main()
