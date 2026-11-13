"""Single-shot pslist measurement for the subprocess baseline.

This represents the per-tool-call cost paid by subprocess-based MCP
servers (bornpresident/volatility-mcp-server, Gaffx/volatility-mcp,
OMGhozlan/Volatility-MCP-Server). All three invoke the ``vol`` CLI
in a freshly spawned Python interpreter on every tool call, so this
runner mirrors that pattern: one fresh ``vol -f IMAGE windows.pslist``
invocation per trial, capturing stdout exactly as their MCP servers
relay it back to Claude.

Output: JSON file with {system, output_str, output_bytes, latency_s,
n_processes}.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path


def resolve_vol_cmd() -> list[str]:
    """Return the command prefix to invoke the volatility3 CLI."""
    vol = shutil.which("vol")
    if vol:
        return [vol]
    return [sys.executable, "-m", "volatility3"]


def count_processes(stdout: str) -> int:
    """Count rows in vol.py default text-renderer pslist output.

    A data row begins with a numeric PID column; banner, progress, and
    header lines do not.
    """
    count = 0
    for line in stdout.splitlines():
        first = line.split(None, 1)
        if first and first[0].isdigit():
            count += 1
    return count


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    cmd = [*resolve_vol_cmd(), "-f", args.image, "windows.pslist"]

    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=600,
    )
    t1 = time.perf_counter()

    output_str = proc.stdout
    record = {
        "system": "volpy",
        "output_str": output_str,
        "output_bytes": len(output_str.encode("utf-8")),
        "latency_s": t1 - t0,
        "n_processes": count_processes(output_str),
    }
    Path(args.output).write_text(json.dumps(record), encoding="utf-8")


if __name__ == "__main__":
    main()
