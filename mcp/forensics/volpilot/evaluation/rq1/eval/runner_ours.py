"""Single-shot plugin measurement for VolPilot (this project).

Spawned as a fresh subprocess per trial by an orchestrator. Records the
wall-clock cost of plugin invocation(s) after Session initialisation.

Workloads:
  - single: one ``run_plugin("pslist")`` call
  - chain:  five plugins back-to-back (pslist, dlllist, handles,
            malware.malfind, netscan). All share one Session, so the
            Context and intermediate caches are reused across calls.

Output: JSON file with {system, workload, latency_s, n_processes,
output_bytes (single) | output_bytes_per_plugin + output_bytes_total
(chain), chain (if applicable)}.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from session import Session

CHAIN = ["pslist", "dlllist", "cmdline", "malware.malfind", "netscan"]

# Bind malfind to a single representative PID to keep W2 chain wall-time
# tractable on large images. 880 is lsass.exe in win11.mem; remap to the
# new lsass.exe PID if the image is swapped. lsass is chosen because it
# is the canonical credential-injection target (Mimikatz family) and
# always present on Windows.
MALFIND_PID = 880


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--output", required=True)
    p.add_argument(
        "--workload",
        choices=["single", "chain"],
        default="single",
        help="single = pslist only; chain = 5-plugin triage sequence",
    )
    args = p.parse_args()

    # compute_hash=False: SHA-256 of a 36 GB image takes ~70 s and is a
    # one-time server-startup cost in production, not part of per-tool-call
    # latency. Including it per trial would inflate ours' measured latency
    # by an apples-to-oranges margin relative to subprocess baselines whose
    # startup does no such hash.
    sess = Session(args.image, compute_hash=False)

    if args.workload == "single":
        t0 = time.perf_counter()
        result = sess.run_plugin("pslist")
        t1 = time.perf_counter()
        output_str = json.dumps(result, ensure_ascii=False)
        record = {
            "system": "ours",
            "workload": "single",
            "latency_s": t1 - t0,
            "n_processes": len(result.get("results", [])),
            "output_bytes": len(output_str.encode("utf-8")),
        }
    else:
        # chain: time the full 5-plugin sequence on one Session.
        # Per-plugin timings + bytes are recorded so a slow or verbose
        # plugin can be identified without re-running the whole chain.
        # Bytes proxy what FastMCP would serialise back to Claude.
        results = {}
        per_plugin_s: dict[str, float] = {}
        per_plugin_bytes: dict[str, int] = {}
        t0 = time.perf_counter()
        for name in CHAIN:
            pt0 = time.perf_counter()
            kwargs = {"pid": MALFIND_PID} if name == "malware.malfind" else {}
            results[name] = sess.run_plugin(name, **kwargs)
            per_plugin_s[name] = time.perf_counter() - pt0
            per_plugin_bytes[name] = len(
                json.dumps(results[name], ensure_ascii=False).encode("utf-8")
            )
        t1 = time.perf_counter()
        record = {
            "system": "ours",
            "workload": "chain",
            "latency_s": t1 - t0,
            "per_plugin_s": per_plugin_s,
            "chain": CHAIN,
            "n_processes": len(results["pslist"].get("results", [])),
            "output_bytes_per_plugin": per_plugin_bytes,
            "output_bytes_total": sum(per_plugin_bytes.values()),
        }

    Path(args.output).write_text(json.dumps(record), encoding="utf-8")


if __name__ == "__main__":
    main()
