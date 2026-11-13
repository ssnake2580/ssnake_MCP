"""Measure Gaffx MCP server's plugin invocation latency (W1 only).

Each trial spawns a fresh Python subprocess of runner_gaffx.py, which
boots the FastAPI middleware and the Gaffx MCP server, opens an MCP
client session, and calls one tool. Only the tool call is timed
(server boot and FastAPI health probe excluded), matching the
exclusion rule used for our MCP and bornpresident.

Workloads:
  - W1 single: one get_processes call (pslist via FastAPI subprocess).

W2 chain is intentionally absent: Gaffx exposes only 3 MCP tools
(get_processes, get_connections, get_cmdline) and cannot run the
5-plugin triage chain used for the other systems. The W2 column in
the paper table is marked "not supported" for this baseline.

Output:
  - stdout: Markdown-friendly summary.
  - eval/gaffx_results.json: mean / std / per-trial latency for W1.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
PROJECT = EVAL_DIR.parents[2]
RUNNER = EVAL_DIR / "runner_gaffx.py"
SYSTEM_NAME = "gaffx MCP"
RESULT_JSON = "gaffx_results.json"


def run_trial(image: str, workload: str) -> dict:
    fd, raw_path = tempfile.mkstemp(suffix=".json", prefix=f"gaffx_{workload}_")
    os.close(fd)
    out_path = Path(raw_path)
    cmd = [
        sys.executable,
        str(RUNNER),
        "--image", image,
        "--output", str(out_path),
        "--workload", workload,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, cwd=str(PROJECT), timeout=1800)
        return json.loads(out_path.read_text(encoding="utf-8"))
    finally:
        out_path.unlink(missing_ok=True)


def aggregate(records: list[dict]) -> dict:
    latency = [r["latency_s"] for r in records]
    n_procs = [r["n_processes"] for r in records]
    bytes_per_trial = [
        r.get("output_bytes_total", r.get("output_bytes", 0)) for r in records
    ]

    def m_s(xs: list[float]) -> tuple[float, float]:
        return statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)

    lm, ls = m_s(latency)
    bm, bs = m_s(bytes_per_trial)
    return {
        "trials": len(records),
        "latency_mean": lm,
        "latency_std": ls,
        "latency_per_trial": latency,
        "output_bytes_mean": bm,
        "output_bytes_std": bs,
        "output_bytes_per_trial": bytes_per_trial,
        "throughput_kbps_mean": (bm / 1024.0) / lm if lm > 0 else 0.0,
        "n_processes": n_procs[0] if n_procs else 0,
        "n_processes_consistent": len(set(n_procs)) == 1,
    }


def fmt_pm(mean: float, std: float, decimals: int = 2) -> str:
    return f"{mean:.{decimals}f} +/- {std:.{decimals}f}"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--runs", type=int, default=20, help="Measured trials per workload (default 20)")
    p.add_argument("--no-warmup", action="store_true")
    p.add_argument(
        "--workloads",
        default="single",
        help="Comma-separated workloads. Gaffx only supports 'single'.",
    )
    args = p.parse_args()

    image_path = Path(args.image)
    if not image_path.is_absolute():
        image_path = (PROJECT / image_path).resolve()
    if not image_path.exists():
        sys.exit(f"Image not found: {image_path}")

    image = str(image_path)
    workloads = [w.strip() for w in args.workloads.split(",") if w.strip()]
    for wl in workloads:
        if wl != "single":
            sys.exit(
                f"Gaffx supports only the 'single' workload (3 MCP tools, "
                f"no dlllist/malfind). Refusing to run: {wl}"
            )
    aggregates: dict[str, dict] = {}

    print(f"Image:           {image}")
    print(f"Trials/workload: {args.runs}")
    print()

    for wl in workloads:
        if not args.no_warmup:
            print(f"[warmup] {wl} ...", flush=True)
            try:
                run_trial(image, wl)
            except subprocess.CalledProcessError as e:
                err = e.stderr.decode("utf-8", "replace") if e.stderr else str(e)
                sys.exit(f"warmup failed for {wl}: {err}")

        print(f"[{wl}] {args.runs} trials")
        records: list[dict] = []
        for i in range(args.runs):
            r = run_trial(image, wl)
            print(f"  trial {i + 1:>2}: latency={r['latency_s']:.3f}s  procs={r['n_processes']}")
            records.append(r)
        aggregates[wl] = aggregate(records)

    print()
    print(f"{'System':<19}{'Workload':<10}{'Latency (s)':<18}{'Bytes (KB)':<14}{'KB/s':<9}{'Trials'}")
    print("-" * 85)
    for wl, a in aggregates.items():
        kb_m = a['output_bytes_mean'] / 1024.0
        kb_s = a['output_bytes_std'] / 1024.0
        print(
            f"{SYSTEM_NAME:<19}{wl:<10}"
            f"{fmt_pm(a['latency_mean'], a['latency_std']):<18}"
            f"{fmt_pm(kb_m, kb_s, decimals=1):<14}"
            f"{a['throughput_kbps_mean']:>6.1f}   "
            f"{a['trials']}"
        )
    print()

    for wl, a in aggregates.items():
        if not a["n_processes_consistent"]:
            print(f"WARNING: process counts varied across trials in {wl}")

    out_path = EVAL_DIR / RESULT_JSON
    out_path.write_text(
        json.dumps(
            {
                "image": image,
                "runs": args.runs,
                "system": SYSTEM_NAME,
                "workloads": aggregates,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
