"""E1 orchestrator: token & latency comparison for windows.pslist.

For each system under test, spawns a fresh Python subprocess running the
appropriate single-shot runner. Each fresh subprocess approximates a
'cold' tool call from Claude's point of view -- exactly what the
subprocess-based MCP servers pay per call, and what our server pays once
on first invocation after startup.

Pipeline per trial:
    1. orchestrator -> subprocess.run(runner_X.py --image ... --output ...)
    2. runner writes a JSON record with output_str, output_bytes, latency_s
    3. orchestrator reads JSON, encodes output_str via tiktoken cl100k_base
    4. aggregate mean / std across N trials

Result table is printed to stdout and the raw aggregate is written to
``eval/e1_results.json`` for paper inclusion.
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

import tiktoken

EVAL_DIR = Path(__file__).resolve().parent
PROJECT = EVAL_DIR.parents[2]

SYSTEMS: dict[str, list[str]] = {
    "VolPilot (ours)": [sys.executable, str(EVAL_DIR / "runner_ours.py")],
    "vol.py text (subprocess)": [sys.executable, str(EVAL_DIR / "runner_volpy.py")],
}


def run_trial(cmd: list[str], image: str) -> dict:
    fd, raw_path = tempfile.mkstemp(suffix=".json", prefix="e1_")
    os.close(fd)
    out_path = Path(raw_path)
    full = [*cmd, "--image", image, "--output", str(out_path)]
    try:
        subprocess.run(full, check=True, capture_output=True, cwd=str(PROJECT), timeout=600)
        return json.loads(out_path.read_text(encoding="utf-8"))
    finally:
        out_path.unlink(missing_ok=True)


def aggregate(records: list[dict], encoder) -> dict:
    bytes_ = [r["output_bytes"] for r in records]
    tokens = [len(encoder.encode(r["output_str"])) for r in records]
    latency = [r["latency_s"] for r in records]
    procs = [r["n_processes"] for r in records]

    def m_s(xs: list[float]) -> tuple[float, float]:
        return statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)

    bm, bs = m_s(bytes_)
    tm, ts = m_s(tokens)
    lm, ls = m_s(latency)
    return {
        "n_processes": procs[0] if procs else 0,
        "n_processes_consistent": len(set(procs)) == 1,
        "bytes_mean": bm,
        "bytes_std": bs,
        "tokens_mean": tm,
        "tokens_std": ts,
        "latency_mean": lm,
        "latency_std": ls,
        "trials": len(records),
    }


def fmt_pm(mean: float, std: float, decimals: int = 1) -> str:
    return f"{mean:.{decimals}f} ± {std:.{decimals}f}"


def print_table(aggregates: dict[str, dict]) -> None:
    headers = ["System", "Output bytes", "Output tokens", "Latency (s)"]
    rows: list[list[str]] = []
    for name, a in aggregates.items():
        rows.append([
            name,
            fmt_pm(a["bytes_mean"], a["bytes_std"], 0),
            fmt_pm(a["tokens_mean"], a["tokens_std"], 0),
            fmt_pm(a["latency_mean"], a["latency_std"], 2),
        ])
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]

    def line(cells: list[str]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths))

    print()
    print(line(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(line(row))
    print()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True, help="Path to memory image (e.g. win11.mem)")
    p.add_argument("--runs", type=int, default=5, help="Trials per system (default 5)")
    p.add_argument(
        "--no-warmup",
        action="store_true",
        help="Skip the per-system warmup trial (use only if ISF symbols already cached)",
    )
    args = p.parse_args()

    image_path = Path(args.image)
    if not image_path.is_absolute():
        image_path = (PROJECT / image_path).resolve()
    if not image_path.exists():
        sys.exit(f"Image not found: {image_path}")

    encoder = tiktoken.get_encoding("cl100k_base")

    print(f"Image:           {image_path}")
    print(f"Trials/system:   {args.runs}")
    print(f"Tokenizer:       tiktoken cl100k_base (Claude proxy)")
    print()

    if not args.no_warmup:
        for name, cmd in SYSTEMS.items():
            print(f"[warmup] {name} ...", flush=True)
            try:
                run_trial(cmd, str(image_path))
            except subprocess.CalledProcessError as e:
                print(f"  FAILED: {e.stderr.decode('utf-8', 'replace') if e.stderr else e}")
                raise

    aggregates: dict[str, dict] = {}
    for name, cmd in SYSTEMS.items():
        print(f"[{name}] {args.runs} trials")
        records: list[dict] = []
        for i in range(args.runs):
            r = run_trial(cmd, str(image_path))
            print(f"  trial {i + 1}: bytes={r['output_bytes']:>8}  latency={r['latency_s']:.2f}s  procs={r['n_processes']}")
            records.append(r)
        aggregates[name] = aggregate(records, encoder)

    print_table(aggregates)

    for name, a in aggregates.items():
        if not a["n_processes_consistent"]:
            print(f"WARNING: {name} returned varying process counts across trials.")

    out_path = EVAL_DIR / "e1_results.json"
    out_path.write_text(
        json.dumps(
            {
                "image": str(image_path),
                "runs": args.runs,
                "tokenizer": "tiktoken/cl100k_base",
                "results": aggregates,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
