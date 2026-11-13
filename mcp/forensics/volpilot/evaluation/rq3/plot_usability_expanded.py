"""Render usability.png from the final participant observations in rq3.csv.

Run from any directory:
    uv run --with matplotlib python /path/to/plot_usability_expanded.py

Group totals and overall means are calculated from the CSV, without fixed
cohort weights. The current study includes 32 participants (16 per group).
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
CSV_PATH = HERE / "rq3.csv"
OUT_PATH = HERE / "usability.png"

# Internal proficiency keys (as stored in the CSV) and their figure labels.
TIERS = ["beginner", "intermediate", "expert"]
TIER_LABELS = ["Beginner", "Intermediate", "Expert"]


def load():
    time = defaultdict(list)
    conv = defaultdict(list)
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["proficiency"].strip(), row["group"].strip())
            time[key].append(float(row["completion_time_min"]))
            conv[key].append(float(row["convenience_score"]))
    for tier in TIERS:
        for group in ("control", "test"):
            if not time[(tier, group)]:
                raise ValueError(f"Missing observations for {tier}/{group}")
    return time, conv


def mean(xs):
    return sum(xs) / len(xs)


def main():
    time, conv = load()

    t_ctrl = np.array([mean(time[(t, "control")]) for t in TIERS])
    t_test = np.array([mean(time[(t, "test")]) for t in TIERS])
    c_ctrl = np.array([mean(conv[(t, "control")]) for t in TIERS])
    c_test = np.array([mean(conv[(t, "test")]) for t in TIERS])

    x = np.arange(len(TIERS))
    width = 0.36
    control_color = "#C8504F"
    mcp_color = "#5B9BD5"
    control_line = "#7A2E2D"
    mcp_line = "#2E5F8A"

    plt.rcParams.update({"font.size": 8})

    fig, ax = plt.subplots(figsize=(3.5, 2.8))
    ax2 = ax.twinx()

    ax.bar(x - width / 2, t_ctrl, width, label="Control",
           color=control_color, edgecolor="black", linewidth=0.3, zorder=2)
    ax.bar(x + width / 2, t_test, width, label="Test (ours)",
           color=mcp_color, edgecolor="black", linewidth=0.3, zorder=2)

    ax2.plot(x - width / 2, c_ctrl, "o--", color=control_line,
             markersize=5, linewidth=1.3, markeredgecolor="black",
             markeredgewidth=0.3, zorder=4)
    ax2.plot(x + width / 2, c_test, "s--", color=mcp_line,
             markersize=5, linewidth=1.3, markeredgecolor="black",
             markeredgewidth=0.3, zorder=4)

    ax.set_ylabel("Completion time, min (bars)")
    ax2.set_ylabel("Convenience, 1-10 (lines)")
    ax.set_ylim(0, float(max(t_ctrl.tolist() + t_test.tolist())) * 1.18)
    ax2.set_ylim(0, 10.5)
    ax.set_xticks(x)
    ax.set_xticklabels(TIER_LABELS)
    ax.legend(loc="upper right", fontsize=7, frameon=True)
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)

    fig.tight_layout()
    fig.savefig(OUT_PATH, dpi=300, bbox_inches="tight")

    plt.close(fig)
    print(f"wrote {OUT_PATH}")
    print("Participant-level aggregates from rq3.csv:")
    for group in ("control", "test"):
        all_times = [v for tier in TIERS for v in time[(tier, group)]]
        all_scores = [v for tier in TIERS for v in conv[(tier, group)]]
        counts = "/".join(str(len(time[(tier, group)])) for tier in TIERS)
        print(f"  {group}: n={len(all_times)}; beginner/intermediate/expert={counts}")
        print(f"    completion time: {mean(all_times):.1f} min")
        print(f"    convenience score: {mean(all_scores):.1f} / 10")



if __name__ == "__main__":
    main()
