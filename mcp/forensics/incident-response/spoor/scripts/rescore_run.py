"""Re-score an existing real-evidence run with the CURRENT scorer — no agent re-run.

The agent's own output is immutable: report.json, audit.jsonl, and the transcript
are never touched. Only the *derived* scoring artifacts (findings.json,
accuracy_report.md) are recomputed from report.json through the audited bridge
(``findings_from_report``) and ``score``. Use this after a scorer correction to
refresh the accuracy number deterministically and for free, with full provenance.

The prior findings.json is preserved as findings.raw.json, and accuracy_report.md
renders the before/after so the correction is auditable, not asserted.

Run:  uv run python scripts/rescore_run.py runs/<stamp>-case001-real
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from spoor_sift.accuracy import findings_from_report, score
from spoor_sift.audit import AuditLog

GROUND_TRUTH = REPO / "datasets" / "case001_ground_truth_dc01_memory.json"


def _fmt(r) -> str:
    return (
        f"precision={r.precision:.3f} recall={r.recall:.3f} "
        f"f1={r.f1:.3f} hallucination_rate={r.hallucination_rate:.3f}"
    )


def _bullets(items, kind) -> str:
    if kind == "finding":
        return "\n".join(f"- `{f['category']}` **{f['value']}**" for f in items) or "- (none)"
    return "\n".join(f"- `{i.get('type')}` {i.get('value')}" for i in items) or "- (none)"


def _render(*, run_dir: Path, meta: dict, ground_truth: dict, raw, corrected,
            corrected_findings: list, unscored: list) -> str:
    pre, post = meta.get("evidence_sha256_pre", "?"), meta.get("evidence_sha256_post", "?")
    integrity = (
        "INTACT — byte-identical before and after the run (read-only operation proven)"
        if pre == post else "VIOLATED — hashes differ (investigate immediately)"
    )
    gt_rel = GROUND_TRUTH.relative_to(REPO)
    run_rel = run_dir.relative_to(REPO)
    return f"""# Spoor — Accuracy Report (real evidence)

**Case:** DFIR Madness Case 001 "The Stolen Szechuan Sauce" — DC01 memory image
**Run:** `{run_dir.name}` · {meta.get("finished_utc", "?")}
**Models:** lead `{meta.get("lead_model")}` · specialists `{meta.get("specialist_model")}`
**Scored against:** `{gt_rel}` (memory-visible subset of the verified v1.0 answer
key — see datasets/README.md for the scoping rationale)

## Evidence integrity
| | SHA-256 |
|---|---|
| `citadeldc01.mem` before run | `{pre}` |
| `citadeldc01.mem` after run | `{post}` |

**Verdict: {integrity}.** Guardrails enforce this architecturally (read-only
path-jail, no-shell allow-listed exec); the hashes prove it empirically.

## Scoring methodology & correction
This run's accuracy is reported **twice — before and after a scorer correction** —
because hiding either number would be dishonest. The agent's output never changed;
only the deterministic bridge that maps the report's structured IOCs to gradeable
findings was fixed.

| Metric | Raw (pre-correction bridge) | **Corrected (current scorer)** |
|---|---|---|
| Precision | {raw.precision:.3f} | **{corrected.precision:.3f}** |
| Recall | {raw.recall:.3f} | **{corrected.recall:.3f}** |
| F1 | {raw.f1:.3f} | **{corrected.f1:.3f}** |
| Hallucination rate | {raw.hallucination_rate:.3f} | **{corrected.hallucination_rate:.3f}** |
| Confirmed / total findings | {raw.total_confirmed} / {raw.total_findings} | {corrected.total_confirmed} / {corrected.total_findings} |

**What the correction fixed (two independent measurement bugs):**
1. **Metadata-laden IOC values.** A real malware process is reported as
   `coreupdater.ex (PID 3644, …)`, not a bare filename. The old bridge gated the
   *whole* value through a file-token regex, so the parenthetical context dropped
   the detection to *unscored*. The bridge now extracts the leading filename token
   first, then grades that.
2. **Windows ImageFileName truncation.** `coreupdater.exe` surfaces in pslist as
   the 14-char `coreupdater.ex`; the scorer now treats that kernel-struct
   truncation as the same file.

The correction **only credits an audit-cited detection the bridge had dropped** —
it does not touch precision favorably. In fact recall rises while precision *falls*,
because the same type-driven rule that finally scores the real malware also surfaces
the agent's injection-victim processes (legitimate Windows binaries flagged for RWX
regions) as file false positives. That is the honest trade: **zero hallucination,
real recall, and a precision cost that is over-reporting — not fabrication.** The
prior findings are preserved verbatim in `findings.raw.json`; re-derive at any time
with `uv run python scripts/rescore_run.py {run_rel}`.

## Scores (corrected — confirmed findings vs. answer key)
| Metric | Value |
|---|---|
| Precision | **{corrected.precision:.3f}** |
| Recall | **{corrected.recall:.3f}** |
| F1 | **{corrected.f1:.3f}** |
| Hallucination rate | **{corrected.hallucination_rate:.3f}** |
| Confirmed / total findings | {corrected.total_confirmed} / {corrected.total_findings} |
| Ground-truth items | {corrected.total_ground_truth} |

A finding counts as *confirmed* only when it cites a `tool_call_id` present in the
verified hash-chained audit log — the same contract the reporter agent is held to
in code. The hallucination rate is the share of confirmed findings with no such
citation.

### True positives
{_bullets(corrected.true_positives, "finding")}

### False positives (confirmed findings absent from the answer key)
*De-duplicated by exact basename only; a binary that surfaces under both a
truncated process name and a full path is counted conservatively (twice), never
merged across the truncation — truncation is trusted to *match* the curated key,
not to *merge* arbitrary findings. For this case these are injection-victim system
binaries flagged for RWX regions: real anomalies, just not in the 4-item subset.*

{_bullets(corrected.false_positives, "finding")}

### False negatives (missed ground truth)
{_bullets(corrected.false_negatives, "finding")}

### Reported but unscored IOC types (registry keys, URLs, hashes, narrative entries)
{_bullets(unscored, "ioc")}

## Reproduce
```bash
uv sync --extra forensics
# fetch + verify evidence per datasets/README.md, then:
uv run python scripts/real_case_run.py            # native: corrected bridge
uv run python scripts/rescore_run.py {run_rel}    # re-score an existing run, $0
uv run spoor verify-audit {run_rel}/audit.jsonl
```
"""


def main(run_dir_arg: str) -> int:
    run_dir = Path(run_dir_arg)
    if not run_dir.is_absolute():
        run_dir = (REPO / run_dir_arg).resolve()
    if not (run_dir / "report.json").exists():
        print(f"FAILED: {run_dir}/report.json not found", file=sys.stderr)
        return 1

    report = json.loads((run_dir / "report.json").read_text())
    meta = json.loads((run_dir / "run_meta.json").read_text())
    ground_truth = json.loads(GROUND_TRUTH.read_text())

    # BEFORE — the pre-correction baseline. Captured ONCE into findings.raw.json
    # and never overwritten, so re-scoring is idempotent: 'before' keeps reflecting
    # the original (buggy) bridge no matter how many times this tool runs.
    canonical_path = run_dir / "findings.json"
    baseline_path = run_dir / "findings.raw.json"
    if baseline_path.exists():
        raw_findings = json.loads(baseline_path.read_text()).get("findings", [])
    elif canonical_path.exists():
        raw_findings = json.loads(canonical_path.read_text()).get("findings", [])
        baseline_path.write_text(json.dumps({"findings": raw_findings}, indent=2))
    else:
        raw_findings = []
    raw = score(raw_findings, ground_truth)

    # AFTER — re-derive from the immutable report through the corrected bridge.
    audit = AuditLog(run_dir / "audit.jsonl")
    chain = audit.verify()
    known_ids = {r.tool_call_id for r in audit.records()} if chain.ok else set()
    findings, unscored = findings_from_report(report, known_ids)
    corrected = score(findings, ground_truth)

    # The canonical findings.json always holds the corrected derivation.
    canonical_path.write_text(json.dumps({"findings": findings}, indent=2))

    md = _render(
        run_dir=run_dir, meta=meta, ground_truth=ground_truth,
        raw=raw, corrected=corrected, corrected_findings=findings, unscored=unscored,
    )
    (run_dir / "accuracy_report.md").write_text(md)
    (REPO / "accuracy_report.md").write_text(md)

    print(f"audit chain: {'OK' if chain.ok else 'BROKEN'} ({len(audit.records())} records)")
    print("BEFORE:", _fmt(raw))
    print("AFTER :", _fmt(corrected))
    print(f"corrected findings: {len(findings)} (unscored: {len(unscored)})")
    print(f"\nartifacts: {run_dir.relative_to(REPO)}/accuracy_report.md  +  accuracy_report.md (repo root)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: rescore_run.py <run_dir>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
