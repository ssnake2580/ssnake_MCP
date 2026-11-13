"""Export the canonical real-evidence run to one static JSON the proof-site
consumes. Reuses Spoor's own audit + scorer modules, so the published audit
records and accuracy numbers are identical to the engine — never re-typed.

Run:  uv run python scripts/export_site_data.py
Out:  web/data/case001.json   (committed; the site build stays pure-Node)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from spoor_sift.accuracy import findings_from_report, score  # noqa: E402
from spoor_sift.audit import AuditLog  # noqa: E402

RUN_DIR = REPO / "runs" / "2026-06-12-231634-case001-real"
GROUND_TRUTH = REPO / "datasets" / "case001_ground_truth_dc01_memory.json"
OUT = REPO / "web" / "data" / "case001.json"

FRAMING = (
    "Zero hallucination, real recall, and a precision cost that is over-reporting "
    "— not fabrication. The same type-driven rule that finally scores the real "
    "malware also surfaces the agent's injection-victim processes (legitimate "
    "Windows binaries flagged for RWX regions) as file false positives — real "
    "anomalies, just not in the 4-item memory-visible answer key."
)
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})")


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _metrics(r) -> dict:
    return {
        "precision": round(r.precision, 3),
        "recall": round(r.recall, 3),
        "f1": round(r.f1, 3),
        "hallucination_rate": round(r.hallucination_rate, 3),
        "confirmed_total": f"{r.total_confirmed}/{r.total_findings}",
        "ground_truth_items": r.total_ground_truth,
    }


def main() -> int:
    report = json.loads((RUN_DIR / "report.json").read_text())
    meta = json.loads((RUN_DIR / "run_meta.json").read_text())
    ground_truth = json.loads(GROUND_TRUTH.read_text())

    # Export-time gate: verify the source chain before publishing anything.
    log = AuditLog(RUN_DIR / "audit.jsonl")
    chain = log.verify()
    if not chain.ok:
        print(f"REFUSING to export: source chain broken at seq {chain.broken_seq}", file=sys.stderr)
        return 1
    known_ids = {rec.tool_call_id for rec in log.records()}

    audit = _read_jsonl(RUN_DIR / "audit.jsonl")  # byte-exact records

    # Accuracy via the engine's own scorer (computed, not parsed from markdown).
    findings, unscored = findings_from_report(report, known_ids)
    corrected = score(findings, ground_truth)
    raw_path = RUN_DIR / "findings.raw.json"
    raw_findings = json.loads(raw_path.read_text()).get("findings", []) if raw_path.exists() else []
    raw = score(raw_findings, ground_truth)

    data = {
        "meta": {
            "case": "DFIR Madness Case 001 — The Stolen Szechuan Sauce",
            "run_id": meta["thread_id"],
            "host": "DC01 (10.42.85.10)",
            "captured": "2020-09-19",
            "lead_model": meta["lead_model"],
            "specialist_model": meta["specialist_model"],
            "started_utc": meta["started_utc"],
            "finished_utc": meta["finished_utc"],
            "audit_records": meta["audit_records"],
            "audit_chain_ok": meta["audit_chain_ok"],
            "evidence_sha256_pre": meta["evidence_sha256_pre"],
            "evidence_sha256_post": meta["evidence_sha256_post"],
            "evidence_integrity_ok": meta["evidence_integrity_ok"],
            "scenario": meta["scenario"],
        },
        "audit": audit,
        "verdict": {
            "executive_summary": report["executive_summary"],
            "findings": report["findings"],
            "iocs": report["iocs"],
            "open_questions": report["open_questions"],
            "enforcement": report["enforcement"],
            "report_audit_id": report["report_audit_id"],
        },
        "accuracy": {
            **_metrics(corrected),
            "pre_correction": {
                "precision": round(raw.precision, 3),
                "recall": round(raw.recall, 3),
                "f1": round(raw.f1, 3),
            },
            "true_positives": corrected.true_positives,
            "false_positives": corrected.false_positives,
            "false_negatives": corrected.false_negatives,
            "unscored": unscored,
            "framing": FRAMING,
        },
    }

    leak = SECRET_RE.search(json.dumps(data))
    if leak:
        print(f"REFUSING to export: possible secret {leak.group(0)[:6]}…", file=sys.stderr)
        return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"wrote {OUT.relative_to(REPO)} — {len(audit)} records, chain OK, "
        f"P{corrected.precision:.2f}/R{corrected.recall:.2f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
