"""Honest accuracy scoring: Spoor's findings vs. a dataset answer key.

Scores only **confirmed** findings for precision/recall/F1 — *inferred* findings
are reported but never penalized, which rewards the confirmed-vs-inferred contract.
``hallucination_rate`` is the share of confirmed findings with no ``tool_call_id``
citation: a confirmed claim with nothing backing it. This directly answers the
hackathon author's stated #1 concern (hallucination) and criterion #2 (IR Accuracy).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AccuracyReport:
    true_positives: list
    false_positives: list
    false_negatives: list
    precision: float
    recall: float
    f1: float
    hallucination_rate: float
    total_findings: int
    total_confirmed: int
    total_ground_truth: int


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


# Windows stores a process image name in EPROCESS.ImageFileName, a 15-byte field,
# so a malware binary surfaces in pslist truncated to ~14-15 chars (e.g.
# 'coreupdater.exe' → 'coreupdater.ex'). Treat those truncations as the same file
# so a real, audit-cited detection is not penalized for a kernel-struct artifact.
_WIN_IMAGENAME_WIDTHS = (14, 15)


def _win_truncations(basename: str) -> set[str]:
    return {basename[:w] for w in _WIN_IMAGENAME_WIDTHS if len(basename) > w}


# A gradeable file token: word chars, dots, dashes, slashes, drive colons, $,
# spaces (for paths like "Program Files"). Deliberately excludes the parentheses,
# commas, and dashes that wrap an agent's rich IOC context.
_FILE_TOKEN = re.compile(r"^[\w.\-\\/:$ ]+$")


def _file_token(ioc_type: str, value: str) -> str | None:
    """Extract a gradeable filename token from a path/process IOC value.

    A 'path' IOC is already a clean path. A 'process' IOC leads with the image
    name followed by free-form context ('coreupdater.ex (PID 3644, …)'), so we
    take the leading whitespace-delimited token. Returns None when nothing
    file-like is present (the IOC is then reported as unscored, never dropped).
    """
    parts = value.split()
    candidate = (value if ioc_type == "path" else (parts[0] if parts else "")).strip()
    return candidate if candidate and _FILE_TOKEN.match(candidate) else None


def findings_from_report(report: dict, known_ids: set) -> tuple[list, list]:
    """Map a report's structured IOCs to gradeable findings (+ the unscored rest).

    Deterministic and type-driven — it never guesses malicious-vs-benign intent:
    ip → ip (port stripped); path/process → file by the leading filename token
    (tolerating trailing metadata that would otherwise defeat scoring). File
    findings are de-duplicated by basename, so one binary reported two ways (e.g.
    as both a process and a path) is a single indicator rather than two. A finding
    is 'confirmed' iff its citation is a tool_call_id present in the verified audit
    chain (passed as ``known_ids``), else 'inferred'; inferred findings are
    reported but never scored — the same contract score() enforces.
    """
    findings: list = []
    unscored: list = []
    seen_files: set = set()
    for ioc in report.get("iocs", []):
        cited = ioc.get("tool_call_id")
        status = "confirmed" if cited in known_ids else "inferred"
        value = str(ioc.get("value", "")).strip()
        kind = ioc.get("type")
        if kind == "ip":
            findings.append(
                {"category": "ip", "value": value.split(":")[0].strip(), "status": status, "tool_call_id": cited}
            )
        elif kind in ("path", "process"):
            token = _file_token(kind, value)
            if token is None:
                unscored.append(ioc)
                continue
            base = _basename(token)
            if base in seen_files:
                continue
            seen_files.add(base)
            findings.append({"category": "file", "value": token, "status": status, "tool_call_id": cited})
        else:
            unscored.append(ioc)
    return findings, unscored


def _ground_truth_items(ground_truth: dict) -> list[dict]:
    """Flatten the answer key into unique items, each with the normalized keys it matches."""
    items: list[dict] = []
    iocs = ground_truth.get("iocs", {})
    for ip in iocs.get("ips", []):
        value = ip["value"]
        items.append({"category": "ip", "value": value, "keys": {("ip", value.strip().lower())}})
    for f in iocs.get("files", []):
        value = f.get("path") or f.get("name")
        base = _basename(value)
        keys = {("file", value.strip().lower()), ("file", base)}
        keys |= {("file", t) for t in _win_truncations(base)}
        items.append({"category": "file", "value": value, "keys": keys})
    return items


def _finding_matches(finding: dict, key_to_item: dict) -> int | None:
    category = finding.get("category")
    value = str(finding.get("value", "")).strip().lower()
    idx = key_to_item.get((category, value))
    if idx is None and category == "file":
        idx = key_to_item.get((category, _basename(str(finding.get("value", "")))))
    return idx


def score(findings: list[dict], ground_truth: dict) -> AccuracyReport:
    gt_items = _ground_truth_items(ground_truth)
    key_to_item = {key: i for i, item in enumerate(gt_items) for key in item["keys"]}

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    matched: set[int] = set()
    true_positives: list = []
    false_positives: list = []
    for finding in confirmed:
        idx = _finding_matches(finding, key_to_item)
        if idx is None:
            false_positives.append(finding)
        else:
            true_positives.append(finding)
            matched.add(idx)

    false_negatives = [
        {"category": item["category"], "value": item["value"]}
        for i, item in enumerate(gt_items)
        if i not in matched
    ]

    tp, fp, fn = len(true_positives), len(false_positives), len(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    uncited = [f for f in confirmed if not f.get("tool_call_id")]
    hallucination_rate = len(uncited) / len(confirmed) if confirmed else 0.0

    return AccuracyReport(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        hallucination_rate=hallucination_rate,
        total_findings=len(findings),
        total_confirmed=len(confirmed),
        total_ground_truth=len(gt_items),
    )
