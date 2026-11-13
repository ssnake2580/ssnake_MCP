# Spoor — Accuracy Report (real evidence)

**Case:** DFIR Madness Case 001 "The Stolen Szechuan Sauce" — DC01 memory image
**Run:** `2026-06-14-155749-case001-real` · 2026-06-14T16:07:57.420910+00:00
**Models:** lead `anthropic/claude-sonnet-4.6` · specialists `anthropic/claude-sonnet-4.6`
**Scored against:** `datasets/case001_ground_truth_dc01_memory.json` (memory-visible subset of the
verified v1.0 answer key — see datasets/README.md for the scoping rationale)

## Evidence integrity
| | SHA-256 |
|---|---|
| `citadeldc01.mem` before run | `8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62` |
| `citadeldc01.mem` after run | `8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62` |

**Verdict: INTACT — byte-identical before and after the run (read-only operation proven).** Guardrails enforce this architecturally (read-only
path-jail, no-shell allow-listed exec); the hashes prove it empirically.

## Scores (confirmed findings vs. answer key)
| Metric | Value |
|---|---|
| Precision | **0.286** |
| Recall | **0.500** |
| F1 | **0.364** |
| Hallucination rate | **0.000** |
| Confirmed / total findings | 7 / 7 |
| Ground-truth items | 4 |

A finding counts as *confirmed* only when it cites a `tool_call_id` present in
the verified hash-chained audit log — the same contract the reporter agent is
held to in code. The hallucination rate is the share of confirmed findings with
no such citation.

### True positives
- `ip` **203.78.103.109**
- `file` **coreupdater.exe**

### False positives
- `file` **spoolsv.exe**
- `file` **Microsoft.ActiveDirectory.WebServices.exe**
- `file` **explorer.exe**
- `file` **ServerManager.exe**
- `file` **svchost.exe**

### False negatives (missed ground truth)
- `ip` **194.61.24.102**
- `file` **secret.zip**

### Reported but unscored IOC types (registry keys, URLs, hashes, narrative entries)
- `url` 203.78.103.109:443
- `hash` SHA-256: 8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62 (citadeldc01.mem)
- `hash` MD5: 0623f97fc80c12aa508ed9926b2ec04e (citadeldc01.mem)
- `other` PAGE_EXECUTE_READWRITE + VadS tag in non-image memory — 15 regions across 5 processes — process injection indicator
- `other` Orphaned parent PIDs: PPID 2244 (coreupdater.exe), PPID 1904 (ServerManager.exe), PPID 3960 (explorer.exe) — none present in process list
- `other` spoolsv.exe starting 2 hours 7 minutes after system boot (03:29:40 UTC vs boot at 01:22:38 UTC) — Print Spooler exploitation indicator

## Reproduce
```bash
uv sync --extra forensics
# fetch + verify evidence per datasets/README.md, then:
uv run python scripts/real_case_run.py
uv run spoor accuracy-report runs/2026-06-14-155749-case001-real/findings.json datasets/case001_ground_truth_dc01_memory.json
uv run spoor verify-audit runs/2026-06-14-155749-case001-real/audit.jsonl
```
