# Spoor — Accuracy Report (real evidence)

**Case:** DFIR Madness Case 001 "The Stolen Szechuan Sauce" — DC01 memory image
**Run:** `2026-06-12-231634-case001-real` · 2026-06-12T23:25:14.264861+00:00
**Models:** lead `anthropic/claude-sonnet-4.6` · specialists `anthropic/claude-sonnet-4.6`
**Scored against:** `datasets/case001_ground_truth_dc01_memory.json` (memory-visible subset of the verified v1.0 answer
key — see datasets/README.md for the scoping rationale)

## Evidence integrity
| | SHA-256 |
|---|---|
| `citadeldc01.mem` before run | `8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62` |
| `citadeldc01.mem` after run | `8079a7459b1739caf7d4fbf6dde5eb0ae7a9d24dbde657debf4d5202c8dc6b62` |

**Verdict: INTACT — byte-identical before and after the run (read-only operation proven).** Guardrails enforce this architecturally (read-only
path-jail, no-shell allow-listed exec); the hashes prove it empirically.

## Scoring methodology & correction
This run's accuracy is reported **twice — before and after a scorer correction** —
because hiding either number would be dishonest. The agent's output never changed;
only the deterministic bridge that maps the report's structured IOCs to gradeable
findings was fixed.

| Metric | Raw (pre-correction bridge) | **Corrected (current scorer)** |
|---|---|---|
| Precision | 0.333 | **0.250** |
| Recall | 0.250 | **0.500** |
| F1 | 0.286 | **0.333** |
| Hallucination rate | 0.000 | **0.000** |
| Confirmed / total findings | 3 / 3 | 8 / 8 |

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
with `uv run python scripts/rescore_run.py runs/2026-06-12-231634-case001-real`.

## Scores (corrected — confirmed findings vs. answer key)
| Metric | Value |
|---|---|
| Precision | **0.250** |
| Recall | **0.500** |
| F1 | **0.333** |
| Hallucination rate | **0.000** |
| Confirmed / total findings | 8 / 8 |
| Ground-truth items | 4 |

A finding counts as *confirmed* only when it cites a `tool_call_id` present in the
verified hash-chained audit log — the same contract the reporter agent is held to
in code. The hallucination rate is the share of confirmed findings with no such
citation.

### True positives
- `ip` **203.78.103.109**
- `file` **coreupdater.ex**

### False positives (confirmed findings absent from the answer key)
*De-duplicated by exact basename only; a binary that surfaces under both a
truncated process name and a full path is counted conservatively (twice), never
merged across the truncation — truncation is trusted to *match* the curated key,
not to *merge* arbitrary findings. For this case these are injection-victim system
binaries flagged for RWX regions: real anomalies, just not in the 4-item subset.*

- `file` **Microsoft.Acti**
- `file` **spoolsv.exe**
- `file` **explorer.exe**
- `file` **ServerManager.**
- `file` **svchost.exe**
- `file` **C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe**

### False negatives (missed ground truth)
- `ip` **194.61.24.102**
- `file` **secret.zip**

### Reported but unscored IOC types (registry keys, URLs, hashes, narrative entries)
- `url` 203.78.103.109:443/tcp
- `other` Phantom PPID 2244 (parent of coreupdater.ex PID 3644) — non-existent process
- `other` Phantom PPID 3960 (parent of explorer.exe PID 3472) — non-existent process
- `other` Phantom PPID 1904 (parent of ServerManager. PID 400) — non-existent process
- `other` Session 2 process on domain controller — coreupdater.ex PID 3644 — indicates attacker-controlled second interactive session
- `other` 15 VadS PAGE_EXECUTE_READWRITE anonymous memory regions across 5 processes — memory injection pattern
- `other` Network connection artifact: 10.42.85.10:62613 -> 203.78.103.109:443 ESTABLISHED (TCPv4, owner coreupdater.ex PID 3644)

## Reproduce
```bash
uv sync --extra forensics
# fetch + verify evidence per datasets/README.md, then:
uv run python scripts/real_case_run.py            # native: corrected bridge
uv run python scripts/rescore_run.py runs/2026-06-12-231634-case001-real    # re-score an existing run, $0
uv run spoor verify-audit runs/2026-06-12-231634-case001-real/audit.jsonl
```
