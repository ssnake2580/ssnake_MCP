# Spoor Submission Presentation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the two remaining FIND EVIL! artifacts — a silent ≤5-min demo walkthrough (`scripts/demo_walkthrough.sh` + a `spoor show-report` helper) and the Devpost writeup (`docs/devpost.md`).

**Architecture:** A self-narrating bash driver prints boxed banners (the on-screen narration, since the video has no voice) and runs only **$0** commands off the committed real run. The single new code unit is a `spoor show-report` CLI subcommand that renders `report.json` cleanly (raw JSON is unreadable on camera). The live `make real` kickoff (beat ②) is recorded separately and spliced in editing — never baked into the script. Devpost copy is derived prose, every claim cross-checked against the repo.

**Tech Stack:** Python 3.12 (argparse CLI, pytest), bash, Markdown. Run via `uv`.

**Spec:** `docs/superpowers/specs/2026-06-13-spoor-submission-presentation-design.md`

---

## File Structure

- **Create** `scripts/demo_walkthrough.sh` — the silent driver (banners + $0 commands + keypress pauses).
- **Create** `docs/devpost.md` — ready-to-paste Devpost copy.
- **Create** `tests/test_show_report.py` — tests for the report renderer.
- **Modify** `spoor_sift/cli.py` — add `render_report()` + `cmd_show_report()` + subparser wiring.
- **Modify** `README.md` — a short "Demo" pointer to the script.

---

### Task 1: `spoor show-report` — clean report renderer (beat ③)

**Files:**
- Test: `tests/test_show_report.py` (create)
- Modify: `spoor_sift/cli.py` (add `render_report`, `cmd_show_report`, wiring)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_show_report.py
from spoor_sift.cli import render_report

REPORT = {
    "executive_summary": "DC01 is compromised by coreupdater.exe beaconing to 203.78.103.109.",
    "findings": [
        {"claim": "coreupdater.ex (PID 3644) ran with a phantom parent.", "status": "confirmed", "tool_call_id": "a" * 64},
        {"claim": "The intrusion vector was likely RDP.", "status": "inferred", "tool_call_id": None},
    ],
    "iocs": [
        {"type": "ip", "value": "203.78.103.109", "tool_call_id": "a" * 64},
        {"type": "process", "value": "coreupdater.ex (PID 3644)", "tool_call_id": "a" * 64},
    ],
}


def test_render_report_shows_summary_confirmed_findings_and_iocs():
    out = render_report(REPORT)
    assert "DC01 is compromised by coreupdater.exe" in out
    assert "coreupdater.ex (PID 3644) ran with a phantom parent." in out
    assert "203.78.103.109" in out


def test_render_report_excludes_inferred_from_confirmed_section():
    out = render_report(REPORT)
    # inferred claims must not be presented as confirmed findings
    assert "The intrusion vector was likely RDP." not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH="$HOME/.local/bin:$PATH"; uv run pytest tests/test_show_report.py -q`
Expected: FAIL — `ImportError: cannot import name 'render_report' from 'spoor_sift.cli'`

- [ ] **Step 3: Add `render_report` + `cmd_show_report` to `spoor_sift/cli.py`**

Add after `cmd_accuracy_report` (around line 85):

```python
def render_report(report: dict) -> str:
    """Render a run's report.json for a terminal demo: summary, confirmed
    findings (each audit-cited), and indicators. Inferred claims are omitted
    from the confirmed section — the same confirmed-vs-inferred contract score()
    enforces."""
    lines: list[str] = []
    summary = str(report.get("executive_summary", "")).strip()
    if summary:
        lines += ["EXECUTIVE SUMMARY", summary, ""]
    findings = report.get("findings", [])
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    lines.append(f"CONFIRMED FINDINGS — {len(confirmed)}/{len(findings)} (each cites a verified tool_call_id)")
    for f in confirmed[:6]:
        claim = " ".join(str(f.get("claim", "")).split())
        lines.append(f"  [+] {claim[:140]}")
    iocs = report.get("iocs", [])
    if iocs:
        lines += ["", f"INDICATORS — {len(iocs)}"]
        for i in iocs[:8]:
            lines.append(f"  - [{i.get('type')}] {' '.join(str(i.get('value', '')).split())[:90]}")
    return "\n".join(lines)


def cmd_show_report(run_dir: str) -> int:
    path = Path(run_dir)
    report_path = path if path.suffix == ".json" else path / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    print(render_report(report))
    return 0
```

Wire the subparser in `main()` — add after the `accuracy-report` parser (around line 99):

```python
    p_show = sub.add_parser("show-report", help="render a run's report.json for a demo")
    p_show.add_argument("run_dir", help="a runs/<stamp>/ dir or a report.json path")
```

And add the dispatch branch after the `accuracy-report` branch (around line 107):

```python
    if args.command == "show-report":
        return cmd_show_report(args.run_dir)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_show_report.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Verify it renders the real run cleanly**

Run: `uv run spoor show-report runs/2026-06-12-231634-case001-real`
Expected: EXECUTIVE SUMMARY paragraph, a CONFIRMED FINDINGS block (coreupdater.ex, C2, hollowing…), and an INDICATORS list. No raw JSON, no truncated-mid-word ugliness.

- [ ] **Step 6: Run the full suite (no regressions)**

Run: `set -o pipefail; uv run pytest -q 2>&1 | tail -3`
Expected: all pass (112 total).

- [ ] **Step 7: Commit**

```bash
git add spoor_sift/cli.py tests/test_show_report.py
git commit -m "feat: spoor show-report — clean report rendering for the demo"
```

---

### Task 2: `scripts/demo_walkthrough.sh` — the silent driver

**Files:**
- Create: `scripts/demo_walkthrough.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Spoor — silent demo walkthrough. No voice: the on-screen banners narrate.
# $0 and self-contained — runs only free commands off the committed real run.
# Beat ② (the live `make real` kickoff) is recorded SEPARATELY and spliced in
# editing; never bake a paid, evidence-dependent run into this script.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN_DIR="${1:-runs/2026-06-12-231634-case001-real}"
GT="datasets/case001_ground_truth_dc01_memory.json"
UV="${UV:-uv}"
BAR="════════════════════════════════════════════════════════════════════"

banner() { printf '\n%s\n  %s\n%s\n\n' "$BAR" "$1" "$BAR"; }
pause()  { printf '  [ press enter ▸ ] '; read -r _ || true; printf '\n'; }
runcmd() { printf '  $ %s\n\n' "$*"; "$@"; }

banner "SPOOR — find evil, and prove it.    ·    FIND EVIL! / SANS hackathon"
pause

banner "① EVIDENCE — DC01 domain controller, suspected compromise. 2.1 GB RAM capture, READ-ONLY."
if [ -f evidence/case001/citadeldc01.mem ]; then
  runcmd ls -lh evidence/case001/citadeldc01.mem
else
  printf '  (evidence image is gitignored/local — integrity hashes from the committed run:)\n\n'
  "$UV" run python - "$RUN_DIR" <<'PY'
import json, sys
m = json.load(open(f"{sys.argv[1]}/run_meta.json"))
print("    pre :", m["evidence_sha256_pre"])
print("    post:", m["evidence_sha256_post"])
print("    integrity_ok:", m["evidence_integrity_ok"])
PY
fi
pause

banner "② AUTONOMOUS RUN — one prompt; a multi-agent graph works the case.  [ splice live 'make real' clip here ]"
printf "  Recorded separately: 'make real' prints 'hashing evidence… <sha256>',\n  'lead/specialist: sonnet', then streams '▶ supervisor → triage' … (Ctrl-C after).\n"
pause

banner "③ THE VERDICT — real evil found, every claim tied to evidence."
runcmd "$UV" run spoor show-report "$RUN_DIR"
pause

banner "④ CAN YOU TRUST IT? Every confirmed finding cites a tool_call_id in a hash-chained audit log."
runcmd "$UV" run spoor verify-audit "$RUN_DIR/audit.jsonl"
pause

banner "⑤ TRY TO MAKE IT MISBEHAVE — read-only jail, allow-listed exec, evidence off-limits."
runcmd "$UV" run spoor demo-guardrails
pause

banner "⑥ THE NUMBERS — honest, on real evidence. Hallucination 0.000."
runcmd "$UV" run spoor accuracy-report "$RUN_DIR/findings.json" "$GT"
pause

banner "SPOOR — github.com/RECTOR-LABS/spoor"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x scripts/demo_walkthrough.sh`

- [ ] **Step 3: Run it end-to-end at $0 and confirm every beat renders clean**

Run: `export PATH="$HOME/.local/bin:$PATH"; printf '\n\n\n\n\n\n\n\n' | ./scripts/demo_walkthrough.sh`
Expected: all 8 banners print in order; beat ③ shows the rendered report; ④ "audit chain intact: 8 record(s)…"; ⑤ four `[BLOCKED]` + one `[OK]`; ⑥ `precision 0.250 / recall 0.500 / f1 0.333 / hallucination_rate 0.000`. No errors, no stack traces, no spend.

- [ ] **Step 4: Commit**

```bash
git add scripts/demo_walkthrough.sh
git commit -m "feat: silent demo walkthrough driver (self-narrating, \$0)"
```

---

### Task 3: `docs/devpost.md` — the Devpost writeup

**Files:**
- Create: `docs/devpost.md`

- [ ] **Step 1: Write the copy** following the approved spec's "Devpost writeup" section. Structure, in order: **Tagline** (the ≤200-char line from the spec) · **Inspiration** · **What it does** · **The trust stack** · **Accuracy, measured honestly** · **How we built it** · **Challenges** · **What's next** · **Built with** (`python langgraph mcp anthropic-claude volatility3 sift`) · **Submission artifacts** (bulleted cross-links to all 8 SPEC §10 items).

  Lead with the trust differentiator; never open on the 0.25. Use the honest accuracy frame: "R 0.50 / hallucination 0.000 — found the malware + C2; precision 0.25 = over-reporting real injection sites, not fabrication; we found and fixed a scorer bug ourselves and published both numbers."

- [ ] **Step 2: Cross-check every factual claim against the repo (no unverifiable claims)**

| Claim in copy | Verify against |
|---|---|
| hallucination 0.000, P0.25/R0.50/F1 0.33 | `accuracy_report.md` |
| evidence integrity INTACT (pre==post hash) | `runs/2026-06-12-231634-case001-real/run_meta.json` |
| audit chain 8 records verified | `uv run spoor verify-audit runs/2026-06-12-231634-case001-real/audit.jsonl` |
| coreupdater.exe, C2 203.78.103.109, hollowing, Session-2 | `runs/2026-06-12-231634-case001-real/report.json` |
| 110 tests | `uv run pytest -q` (will be 112 after Task 1) |
| 12 forensic tools, MCP server, supervisor graph | `README.md` / `SPEC.md` |

Run each check; fix any copy that doesn't match. Update the test count to the actual post-Task-1 number.

- [ ] **Step 3: Commit**

```bash
git add docs/devpost.md
git commit -m "docs: Devpost writeup (ready to paste)"
```

---

### Task 4: README "Demo" pointer

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a short Demo subsection** near the existing quick-start / `make demo` content:

```markdown
### Watch it (silent walkthrough)

```bash
./scripts/demo_walkthrough.sh          # $0 — runs off the committed real run
```

Prints the full submission story beat-by-beat: the verdict (`spoor show-report`),
the tamper-evident audit (`spoor verify-audit`), guardrail-bypass attempts that
fail (`spoor demo-guardrails`), and the honest accuracy number. The live
autonomous run is `make real`.
```

- [ ] **Step 2: Verify the snippet is accurate** (the script path + the three `spoor` subcommands exist).

Run: `uv run spoor --help`
Expected: lists `verify-audit`, `demo-guardrails`, `accuracy-report`, `show-report`.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README demo pointer"
```

---

### Task 5: Final verification

- [ ] **Step 1: Full suite green**

Run: `set -o pipefail; uv run pytest -q 2>&1 | tail -3`
Expected: 112 passed.

- [ ] **Step 2: End-to-end walkthrough at $0**

Run: `printf '\n%.0s' {1..8} | ./scripts/demo_walkthrough.sh | tail -40`
Expected: beats ③–⑥ render correctly; no errors; OpenRouter credit unchanged (no spend).

- [ ] **Step 3: Confirm clean tree + push**

```bash
git status --short          # expect clean
git log --oneline -5        # the new commits, all signed
git push origin feat/sift-mcp-spine
```

---

## Self-Review

**Spec coverage:** demo storyboard → Task 2 (beats ①③④⑤⑥⑦) + Task 1 (beat ③ renderer); beat ② handled as a documented manual splice (Task 2 banner). Devpost outline → Task 3. README pointer → Task 4. Driver-script $0/self-contained/graceful-degradation → Task 2 (the `.mem`-absent branch). All spec deliverables covered.

**Placeholder scan:** No TBD/TODO. The Devpost prose is written at execution from the spec's approved outline with an explicit claim→source cross-check table — content is specified, not hand-waved.

**Type consistency:** `render_report(report: dict) -> str` and `cmd_show_report(run_dir: str) -> int` are used identically in cli.py and the test. The subcommand name `show-report` matches in the parser, the dispatch branch, the bash script, and the README. The run dir `runs/2026-06-12-231634-case001-real` is consistent across all tasks.
