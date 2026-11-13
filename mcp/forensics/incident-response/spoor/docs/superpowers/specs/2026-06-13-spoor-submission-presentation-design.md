# Spoor — Submission Presentation Design (Deliverable 16)

**Date:** 2026-06-13 · **Status:** Approved (brainstorming → spec) · **Deadline:** 2026-06-15

## Goal

Produce the two remaining FIND EVIL! submission artifacts:
1. A **silent ≤5-min demo video** walkthrough.
2. The **Devpost writeup** (`docs/devpost.md`, ready to paste).

7 of 8 SPEC §10 artifacts already exist (repo+LICENSE, architecture.svg, README/SPEC,
datasets/README, accuracy_report.md, `make demo`, committed `runs/` logs+tokens). This
deliverable closes the only gap (the video) and packages the submission narrative.

## Constraints & principles

- **Silent walkthrough, NO voice** → on-screen text must carry the entire narrative.
- **≤5 min** (target ~4.5).
- **Mostly $0.** Only spend is ~$0.10–0.30 for the live run kickoff (beat ②). **Sonnet-only**, no Opus.
- **Honest framing.** Lead with the trust differentiator (hallucination 0.000, auditability,
  evidence integrity). Frame accuracy (P 0.250 / R 0.500 / F1 0.333) honestly — the precision
  cost is *over-reporting real injection sites, not fabrication*. **No agent re-tuning, no gaming.**
- **Strategy:** amplify the strength (trust/auditability), don't chase the weakness (raw accuracy).

## Locked decisions (from brainstorming)

1. **Format:** silent terminal walkthrough.
2. **Narrative arc:** "Find Evil, then prove you can trust it" — hook on finding real evil, pay off on the trust stack.
3. **Autonomous-run beat:** Hybrid — live `make real` kickoff (first routing lines stream, then Ctrl-C) cutting to committed artifacts. Proves live autonomy without a full multi-minute run or budget risk.
4. **Capture:** a single self-narrating driver script `scripts/demo_walkthrough.sh` that prints a boxed banner before each beat, runs the $0 command, and pauses for a keypress so one recording take is fully paced by the operator.

## Demo storyboard (~4.5 min)

| # | On-screen banner (printed by the script) | Command shown | ~time |
|---|------------------------------------------|---------------|-------|
| 0 | `SPOOR — find evil, and prove it.` · FIND EVIL! / SANS | title banner | 8s |
| ① | `① EVIDENCE — DC01 domain controller, suspected compromise. 2.1 GB RAM capture, mounted READ-ONLY.` | `ls -lh evidence/case001/citadeldc01.mem` (graceful note if absent) | 20s |
| ② | `② AUTONOMOUS RUN — one prompt, a multi-agent graph works the case.` **(LIVE, manual)** | `make real` → streams `hashing evidence… <sha256>`, `lead/specialist: sonnet`, `▶ supervisor → triage`, `▶ triage → …`, then **Ctrl-C** | 35s |
| ③ | `③ THE VERDICT — real evil found: coreupdater.exe → C2 203.78.103.109, process hollowing, attacker session on a DC.` | render committed `report.json` exec-summary + key findings | 45s |
| ④ | `④ CAN YOU TRUST IT? Every confirmed finding cites a tool_call_id in a hash-chained audit log.` | `spoor verify-audit runs/…/audit.jsonl` → chain OK, 8 records | 40s |
| ⑤ | `⑤ TRY TO MAKE IT MISBEHAVE — read-only jail, allow-listed exec, evidence off-limits.` | `spoor demo-guardrails` → bypass attempts **BLOCKED** | 35s |
| ⑥ | `⑥ THE NUMBERS — honest, on real evidence. Hallucination 0.000.` | render `accuracy_report.md` → P0.25/R0.50/F1 0.33/**halluc 0.000**, integrity INTACT | 45s |
| ⑦ | `SPOOR — github.com/RECTOR-LABS/spoor` | close banner | 8s |

## Driver script design — `scripts/demo_walkthrough.sh`

- **$0 and self-contained.** Runs only beats ①, ③, ④, ⑤, ⑥, ⑦ off the *committed* artifacts.
  Safe for anyone to run — no API key, no charges. Doubles as a repo "try-it" artifact.
- **Boxed ASCII banners** print the on-screen narration before each command.
- **Pauses between beats** (`read -r`) so the operator paces a single recording take.
- **Beat ② (live `make real`) is NOT in the script** — run manually in the same take, Ctrl-C after
  the first routing lines. Rationale: never bury a paid, evidence-dependent live run inside a script
  someone might run unawares. One continuous take: `make real` → Ctrl-C → `./scripts/demo_walkthrough.sh`.
- **Graceful degradation:** beat ① references the gitignored `.mem`; if absent (someone else running it),
  show the committed `run_meta.json` hashes + a note instead of failing.

## Devpost writeup — `docs/devpost.md`

**Tagline (≤200 chars):** *"Autonomous DFIR you can audit — every finding cited to evidence, every
action logged in a tamper-evident chain, the evidence provably never touched. Hallucination rate: 0.000."*

| Section | Angle / key content |
|---|---|
| **Inspiration** | The author's stated #1 fear: an autonomous IR agent that *hallucinates*. Spoor's premise — trust through auditability, not hope. |
| **What it does** | Autonomously investigates real evidence → finds evil (coreupdater.exe, C2 203.78.103.109, hollowing, attacker DC session). Every confirmed finding cites a tool_call_id; whole run hash-chain audited; evidence read-only + integrity-proven; destructive actions gated by human approval. |
| **The trust stack** *(differentiator, front and center)* | Hallucination 0.000 · tamper-evident audit (break one byte → chain fails) · evidence SHA-256 byte-identical pre/post · guardrail-bypass attempts fail by design. |
| **Accuracy, measured honestly** | R 0.50 / halluc 0.000 — found the malware + C2. Precision 0.25 = over-reporting real injection sites, not fabrication. We found and fixed a scorer bug ourselves and published both numbers — self-correction in the open. |
| **How we built it** | Python · LangGraph supervisor (lead → triage/timeline/IOC/reporter) · MCP server, 12 forensic tools · native Volatility 3 in a sandboxed runner · hash-chained audit · citation-enforced reporter · guardrails. 110 tests, TDD. |
| **Challenges** | Real 2.1 GB image at scale (netscan dedup, token caps) · enforcing citations without killing recall · the honest scorer-correction call · keeping evidence provably untouched. |
| **What's next** | More cases (kill N=1) · richer IOC typing (malicious-file vs injection-site) · full SIFT timeline. |
| **Built with** | `python` `langgraph` `mcp` `anthropic-claude` `volatility3` `sift` |
| **Submission artifacts** *(footer checklist)* | Cross-links all 8 SPEC §10 items: repo+LICENSE · demo video · architecture.svg · README/SPEC · datasets/README · accuracy_report.md · `make demo` · `runs/` audit+tokens. |

## Deliverables

1. `scripts/demo_walkthrough.sh` — executable, runs clean at $0, banners legible, beats ①③④⑤⑥⑦.
2. `docs/devpost.md` — ready-to-paste copy, every claim cross-checked against the repo.
3. *(Conditional)* a $0 report pretty-printer for beats ③/⑥, only if raw JSON/markdown reads poorly on camera.
4. README — a short "Demo" pointer to the script.

## Open implementation checks (done during build, not now)

- Confirm `spoor demo-guardrails` output actually shows blocked bypass attempts as described.
- Confirm `report.json` / `accuracy_report.md` render cleanly on camera; add a printer only if needed.
- Confirm beat ① degrades gracefully when the `.mem` is absent.

## Out of scope

- No agent prompt re-tuning / no chasing precision.
- No second case unless RECTOR tops up budget and opts in separately.
- No new product features beyond the demo helper (+ optional printer).
- Recording/editing the video and submitting on Devpost are RECTOR's actions.

## Success criteria

- `./scripts/demo_walkthrough.sh` runs clean end-to-end at $0; banners legible; covers beats ①③④⑤⑥⑦.
- One continuous screen recording (live kickoff + script) ≤5 min tells the arc without voice.
- `docs/devpost.md` covers all Devpost fields, cross-links all 8 SPEC §10 artifacts, frames accuracy honestly.
