# Spoor — autonomous DFIR you can audit

> **Tagline:** Autonomous DFIR you can audit — every finding cited to evidence, every action logged in a tamper-evident chain, the evidence provably never touched. **Hallucination rate: 0.000.**

---

## Inspiration

The hackathon brief named the fear out loud: the thing standing between an LLM and a real incident-response seat is **hallucination**. An analyst who invents a process, a beacon, or a logon is worse than no analyst — a confident wrong answer gets *acted on*, and in IR that means pulling the wrong box off the network at 3 a.m.

So we didn't start from "make the agent smarter." We started from a harder question: **why would a responder ever trust an autonomous agent's report?** Our answer is the same reason they trust `volatility` or `dd` — not because it's clever, but because every claim is tied to a verifiable execution and the evidence is provably untouched. Spoor is built so trust is *architectural*, not hoped for.

## What it does

You point Spoor at a piece of evidence and give it one prompt. A **LangGraph multi-agent graph** — a Lead Investigator routing triage, timeline, IOC-correlation, and reporter specialists — works the case autonomously and returns a report where **every confirmed finding cites the exact tool call that proves it**.

On the real **DFIR Madness Case 001 — "The Stolen Szechuan Sauce"** domain-controller memory image (2.1 GB), driving **native Volatility 3**, Spoor found the evil on its own:

- **`coreupdater.exe` (PID 3644)** — a rogue process with a *phantom* parent PID (2244, a process that doesn't exist), no command line, alive for a ~15-second window before self-terminating.
- A confirmed **C2 channel**: `10.42.85.10:62613 → 203.78.103.109:443`, ESTABLISHED, owned by that process.
- **Code injection** — 15 anonymous `PAGE_EXECUTE_READWRITE` regions across **5 processes**, including the Active Directory Web Services process on the DC.
- An **attacker Session-2 logon** — a second interactive session on a domain controller.

Anything Spoor can't back with a tool execution is labeled an **inference**, not a finding — enforced in code, not in a prompt.

## The trust stack (the part that's different)

| What | How you can check it | Result on the real run |
|---|---|---|
| **No hallucinations** | a finding is *confirmed* only by citing a `tool_call_id` that exists in the verified audit chain — `submit_report` downgrades the rest to inferences, deterministically | **hallucination rate 0.000** |
| **Tamper-evident audit** | every tool call appends a hash-chained record; flip one byte and the chain breaks | `spoor verify-audit` → **8 records, chain intact** |
| **Evidence never touched** | SHA-256 of the image before vs. after the run | **byte-identical** (`8079a745…`) — read-only proven |
| **Guardrails fail closed** | path traversal, absolute-path escape, symlink escape, non-allow-listed binary | `spoor demo-guardrails` → **4/4 BLOCKED** in code |
| **Human in the loop** | destructive actions `interrupt()` for approval *before* any side effect; approve *and* reject are audited | approval gate, B4 |

Break the chain and **every** confirmed claim is voided. That's the point: the report is only as trustworthy as a log you can independently verify — so we made the log independently verifiable.

## Accuracy, measured honestly

Scored against the memory-visible subset of the verified answer key:

| Metric | Value |
|---|---|
| Recall | **0.500** |
| Precision | **0.250** |
| F1 | **0.333** |
| **Hallucination rate** | **0.000** |

Recall 0.50 with **zero hallucination** means Spoor found the real malware and the real C2 — and cited both. **Precision 0.25 is over-reporting, not fabrication.** The same type-driven rule that finally credits `coreupdater.exe` also flags five legitimate Windows binaries (ADWS, `spoolsv`, `explorer`, `svchost`, `ServerManager`) that *genuinely* carry injected RWX regions — real anomalies, just not in the curated 4-item subset. They're false positives against the key, not invented evidence.

And we show our work. Mid-build we caught **our own scorer** silently dropping the malware detection — a metadata-laden IOC value plus Windows' 14-character process-name truncation (`coreupdater.exe` → `coreupdater.ex`). We fixed it **test-first** and published **both the raw and the corrected numbers** with full methodology. Recall went up, precision went *down*, and we reported the drop. The two remaining misses are honest too: a brute-force source IP and a deleted `secret.zip` that simply aren't present in a single memory snapshot. Self-correction in the open is the whole thesis.

## How we built it

- **Python 3.12** + **LangGraph**: a supervisor graph (`create_supervisor` + checkpointer) routes a Lead Investigator over triage / timeline / IOC-correlation / reporter specialists across a shared `CaseState`. A deterministic **completeness gate** re-engages the graph if it ever tries to conclude without an enforced report.
- An **MCP server** (FastMCP, stdio) exposing **12 read-only forensic tools** — usable both by the agents and by any MCP client (Claude Code, Claude Desktop).
- **Native Volatility 3** over the real image, plus Sleuth Kit, RegRipper, plaso, and YARA — every tool behind one spine: *typed input → guardrails → no-shell allow-listed runner → hash-chained audit record → structured JSON*.
- **Five security boundaries** (path jail, no-shell allow-list, workspace disjointness, approval gate, tamper-evident audit), each shipping with **live bypass tests**.
- **TDD throughout — 112 tests**, written test-first, including the guardrail-bypass attempts above.
- Runs on **Claude Sonnet 4.6** (lead and specialists) via OpenRouter; no key is committed.

## Challenges we ran into

- **Real evidence at scale.** A 2.1 GB image floods a context window — we added server-side row caps, netscan dedup, and token budgeting so the model reasons over signal, not noise.
- **Citations without killing recall.** The confirmed-vs-inferred contract had to live in `submit_report`'s implementation, not a prompt — deterministic, or it isn't trust.
- **The honest call.** Our scorer fix *lowered* our headline precision. We shipped it and published both numbers anyway.
- **Provably read-only.** Proving the evidence was untouched end-to-end meant hashing before and after and enforcing the jail architecturally, not asserting it.

## What we learned

Trust in an autonomous agent is an *engineering* property, not a model property. The model finds the evil; the harness — citations, audit chain, guardrails, integrity proof — is what makes the answer usable. And measuring yourself honestly is uncomfortable by design: the most credible number we have is the one that made us look *worse*.

## What's next

- **Kill the N=1** — more public cases to move accuracy off a single sample.
- **Richer IOC typing** (malicious-file vs. injection-site) to close the precision gap *honestly*, not by hiding over-reports.
- **Full SIFT timeline** on the workstation disk image, end to end.

## Built with

`python` · `langgraph` · `mcp` · `anthropic-claude` (Sonnet 4.6) · `volatility3` · `sift`

## Submission artifacts

All eight required items, cross-linked:

1. **Public repo + MIT license** — [github.com/RECTOR-LABS/spoor](https://github.com/RECTOR-LABS/spoor) · [`LICENSE`](../LICENSE)
2. **Demo video (≤5 min)** — silent walkthrough; reproduce it locally with [`./scripts/demo_walkthrough.sh`](../scripts/demo_walkthrough.sh) (evidence → autonomous run → cited verdict → live audit verify → guardrail-bypass attempts that fail → the honest accuracy number)
3. **Architecture diagram** (security boundaries labeled) — [`assets/architecture.svg`](../assets/architecture.svg)
4. **Written project description** — [`README.md`](../README.md) + [`SPEC.md`](../SPEC.md)
5. **Dataset documentation** (source, license, hashes, ground truth, fetch script) — [`datasets/README.md`](../datasets/README.md)
6. **Accuracy report + evidence-integrity assessment** — [`accuracy_report.md`](../accuracy_report.md)
7. **Try-it-out instructions** — `make demo` + quick-start in [`README.md`](../README.md), plus the MCP `mcpServers` config for direct use
8. **Agent execution logs (timestamps) + token usage** — [`runs/2026-06-12-231634-case001-real/`](../runs/2026-06-12-231634-case001-real/): hash-chained [`audit.jsonl`](../runs/2026-06-12-231634-case001-real/audit.jsonl) + [`token_usage.json`](../runs/2026-06-12-231634-case001-real/token_usage.json)
