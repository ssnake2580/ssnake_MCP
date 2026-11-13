# Spoor — Plan

Execution plan against the **FIND EVIL!** deadline: **2026-06-15, 11:45pm EDT**. Today is **2026-06-06** → **9 days**. This is a solo / tiny-team build; the plan is front-loaded so the hardest unknown (the DFIR domain ramp) is burned down first, and so a *submittable* slice exists by the midpoint with polish as the tail.

> **Strategy in one line:** out-engineer the field on the rubric's engineering-heavy half (autonomy, architectural constraints, audit trail, usability) while clearing a *credible, measured* accuracy bar on a known-answer dataset. Don't try to out-forensics the forensics pros.

---

## 0. Pre-flight (before Day 1 — ~30 min)

- [ ] Create repo `spoor` (private until ready, then public). Add `LICENSE` = **Apache-2.0** (or MIT), `.gitignore` (`.env`, `*.plaso`, `evidence/`, `runs/*.local`, VM artifacts), `README` stub.
- [ ] `.env.example` with **env-var references only — no values**: `ANTHROPIC_API_KEY=`, `VT_API_KEY=` (optional), `EVIDENCE_ROOT=/cases/case001`, `SPOOR_MODEL=claude-...`.
- [ ] Confirm host can run the SIFT OVA (≥ 8.8GB download, ≥ 8GB RAM to the VM for plaso/Volatility).

---

## Milestones vs. the 9-day window

| Day | Date | Milestone (exit gate) |
|----|------|------------------------|
| **1** | Sat 06-07 | **Domain + environment up.** SIFT VM running, evidence mounted read-only, dataset chosen w/ answer key. *I can run `vol`/`log2timeline`/`psort`/RegRipper by hand and know what good output looks like.* |
| **2** | Sun 06-08 | **MCP server skeleton + Phase-0 proof.** `spoor-sift` exposes 3 memory tools over stdio; registered in **Claude Code/Desktop**; Claude can list processes on the real image. *Vertical slice proven before any orchestration.* |
| **3** | Mon 06-09 | **Tool layer complete.** ~10–12 tools (memory/timeline/disk/registry/IOC), structured JSON out, allow-list + path-jail in place, audit-record emit wired. `test_guardrails.py` green (bypass attempts fail). |
| **4** | Tue 06-10 | **Orchestration v1.** LangGraph supervisor + Triage & Timeline agents over `CaseState`; MCP tools loaded via adapters; checkpointer on. End-to-end run produces *some* findings autonomously. |
| **5** | Wed 06-11 | **Orchestration complete + approval gate.** IOC/Correlation + Reporter agents; `interrupt()` approval gate demoed on a (simulated) live action; confirmed-vs-inferred report contract enforced. |
| **6** | Thu 06-12 | **Accuracy + audit hardening.** `accuracy_report.md` vs. answer key (precision/recall + evidence-integrity hashes); `verify-audit` command; self-correction on a forced tool failure works. **Feature-freeze target.** |
| **7** | Fri 06-13 | **Repro + docs.** `make demo` one-command run; README, architecture diagram (security boundaries), dataset docs, try-it-out. Full dry-run from clean checkout. |
| **8** | Sat 06-14 | **Demo video ≤ 5 min** recorded + edited; submission assets assembled; **Challenge-step audit** (try to break my own guardrails / find gaps); fix what's found. |
| **9** | Sun 06-15 | **Buffer + submit early** (well before 11:45pm EDT). Final checklist pass; repo public; Devpost form. *Do not leave submission to the last hour.* |

**Critical path:** Day 1 (domain+VM) → Day 2 (MCP proof) → Day 3 (tools) → Day 4–5 (orchestration) → Day 6 (accuracy/audit). Days 7–9 are polish + buffer and absorb slippage. **If Day 4 slips**, fall back to the Phase-0 **Claude-Code-direct** path (SPEC §3-A) as the shippable artifact and treat orchestration as upside — still a valid, complete submission.

---

## Task breakdown

### Day 1 — Domain ramp + environment (the make-or-break day)
- [ ] Download + boot **SIFT Workstation** OVA; verify Volatility 3, plaso (`log2timeline`/`psort`), Sleuth Kit (`fls`/`icat`), RegRipper, YARA all run. *(SIFT: <https://www.sans.org/tools/sift-workstation>)*
- [ ] **Domain study (time-boxed):** SIFT cheat sheet end-to-end (<https://www.sans.org/posters/sift-cheat-sheet>); read **one full public case walkthrough** (memory + super-timeline) so I've seen the real workflow once. Volatility 3 docs (<https://volatility3.readthedocs.io/>); plaso docs (<https://plaso.readthedocs.io/>).
- [ ] Choose dataset **with a published answer key** (DFIR-Madness-style Case 001 or equiv). Record source/license/SHA256 in `datasets/README.md`. Mount images **read-only**; capture pre-hashes.
- [ ] **By hand**, run the triage sequence on the real image (`windows.pslist`/`pstree`/`netscan`/`malfind`/`cmdline`) and confirm the JSON renderer flags; build a `.plaso` and `psort` a slice. *Capture the exact commands — these become the tool wrappers.*
- **Gate:** I can reproduce the dataset's known "evil" by hand and I know each tool's output shape. *If I can't, the domain risk is realized — escalate scope cut immediately.*

### Day 2 — MCP server skeleton + Phase-0 proof
- [ ] `uv init`; `uv add "mcp[cli]" httpx`; Python ≥ 3.10. *(Build-server tutorial: <https://modelcontextprotocol.io/docs/develop/build-server>)*
- [ ] `spoor_sift/server.py`: `FastMCP("spoor-sift")`; implement `vol_pslist`, `vol_pstree`, `vol_netscan` with `@mcp.tool()`, type hints + docstrings, returning parsed JSON; `mcp.run(transport="stdio")`.
- [ ] Path-jail + allow-list helpers (`validate_in_evidence_root`, `ALLOWED_BINARIES`).
- [ ] Register in **Claude Desktop/Code** via `mcpServers` config (`command`/`args`/`cwd`); confirm Claude calls the tools against the real image and gets sane structured results.
- **Gate:** A frontier model, through MCP, autonomously lists/triages processes on the actual evidence. Vertical slice proven.

### Day 3 — Complete the tool layer + guardrails
- [ ] Add remaining tools: `vol_malfind`, `vol_cmdline`, `log2timeline_run`, `psort_query`, `tsk_fls`, `tsk_icat`, `regripper_run`, `hash_file`, `yara_scan` (+ optional `vt_lookup`, offline by default, env-gated).
- [ ] `audited()` wrapper: append hash-chained JSONL record per call (`ts, tool, args, exit_code, stdout_sha256, prev_hash, hash`).
- [ ] `tests/test_guardrails.py`: assert path-traversal, non-allow-listed binary, and write-to-evidence attempts all **fail**. *(Criterion 4 — "tested for bypass".)*
- [ ] Unit tests per tool on a tiny fixture (parsing correctness).
- **Gate:** All tools return structured JSON; guardrail tests green; audit log verifiable.

### Day 4 — Orchestration v1 (LangGraph)
- [ ] `uv add langgraph langgraph-supervisor langchain-mcp-adapters langchain-anthropic`.
- [ ] Define `CaseState` (TypedDict: evidence paths, findings[], iocs[], timeline_ref, open_questions[]).
- [ ] Load `spoor-sift` tools via `langchain-mcp-adapters`; build **Triage** + **Timeline** `create_react_agent`s with playbook prompts; wrap in `create_supervisor([...], model, prompt=LEAD)`; compile with `InMemorySaver` checkpointer. *(Refs: <https://github.com/langchain-ai/langgraph-supervisor-py>, <https://github.com/langchain-ai/langchain-mcp-adapters>)*
- [ ] First autonomous end-to-end run on the demo image; capture transcript + token usage.
- **Gate:** Supervisor routes triage→timeline and emits findings without human steering.

### Day 5 — Orchestration complete + approval gate
- [ ] Add **IOC/Correlation** + **Reporter** agents. Reporter enforces **confirmed-vs-inferred**; each confirmed finding must carry a `tool_call_id` or be downgraded.
- [ ] Wire the **approval interrupt**: `state_changing`/`live_endpoint` tools call `interrupt()` with a `HumanInterrupt` (action+args, `allow_accept`/`allow_edit`/`allow_respond`); resume via `Command(resume=...)`. Demo it on a *simulated* live action. *(HITL: <https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/>)*
- [ ] Generate the incident **report** (Markdown + JSON) from `CaseState`.
- **Gate:** Full 4-agent pipeline produces a cited report; approval gate provably pauses/resumes.

### Day 6 — Accuracy, audit, self-correction (feature-freeze)
- [ ] `accuracy_report.md`: diff findings vs. answer key → precision/recall on IOCs; **evidence-integrity** section with pre/post SHA256 proving read-only.
- [ ] `spoor verify-audit`: walk the JSONL, recompute the hash chain, confirm intact.
- [ ] Force a tool failure (bad arg / missing hive) and verify the supervisor **self-corrects** (re-routes/retries) — record it; this is the tiebreaker criterion.
- [ ] Per-run **token-usage summary** written under `runs/` (submission item #8).
- **Gate:** Accuracy numbers exist and are honest; audit chain verifies; self-correction demonstrated. **Freeze features.**

### Day 7 — Reproducibility + documentation
- [ ] `make demo` (or `Taskfile`): clean → fetch dataset (script) → run pipeline → emit report + audit + token summary.
- [ ] README: quick-start, architecture, env-var table, Claude-Code `mcpServers` snippet, limitations (incl. the honest domain-ramp caveat).
- [ ] **Architecture diagram (SVG)** explicitly labeling security boundaries (read-only mount, allow-list, approval gate) → `assets/`.
- [ ] Finalize `datasets/README.md` (no committed binaries — hashes + fetch only).
- [ ] **Clean-checkout dry run** on a fresh clone; fix anything that isn't reproducible.
- **Gate:** A stranger can `make demo` and get the same report + audit log.

### Day 8 — Demo video + challenge-step audit
- [ ] Record **≤ 5 min**: problem (GTG-1002 framing) → point Spoor at evidence → autonomous run → report with live **audit-trace** of one finding → **guardrail-bypass attempt that fails** → accuracy numbers. Edit tight.
- [ ] **Challenge step (CLAUDE.md):** actively try to break my own work — bypass the allow-list, tamper the audit log, feed adversarial paths, sanity-check accuracy claims. Fix every gap found.
- [ ] Assemble all 8 submission artifacts; cross-check against SPEC §10.
- **Gate:** Video done; self-audit passed; assets complete.

### Day 9 — Buffer + submit
- [ ] Make repo public; verify `LICENSE` visible at root.
- [ ] Final submission checklist (SPEC §10); commit `runs/` sample logs.
- [ ] **Submit on Devpost with hours to spare** — never the last hour.
- **Gate:** Submitted, confirmation received.

---

## Setup quick-reference

```bash
# SIFT Workstation: download OVA from sans.org/tools/sift-workstation, import to VMware/VirtualBox.
# Mount evidence READ-ONLY, e.g.:  ewfmount case.E01 /mnt/ewf  &&  mount -o ro,loop ... /cases/case001

# MCP server (Python ≥ 3.10), on the SIFT VM:
uv init spoor && cd spoor
uv add "mcp[cli]" httpx
# orchestration:
uv add langgraph langgraph-supervisor langchain-mcp-adapters langchain-anthropic

# secrets via env only (NO values in repo):
cp .env.example .env   # then fill ANTHROPIC_API_KEY, EVIDENCE_ROOT, (optional) VT_API_KEY

# Claude Desktop/Code registration (~/Library/Application Support/Claude/claude_desktop_config.json):
# { "mcpServers": { "spoor-sift": { "command": "uv",
#     "args": ["--directory","/ABS/PATH/spoor","run","spoor_sift/server.py"] } } }
```

**Env vars (all referenced, never committed):**
`ANTHROPIC_API_KEY` (required) · `SPOOR_MODEL` · `EVIDENCE_ROOT` · `VT_API_KEY` (optional, VT lookups off by default) · `SPOOR_AUDIT_PATH`.

---

## Definition of Done (ship gate — all must be true)

1. **Public repo** with **MIT/Apache-2.0** `LICENSE` visible at root; **no secrets** (env-var refs + `.env.example` only; evidence/`.plaso` gitignored).
2. **Autonomous run**: `make demo` drives memory→timeline→disk→registry→IOC and emits an incident report **without human steering** (approval gate fires only on flagged actions).
3. **Accuracy**: `accuracy_report.md` reports precision/recall vs. the dataset answer key **and** evidence-integrity hashes proving read-only operation.
4. **Constraints architectural + tested**: read-only mount + server allow-list + path-jail; `test_guardrails.py` shows bypass attempts **fail**.
5. **Audit trail**: hash-chained JSONL; every confirmed finding cites its `tool_call_id`; `verify-audit` confirms the chain.
6. **Self-correction** demonstrated on a forced tool failure (tiebreaker criterion).
7. **Submission artifacts**: all **8 required items** present and cross-checked (SPEC §10); demo video **≤ 5 min**.
8. **Reproducible** from a clean checkout by someone who isn't me.
9. **Challenge-step** self-audit complete; found issues fixed, not just noted.

---

## Honest feasibility verdict

**Verdict: achievable in 9 days — *conditional on Day 1*.**

The engineering core is **high-confidence**. An MCP server wrapping subprocess tools, a LangGraph supervisor with specialist sub-agents, an `interrupt()` approval gate, and a hash-chained audit log are all patterns I can build cleanly and quickly — every API in the SPEC is verified against current docs (FastMCP `@mcp.tool()` + stdio; `create_supervisor`/`create_react_agent`; `interrupt()`/`Command(resume=...)`; checkpointers). The rubric is, by design, **half engineering** (autonomy, constraint implementation, audit trail, usability), and that half is my bullseye. A *complete, submittable* artifact exists by Day 5–6, with Days 7–9 as polish + buffer, and a Phase-0 Claude-Code-direct fallback if orchestration slips.

The **real risk is domain, not delivery.** I'm a senior agent engineer, **not** a senior DFIR analyst — the gap is forensic judgment: which artifact answers which question, what an attacker footprint actually looks like, and where analysts get fooled. That gap is concentrated in two criteria (IR Accuracy, Breadth/Depth) and is precisely why Day 1 is a **gate, not a task**: stand up the VM, study the SANS-published playbook, and pick a dataset **with an answer key** so I can *measure* my forensic correctness instead of guessing at it. Encoding the published triage methodology into the prompts — rather than trusting model priors — is the core mitigation. If Day 1's gate isn't met (I can't reproduce the known "evil" by hand), the domain risk is real and the response is to **cut scope, not fake depth**: narrow to the memory-forensics spine done *excellently* against a known answer, and lean even harder on the engineering criteria.

**Net:** strong, honest submission that competes on the engineering-heavy half of the rubric and clears a *credible, measured* accuracy bar — not a forensics-expert tour de force, and the README will say so plainly. *Wallahu a'lam* — the unknowns are front-loaded into Day 1 on purpose, which is exactly where they belong.
