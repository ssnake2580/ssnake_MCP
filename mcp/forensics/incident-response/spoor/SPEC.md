# Spoor — Spec

> *Spoor* — the track or scent trail an animal leaves behind. Spoor is an autonomous DFIR agent that follows the forensic artifacts an intruder leaves on a system, and runs the trail to ground.

**One-liner:** An autonomous digital-forensics & incident-response (DFIR) agent that drives the SANS SIFT Workstation's forensic tooling through a purpose-built MCP server, orchestrated by a LangGraph multi-agent graph with architectural guardrails and a tamper-evident audit trail.

---

## 1. Hackathon context

| | |
|---|---|
| **Event** | "FIND EVIL!" — SANS Institute's first hackathon for autonomous incident response (Devpost) |
| **Deadline** | **2026-06-15, 11:45pm EDT** (hard) |
| **Prizes** | $22,000+ total — 1st $10K, 2nd $7.5K, 3rd $4.5K (+ SANS Summit pass / OnDemand course / webcast for top placements) |
| **Mission** | Turn the **Protocol SIFT** proof-of-concept into a *fully autonomous DFIR agent* — an AI co-pilot that triages incidents "at the speed adversaries now operate" |
| **Required tech** | **SANS SIFT Workstation** (free Ubuntu VM, 200+ IR tools) + **Model Context Protocol (MCP)**. Supported approaches explicitly include custom MCP servers and multi-agent frameworks (AutoGen, **CrewAI**, **LangGraph**), Claude Code/OpenClaw, and agentic IDEs (Cursor/Cline/Aider) |
| **Tracks** | No formal track split; single goal evaluated across 6 criteria. (Promoted alongside Cybersecurity / ML-AI / Beginner framing; **no blockchain**.) |
| **Submission (8 required)** | (1) public GitHub repo w/ **MIT or Apache-2.0** license file; (2) demo video ≤ **5 min**; (3) **architecture diagram identifying security boundaries**; (4) written project description; (5) **dataset documentation**; (6) **accuracy report with evidence-integrity assessment**; (7) try-it-out instructions or live URL; (8) **agent execution logs with timestamps + token usage** |

**Judging criteria — all six equally weighted** (autonomous execution is the *tiebreaker*):

1. **Autonomous Execution Quality** *(tiebreaker)* — "Does the agent reason about next steps, handle failures, and self-correct in real time?"
2. **IR Accuracy** — "Are findings correct? Hallucinations caught and flagged? Confirmed findings distinguished from inferences?"
3. **Breadth and Depth of Analysis** — "Depth on fewer types beats shallow coverage of many."
4. **Constraint Implementation** — "Are guardrails **architectural or prompt-based**? Judges evaluate where security boundaries are enforced and whether they were **tested for bypass**."
5. **Audit Trail Quality** — "Can judges trace any finding back to the **specific tool execution** that produced it?"
6. **Usability and Documentation** — "Can another practitioner deploy and build on this?"

> The criteria are the product spec. Every design decision below maps to one of them; §9 is the criteria→feature traceability matrix. *Winning code is reviewed for upstream integration into Protocol SIFT* — so this is built to be merged, not just demoed.

Sources: <https://findevil.devpost.com/> · <https://findevil.devpost.com/rules> · <https://www.sans.org/blog/sans-launches-first-hackathon-autonomous-incident-response>

---

## 2. Problem & target user

**User:** a DFIR analyst (or a lean SOC IR function) handed a fresh incident — a disk image, a memory capture, a pile of logs — and a clock. The adversary, increasingly, is itself an agent: Anthropic's Nov-2025 disclosure of **GTG-1002** documented attackers running recon→exploitation→lateral-movement at **80–90% autonomy** and request rates "physically impossible" for humans. Human-paced triage is now structurally outmatched.

**The pain (concrete):**
- **Triage is mechanical but slow.** The first 30 minutes is the same muscle memory every time — `pslist`/`pstree`, autoruns, network artifacts, MFT/`$MFT`, web history, prefetch — yet it's hand-driven, tool-by-tool, with results copy-pasted between terminals.
- **Tools don't share a brain.** Volatility, plaso, RegRipper, Sleuth Kit each speak their own dialect; correlating a suspicious PID to a registry Run key to a timeline entry is the analyst's job, by hand.
- **Findings lose their chain.** By the time a report is written, "we think `svch0st.exe` is the dropper" is often divorced from the exact command that produced the evidence — which is precisely what an audit (or a courtroom) demands.

**What "good" looks like:** the analyst points Spoor at evidence, states the question ("is this host compromised, and how?"), and gets back a *defensible* incident narrative — confirmed findings vs. inferences clearly separated, every claim hyperlinked to the tool invocation + raw output that backs it, and a timeline of attacker activity — in minutes, with the analyst approving any state-changing or live-endpoint step.

**Honest framing of *my* edge and gap.** The engineering *shape* of this problem — an autonomous MCP agent, multi-agent orchestration, hard guardrails, end-to-end audit trails — is squarely in my wheelhouse. The **gap is DFIR domain depth**: knowing *which* artifact answers *which* question, what a real attacker footprint looks like, and where analysts get fooled. That gap is the #1 project risk and is treated as such throughout (§8). The mitigation is to *encode the senior-analyst playbook explicitly* (the SANS-published methodologies) rather than hope the LLM has internalized it.

---

## 3. Concept

### Recommended: **Spoor** — autonomous DFIR agent = MCP tool layer + LangGraph orchestration + guardrail/audit spine

Three cleanly separated layers, each mapping to judging criteria:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ORCHESTRATION  (LangGraph)                          → Autonomy, Breadth   │
│  Lead Investigator (supervisor) routes a case to specialist sub-agents     │
│  that own a phase of the playbook; supervisor decides next step, handles   │
│  tool failures, and self-corrects. State persisted via checkpointer.       │
│    ├─ Triage agent        (memory + quick-win artifacts)                   │
│    ├─ Timeline agent      (plaso super-timeline + pivots)                  │
│    ├─ IOC/Correlation agent (extract + cross-reference indicators)         │
│    └─ Reporter agent      (narrative + confirmed-vs-inferred + citations)  │
└──────────────────────────────────────────────────────────────────────────┘
                         │ MCP (JSON-RPC over stdio)
                         ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  MCP SERVER  "spoor-sift"   (FastMCP, runs ON the SIFT VM) → Accuracy,Audit│
│  Wraps a curated subset of SIFT tools as typed MCP tools. Each tool:       │
│   • validates inputs   • runs READ-ONLY by default   • returns structured  │
│     JSON (parsed, not raw text)   • emits a signed audit record per call   │
│    vol_pslist · vol_netscan · vol_malfind · vol_cmdline ·                  │
│    log2timeline_run · psort_query · regripper_run · tsk_fls · tsk_icat ·   │
│    hash_file · yara_scan · vt_lookup(optional)                             │
└──────────────────────────────────────────────────────────────────────────┘
                         │ subprocess (allow-listed binaries only)
                         ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  SANS SIFT WORKSTATION   (Ubuntu VM, evidence mounted read-only)           │
│  Volatility 3 · plaso/log2timeline+psort · Sleuth Kit · RegRipper · YARA   │
└──────────────────────────────────────────────────────────────────────────┘
                         ▲
        ┌────────────────┴─────────────────┐
        │  GUARDRAIL + AUDIT SPINE          │  → Constraint Impl., Audit Trail
        │  • read-only evidence mounts (OS-enforced)                          │
        │  • binary allow-list in the server (not the prompt)                 │
        │  • LangGraph interrupt() approval gate before any write/live action │
        │  • append-only, hash-chained JSONL audit log of every tool call     │
        └────────────────────────────────────────────────────────────────────┘
```

**Why this shape wins points:**
- *Autonomy & self-correction* live in the LangGraph supervisor loop (criterion 1).
- *Accuracy* comes from tools returning **structured, parsed** output the model can't fudge, plus an explicit confirmed-vs-inferred contract enforced in the Reporter (criterion 2).
- *Breadth/depth* is the multi-agent split — each specialist goes deep on its artifact class rather than one agent skimming everything (criterion 3).
- *Constraints are architectural*, not prompt-based: the OS read-only mount + the server-side binary allow-list mean even a fully jailbroken model **cannot** mutate evidence or run an arbitrary command (criterion 4 — explicitly the differentiator the rules call out).
- *Audit trail* is a first-class artifact: every finding carries the `tool_call_id` whose output backs it, and the log is hash-chained so tampering is detectable (criterion 5).

### Alternative concepts (considered, not chosen)

- **A) Direct Claude-Code extension** — register the MCP server straight into Claude Code / Cursor, no orchestration layer. *Faster to demo, lower ceiling:* you inherit the IDE's single-loop autonomy and generic UI, and "constraint implementation" collapses to prompt-level. Good fallback if the orchestration layer slips (it becomes Spoor's Phase-0 smoke test anyway — see Plan Day 2).
- **B) CrewAI role-based crew** instead of LangGraph. Equivalent multi-agent expressiveness and arguably gentler role modeling, but CrewAI's human-in-the-loop and durable-checkpoint story is weaker than LangGraph's first-class `interrupt()` + checkpointer — and the approval gate / audit trail *is* the differentiator here. LangGraph chosen for that reason; the MCP tool layer is framework-agnostic, so a CrewAI swap stays cheap if needed.

---

## 4. MVP features (YAGNI-tight)

Scope is fixed to **one evidence pairing**: a **Windows memory image + its disk image** from a *public, documented* intrusion dataset (so accuracy is checkable against a known answer key — see §6). Everything below is in scope; everything in §7 is explicitly out.

1. **`spoor-sift` MCP server** exposing ~10–12 read-only SIFT tools with typed inputs and **structured JSON** outputs (not raw stdout). Minimum viable toolset:
   - Memory (Volatility 3): `vol_pslist`, `vol_pstree`, `vol_netscan`, `vol_malfind`, `vol_cmdline`.
   - Timeline (plaso): `log2timeline_run` (build `.plaso`), `psort_query` (filter/slice to CSV/JSON).
   - Disk (Sleuth Kit): `tsk_fls` (list/walk), `tsk_icat` (extract a file by inode).
   - Registry: `regripper_run` (named plugin against a hive).
   - Indicators: `hash_file` (MD5/SHA256), `yara_scan` (rules over a file/dir). `vt_lookup` optional, behind env var + offline by default.
2. **LangGraph orchestration**: a supervisor ("Lead Investigator") + 4 specialist sub-agents (Triage, Timeline, IOC/Correlation, Reporter) over a shared `CaseState`. Supervisor handles a failed tool call by re-routing or retrying with adjusted args (self-correction).
3. **Guardrails (architectural):**
   - Evidence mounted **read-only at the OS level**; the server refuses any path outside the evidence root.
   - Server holds a **binary allow-list**; only those executables can be spawned, args schema-validated — arbitrary shell is impossible by construction.
   - **Approval gate**: any tool flagged `state_changing` or `live_endpoint` triggers a LangGraph `interrupt()`; execution pauses until a human approves/edits/rejects.
4. **Tamper-evident audit trail**: append-only **JSONL**, one record per tool call — `{ts, tool, args, exit_code, stdout_sha256, prev_hash, hash}` — hash-chained so any edit/deletion breaks the chain. Findings reference the `tool_call_id` that produced them.
5. **Incident report (the deliverable)**: Markdown + JSON. Sections: executive summary, attacker timeline, **Confirmed Findings** (each ↔ evidence citation), **Inferences / Low-confidence** (clearly separated), IOCs (hashes/IPs/paths), and an appendix of every tool invocation. This directly satisfies submission items #4, #6, #8.
6. **`accuracy_report.md`**: Spoor's findings diffed against the dataset's published answer key — precision/recall on IOCs, plus an **evidence-integrity** statement (pre/post evidence hashes proving read-only operation).
7. **Repro harness**: one `make demo` (or `task demo`) that runs the full pipeline on the bundled sample and regenerates report + audit log, for the judges' "try it out."

---

## 5. Architecture (with real doc refs)

### 5.1 MCP server — `spoor-sift` (Python, FastMCP)

Runs **on the SIFT VM** (where the forensic binaries live) and speaks MCP over **stdio**, the transport the official tutorial uses. Built on the Python SDK's `FastMCP` (`mcp[cli]`, Python ≥ 3.10).

Verified pattern from the official "Build an MCP server" tutorial:

```python
# spoor_sift/server.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("spoor-sift")

@mcp.tool()
async def vol_pslist(memory_image: str) -> dict:
    """List processes from a memory image (Volatility 3 windows.pslist).

    Args:
        memory_image: Absolute path to the .raw/.mem capture (must be under EVIDENCE_ROOT, read-only)
    """
    # validate_in_evidence_root(memory_image); run allow-listed `vol` via subprocess
    # parse Volatility's --renderer=json into a typed dict; write an audit record
    ...

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

Key design rules (each ties to a criterion):
- **Structured output:** invoke Volatility 3 with its **JSON renderer** (`vol -f <img> -r json windows.pslist` — framework `-r/--renderer` flag goes *before* the plugin name) and `psort`/RegRipper with machine-readable output; the tool returns parsed objects, never a wall of stdout. The Volatility docs explicitly recommend the JSON renderer "as an API" for frameworks that harvest plugin output — exactly Spoor's use. *(Accuracy: the model reasons over facts, not free text it can hallucinate around.)*
- **Allow-list + path-jail:** a module-level frozenset of permitted binaries; every evidence path is `realpath`-resolved and asserted to live under `EVIDENCE_ROOT`. *(Constraint Implementation — architectural, server-side.)*
- **Audit emit:** every tool wraps its subprocess in an `audited()` helper that appends the hash-chained record before returning. *(Audit Trail.)*
- **Registration in a host:** for the Phase-0 smoke test, the same server drops straight into Claude Desktop / Claude Code via the standard `mcpServers` config block (`command`/`args`/`cwd`), proving the tools work before the graph is built.

Docs: <https://modelcontextprotocol.io/docs/develop/build-server> · server concepts (tools require client approval) <https://modelcontextprotocol.io/docs/learn/server-concepts> · spec <https://modelcontextprotocol.io/> · Python SDK (FastMCP) <https://github.com/modelcontextprotocol/python-sdk>

### 5.2 Orchestration — LangGraph

A **supervisor** graph (`langgraph-supervisor`) where the Lead Investigator routes the case to specialist `create_react_agent` sub-agents, each bound to the MCP tools relevant to its phase. State is a typed `CaseState` (evidence paths, findings[], iocs[], timeline_ref, open_questions[]) persisted by a **checkpointer** (`InMemorySaver` for the demo; `PostgresSaver` is a drop-in for durability), which is also the prerequisite for the approval interrupt.

Verified patterns:

```python
# supervisor + specialists (langgraph-supervisor, create_react_agent)
from langgraph_supervisor import create_supervisor
from langgraph.prebuilt import create_react_agent

triage_agent = create_react_agent(
    model=model, tools=[vol_pslist, vol_pstree, vol_netscan, vol_malfind],
    name="triage", prompt=TRIAGE_PLAYBOOK,
)
# ...timeline_agent, ioc_agent, reporter_agent...

graph = create_supervisor(
    [triage_agent, timeline_agent, ioc_agent, reporter_agent],
    model=model,
    prompt=LEAD_INVESTIGATOR_PLAYBOOK,  # encodes the senior-analyst sequencing
).compile(checkpointer=checkpointer)
```

**Connecting MCP tools to the graph:** `langchain-mcp-adapters` exposes `MultiServerMCPClient({...}).get_tools()` — point it at the `spoor-sift` server with a stdio transport block and it returns the server's tools as LangChain tools usable by `create_react_agent`, so the orchestration layer consumes the *exact same* MCP surface a Claude Code user would:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
client = MultiServerMCPClient({
    "spoor-sift": {"command": "uv",
        "args": ["--directory", "/abs/spoor", "run", "spoor_sift/server.py"],
        "transport": "stdio"},
})
tools = await client.get_tools()   # -> bind subsets to each specialist agent
```

Docs: LangGraph overview <https://langchain-ai.github.io/langgraph/> · prebuilt `create_react_agent` <https://github.com/langchain-ai/langgraph/blob/main/libs/prebuilt/README.md> · `langgraph-supervisor` <https://github.com/langchain-ai/langgraph-supervisor-py> · MCP adapters (`MultiServerMCPClient.get_tools()`) <https://github.com/langchain-ai/langchain-mcp-adapters> · LangChain MCP docs <https://docs.langchain.com/oss/python/langchain/mcp>

### 5.3 Guardrail + audit spine

- **Read-only at the OS:** evidence images mounted `ro` (loop/`ewfmount`) and exposed under `EVIDENCE_ROOT`; the workstation user lacks write on that tree. This is the strongest "architectural, not prompt" statement we can make to criterion 4 — it survives a fully jailbroken model.
- **Approval interrupt (human-in-the-loop):** state-changing or live-endpoint tools call LangGraph's `interrupt()`, which pauses the graph (requires a checkpointer) and surfaces a `HumanInterrupt` describing the action + args; the human resumes with `Command(resume=...)` to **accept / edit / reject** (`allow_accept` / `allow_edit` / `allow_respond`). For the read-only MVP this gate is effectively a "promote to live" safety; it's wired and demoed so the *architecture* is provably present even if the demo dataset never triggers a write.
- **Hash-chained audit log:** JSONL, each record carries `prev_hash`; the chain is verified by a `spoor verify-audit` command. Findings store the `tool_call_id` of their source call → criterion 5's "trace any finding back to the specific tool execution" is satisfied literally.

Docs: human-in-the-loop / `interrupt` & `Command(resume=...)` <https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/> · interrupt API & `HumanInterrupt`/`HumanResponse` <https://github.com/langchain-ai/langgraph/blob/main/libs/prebuilt/README.md> · checkpointers <https://github.com/langchain-ai/langgraph/tree/main/libs/checkpoint>

### 5.4 DFIR methodology encoded (the domain bridge)

The prompts are not vibes — they encode the **SANS-published triage playbook** so the agent sequences like a senior analyst:
- **Triage:** memory first (`pslist`→`pstree` for parent/child anomalies, `netscan` for C2, `malfind` for injected code, `cmdline` for launch args), then quick-win disk/registry artifacts (autoruns/Run keys, prefetch, web history).
- **Timeline:** build a **plaso super-timeline** with `log2timeline`, then `psort` to slice to the window of interest around triage pivots — the standard *triage → targeted → super-timeline* progression.
- **IOC/Correlation:** extract hashes/IPs/paths/registry keys and cross-reference them across memory ↔ timeline ↔ disk to turn isolated signals into a causal chain.
- **Reporter:** enforce the **confirmed-vs-inferred** contract; every confirmed finding must cite a `tool_call_id`.

Domain refs: SIFT Workstation + toolset <https://www.sans.org/tools/sift-workstation> · SIFT cheat sheet <https://www.sans.org/posters/sift-cheat-sheet> · Volatility 3 + CLI/renderers <https://volatility3.readthedocs.io/en/latest/vol-cli.html> · Volatility JSON-as-API <https://github.com/volatilityfoundation/volatility/wiki/Unified-Output> · plaso/log2timeline <https://plaso.readthedocs.io/>

---

## 6. Datasets (judging item #5)

Use **public, documented** intrusion evidence with a known answer key so accuracy is measurable and the demo is reproducible without shipping malware blind:
- **Primary:** a *DFIR Madness*-style "Case 001" pairing (Windows memory + disk image) or an equivalent public DFIR challenge image with a published walkthrough/answer key.
- **Fallback (zero-friction):** a Volatility 3 sample memory image (e.g., a public malware-analysis capture) for the memory path, plus a small synthetic disk for the Sleuth Kit path.
- `datasets/README.md` documents: source URL, license, SHA256 of each image, what "evil" is present (the ground truth), and how to fetch (script, not committed binaries). **No malware binaries are committed to the repo**; only hashes + fetch instructions. Evidence is treated as read-only throughout, proven by pre/post hashes in the accuracy report.

---

## 7. Non-goals (out of scope for the hackathon build)

- ❌ Live remote-endpoint response / EDR actions (kill process, isolate host). The approval-gate *architecture* supports it; we do **not** ship live actions — read-only evidence only.
- ❌ Detonating / dynamically analyzing live malware. Static artifacts + hashes + YARA only.
- ❌ Wrapping all 200+ SIFT tools. Curate ~10–12 that cover the memory→timeline→disk→registry→IOC spine; depth over breadth (criterion 3 explicitly rewards this).
- ❌ Web UI / dashboard. CLI + generated Markdown/JSON report is the surface. (A thin read-only viewer is a stretch goal, not MVP.)
- ❌ Multi-OS. Windows evidence only for v1; the tool layer is OS-agnostic but the playbook and dataset are Windows.
- ❌ Fine-tuning / training a model. Orchestration + prompting over a frontier model only (ML-AI framing is satisfied by the agentic system, not a trained model).
- ❌ Auth/multi-tenant/RBAC on the MCP server beyond the allow-list + path-jail.

---

## 8. Risks & unknowns

| # | Risk | Likelihood × Impact | Mitigation |
|---|------|--------------------|------------|
| **R1** | **DFIR domain ramp** — I'm a senior *agent* engineer, not a senior *forensics* analyst. Wrong artifact choices / misread evidence / shallow methodology = low IR-accuracy and breadth scores (criteria 2 & 3 — half the rubric). | **High × High** | **Treat as the headline risk.** (a) Encode the *SANS-published* triage playbook explicitly into prompts rather than trusting model priors. (b) Pick a dataset **with a published answer key** so I can measure accuracy and catch my own domain mistakes before judges do. (c) Time-box domain study to Day 1 (SIFT cheat sheet, one full case walkthrough). (d) Keep the toolset narrow so I can actually understand each tool's output. **This risk is owned, surfaced in the README, and gates the feasibility verdict (§ Plan).** |
| R2 | SIFT VM friction — 8.8GB OVA, Volatility 3 quirks, plaso runtime on a large image is slow/heavy. | Med × Med | Stand up the VM **Day 1** (gate). Pre-bake the `.plaso` for the demo image so the live run isn't bottlenecked on `log2timeline`. Cache tool outputs for the recorded demo. |
| R3 | Non-determinism / hallucination undermines IR-accuracy. | Med × High | Structured (JSON) tool outputs the model reasons over; confirmed-vs-inferred contract; every confirmed claim must cite a `tool_call_id` or it's downgraded to inference. Low temperature on the analytical agents. |
| R4 | Scope creep across 200+ tools / multi-OS / live response. | Med × Med | Hard non-goals (§7); fixed single evidence pairing; YAGNI-tight MVP. |
| R5 | "Constraint tested for bypass" (criterion 4) — judges will *try to break* the guardrails. | Med × High | Make constraints **architectural**: OS read-only mount + server allow-list + path-jail. Ship `tests/test_guardrails.py` that attempts path traversal, non-allow-listed binary, and write-to-evidence — and *demonstrates* they fail. Bypass-resistance is a demoed feature, not a claim. |
| R6 | Token cost / context blow-up on big timelines. | Med × Med | `psort` slices the timeline server-side to the window of interest before it ever reaches the model; paginate/summarize large tool outputs; log token usage per call (also satisfies submission item #8). |
| R7 | MCP adapter / framework version drift mid-build. | Low × Med | Pin versions; the MCP tool layer is framework-agnostic, so a LangGraph→CrewAI fallback (or Claude-Code-direct, §3-A) is cheap insurance. |
| R8 | Solo/tiny team vs. 1,100+ registrants incl. domain experts. | High × Med | Don't out-forensics the forensics pros — **out-engineer** them on the rubric's engineering-heavy half (autonomy, constraints, audit, usability), where my edge is real, while clearing a credible accuracy bar on a known dataset. |

**Open unknowns (to resolve early):** exact Volatility 3 JSON-renderer flags on the shipped SIFT build; `psort` output schema stability; whether the chosen dataset's license permits redistributing hashes/derived timelines (almost certainly yes — we redistribute neither images nor malware). All resolved during Day 1–2 setup.

---

## 9. Criteria → feature traceability

| Judging criterion (equal weight) | Where Spoor earns it |
|---|---|
| Autonomous Execution Quality *(tiebreaker)* | LangGraph supervisor loop: routes phases, retries/re-routes failed tool calls, self-corrects (§5.2) |
| IR Accuracy | Structured JSON tool outputs + confirmed-vs-inferred report contract + accuracy report vs. answer key (§4.5–4.6, §5.1) |
| Breadth & Depth | 4 specialist agents each going deep on an artifact class over the full memory→timeline→disk→registry→IOC spine (§3, §5.4) |
| Constraint Implementation | **Architectural** guardrails: OS read-only mount + server binary allow-list + path-jail + tested-for-bypass suite (§5.3, R5) |
| Audit Trail Quality | Hash-chained JSONL; every finding cites its `tool_call_id`; `verify-audit` command (§4.4, §5.3) |
| Usability & Documentation | `make demo`, README, architecture diagram w/ security boundaries, this SPEC + the PLAN (§4.7) |

---

## 10. Submission checklist (maps 1:1 to the 8 required items)

- [ ] **Public GitHub repo**, `LICENSE` = **MIT or Apache-2.0**, visible at repo root.
- [ ] **Demo video ≤ 5 min** — point at evidence → autonomous run → report + live audit-trace + a guardrail-bypass attempt that *fails*.
- [ ] **Architecture diagram** explicitly labeling the security boundaries (read-only mount, allow-list, approval gate). SVG in `assets/`.
- [ ] **Written project description** (README + this SPEC).
- [ ] **Dataset documentation** — `datasets/README.md` (source, license, hashes, ground truth, fetch script; no committed binaries).
- [ ] **Accuracy report w/ evidence-integrity assessment** — `accuracy_report.md` (precision/recall vs. answer key; pre/post evidence hashes).
- [ ] **Try-it-out instructions** — `make demo` + quick-start in README (and Claude-Code `mcpServers` config for the direct-use path).
- [ ] **Agent execution logs w/ timestamps + token usage** — the hash-chained audit JSONL + a per-run token-usage summary, committed under `runs/`.
- [ ] Sanity: **no secrets in repo** — all keys via env vars (`ANTHROPIC_API_KEY`, optional `VT_API_KEY`); `.env.example` only; `.gitignore` covers `.env`, evidence images, `*.plaso`.
