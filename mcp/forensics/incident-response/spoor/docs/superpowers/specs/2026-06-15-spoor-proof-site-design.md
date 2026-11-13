# Spoor proof-site — design spec

**Date:** 2026-06-15
**Status:** Approved design (brainstorm complete) → ready for implementation planning
**Site:** https://spoor.rectorspace.com
**Repo:** `RECTOR-LABS/spoor`, `web/` subdirectory
**Canonical data run:** `runs/2026-06-12-231634-case001-real/`

---

## 1. Thesis & context

Spoor's central claim is **"don't trust me — verify me."** Everything else (the
hash-chained audit, read-only guardrails, citation enforcement, honest accuracy
measurement) exists to make an autonomous DFIR agent *auditable* rather than
merely plausible.

The proof-site makes that claim something the visitor **does with their own
hands in the browser**, not something we assert. Its centerpiece is an
interactive, client-side-verifiable audit: show the real verdict, let the
visitor recompute the SHA-256 hash chain over the **real** audit records (Web
Crypto), then tamper with a byte and watch the chain break. The site embodies
the product instead of describing it.

The FIND EVIL! hackathon submission is **complete and frozen** — this is a
separate initiative and must not touch Devpost, Vimeo, or the submission.

## 2. Goals / non-goals

**Goals**
- A single dark, static, fast page that lets a technical skeptic verify Spoor's
  audit chain themselves and watch a tamper break it.
- Present the **real, unflattering** accuracy numbers with honest framing.
- Explain the trust stack, each pillar tied to a command that proves it.
- Git-connected Vercel deploy (push-to-deploy + per-PR preview URLs).

**Non-goals**
- No backend, no database, no serverless for content (a build-time `@vercel/og`
  route for the share card is the only non-static piece).
- No "upload your own memory image" SaaS (compute/abuse/evidence/legal risk —
  explicitly rejected).
- No Phase-2 features in v1 (see §12).
- No changes to the hackathon submission.

## 3. Audience

Technical skeptics: FIND EVIL! / SANS judges, DFIR practitioners, and potential
users/employers. The design assumes the visitor's reflex is *"prove it"* and
optimizes for letting them do exactly that.

## 4. Architecture & stack

- **Next.js (App Router)** in `web/`, **Tailwind CSS** + **shadcn/ui**, dark
  forensic theme. Lucide icons. No emoji icons.
- **RSC → static HTML** for every section; **zero client JS** except one island.
- **Exactly one `"use client"` island:** `<VerifiableAudit>` — the verify/tamper
  widget. This is the "islands" benefit without leaving Next.
- **Zero runtime data dependency:** all case data is baked in at build time as a
  typed JSON module (`web/data/case001.json`). The only client-side computation
  is Web Crypto SHA-256.
- Deployed on **Vercel**, **Root Directory = `web/`** (see §10).

## 5. Data pipeline & export schema (W2)

A small **export script** (`scripts/export_site_data.py`, Python — it can import
Spoor's own `audit` module so the serialization is guaranteed identical to the
engine's) reads the committed canonical run and emits one typed
`web/data/case001.json`. It is a dev/CI tool run when the source data changes;
its output JSON is committed, so the site build itself stays pure-Node, and the
export is reproducible and reviewable.

**Inputs** (`runs/2026-06-12-231634-case001-real/`):
- `audit.jsonl` — 8 hash-chained records (the verifiable chain)
- `report.json` — verdict: exec summary, 25 findings (`claim` / `status` /
  `tool_call_id` / `evidence_excerpt`), 16 IOCs, 10 open questions, enforcement
- `run_meta.json` — models, timestamps, evidence integrity hashes, chain status
- `accuracy_report.md` — the numbers + the honest framing prose

**Output** `web/data/case001.json` (shape):

```
{
  meta:    { case, run_id, captured, lead_model, specialist_model,
             started_utc, finished_utc, audit_records, audit_chain_ok,
             evidence_sha256_pre, evidence_sha256_post, evidence_integrity_ok,
             scenario },
  audit:   AuditRecord[]            // 8, byte-exact, all 8 fields each
  verdict: { executive_summary,
             findings: [{ claim, status, tool_call_id, evidence_excerpt }],
             iocs:     [{ type, value, tool_call_id }],
             open_questions: string[],
             enforcement: { audit_chain_ok, confirmed, inferred, downgraded },
             report_audit_id }
  accuracy:{ precision, recall, f1, hallucination_rate,
             confirmed_total, ground_truth_items,
             pre_correction: { precision, recall, f1 },
             true_positives, false_positives, false_negatives, unscored,
             framing }              // the "over-reporting, not fabrication" prose
}
```

**`AuditRecord`** mirrors the Python dataclass exactly:
`{ seq, ts, tool, args, exit_code, stdout_sha256, prev_hash, hash }`.

**Secret-scrub:** the public dataset (DFIR Madness Case 001) is safe to publish.
The export script nonetheless asserts no API-key-shaped tokens appear in any
exported prose; it aborts if one is found. See Decision 1 for the audit records.

## 6. The `<VerifiableAudit>` island (the heart)

The one interactive component. It reproduces Spoor's audit verification in the
browser, exactly.

### 6.1 `canonicalize(value): string`
A TS serializer that **exactly mirrors** Python
`json.dumps(content, sort_keys=True, separators=(",",":"), ensure_ascii=False)`:
- objects → keys sorted by code point, joined `"key":value` with `,` separators,
  wrapped in `{}` — recursively;
- strings → `JSON.stringify(s)` (keeps non-ASCII literal, matching
  `ensure_ascii=False`);
- numbers/booleans/null → `JSON.stringify` (content-field numbers are integers —
  `seq`, `exit_code`, and the nested `args` ints — so there is no float-format
  divergence);
- arrays → `[` + elements canonicalized + `]`.

Our keys and values are ASCII, so JS code-point sort equals Python's. This is
**locked by a golden test** (§11): all 8 real records must hash to their stored
values.

### 6.2 `verifyChain(records): { ok, brokenSeq?, reason? }`
Mirrors `AuditLog.verify()` line-for-line:
- `GENESIS = "0".repeat(64)`; `prev = GENESIS`.
- For each record at index `i`:
  - `seq === i` else broken ("sequence broken: missing, duplicated, or reordered");
  - `prev_hash === prev` else broken ("chain broken: prev_hash mismatch");
  - `sha256hex(canonicalize(contentFields)) === hash` else broken ("record
    tampered: stored hash ≠ content");
  - `prev = hash`.
- `contentFields = { seq, ts, tool, args, exit_code, stdout_sha256, prev_hash }`
  (everything but `hash`).
- `sha256hex` uses `crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))`.

### 6.3 State machine
- `original` — the pristine exported records, frozen.
- `working` — a deep copy the user can mutate.
- Actions:
  - **Verify** — run `verifyChain(working)`, render result (✓ INTACT / ✗ BROKEN
    at seq N + reason). Runs automatically on mount → ✓ INTACT.
  - **Tamper (one-click, hero)** — flip a single character in the selected
    record's `stdout_sha256` (default selection: seq 2, the `vol_netscan`
    record the C2 finding cites), re-verify → ✗ BROKEN at that seq.
  - **Free-edit (inspector)** — every content field is editable; on input,
    re-verify live. Editing any content field (or the stored `hash`) breaks the
    chain at that record.
  - **Reset** — restore `working` from `original`, re-verify → ✓ INTACT.

### 6.4 Render
- **Hero:** verdict headline + the 8-record chain strip (seq 2 highlighted) +
  `Verify / Tamper / Reset` + the live result line + "100% client-side · Web
  Crypto · same math as `spoor verify-audit`".
- **Inspector (expandable):** the 8 records as a clickable list; the selected
  record's fields, with the line **"a finding's `tool_call_id` IS this hash"**
  and the findings that cite it; per-record one-click flip + free-edit.

## 7. Honesty / parity gates (Decision 2)

The client-side ✓ must be a **proof, not a claim**. Three consistent layers:

1. **Export-time (Python):** the export script runs `spoor verify-audit` on the
   source run and refuses to emit if the chain is not `ok` or any stored hash
   fails to recompute.
2. **Build-time (Node, gates the Vercel deploy):** a **prebuild** step recomputes
   the chain with the *same* `canonicalize` + `verifyChain` over
   `web/data/case001.json` and asserts (a) every recomputed hash equals the
   stored hash and (b) `verifyChain` returns `ok`. **If the data and the
   verifier diverge, `next build` fails and nothing deploys.**
3. **Runtime (browser):** the identical `verifyChain` recomputes in the visitor's
   browser.

Additionally, a CI check (GitHub Actions) cross-checks the Node result against
`uv run spoor verify-audit` (Python) so the TS verifier provably matches the
canonical tool. There is **never** a hardcoded "intact ✓" anywhere.

## 8. Page sections (Order A — "prove, then explain")

1. **Hero** — "Autonomous DFIR you can audit." Subhead: an AI agent investigated
   a real compromised domain controller; check its work yourself. CTA: "Verify
   it yourself ↓". Small demo-video poster (links to Vimeo). Subtle spoor /
   animal-track motif (following a trail of evidence).
2. **★ Verifiable audit** — the `<VerifiableAudit>` island (verdict → verify /
   tamper → inspector). The anchor of the page.
3. **Accuracy, honestly** — P 0.25 · R 0.50 · F1 0.33 · hallucination 0.000 ·
   evidence INTACT (byte-identical SHA-256 pre/post). The pre/post
   scorer-correction story; **"over-reporting, not fabrication"** (the injection-
   victim system binaries are real anomalies just outside the 4-item
   memory-visible key); confirmed vs inferred; the 10 open questions (what the
   agent *refuses* to claim).
4. **Trust stack** — five pillars, each with the command that proves it, plus the
   web-grade SVG architecture diagram (re-authored from
   `~/Documents/spoor_architecture.png`):
   1. **Tamper-evident audit** — `spoor verify-audit <run>/audit.jsonl`
   2. **Read-only evidence** — guardrails (path-jail, no-shell allow-listed
      exec); evidence SHA-256 pre == post
   3. **Citation enforcement** — confirmed findings must cite a real
      `tool_call_id`; uncited downgraded (report `enforcement` block)
   4. **Honest accuracy** — `python scripts/rescore_run.py <run>` +
      `accuracy_report.md` (deterministic, reports pre/post)
   5. **Self-correction** — `spoor show-selfcorrect <run>` (run 155749) *(pillar
      named here; full replay UI is Phase 2)*
5. **Footer** — GitHub · demo video (Vimeo) · Devpost · copy-paste repro
   commands.

## 9. Design language

Per RECTOR's globals + Spoor's identity: dark / forensic, terminal-inflected but
polished. Monospace for evidence and hashes. **Green** = intact / confirmed,
**red** = broken / tamper, **amber** = inference. Lucide icons (fingerprint,
shield-check, link, file-search, terminal) — never emoji icons. SVG diagrams,
styled for dark backgrounds. Subtle "spoor = animal track/trail" motif.

## 10. Deployment — Git-connected, push-to-deploy (W9)

- Import `RECTOR-LABS/spoor` into Vercel as a project via the **Vercel Git
  integration** (GitHub). Framework Preset = Next.js, **Root Directory =
  `web/`**, **Production Branch = `main`**.
- **Push-to-deploy:** every push to `main` → production deploy at
  spoor.rectorspace.com; every PR / branch → a unique **preview URL** (used to
  review each W-slice). Instant rollbacks via the dashboard. No `vercel deploy`
  CLI for releases — Git push is the trigger.
- Build runs the §7 prebuild parity assertion; a divergent chain fails the build
  and blocks the deploy.
- **DNS:** on Cloudflare **Personal** account (rector@rectorspace.com), add
  `spoor` CNAME → `cname.vercel-dns.com`, **DNS-only / grey-cloud** (NOT
  Proxied). This is the deliberate exception to the all-Proxied rule (that rule
  is for VPS-origin records); Vercel terminates TLS and issues the cert.
- **One-time human setup:** connect the GitHub repo and authorize the
  RECTOR-LABS org in Vercel, and add the custom domain in project settings
  (Vercel auto-provisions SSL). Flagged as a manual W9 step.
- **Env vars:** none required (fully static content).

## 11. Testing

- **Vitest unit — `canonicalize` parity (golden):** feed the 8 real records;
  assert each `sha256hex(canonicalize(contentFields))` equals its stored `hash`.
  This is the lock that the TS serializer matches Python.
- **Vitest unit — `verifyChain` tamper detection:** for each content field,
  mutate it and assert `verifyChain` returns `ok:false` with the correct
  `brokenSeq`; assert sequence-reorder and prev_hash-break are caught.
- **Parity script (CI):** cross-check the Node verifier's result against
  `uv run spoor verify-audit` on the same run.
- **W10:** Lighthouse + a11y pass (keyboard reachable verify/tamper, contrast,
  reduced-motion), responsive, OG image, copy pass.

## 12. Scope — Phase 1 vs Phase 2

**Phase 1 (this initiative — the irreducible wow):** Hero · ★ Verifiable-audit +
tamper · Accuracy-measured-honestly · Trust stack (5 pillars + SVG) · footer
links. Sections in Order A.

**Phase 2 (after the wow lands):** case-file explorer (timeline / process-tree /
IOC graph, each node citing evidence) · self-correction replay (run 155749 fail
→ recover) · richer architecture interactions.

**This session ends at:** this design doc committed → implementation plan written
(`writing-plans`). Build kickoff (W1+) is a separate decision.

## 13. Decisions log

1. **Audit records ship byte-exact, local path included.** The records' `args`
   contain `/Users/rector/local-dev/spoor/evidence/case001/citadeldc01.mem`,
   which is part of the hashed content. Scrubbing it would change the hash and
   break the very chain we prove. The path is not sensitive; the records are
   published verbatim. **Approved.**
2. **The honesty/parity gate is a build gate, not just a local check** — a
   divergent chain fails `next build` and blocks the Vercel deploy (§7).
   **Approved.**
3. **Session scope** ends at design doc + implementation plan; build kickoff is a
   separate go. **Approved.**
4. **Deploy via Vercel Git integration** (push-to-deploy + preview URLs), not CLI
   deploys. **Added by RECTOR.**

## 14. Risks & open items

- **Canonical-JSON parity** is the highest-risk correctness item; it is fully
  mitigated by the golden test (§11) and the build gate (§7). If a future record
  ever contains a float or non-ASCII key, the serializer needs review — none do
  today.
- **Vercel ↔ GitHub org authorization** is a one-time human step (§10); the build
  itself is deterministic.
- **shadcn/ui footprint** — keep it minimal; pull only the few primitives used
  (button, card, accordion/collapsible, tabs) to preserve the static/lean goal.

## 15. W-slice mapping

| Slice | This spec |
|---|---|
| W1 scaffold (Next + Tailwind + shadcn, `web/`) | §4, §9 |
| W2 export pipeline + scrub | §5, Decision 1 |
| W3 hero + problem + trust-stack (static) | §8 |
| W4 ★ verifiable-audit + tamper island | §6 |
| W5 accuracy-measured-honestly | §8.3 |
| W8 web-grade SVG architecture diagram | §8.4 |
| W9 deploy → spoor.rectorspace.com | §10 |
| W10 polish: a11y / Lighthouse / OG / responsive | §11 |
| Parity / honesty gates | §7, §11 |
