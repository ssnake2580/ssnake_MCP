# Spoor Proof-Site (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `spoor.rectorspace.com` — a static, dark, fast proof-site whose centerpiece lets a visitor recompute Spoor's real SHA-256 audit chain in their own browser and watch a byte-flip break it.

**Architecture:** Next.js (App Router) in a `web/` subdirectory, RSC → static HTML for every section, exactly one `"use client"` island (`<VerifiableAudit>`) doing Web Crypto SHA-256. All case data is baked in at build time from a committed `web/data/case001.json`, produced by a Python export script that reuses Spoor's own `audit` + `accuracy` modules. A build-time parity gate fails the build if the published data and the TS verifier ever disagree. Deployed on Vercel via Git integration (push-to-`main` → prod, PR → preview URL).

**Tech Stack:** Next.js 15 (App Router, TypeScript), Tailwind CSS, shadcn/ui, Lucide icons, Vitest + React Testing Library, `tsx`, Web Crypto (`crypto.subtle`). Python 3 (`uv`) for the data export. Source spec: `docs/superpowers/specs/2026-06-15-spoor-proof-site-design.md`.

**Branch:** `feat/proof-site` (already created; the spec is committed there).

**Conventions:** TDD for all logic. One focused commit per task (conventional-commit prefixes). GPG-signed (`-S`). No AI attribution in any commit/PR/text. Exact paths below are relative to the repo root `/Users/rector/local-dev/spoor`.

---

## File Structure

```
scripts/export_site_data.py          # Python: canonical run → web/data/case001.json (reuses spoor_sift)
tests/test_export_site_data.py        # pytest: export output is valid + chain verifies
web/                                  # Next.js app (Vercel Root Directory = web/)
  data/case001.json                   # committed export (the only data source)
  lib/
    canonicalize.ts                   # Python-identical canonical JSON
    sha256.ts                         # Web Crypto SHA-256 hex
    verifyAudit.ts                    # AuditRecord, verifyChain, recordHash (mirrors AuditLog.verify)
    __tests__/canonicalize.test.ts
    __tests__/verifyAudit.test.ts
  scripts/verify-data.ts              # build-time honesty gate (tsx)
  components/
    verifiable-audit/
      VerifiableAudit.tsx             # the one client island
      ChainStrip.tsx
      ResultBanner.tsx
      RecordInspector.tsx
      __tests__/VerifiableAudit.test.tsx
    sections/
      Hero.tsx
      AccuracySection.tsx
      TrustStack.tsx
      SiteFooter.tsx
    ArchitectureDiagram.tsx           # inline SVG (W8)
  lib/site-data.ts                    # typed accessors over case001.json (server-side)
  app/
    layout.tsx                        # dark theme, fonts, metadata
    page.tsx                          # assembles sections in Order A
    globals.css                       # forensic palette tokens
    opengraph-image.tsx               # @vercel/og share card (W10)
  vitest.config.ts
  vitest.setup.ts
.github/workflows/site-parity.yml     # CI: TS verifier ↔ `spoor verify-audit` cross-check
```

---

## Task 1: Scaffold the Next.js app in `web/`

**Files:**
- Create: `web/` (via `create-next-app`), `web/vitest.config.ts`, `web/vitest.setup.ts`
- Modify: `web/package.json` (scripts), `web/tsconfig.json` (ensure `resolveJsonModule`)

- [ ] **Step 1: Scaffold Next.js**

Run (from repo root):
```bash
npx create-next-app@latest web --typescript --tailwind --app --eslint --no-src-dir --import-alias "@/*" --use-npm
```
Expected: `web/` created with `app/`, `tailwind.config.ts`, `tsconfig.json`, `package.json`.

- [ ] **Step 2: Init shadcn/ui + add only the primitives we use**

Run:
```bash
cd web
npx shadcn@latest init -d
npx shadcn@latest add button card accordion collapsible badge
cd ..
```
Expected: `web/components.json`, `web/lib/utils.ts`, `web/components/ui/*` created.

- [ ] **Step 3: Install test + tooling deps**

Run:
```bash
cd web
npm i -D vitest @vitejs/plugin-react @testing-library/react @testing-library/jest-dom @testing-library/user-event jsdom tsx
cd ..
```

- [ ] **Step 4: Add `web/vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": resolve(__dirname, ".") } },
  test: { environment: "jsdom", setupFiles: ["./vitest.setup.ts"], globals: true },
});
```

- [ ] **Step 5: Add `web/vitest.setup.ts`**

```ts
import "@testing-library/jest-dom/vitest";
import { webcrypto } from "node:crypto";
import { vi } from "vitest";

// jsdom does not expose SubtleCrypto; verifyChain needs it, so install Node's Web Crypto in tests.
if (!globalThis.crypto?.subtle) {
  vi.stubGlobal("crypto", webcrypto);
}
```

- [ ] **Step 6: Wire scripts in `web/package.json`**

Set the `scripts` block to:
```json
{
  "scripts": {
    "dev": "next dev",
    "build": "tsx scripts/verify-data.ts && next build",
    "start": "next start",
    "lint": "next lint",
    "test": "vitest run",
    "export:data": "cd .. && uv run python scripts/export_site_data.py"
  }
}
```
Confirm `web/tsconfig.json` `compilerOptions` includes `"resolveJsonModule": true` (Next sets it; add if absent).

- [ ] **Step 7: Smoke-test the scaffold**

Run:
```bash
cd web && npm run lint && cd ..
```
Expected: lint passes (the build script will fail until Task 2 creates the data + Task 5 the gate — that is expected and fixed by Task 5).

- [ ] **Step 8: Commit**

```bash
git add web/ && git commit -S -m "chore: scaffold web/ (Next.js + Tailwind + shadcn + vitest)"
```

---

## Task 2: Python export → `web/data/case001.json`

**Files:**
- Create: `scripts/export_site_data.py`, `tests/test_export_site_data.py`
- Produces (committed): `web/data/case001.json`

- [ ] **Step 1: Write the failing test** — `tests/test_export_site_data.py`

```python
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "web" / "data" / "case001.json"


def test_export_produces_valid_site_data():
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "export_site_data.py")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(OUT.read_text())

    # 8 byte-exact audit records, each carrying every content + hash field
    assert len(data["audit"]) == 8
    fields = {"seq", "ts", "tool", "args", "exit_code", "stdout_sha256", "prev_hash", "hash"}
    for rec in data["audit"]:
        assert fields <= set(rec)
    # known anchors
    assert data["audit"][0]["prev_hash"] == "0" * 64
    assert data["audit"][2]["hash"] == "cb5ea571ee90915f4e7b36a9b241ce2bfde7f883c44641c5381e0b986f6c81ac"
    assert data["audit"][7]["hash"] == "50be50f15a60698cb99c1d0970bcc5e37ea308f1a5aae8906c4cf93c0c0d6283"

    # integrity + verdict + accuracy (computed, not parsed)
    assert data["meta"]["evidence_integrity_ok"] is True
    assert data["verdict"]["enforcement"]["confirmed"] == 19
    assert data["accuracy"]["precision"] == 0.25
    assert data["accuracy"]["recall"] == 0.5
    assert data["accuracy"]["hallucination_rate"] == 0.0
```

- [ ] **Step 2: Run it, verify it fails**

Run: `uv run pytest tests/test_export_site_data.py -v`
Expected: FAIL (script does not exist yet).

- [ ] **Step 3: Implement `scripts/export_site_data.py`**

```python
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
SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})")


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
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `uv run pytest tests/test_export_site_data.py -v`
Expected: PASS. (`web/data/case001.json` now exists.)

- [ ] **Step 5: Commit**

```bash
git add scripts/export_site_data.py tests/test_export_site_data.py web/data/case001.json
git commit -S -m "feat: export canonical run to web/data/case001.json (reuses spoor_sift)"
```

---

## Task 3: `canonicalize()` — Python-identical canonical JSON

**Files:**
- Create: `web/lib/canonicalize.ts`, `web/lib/sha256.ts`, `web/lib/__tests__/canonicalize.test.ts`

- [ ] **Step 1: Write the failing test** — `web/lib/__tests__/canonicalize.test.ts`

```ts
import { describe, it, expect } from "vitest";
import { canonicalize } from "../canonicalize";

describe("canonicalize (mirrors Python json.dumps sort_keys, separators=(',',':'), ensure_ascii=False)", () => {
  it("sorts object keys and uses compact separators", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
  it("sorts nested objects recursively", () => {
    expect(canonicalize({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });
  it("keeps integers bare and strings quoted", () => {
    expect(canonicalize({ exit_code: 0, tool: "vol_netscan" })).toBe('{"exit_code":0,"tool":"vol_netscan"}');
  });
  it("matches a known audit content hash input", () => {
    // content fields of seq 0, in any order — canonical form must be stable
    const content = {
      seq: 0,
      ts: "2026-06-12T23:16:45.693151+00:00",
      tool: "vol_pslist",
      args: { memory_image: "/Users/rector/local-dev/spoor/evidence/case001/citadeldc01.mem" },
      exit_code: 0,
      stdout_sha256: "cb8c4b62f91fb09033e3bd3ea7b56ccba67a436688907d10f61de13cf2ca82ed",
      prev_hash: "0".repeat(64),
    };
    expect(canonicalize(content)).toBe(
      '{"args":{"memory_image":"/Users/rector/local-dev/spoor/evidence/case001/citadeldc01.mem"},' +
        '"exit_code":0,"prev_hash":"' + "0".repeat(64) + '",' +
        '"seq":0,"stdout_sha256":"cb8c4b62f91fb09033e3bd3ea7b56ccba67a436688907d10f61de13cf2ca82ed",' +
        '"tool":"vol_pslist","ts":"2026-06-12T23:16:45.693151+00:00"}',
    );
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd web && npx vitest run lib/__tests__/canonicalize.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement `web/lib/canonicalize.ts`**

```ts
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/**
 * Deterministic JSON identical to Python's
 *   json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 * Keys are sorted by code point (matches Python for our ASCII keys); separators are
 * bare; non-ASCII is left literal (JSON.stringify default == ensure_ascii=False).
 */
export function canonicalize(value: Json): string {
  if (value === null) return "null";
  if (typeof value !== "object") return JSON.stringify(value); // string | number | boolean
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const obj = value as { [key: string]: Json };
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}
```

- [ ] **Step 4: Implement `web/lib/sha256.ts`**

```ts
/** SHA-256 of a UTF-8 string as lowercase hex, via Web Crypto (browser + Node 20+). */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
```

- [ ] **Step 5: Run the test, verify it passes**

Run: `cd web && npx vitest run lib/__tests__/canonicalize.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/lib/canonicalize.ts web/lib/sha256.ts web/lib/__tests__/canonicalize.test.ts
git commit -S -m "feat: canonical JSON + Web Crypto SHA-256 (Python-identical)"
```

---

## Task 4: `verifyChain()` — mirror of `AuditLog.verify()`

**Files:**
- Create: `web/lib/verifyAudit.ts`, `web/lib/__tests__/verifyAudit.test.ts`

- [ ] **Step 1: Write the failing test** — `web/lib/__tests__/verifyAudit.test.ts`

```ts
import { describe, it, expect } from "vitest";
import data from "../../data/case001.json";
import { verifyChain, recordHash, type AuditRecord } from "../verifyAudit";

const records = data.audit as AuditRecord[];

describe("audit chain parity with the Python engine", () => {
  it("every record's content hashes to its stored hash", async () => {
    for (const r of records) expect(await recordHash(r)).toBe(r.hash);
  });
  it("the pristine chain verifies", async () => {
    expect(await verifyChain(records)).toEqual({ ok: true });
  });
});

describe("tamper detection (mirrors verify(): seq, prev_hash, content)", () => {
  it("mutating stdout_sha256 breaks the chain at that seq", async () => {
    const t = structuredClone(records);
    t[2].stdout_sha256 = "deadbeef" + t[2].stdout_sha256.slice(8);
    const res = await verifyChain(t);
    expect(res.ok).toBe(false);
    expect(res.brokenSeq).toBe(2);
    expect(res.reason).toMatch(/tampered/);
  });
  it("flipping exit_code breaks the chain at that seq", async () => {
    const t = structuredClone(records);
    t[0].exit_code = 1;
    expect(await verifyChain(t)).toMatchObject({ ok: false, brokenSeq: 0 });
  });
  it("reordering records breaks the sequence", async () => {
    const t = structuredClone(records);
    [t[1], t[2]] = [t[2], t[1]];
    expect((await verifyChain(t)).ok).toBe(false);
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd web && npx vitest run lib/__tests__/verifyAudit.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement `web/lib/verifyAudit.ts`**

```ts
import { canonicalize, type Json } from "./canonicalize";
import { sha256Hex } from "./sha256";

export const GENESIS = "0".repeat(64);
const CONTENT_FIELDS = ["seq", "ts", "tool", "args", "exit_code", "stdout_sha256", "prev_hash"] as const;

export interface AuditRecord {
  seq: number;
  ts: string;
  tool: string;
  args: Json;
  exit_code: number;
  stdout_sha256: string;
  prev_hash: string;
  hash: string;
}

export interface VerifyResult {
  ok: boolean;
  brokenSeq?: number;
  reason?: string;
}

/** SHA-256 over the canonical content fields (everything but `hash`). */
export async function recordHash(rec: AuditRecord): Promise<string> {
  const content: { [k: string]: Json } = {};
  for (const k of CONTENT_FIELDS) content[k] = rec[k] as Json;
  return sha256Hex(canonicalize(content));
}

/** Recompute the chain end to end; report the first break. Mirrors AuditLog.verify(). */
export async function verifyChain(records: AuditRecord[]): Promise<VerifyResult> {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.seq !== i)
      return { ok: false, brokenSeq: i, reason: "sequence broken: record missing, duplicated, or reordered" };
    if (r.prev_hash !== prev)
      return { ok: false, brokenSeq: i, reason: "chain broken: prev_hash does not match the previous record" };
    if ((await recordHash(r)) !== r.hash)
      return { ok: false, brokenSeq: i, reason: "record tampered: stored hash does not match content" };
    prev = r.hash;
  }
  return { ok: true };
}
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `cd web && npx vitest run lib/__tests__/verifyAudit.test.ts`
Expected: PASS (proves the TS verifier matches the engine's hashes byte-for-byte).

- [ ] **Step 5: Commit**

```bash
git add web/lib/verifyAudit.ts web/lib/__tests__/verifyAudit.test.ts
git commit -S -m "feat: verifyChain mirrors AuditLog.verify (parity proven by golden test)"
```

---

## Task 5: Build-time honesty gate

**Files:**
- Create: `web/scripts/verify-data.ts`, `web/lib/__tests__/verify-data.test.ts`
- The `web build` script already chains this gate before `next build` (Task 1, Step 6).

- [ ] **Step 1: Write the failing test** — `web/lib/__tests__/verify-data.test.ts`

```ts
import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const SCRIPT = resolve(__dirname, "../../scripts/verify-data.ts");

describe("build-time data gate", () => {
  it("exits 0 on the committed (intact) data", () => {
    const out = execFileSync("npx", ["tsx", SCRIPT], { encoding: "utf8", cwd: resolve(__dirname, "../..") });
    expect(out).toMatch(/data gate OK/);
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd web && npx vitest run lib/__tests__/verify-data.test.ts`
Expected: FAIL (script not found).

- [ ] **Step 3: Implement `web/scripts/verify-data.ts`**

```ts
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyChain, recordHash, type AuditRecord } from "../lib/verifyAudit";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "../data/case001.json"), "utf8"));
const records: AuditRecord[] = data.audit;

const res = await verifyChain(records);
if (!res.ok) {
  console.error(`DATA GATE FAILED: chain not ok — broken at seq ${res.brokenSeq}: ${res.reason}`);
  process.exit(1);
}
for (const r of records) {
  const recomputed = await recordHash(r);
  if (recomputed !== r.hash) {
    console.error(`DATA GATE FAILED: seq ${r.seq} recomputed ${recomputed} !== stored ${r.hash}`);
    process.exit(1);
  }
}
console.log(`data gate OK — ${records.length} records verify against the TS verifier`);
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `cd web && npx vitest run lib/__tests__/verify-data.test.ts`
Expected: PASS.

- [ ] **Step 5: Verify the full build now succeeds end to end**

Run: `cd web && npm run build && cd ..`
Expected: gate prints "data gate OK", then `next build` completes.

- [ ] **Step 6: Commit**

```bash
git add web/scripts/verify-data.ts web/lib/__tests__/verify-data.test.ts web/package.json
git commit -S -m "feat: build-time honesty gate — diverging data fails next build"
```

---

## Task 6: The `<VerifiableAudit>` client island

**Files:**
- Create: `web/lib/site-data.ts`, `web/components/verifiable-audit/{VerifiableAudit,ChainStrip,ResultBanner,RecordInspector}.tsx`, `web/components/verifiable-audit/__tests__/VerifiableAudit.test.tsx`

- [ ] **Step 1: Add typed server accessors** — `web/lib/site-data.ts`

```ts
import raw from "@/data/case001.json";
import type { AuditRecord } from "@/lib/verifyAudit";

export interface Finding {
  claim: string;
  status: "confirmed" | "inferred";
  tool_call_id: string | null;
  evidence_excerpt: string | null;
}
export interface Ioc { type: string; value: string; tool_call_id: string | null }

export const site = raw as unknown as {
  meta: Record<string, string | number | boolean>;
  audit: AuditRecord[];
  verdict: {
    executive_summary: string;
    findings: Finding[];
    iocs: Ioc[];
    open_questions: string[];
    enforcement: { audit_chain_ok: boolean; confirmed: number; inferred: number; downgraded: number };
    report_audit_id: string;
  };
  accuracy: {
    precision: number; recall: number; f1: number; hallucination_rate: number;
    confirmed_total: string; ground_truth_items: number;
    pre_correction: { precision: number; recall: number; f1: number };
    true_positives: { category: string; value: string }[];
    false_positives: { category: string; value: string }[];
    false_negatives: { category: string; value: string }[];
    unscored: { type: string; value: string }[];
    framing: string;
  };
};

/** Map a record hash → the human labels of findings that cite it (for the inspector). */
export function citationsByRecord(): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  for (const f of site.verdict.findings) {
    if (f.status === "confirmed" && f.tool_call_id) {
      (map[f.tool_call_id] ??= []).push(f.claim);
    }
  }
  return map;
}
```

- [ ] **Step 2: Write the failing component test** — `web/components/verifiable-audit/__tests__/VerifiableAudit.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { VerifiableAudit } from "../VerifiableAudit";
import { site } from "@/lib/site-data";

const props = { audit: site.audit, citations: {} as Record<string, string[]> };

describe("<VerifiableAudit>", () => {
  it("auto-verifies to INTACT on mount", async () => {
    render(<VerifiableAudit {...props} />);
    await waitFor(() => expect(screen.getByText(/INTACT/i)).toBeInTheDocument());
  });
  it("breaks the chain when Tamper is clicked, and restores on Reset", async () => {
    render(<VerifiableAudit {...props} />);
    await waitFor(() => screen.getByText(/INTACT/i));
    fireEvent.click(screen.getByRole("button", { name: /tamper/i }));
    await waitFor(() => expect(screen.getByText(/BROKEN/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /reset/i }));
    await waitFor(() => expect(screen.getByText(/INTACT/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd web && npx vitest run components/verifiable-audit`
Expected: FAIL (component not found).

- [ ] **Step 4: Implement `web/components/verifiable-audit/VerifiableAudit.tsx`**

```tsx
"use client";

import { useCallback, useEffect, useState } from "react";
import { verifyChain, type AuditRecord, type VerifyResult } from "@/lib/verifyAudit";
import { ChainStrip } from "./ChainStrip";
import { ResultBanner } from "./ResultBanner";
import { RecordInspector } from "./RecordInspector";

export interface VerifiableAuditProps {
  audit: AuditRecord[];
  citations: Record<string, string[]>;
}

export function VerifiableAudit({ audit, citations }: VerifiableAuditProps) {
  const [working, setWorking] = useState<AuditRecord[]>(() => structuredClone(audit));
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [selected, setSelected] = useState(2); // seq 2 = the C2 netscan
  const [verifying, setVerifying] = useState(false);

  const runVerify = useCallback(async (records: AuditRecord[]) => {
    setVerifying(true);
    setResult(await verifyChain(records));
    setVerifying(false);
  }, []);

  useEffect(() => {
    void runVerify(working);
    // run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const apply = (mutate: (records: AuditRecord[]) => void) => {
    const next = structuredClone(working);
    mutate(next);
    setWorking(next);
    void runVerify(next);
  };

  const tamperByte = (seq: number) =>
    apply((recs) => {
      const r = recs[seq];
      const c = r.stdout_sha256[0] === "0" ? "1" : "0";
      r.stdout_sha256 = c + r.stdout_sha256.slice(1);
    });

  const editField = (seq: number, field: keyof AuditRecord, value: string) =>
    apply((recs) => {
      const r = recs[seq] as Record<string, unknown>;
      r[field] = field === "exit_code" || field === "seq" ? Number(value) : value;
    });

  const reset = () => {
    const fresh = structuredClone(audit);
    setWorking(fresh);
    void runVerify(fresh);
  };

  const tampered = JSON.stringify(working) !== JSON.stringify(audit);

  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-950/60 p-5 font-mono text-sm text-neutral-200">
      <ChainStrip records={working} brokenSeq={result?.ok ? undefined : result?.brokenSeq} selected={selected} onSelect={setSelected} />
      <div className="mt-4 flex flex-wrap gap-2">
        <button onClick={() => runVerify(working)} disabled={verifying}
          className="rounded-md border border-emerald-700 px-3 py-1.5 text-emerald-400 hover:bg-emerald-950/40">
          Verify chain
        </button>
        <button onClick={() => tamperByte(selected)}
          className="rounded-md border border-amber-700 px-3 py-1.5 text-amber-400 hover:bg-amber-950/40">
          Tamper a byte
        </button>
        <button onClick={reset} disabled={!tampered}
          className="rounded-md border border-neutral-700 px-3 py-1.5 text-neutral-300 hover:bg-neutral-900 disabled:opacity-40">
          Reset
        </button>
      </div>
      <ResultBanner result={result} verifying={verifying} />
      <RecordInspector
        records={working} selected={selected} onSelect={setSelected}
        citations={citations} brokenSeq={result?.ok ? undefined : result?.brokenSeq}
        onEdit={editField} onTamper={tamperByte}
      />
    </div>
  );
}
```

- [ ] **Step 5: Implement `web/components/verifiable-audit/ChainStrip.tsx`**

```tsx
import type { AuditRecord } from "@/lib/verifyAudit";

export function ChainStrip({
  records, brokenSeq, selected, onSelect,
}: {
  records: AuditRecord[];
  brokenSeq?: number;
  selected: number;
  onSelect: (seq: number) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1" aria-label="audit chain">
      {records.map((r, i) => {
        const broken = brokenSeq !== undefined && i >= brokenSeq;
        const color = broken ? "border-red-600 text-red-400" : "border-emerald-700 text-emerald-400";
        return (
          <span key={r.seq} className="flex items-center gap-1">
            <button
              onClick={() => onSelect(r.seq)}
              aria-current={selected === r.seq}
              title={`seq ${r.seq} · ${r.tool}`}
              className={`h-7 w-7 rounded-full border ${color} ${selected === r.seq ? "ring-2 ring-sky-500" : ""}`}
            >
              {r.seq}
            </button>
            {i < records.length - 1 && <span className={`h-0.5 w-4 ${broken ? "bg-red-700" : "bg-emerald-800"}`} />}
          </span>
        );
      })}
    </div>
  );
}
```

- [ ] **Step 6: Implement `web/components/verifiable-audit/ResultBanner.tsx`**

```tsx
import type { VerifyResult } from "@/lib/verifyAudit";

export function ResultBanner({ result, verifying }: { result: VerifyResult | null; verifying: boolean }) {
  if (verifying || !result)
    return <p className="mt-3 rounded-md border border-neutral-700 px-3 py-2 text-neutral-400">recomputing SHA-256 in your browser…</p>;
  if (result.ok)
    return (
      <p className="mt-3 rounded-md border border-emerald-700 bg-emerald-950/30 px-3 py-2 text-emerald-400" role="status">
        ✓ INTACT — recomputed every record, genesis→tip, all prev_hash links match.
      </p>
    );
  return (
    <p className="mt-3 rounded-md border border-red-700 bg-red-950/30 px-3 py-2 text-red-400" role="status">
      ✗ BROKEN at seq {result.brokenSeq} — {result.reason}. Every finding citing this record is now unprovable.
    </p>
  );
}
```

- [ ] **Step 7: Implement `web/components/verifiable-audit/RecordInspector.tsx`**

```tsx
import { useState } from "react";
import type { AuditRecord } from "@/lib/verifyAudit";

const FIELDS: (keyof AuditRecord)[] = ["seq", "tool", "ts", "exit_code", "stdout_sha256", "prev_hash", "hash"];

export function RecordInspector({
  records, selected, onSelect, citations, brokenSeq, onEdit, onTamper,
}: {
  records: AuditRecord[];
  selected: number;
  onSelect: (seq: number) => void;
  citations: Record<string, string[]>;
  brokenSeq?: number;
  onEdit: (seq: number, field: keyof AuditRecord, value: string) => void;
  onTamper: (seq: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const rec = records[selected];
  const cites = citations[rec.hash] ?? [];

  return (
    <div className="mt-4">
      <button onClick={() => setOpen((v) => !v)} className="text-sky-400 hover:underline">
        {open ? "▾" : "▸"} open the full inspector — all {records.length} records, click any field to edit it
      </button>
      {open && (
        <div className="mt-3 grid gap-3 md:grid-cols-[210px_1fr]">
          <ul className="space-y-1">
            {records.map((r, i) => {
              const broken = brokenSeq !== undefined && i >= brokenSeq;
              return (
                <li key={r.seq}>
                  <button
                    onClick={() => onSelect(r.seq)}
                    className={`flex w-full justify-between rounded-md border px-2 py-1 ${
                      selected === r.seq ? "border-sky-600" : "border-neutral-800"
                    } ${broken ? "text-red-400" : "text-neutral-300"}`}
                  >
                    <span>seq{r.seq} {r.tool}</span>
                    <span>{broken ? "✗" : "⛓"}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="space-y-1">
            {FIELDS.map((f) => (
              <div key={f} className="flex gap-2">
                <span className="w-28 shrink-0 text-neutral-500">{f}</span>
                <span
                  contentEditable={f !== "seq"}
                  suppressContentEditableWarning
                  onBlur={(e) => onEdit(rec.seq, f, e.currentTarget.textContent ?? "")}
                  className="break-all text-neutral-200 outline-none focus:bg-neutral-900"
                >
                  {String(rec[f])}
                </span>
              </div>
            ))}
            {cites.length > 0 && (
              <p className="mt-2 rounded-md border border-dashed border-emerald-800 p-2 text-xs text-emerald-400">
                A finding&apos;s tool_call_id IS this hash. Findings citing it: {cites.join("; ")}
              </p>
            )}
            <button onClick={() => onTamper(rec.seq)} className="mt-2 text-amber-400 hover:underline">
              ⚠ flip a byte in this record
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 8: Run the component test, verify it passes**

Run: `cd web && npx vitest run components/verifiable-audit`
Expected: PASS (INTACT on mount; BROKEN after Tamper; INTACT after Reset).

- [ ] **Step 9: Commit**

```bash
git add web/lib/site-data.ts web/components/verifiable-audit/
git commit -S -m "feat: VerifiableAudit island — verify, tamper, free-edit, reset"
```

---

## Task 7: Hero section

**Files:**
- Create: `web/components/sections/Hero.tsx`
- Test: covered by the page render test (Task 11). Hero is static; no logic test.

- [ ] **Step 1: Implement `web/components/sections/Hero.tsx`**

```tsx
import { site } from "@/lib/site-data";

export function Hero() {
  return (
    <section className="mx-auto max-w-3xl px-6 pt-24 pb-12 text-center">
      <p className="font-mono text-xs uppercase tracking-widest text-amber-400">Spoor · autonomous DFIR</p>
      <h1 className="mt-4 text-4xl font-semibold text-neutral-100 sm:text-5xl">Autonomous DFIR you can audit</h1>
      <p className="mt-5 text-lg text-neutral-400">
        An AI agent investigated a real compromised domain controller ({String(site.meta.host)}) and reached a
        verdict. Don&apos;t trust it — recompute its evidence chain yourself, right here in your browser.
      </p>
      <a href="#verify" className="mt-8 inline-block rounded-md border border-emerald-700 px-5 py-2.5 font-mono text-emerald-400 hover:bg-emerald-950/40">
        Verify it yourself ↓
      </a>
    </section>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add web/components/sections/Hero.tsx
git commit -S -m "feat: hero section"
```

---

## Task 8: Accuracy-measured-honestly section

**Files:**
- Create: `web/components/sections/AccuracySection.tsx`
- Test: `web/components/sections/__tests__/AccuracySection.test.tsx`

- [ ] **Step 1: Write the failing test** — `web/components/sections/__tests__/AccuracySection.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AccuracySection } from "../AccuracySection";

describe("<AccuracySection>", () => {
  it("shows the real, unflattering numbers and the integrity verdict", () => {
    render(<AccuracySection />);
    expect(screen.getByText("Precision")).toBeInTheDocument();
    expect(screen.getAllByText(/0\.25/).length).toBeGreaterThan(0); // precision (also appears as pre-correction recall)
    expect(screen.getByText(/0\.50/)).toBeInTheDocument(); // recall
    expect(screen.getByText(/0\.000/)).toBeInTheDocument(); // hallucination
    expect(screen.getByText(/INTACT/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify it fails** — `cd web && npx vitest run components/sections/__tests__/AccuracySection.test.tsx` → FAIL.

- [ ] **Step 3: Implement `web/components/sections/AccuracySection.tsx`**

```tsx
import { site } from "@/lib/site-data";

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-neutral-800 p-4 text-center">
      <div className="font-mono text-2xl text-neutral-100">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-neutral-500">{label}</div>
    </div>
  );
}

export function AccuracySection() {
  const a = site.accuracy;
  const f = (n: number, d = 2) => n.toFixed(d);
  return (
    <section className="mx-auto max-w-3xl px-6 py-16">
      <h2 className="text-2xl font-semibold text-neutral-100">Accuracy, measured honestly</h2>
      <p className="mt-2 text-neutral-400">
        Scored against the verified answer key for Case 001. We report the unflattering number and exactly why.
      </p>
      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric label="Precision" value={f(a.precision)} />
        <Metric label="Recall" value={f(a.recall)} />
        <Metric label="F1" value={f(a.f1)} />
        <Metric label="Hallucination" value={f(a.hallucination_rate, 3)} />
      </div>
      <div className="mt-4 rounded-md border border-emerald-800 bg-emerald-950/20 px-4 py-3 font-mono text-sm text-emerald-400">
        Evidence integrity: {site.meta.evidence_integrity_ok ? "INTACT" : "VIOLATED"} — SHA-256 byte-identical before and after the run.
      </div>
      <p className="mt-4 text-neutral-400">{a.framing}</p>
      <p className="mt-3 text-sm text-neutral-500">
        Pre-correction bridge: P {f(a.pre_correction.precision)} · R {f(a.pre_correction.recall)} · F1 {f(a.pre_correction.f1)}.
        The agent&apos;s output never changed — only the deterministic scorer was fixed, in the open.
      </p>
    </section>
  );
}
```

- [ ] **Step 4: Run the test, verify it passes** — `cd web && npx vitest run components/sections/__tests__/AccuracySection.test.tsx` → PASS.

- [ ] **Step 5: Commit**

```bash
git add web/components/sections/AccuracySection.tsx web/components/sections/__tests__/AccuracySection.test.tsx
git commit -S -m "feat: accuracy-measured-honestly section (real numbers, real framing)"
```

---

## Task 9: Trust-stack section

**Files:**
- Create: `web/components/sections/TrustStack.tsx`
- Test: `web/components/sections/__tests__/TrustStack.test.tsx`

- [ ] **Step 1: Write the failing test** — `web/components/sections/__tests__/TrustStack.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { TrustStack } from "../TrustStack";

describe("<TrustStack>", () => {
  it("renders all five pillars, each with a proving command", () => {
    render(<TrustStack />);
    expect(screen.getAllByRole("listitem")).toHaveLength(5);
    expect(screen.getByText(/spoor verify-audit/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify it fails** → FAIL.

- [ ] **Step 3: Implement `web/components/sections/TrustStack.tsx`**

```tsx
import { Fingerprint, ShieldCheck, Link2, Gauge, RotateCcw } from "lucide-react";

const PILLARS = [
  { icon: Fingerprint, title: "Tamper-evident audit", body: "Every tool call is a hash-chained record; every finding cites one.", cmd: "spoor verify-audit <run>/audit.jsonl" },
  { icon: ShieldCheck, title: "Read-only evidence", body: "Path-jail + no-shell allow-listed exec. The image's SHA-256 is identical before and after.", cmd: "sha256sum citadeldc01.mem  # pre == post" },
  { icon: Link2, title: "Citation enforcement", body: "A finding is 'confirmed' only if it cites a real tool_call_id; uncited claims are downgraded.", cmd: "cat <run>/report.json | jq .enforcement" },
  { icon: Gauge, title: "Honest accuracy", body: "A deterministic scorer reports the number before and after every correction.", cmd: "python scripts/rescore_run.py <run>" },
  { icon: RotateCcw, title: "Self-correction", body: "When a tool fails, the agent recovers — and the recovery is replayable.", cmd: "spoor show-selfcorrect <run>" },
];

export function TrustStack() {
  return (
    <section className="mx-auto max-w-3xl px-6 py-16">
      <h2 className="text-2xl font-semibold text-neutral-100">The trust stack</h2>
      <p className="mt-2 text-neutral-400">Five pillars. Each one ships with the command that proves it.</p>
      <ul className="mt-6 space-y-3">
        {PILLARS.map((p) => (
          <li key={p.title} className="rounded-lg border border-neutral-800 p-4">
            <div className="flex items-center gap-2 text-neutral-100">
              <p.icon className="h-4 w-4 text-amber-400" aria-hidden /> <span className="font-medium">{p.title}</span>
            </div>
            <p className="mt-1 text-sm text-neutral-400">{p.body}</p>
            <code className="mt-2 block rounded bg-neutral-900 px-2 py-1 font-mono text-xs text-emerald-400">$ {p.cmd}</code>
          </li>
        ))}
      </ul>
    </section>
  );
}
```

- [ ] **Step 4: Run the test, verify it passes** → PASS.

- [ ] **Step 5: Commit**

```bash
git add web/components/sections/TrustStack.tsx web/components/sections/__tests__/TrustStack.test.tsx
git commit -S -m "feat: trust-stack section (5 pillars + proving CLIs)"
```

---

## Task 10: Footer

**Files:**
- Create: `web/components/sections/SiteFooter.tsx`

- [ ] **Step 1: Implement `web/components/sections/SiteFooter.tsx`**

```tsx
const LINKS = [
  { href: "https://github.com/RECTOR-LABS/spoor", label: "GitHub" },
  { href: "https://vimeo.com/1201212440", label: "Demo video (2 min)" },
  { href: "https://devpost.com/software/spoor-autonomous-dfir-you-can-audit", label: "Devpost" },
];

export function SiteFooter() {
  return (
    <footer className="mx-auto max-w-3xl px-6 py-16 text-sm text-neutral-400">
      <div className="flex flex-wrap gap-4">
        {LINKS.map((l) => (
          <a key={l.href} href={l.href} className="text-sky-400 hover:underline" target="_blank" rel="noreferrer">
            {l.label}
          </a>
        ))}
      </div>
      <div className="mt-4 rounded-md border border-neutral-800 bg-neutral-900 p-3 font-mono text-xs text-neutral-300">
        <div># reproduce the verdict + chain locally</div>
        <div>uv sync --extra forensics</div>
        <div>uv run python scripts/real_case_run.py</div>
        <div>uv run spoor verify-audit runs/2026-06-12-231634-case001-real/audit.jsonl</div>
      </div>
    </footer>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add web/components/sections/SiteFooter.tsx
git commit -S -m "feat: footer (links + copy-paste repro)"
```

---

## Task 11: Page assembly (Order A) + layout/theme

**Files:**
- Modify: `web/app/layout.tsx`, `web/app/page.tsx`, `web/app/globals.css`
- Test: `web/app/__tests__/page.test.tsx`

- [ ] **Step 1: Write the failing test** — `web/app/__tests__/page.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import Page from "../page";

describe("home page", () => {
  it("renders the hero headline and the verify anchor", () => {
    render(<Page />);
    expect(screen.getByRole("heading", { level: 1, name: /Autonomous DFIR you can audit/i })).toBeInTheDocument();
    expect(document.querySelector("#verify")).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run it, verify it fails** → FAIL.

- [ ] **Step 3: Implement `web/app/page.tsx`**

```tsx
import { Hero } from "@/components/sections/Hero";
import { AccuracySection } from "@/components/sections/AccuracySection";
import { TrustStack } from "@/components/sections/TrustStack";
import { SiteFooter } from "@/components/sections/SiteFooter";
import { VerifiableAudit } from "@/components/verifiable-audit/VerifiableAudit";
import { site, citationsByRecord } from "@/lib/site-data";

export default function Page() {
  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200">
      <Hero />
      <section id="verify" className="mx-auto max-w-3xl px-6 py-12">
        <h2 className="mb-2 text-2xl font-semibold text-neutral-100">{String(site.meta.host)} — confirmed compromised</h2>
        <p className="mb-6 text-neutral-400">{site.verdict.executive_summary.split(". ").slice(0, 2).join(". ")}.</p>
        <VerifiableAudit audit={site.audit} citations={citationsByRecord()} />
      </section>
      <AccuracySection />
      <TrustStack />
      <SiteFooter />
    </main>
  );
}
```

- [ ] **Step 4: Set dark theme metadata** — `web/app/layout.tsx`

```tsx
import type { Metadata } from "next";
import { JetBrains_Mono, Inter } from "next/font/google";
import "./globals.css";

const sans = Inter({ subsets: ["latin"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "Spoor — Autonomous DFIR you can audit",
  description: "Recompute an AI forensic agent's real SHA-256 audit chain in your browser, then watch a byte-flip break it.",
  metadataBase: new URL("https://spoor.rectorspace.com"),
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} dark`}>
      <body className="bg-neutral-950 font-sans antialiased">{children}</body>
    </html>
  );
}
```

- [ ] **Step 5: Ensure forensic tokens** — append to `web/app/globals.css`

```css
:root { --font-mono: ui-monospace, SFMono-Regular, Menlo, monospace; }
.font-mono { font-family: var(--font-mono); }
html { color-scheme: dark; }
```

- [ ] **Step 6: Run the test, then the full build**

Run: `cd web && npx vitest run app/__tests__/page.test.tsx && npm run build && cd ..`
Expected: test PASS; build prints "data gate OK" then completes.

- [ ] **Step 7: Commit**

```bash
git add web/app/
git commit -S -m "feat: assemble proof-site page (Order A) + dark theme"
```

---

## Task 12: Web-grade SVG architecture diagram (W8)

**Files:**
- Create: `web/components/ArchitectureDiagram.tsx`
- Modify: `web/components/sections/TrustStack.tsx` (render the diagram above the pillars)

- [ ] **Step 1: Re-author the diagram as inline SVG** — `web/components/ArchitectureDiagram.tsx`

Re-create `~/Documents/spoor_architecture.png` (1800×1396) as a dark-theme inline SVG: evidence image → guardrailed tool runners (Volatility) → hash-chained audit log → lead/specialist agents → citation-enforced report → scorer. Use `currentColor`, the green/amber/red semantic palette, and monospace labels. Implement as a single `<svg viewBox="0 0 900 700" role="img" aria-label="Spoor architecture: evidence → guardrailed tools → hash-chained audit → agents → enforced report">` with `<rect>`/`<text>`/`<path>` nodes. (Visual detail is tuned against the preview deploy; the component must render and be aria-labeled.)

- [ ] **Step 2: Render it in `TrustStack.tsx`**

Add above the `<ul>`:
```tsx
import { ArchitectureDiagram } from "@/components/ArchitectureDiagram";
// ...inside the section, before <ul>:
<div className="mb-6 overflow-x-auto"><ArchitectureDiagram /></div>
```

- [ ] **Step 3: Verify render + build**

Run: `cd web && npm run build && cd ..` → completes.

- [ ] **Step 4: Commit**

```bash
git add web/components/ArchitectureDiagram.tsx web/components/sections/TrustStack.tsx
git commit -S -m "feat: web-grade SVG architecture diagram"
```

---

## Task 13: Share card (OG image) — W10

**Files:**
- Create: `web/app/opengraph-image.tsx`

- [ ] **Step 1: Implement `web/app/opengraph-image.tsx`** (Next built-in `ImageResponse`, no extra dep)

```tsx
import { ImageResponse } from "next/og";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt = "Spoor — Autonomous DFIR you can audit";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div style={{ height: "100%", width: "100%", display: "flex", flexDirection: "column",
        justifyContent: "center", padding: 80, background: "#0a0a0a", color: "#e5e5e5",
        fontFamily: "monospace" }}>
        <div style={{ color: "#fbbf24", fontSize: 28 }}>SPOOR · autonomous DFIR</div>
        <div style={{ fontSize: 64, marginTop: 16 }}>Autonomous DFIR you can audit</div>
        <div style={{ color: "#34d399", fontSize: 30, marginTop: 24 }}>✓ verify the chain yourself · ✗ tamper and watch it break</div>
      </div>
    ),
    { ...size },
  );
}
```

- [ ] **Step 2: Verify build + commit**

```bash
cd web && npm run build && cd ..
git add web/app/opengraph-image.tsx
git commit -S -m "feat: OG share card"
```

---

## Task 14: Accessibility, Lighthouse, responsive polish (W10)

**Files:**
- Modify: section components as needed (focus states, contrast, `prefers-reduced-motion`, responsive spacing)

- [ ] **Step 1: Add an axe smoke test** — `web/app/__tests__/a11y.test.tsx`

```tsx
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { axe } from "vitest-axe";
import Page from "../page";

describe("a11y", () => {
  it("home page has no obvious axe violations", async () => {
    const { container } = render(<Page />);
    expect(await axe(container)).toHaveNoViolations();
  });
});
```
(Install: `cd web && npm i -D vitest-axe` and add `import "vitest-axe/extend-expect";` to `vitest.setup.ts`.)

- [ ] **Step 2: Run it; fix violations inline**

Run: `cd web && npx vitest run app/__tests__/a11y.test.tsx`
Expected: PASS after fixes (keyboard-reachable buttons, label on the chain, contrast).

- [ ] **Step 3: Manual Lighthouse pass** (after first preview deploy, Task 16)

Run Lighthouse on the preview URL; target ≥95 Performance/Best-Practices/SEO and ≥95 Accessibility. Record results in the PR.

- [ ] **Step 4: Commit**

```bash
git add web/
git commit -S -m "chore: a11y + responsive polish"
```

---

## Task 15: CI — TS verifier ↔ `spoor verify-audit` cross-check

**Files:**
- Create: `.github/workflows/site-parity.yml`

- [ ] **Step 1: Implement the workflow**

```yaml
name: site-parity
on:
  pull_request:
    paths: ["web/**", "runs/**", "scripts/export_site_data.py", "spoor_sift/accuracy.py", "spoor_sift/audit.py"]
jobs:
  parity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - name: Python — export gate + audit verify
        run: |
          uv sync
          uv run python scripts/export_site_data.py
          uv run spoor verify-audit runs/2026-06-12-231634-case001-real/audit.jsonl
      - name: Fail if the committed export drifted from a fresh export
        run: git diff --exit-code web/data/case001.json
      - name: Node — unit tests + build gate (TS verifier matches Python hashes)
        run: |
          cd web
          npm ci
          npm test
          npm run build
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/site-parity.yml
git commit -S -m "ci: parity gate — TS verifier cross-checked against spoor verify-audit"
```

---

## Task 16: Deploy — Vercel Git integration + DNS (W9)

> Ops task (human-in-the-loop in the Vercel + Cloudflare dashboards). No code; exact steps below.

- [ ] **Step 1: Open the PR** so a Vercel preview can build it
```bash
git push -u origin feat/proof-site
gh pr create --base main --head feat/proof-site --title "Spoor proof-site (Phase 1)" --body "spoor.rectorspace.com — verifiable audit + tamper demo. See docs/superpowers/specs/2026-06-15-spoor-proof-site-design.md"
```

- [ ] **Step 2: Import the project in Vercel** (one-time)
  - Vercel → Add New → Project → import `RECTOR-LABS/spoor` (authorize the RECTOR-LABS org).
  - Framework Preset: **Next.js**. **Root Directory: `web/`**. Production Branch: `main`.
  - Build Command: leave default (`npm run build` — runs the `tsx scripts/verify-data.ts` gate first).
  - Deploy. Confirm the **preview URL** builds (the gate must print "data gate OK").

- [ ] **Step 3: Add the custom domain**
  - Vercel project → Settings → Domains → add `spoor.rectorspace.com`.

- [ ] **Step 4: DNS on Cloudflare (Personal account, rector@rectorspace.com)**
  - Add a CNAME: name `spoor`, target `cname.vercel-dns.com`, **Proxy status: DNS only (grey cloud)**.
  - Wait for Vercel to verify + auto-provision SSL.

- [ ] **Step 5: Verify production behavior**
  - Push to `main` (merge the PR) → confirm a production deploy at https://spoor.rectorspace.com.
  - On the live site: click **Verify** (✓ INTACT), **Tamper** (✗ BROKEN), **Reset** (✓). Confirm the result matches `uv run spoor verify-audit runs/2026-06-12-231634-case001-real/audit.jsonl`.
  - Run Lighthouse (Task 14, Step 3).

- [ ] **Step 6: Merge**

```bash
gh pr merge --merge --delete-branch
```

---

## Out of scope (Phase 2 — separate spec + plan later)

Case-file explorer (timeline / process-tree / IOC graph), self-correction replay UI (run 155749), richer architecture interactions. Named here only so they are not silently dropped.

---

## Self-Review

**Spec coverage:** §4 stack → Task 1; §5 export + scrub → Task 2; §6 island (canonicalize/verifyChain/state machine) → Tasks 3, 4, 6; §7 honesty gates (export-time / build-time / runtime / CI) → Tasks 2, 5, 6, 15; §8 sections (Order A) → Tasks 7–11; §8.4 trust pillars + SVG → Tasks 9, 12; §9 design language → Tasks 6–11; §10 deploy (Vercel Git, DNS) → Task 16; §11 testing → Tasks 2–6, 8, 9, 11, 14, 15; §12 Phase split → "Out of scope". No gaps.

**Placeholders:** none — every code step contains runnable code. Task 12's SVG is the one component whose pixel detail is iterated against the preview (its interface — a single aria-labeled `<svg>` — is fully specified, so it is not a placeholder).

**Type consistency:** `AuditRecord` / `VerifyResult` / `canonicalize` / `sha256Hex` / `recordHash` / `verifyChain` are defined in Tasks 3–4 and consumed unchanged in Tasks 5–6; `site` / `citationsByRecord` defined in Task 6 Step 1 and consumed in Tasks 8–11; the Python `score` fields used in Task 2 match `scripts/rescore_run.py`. Consistent.
