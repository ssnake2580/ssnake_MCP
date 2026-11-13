"use client";

import { useCallback, useEffect, useRef, useState } from "react";
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
  const genRef = useRef(0);

  const runVerify = useCallback(async (records: AuditRecord[]) => {
    const gen = ++genRef.current;
    setVerifying(true);
    const res = await verifyChain(records);
    if (gen !== genRef.current) return; // stale — a newer verify has superseded this one
    setResult(res);
    setVerifying(false);
  }, []);

  useEffect(() => {
    // Recompute the real chain in-browser on mount — Web Crypto is client-only, so it
    // can't run during render. runVerify updates loading/result state asynchronously
    // (after the SHA-256 await), which is the intended one-time mount synchronization.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void runVerify(working);
    // run once on mount; `working` is deliberately excluded so this fires only on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const apply = (mutate: (records: AuditRecord[]) => void) => {
    const next = structuredClone(working);
    mutate(next);
    setWorking(next);
    void runVerify(next);
  };

  // `seq` doubles as the array index: the exported chain is always 0-indexed and
  // contiguous (verifyChain enforces seq===index), and `seq` is non-editable in the
  // inspector — so recs[seq] is always the record the visitor selected.
  const tamperByte = (seq: number) =>
    apply((recs) => {
      const r = recs[seq];
      const c = r.stdout_sha256[0] === "0" ? "1" : "0";
      r.stdout_sha256 = c + r.stdout_sha256.slice(1);
    });

  const editField = (seq: number, field: keyof AuditRecord, value: string) =>
    apply((recs) => {
      const r = recs[seq] as unknown as Record<string, unknown>;
      r[field] = field === "exit_code" || field === "seq" ? Number(value) : value;
    });

  const reset = () => {
    const fresh = structuredClone(audit);
    setWorking(fresh);
    void runVerify(fresh);
  };

  const tampered = JSON.stringify(working) !== JSON.stringify(audit);
  // A passing result has no broken record; otherwise surface the first break to both views.
  const brokenSeq = result?.ok ? undefined : result?.brokenSeq;

  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-950/60 p-5 font-mono text-sm text-neutral-200">
      <ChainStrip records={working} brokenSeq={brokenSeq} selected={selected} onSelect={setSelected} />
      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" onClick={() => runVerify(working)} disabled={verifying}
          className="rounded-md border border-emerald-700 px-3 py-1.5 text-emerald-400 hover:bg-emerald-950/40">
          Verify chain
        </button>
        <button type="button" onClick={() => tamperByte(selected)}
          className="rounded-md border border-amber-700 px-3 py-1.5 text-amber-400 hover:bg-amber-950/40">
          Tamper a byte
        </button>
        <button type="button" onClick={reset} disabled={!tampered}
          className="rounded-md border border-neutral-700 px-3 py-1.5 text-neutral-300 hover:bg-neutral-900 disabled:opacity-40">
          Reset
        </button>
      </div>
      <ResultBanner result={result} verifying={verifying} />
      <RecordInspector
        records={working} selected={selected} onSelect={setSelected}
        citations={citations} brokenSeq={brokenSeq}
        onEdit={editField} onTamper={tamperByte}
      />
    </div>
  );
}
