import type { VerifyResult } from "@/lib/verifyAudit";

export function ResultBanner({ result, verifying }: { result: VerifyResult | null; verifying: boolean }) {
  if (verifying || !result)
    return <p role="status" className="mt-3 rounded-md border border-neutral-700 px-3 py-2 text-neutral-400">recomputing SHA-256 in your browser…</p>;
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
