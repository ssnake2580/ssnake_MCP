import { Fingerprint, ShieldCheck, Link2, Gauge, RotateCcw } from "lucide-react";
import { ArchitectureDiagram } from "@/components/ArchitectureDiagram";

const PILLARS = [
  { icon: Fingerprint, title: "Tamper-evident audit", body: "Every tool call is a hash-chained record; every finding cites one.", cmd: "spoor verify-audit <run>/audit.jsonl" },
  { icon: ShieldCheck, title: "Read-only evidence", body: "Path-jail + no-shell allow-listed exec. The image's SHA-256 is identical before and after.", cmd: "sha256sum citadeldc01.mem  # pre == post" },
  { icon: Link2, title: "Citation enforcement", body: "A finding is 'confirmed' only if it cites a real tool_call_id; uncited claims are downgraded.", cmd: "cat <run>/report.json | jq .enforcement" },
  { icon: Gauge, title: "Honest accuracy", body: "A deterministic scorer reports the number before and after every correction.", cmd: "python scripts/rescore_run.py <run>" },
  { icon: RotateCcw, title: "Self-correction", body: "When a tool fails, the agent recovers — and the recovery is replayable.", cmd: "spoor show-selfcorrect <run>" },
];

export function TrustStack() {
  return (
    <section className="mx-auto max-w-3xl px-6 py-16" aria-labelledby="trust-stack-heading">
      <h2 id="trust-stack-heading" className="text-2xl font-semibold text-neutral-100">The trust stack</h2>
      <p className="mt-2 text-neutral-400">Five pillars. Each one ships with the command that proves it.</p>
      <div className="mb-6 overflow-x-auto">
        <ArchitectureDiagram />
      </div>
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
