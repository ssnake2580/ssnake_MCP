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
    <section className="mx-auto max-w-3xl px-6 py-16" aria-labelledby="accuracy-heading">
      <h2 id="accuracy-heading" className="text-2xl font-semibold text-neutral-100">Accuracy, measured honestly</h2>
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
