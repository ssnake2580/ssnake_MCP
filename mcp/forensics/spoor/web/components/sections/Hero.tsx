import { ArrowDown } from "lucide-react";
import { site } from "@/lib/site-data";

export function Hero() {
  return (
    <section className="mx-auto max-w-3xl px-6 pt-24 pb-12 text-center">
      <p className="font-mono text-xs uppercase tracking-widest text-amber-400">Spoor · autonomous DFIR</p>
      <h1 className="mt-4 text-4xl font-semibold text-neutral-100 sm:text-5xl">Autonomous DFIR you can audit</h1>
      <p className="mt-5 text-lg text-neutral-400">
        An AI agent investigated a real compromised domain controller ({site.meta.host}) and reached a
        verdict. Don&apos;t trust it — recompute its evidence chain yourself, right here in your browser.
      </p>
      <a href="#verify" className="mt-8 inline-flex items-center gap-1.5 rounded-md border border-emerald-700 px-5 py-2.5 font-mono text-emerald-400 hover:bg-emerald-950/40">
        Verify it yourself <ArrowDown className="h-4 w-4" aria-hidden />
      </a>
    </section>
  );
}
