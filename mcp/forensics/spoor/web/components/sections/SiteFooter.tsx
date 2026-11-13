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
