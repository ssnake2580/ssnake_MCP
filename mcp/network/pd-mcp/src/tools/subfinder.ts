import { runBinary, parseJsonl, cleanList } from "./runner.js";

export interface SubfinderResult {
  subdomains: string[];
  count: number;
  error?: string;
}

export async function executeSubfinder(
  domain: string,
  silent = true
): Promise<SubfinderResult> {
  const args = ["-d", domain, "-json"];
  if (silent) args.push("-silent");
  const r = await runBinary("subfinder", args, { timeoutMs: 300_000 });
  const subs = parseJsonl<string>(r.lines, (p) =>
    typeof p.host === "string" && p.host ? p.host : null
  );
  if (r.exitCode !== 0 && subs.length === 0) {
    return { subdomains: [], count: 0, error: `subfinder failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { subdomains: [...new Set(subs)], count: subs.length };
}
