import { existsSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { runBinary, cleanDomain } from "./runner.js";

function defaultResolvers(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const p = join(here, "..", "assets", "resolvers.txt");
  return existsSync(p) ? p : "";
}

export interface ShufflednsResult {
  subdomains: string[];
  count: number;
  error?: string;
}

// Active subdomain brute-force via shuffledns. Requires a wordlist file.
export async function executeShuffledns(
  domain: string,
  wordlist: string,
  resolvers?: string[]
): Promise<ShufflednsResult> {
  const d = cleanDomain(domain);
  const wl = String(wordlist ?? "").trim();
  if (!wl || !existsSync(wl)) {
    return { subdomains: [], count: 0, error: `wordlist not found: ${wl}` };
  }
  const args = ["-d", d, "-w", wl, "-mode", "bruteforce", "-silent", "-nc", "-duc"];
  const resolversFile =
    resolvers && resolvers.length > 0 ? "" : defaultResolvers();
  if (resolvers && resolvers.length > 0) {
    args.push("-r", resolvers.join(","));
  } else if (resolversFile) {
    args.push("-r", resolversFile);
  }
  const r = await runBinary("shuffledns", args, { timeoutMs: 600_000 });
  const seen = new Set<string>();
  const subdomains: string[] = [];
  for (const line of r.lines) {
    const s = line.trim().toLowerCase();
    if (!s || /[\s]/.test(s)) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    subdomains.push(s);
  }
  if (r.exitCode !== 0 && subdomains.length === 0) {
    return { subdomains: [], count: 0, error: `shuffledns failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { subdomains, count: subdomains.length };
}
