import { runBinary, cleanList } from "./runner.js";

export interface DnsxResult {
  resolved: Array<{ domain: string; ip: string; type: string }>;
  count: number;
  error?: string;
}

export async function executeDnsx(
  domains: string[],
  recordType?: string,
  resolvers?: string[]
): Promise<DnsxResult> {
  const list = cleanList(domains);
  if (list.length === 0) return { resolved: [], count: 0, error: "no valid domains" };
  const args = ["-json", "-silent"];
  if (recordType) args.push("-a", recordType);
  if (resolvers && resolvers.length > 0) args.push("-r", resolvers.join(","));
  const r = await runBinary("dnsx", args, {
    timeoutMs: 300_000,
    stdin: list.join("\n") + "\n",
  });
  const resolved: Array<{ domain: string; ip: string; type: string }> = [];
  const seen = new Set<string>();
  for (const line of r.lines) {
    let p: any;
    try { p = JSON.parse(line); } catch { continue; }
    if (!p.host || !Array.isArray(p.a)) continue;
    for (const ip of p.a) {
      const key = `${p.host}|${ip}`;
      if (seen.has(key)) continue;
      seen.add(key);
      resolved.push({ domain: p.host, ip: String(ip), type: "A" });
    }
  }
  if (r.exitCode !== 0 && resolved.length === 0) {
    return { resolved: [], count: 0, error: `dnsx failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { resolved, count: resolved.length };
}
