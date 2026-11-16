import { runBinary, parseJsonl, cleanList } from "./runner.js";

export interface KatanaResult {
  endpoints: string[];
  count: number;
  error?: string;
}

export async function executeKatana(
  urls: string[],
  depth = 2,
  scope?: string,
  maxDurationSeconds?: number
): Promise<KatanaResult> {
  const list = cleanList(urls, 100);
  if (list.length === 0) return { endpoints: [], count: 0, error: "no valid urls" };
  const d = Math.min(Math.max(Math.floor(depth) || 2, 1), 5);
  const args = ["-d", String(d), "-jsonl", "-silent"];
  if (scope) args.push("-f", scope);
  if (maxDurationSeconds && maxDurationSeconds > 0) {
    args.push("-ct", `${Math.min(maxDurationSeconds, 600)}s`);
  }
  const r = await runBinary("katana", args, {
    timeoutMs: 600_000,
    stdin: list.join("\n") + "\n",
  });
  const endpoints = parseJsonl<string>(r.lines, (p) =>
    p.request && p.request.endpoint ? String(p.request.endpoint) : null
  );
  if (r.exitCode !== 0 && endpoints.length === 0) {
    return { endpoints: [], count: 0, error: `katana failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { endpoints: [...new Set(endpoints)], count: endpoints.length };
}
