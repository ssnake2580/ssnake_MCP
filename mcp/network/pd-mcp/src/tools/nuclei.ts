import { runBinary, parseJsonl, cleanList } from "./runner.js";

export interface NucleiVulnerability {
  template: string;
  templateID: string;
  info: { name: string; severity: string; description?: string };
  matcherName?: string;
  type: string;
  host: string;
  matched?: string;
}

export interface NucleiResult {
  vulnerabilities: NucleiVulnerability[];
  count: number;
  error?: string;
}

export async function executeNuclei(
  targets: string[],
  templateIds?: string[],
  severity?: string[]
): Promise<NucleiResult> {
  const list = cleanList(targets, 500);
  if (list.length === 0) return { vulnerabilities: [], count: 0, error: "no valid targets" };
  const args = ["-jsonl", "-silent", "-duc", "-nc"];
  const ids = (templateIds ?? []).map((t) => String(t).trim()).filter((t) => t && t.length <= 200 && !/[\0\r\n]/.test(t));
  if (ids.length > 0) args.push("-id", ids.join(","));
  const sev = (severity ?? [])
    .map((s) => String(s).trim().toLowerCase())
    .filter((s) => ["critical", "high", "medium", "low", "info", "unknown"].includes(s));
  if (sev.length > 0) args.push("-severity", sev.join(","));
  const r = await runBinary("nuclei", args, {
    timeoutMs: 900_000,
    stdin: list.join("\n") + "\n",
  });
  const vulnerabilities = parseJsonl<NucleiVulnerability>(r.lines, (p) =>
    p.info && p.type
      ? {
          template: p.template,
          templateID: p["template-id"] || p.templateID,
          info: {
            name: p.info.name,
            severity: p.info.severity,
            description: p.info.description,
          },
          matcherName: p["matcher-name"],
          type: p.type,
          host: p.host,
          matched: p.matched,
        }
      : null
  );
  // Nuclei exits non-zero when findings are detected — that is not a failure.
  if (r.exitCode !== 0 && r.exitCode !== 1 && vulnerabilities.length === 0) {
    return { vulnerabilities: [], count: 0, error: `nuclei failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { vulnerabilities, count: vulnerabilities.length };
}
