import { runBinary, parseJsonl, cleanList, cleanPortSpec } from "./runner.js";

export interface NaabuResult {
  openPorts: Array<{ host: string; port: number }>;
  count: number;
  error?: string;
}

// scanType: "c" = connect scan (works unprivileged), "s" = SYN scan (needs CAP_NET_RAW/root)
export async function executeNaabu(
  hosts: string[],
  ports?: string,
  topPorts?: number,
  scanType: "c" | "s" = "c"
): Promise<NaabuResult> {
  const list = cleanList(hosts);
  if (list.length === 0) return { openPorts: [], count: 0, error: "no valid hosts" };
  const portSpec = cleanPortSpec(ports);
  const args = ["-json", "-silent", "-scan-type", scanType];
  if (portSpec) {
    args.push("-p", portSpec);
  } else {
    args.push("-top-ports", String(topPorts && topPorts > 0 ? Math.min(topPorts, 1000) : 100));
  }
  const r = await runBinary("naabu", args, {
    timeoutMs: 600_000,
    stdin: list.join("\n") + "\n",
  });
  const openPorts = parseJsonl<{ host: string; port: number }>(r.lines, (p) =>
    p.host && p.port ? { host: String(p.host), port: Number(p.port) } : null
  );
  if (r.exitCode !== 0 && openPorts.length === 0) {
    return { openPorts: [], count: 0, error: `naabu failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { openPorts, count: openPorts.length };
}
