import { runBinary, parseJsonl, cleanList } from "./runner.js";

export interface TlsxResult {
  hosts: Array<{
    host: string;
    port?: number;
    probeStatus?: boolean;
    tlsVersion?: string;
    cipher?: string;
    subjectAN?: string[];
    expired?: boolean;
    selfSigned?: boolean;
    wildcard?: boolean;
  }>;
  count: number;
  error?: string;
}

export async function executeTlsx(
  hosts: string[],
  port = 443
): Promise<TlsxResult> {
  const list = cleanList(hosts, 500);
  if (list.length === 0) return { hosts: [], count: 0, error: "no valid hosts" };
  const p = Math.min(Math.max(Math.floor(port) || 443, 1), 65535);
  const args = [
    "-json", "-silent", "-nc", "-duc",
    "-p", String(p),
    "-so", "-tv", "-cipher", "-expired", "-ss", "-wc", "-ps",
  ];
  const r = await runBinary("tlsx", args, {
    timeoutMs: 300_000,
    stdin: list.join("\n") + "\n",
  });
  const found = parseJsonl<TlsxResult["hosts"][number]>(r.lines, (x) =>
    x.host
      ? {
          host: String(x.host),
          port: x.port,
          probeStatus: x.probe_status,
          tlsVersion: x.tls_version,
          cipher: x.cipher,
          subjectAN: Array.isArray(x.subject_an) ? x.subject_an : undefined,
          expired: x.expired,
          selfSigned: x.self_signed,
          wildcard: x.wildcard,
        }
      : null
  );
  if (r.exitCode !== 0 && found.length === 0) {
    return { hosts: [], count: 0, error: `tlsx failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { hosts: found, count: found.length };
}
