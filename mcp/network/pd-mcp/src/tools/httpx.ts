import { runBinary, parseJsonl, cleanList } from "./runner.js";

export interface HttpxResult {
  responses: Array<{
    url: string;
    statusCode?: number;
    contentLength?: number;
    title?: string;
    webserver?: string;
    tech?: string[];
  }>;
  count: number;
  error?: string;
}

export async function executeHttpx(
  urls: string[],
  followRedirects = false,
  techDetect = false
): Promise<HttpxResult> {
  const list = cleanList(urls);
  if (list.length === 0) return { responses: [], count: 0, error: "no valid urls/hosts" };
  const args = ["-json", "-silent"];
  if (followRedirects) args.push("-fr");
  if (techDetect) args.push("-td");
  const r = await runBinary("httpx", args, {
    timeoutMs: 300_000,
    stdin: list.join("\n") + "\n",
  });
  const responses = parseJsonl<HttpxResult["responses"][number]>(r.lines, (p) =>
    p.url || p.host
      ? {
          url: String(p.url || p.host),
          statusCode: p.status_code,
          contentLength: p.content_length,
          title: p.title,
          webserver: p.webserver,
          tech: Array.isArray(p.tech) ? p.tech : undefined,
        }
      : null
  );
  if (r.exitCode !== 0 && responses.length === 0) {
    return { responses: [], count: 0, error: `httpx failed (exit ${r.exitCode}): ${r.stderr.slice(-2000)}` };
  }
  return { responses, count: responses.length };
}
