// Verification driver: speaks JSON-RPC stdio to the adapted PD MCP server,
// runs tools/list + one live tools/call per wrapped binary. Exits non-zero
// on any failure.
import { spawn } from "child_process";

const DIR = import.meta.dir;
const server = spawn("bun", ["src/index.ts"], {
  cwd: DIR,
  stdio: ["pipe", "pipe", "pipe"],
});

let buf = "";
let nextId = 0;
const pending = new Map<number, (v: any) => void>();
const failures: string[] = [];

server.stdout.on("data", (d: Buffer) => {
  buf += d.toString();
  const parts = buf.split("\n");
  buf = parts.pop()!;
  for (const p of parts) {
    if (!p.trim()) continue;
    let msg: any;
    try { msg = JSON.parse(p); } catch { continue; }
    if (msg.id != null && pending.has(msg.id)) {
      pending.get(msg.id)!(msg);
      pending.delete(msg.id);
    }
  }
});
server.stderr.on("data", (d: Buffer) => {
  const s = d.toString();
  if (!s.includes("running on stdio")) process.stderr.write("[srv] " + s);
});
server.on("exit", (c) => console.log(`server exited: ${c}`));

function rpc(method: string, params: any = {}, timeoutMs = 180_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, resolve);
    server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error(`rpc timeout: ${method}`));
      }
    }, timeoutMs);
  });
}

function notify(method: string, params: any = {}) {
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

function summarize(name: string, res: any) {
  const text = res?.result?.content?.[0]?.text ?? "";
  let parsed: any = null;
  try { parsed = JSON.parse(text); } catch {}
  const preview = text.slice(0, 300).replace(/\n/g, " ");
  const errFlag = res?.result?.isError ? " isError=true" : "";
  console.log(`--- ${name}${errFlag}\n    preview: ${preview}`);
  return parsed;
}

async function main() {
  await rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "kestrel-race-driver", version: "1.0" },
  });
  notify("notifications/initialized");

  const list = await rpc("tools/list");
  const names = (list.result.tools as any[]).map((t) => t.name);
  console.log("TOOLS:", names.join(", "));
  const want = ["subfinder","dnsx","naabu","httpx","katana","nuclei","tlsx","shuffledns","bug_bounty_workflow"];
  for (const w of want) if (!names.includes(w)) failures.push(`missing tool: ${w}`);

  const calls: Array<[string, any, (p: any) => boolean]> = [
    ["subfinder", { domain: "example.com" }, (p) => Array.isArray(p?.subdomains)],
    ["dnsx", { domains: ["example.com"], recordType: "A" }, (p) => Array.isArray(p?.resolved) && p.resolved.length > 0],
    ["naabu", { hosts: ["127.0.0.1"], ports: "80,443", scanType: "c" }, (p) => Array.isArray(p?.openPorts)],
    ["httpx", { urls: ["https://example.com"], followRedirects: true }, (p) => Array.isArray(p?.responses) && p.responses.length > 0],
    ["katana", { urls: ["https://example.com"], depth: 2, maxDurationSeconds: 60 }, (p) => Array.isArray(p?.endpoints)],
    ["nuclei", { targets: ["https://example.com"], templateIds: ["http-missing-security-headers"], severity: ["info"], confirm: true }, (p) => Array.isArray(p?.vulnerabilities)],
    ["tlsx", { hosts: ["example.com"], port: 443 }, (p) => Array.isArray(p?.hosts) && p.hosts.length > 0],
    ["shuffledns", { domain: "example.com", wordlist: `${DIR}/wordlist.txt` }, (p) => Array.isArray(p?.subdomains)],
  ];

  for (const [tool, args, check] of calls) {
    const t0 = Date.now();
    try {
      const res = await rpc("tools/call", { name: tool, arguments: args }, 420_000);
      const parsed = summarize(tool, res);
      const ok = check(parsed) && !res?.result?.isError;
      console.log(`    => ${ok ? "PASS" : "FAIL"} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
      if (!ok) failures.push(`tool call failed: ${tool}`);
    } catch (e) {
      console.log(`    => ERROR ${e}`);
      failures.push(`tool call error: ${tool}: ${e}`);
    }
  }

  server.kill("SIGTERM");
  setTimeout(() => {
    if (failures.length) {
      console.log("\nFAILURES:\n - " + failures.join("\n - "));
      process.exit(1);
    }
    console.log("\nALL CHECKS PASSED");
    process.exit(0);
  }, 1500);
}

main().catch((e) => { console.error("driver fatal:", e); process.exit(2); });
