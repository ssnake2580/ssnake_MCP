// pd-call.ts — one-shot MCP stdio caller: bun pd-call.ts <tool> '<json-args>'
import { spawn } from "child_process";
const [tool, argsJson] = process.argv.slice(2);
if (!tool) { console.error("usage: bun pd-call.ts <tool> '<json>'"); process.exit(2); }
const server = spawn("bun", ["src/index.ts"], {
   cwd: import.meta.dir,
 server.kill(); process.exit(0);
  stdio: ["pipe", "pipe", "inherit"],
  env: { ...process.env, PD_TOOLS_DIR: "/home/toxic/.pdtm/go/bin" },
});
let buf = ""; let id = 0;
const pending = new Map<number, (v: any) => void>();
server.stdout.on("data", (d: Buffer) => {
  buf += d.toString();
  const parts = buf.split("\n"); buf = parts.pop()!;
  for (const p of parts) {
    if (!p.trim()) continue;
    try { const m = JSON.parse(p);
      if (m.id != null && pending.has(m.id)) { pending.get(m.id)!(m); pending.delete(m.id); }
    } catch {}
  }
});
const rpc = (m: string, p: any = {}, t = 180000): Promise<any> => new Promise((res, rej) => {
  const i = ++id; pending.set(i, res);
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: i, method: m, params: p }) + "\n");
  setTimeout(() => { if (pending.has(i)) { pending.delete(i); rej(new Error("timeout " + m)); } }, t);
});
const notify = (m: string, p: any = {}) =>
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: m, params: p }) + "\n");
await rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "pd-call", version: "1.0" } });
notify("notifications/initialized");
const r = await rpc("tools/call", { name: tool, arguments: JSON.parse(argsJson || "{}") });
console.log(JSON.stringify(r.result, null, 2).slice(0, 30000));
   cwd: import.meta.dir,
 server.kill(); process.exit(0);
