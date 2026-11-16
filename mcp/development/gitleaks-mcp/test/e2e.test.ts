import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// Build a token-shaped string at runtime so no secret-looking literal lives in the repo.
const FAKE = "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5".slice(0, 36);
const git = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, stdio: "pipe" });

async function connect() {
  const client = new Client({ name: "test", version: "0" });
  await client.connect(new StdioClientTransport({ command: "node", args: ["dist/src/index.js"], stderr: "pipe" }));
  return client;
}
const call = async (c: Client, name: string, args: Record<string, unknown>) => {
  const r = await c.callTool({ name, arguments: args });
  const text = (r.content as { text: string }[])[0].text;
  return { isError: r.isError, text, json: r.isError ? null : JSON.parse(text) };
};

test("lists tools, resource and prompt", async () => {
  const c = await connect();
  const tools = (await c.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(tools, ["scan_path", "scan_repo", "scan_staged", "scan_text"]);
  assert.equal((await c.listResources()).resources[0].uri, "gitleaks://about");
  assert.equal((await c.listPrompts()).prompts[0].name, "pre-push-check");
  await c.close();
});

test("finds a secret, never returns its value", async () => {
  const dir = mkdtempSync(join(tmpdir(), "glmcp-"));
  const c = await connect();
  try {
    git(dir, "init", "-q");
    git(dir, "config", "user.email", "t@t.t"); git(dir, "config", "user.name", "t");
    writeFileSync(join(dir, "config.env"), `GITHUB_TOKEN=${FAKE}\n`);
    git(dir, "add", "."); // staged, not committed

    const staged = await call(c, "scan_staged", { path: dir });
    assert.equal(staged.json.findingsCount, 1);
    assert.equal(staged.json.findings[0].rule, "github-pat");
    assert.ok(!staged.text.includes(FAKE), "secret must not appear in output");
    assert.ok(!staged.text.includes(FAKE.slice(4, 20)), "no partial secret either");

    git(dir, "commit", "-qm", "x");
    const repo = await call(c, "scan_repo", { path: dir });
    assert.equal(repo.json.findingsCount, 1);
    assert.ok(repo.json.findings[0].commit);

    const path = await call(c, "scan_path", { path: dir });
    assert.equal(path.json.findingsCount, 1);
  } finally { await c.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("scan_text and clean input and errors", async () => {
  const c = await connect();
  try {
    assert.equal((await call(c, "scan_text", { text: `token = "${FAKE}"` })).json.findingsCount, 1);
    assert.equal((await call(c, "scan_text", { text: "hello world" })).json.findingsCount, 0);
    const bad = await call(c, "scan_path", { path: "/definitely/not/here" });
    assert.equal(bad.isError, true);
    assert.match(bad.text, /does not exist/);
  } finally { await c.close(); }
});

test("log_opts is allowlisted (no file-writing or exec flags)", async () => {
  const { validateLogOpts } = await import("../src/gitleaks.js");
  assert.equal(validateLogOpts("main..HEAD"), "main..HEAD");
  assert.equal(validateLogOpts("@{upstream}..HEAD -n 20"), "@{upstream}..HEAD -n 20");
  assert.equal(validateLogOpts("--since=2024-01-01"), "--since=2024-01-01");
  for (const bad of ["--output=/tmp/pwned", "--ext-diff", "--textconv", "-p; rm -rf ~", "$(id)", "HEAD --exec=x", "--open-files-in-pager=sh"]) {
    assert.throws(() => validateLogOpts(bad), Error, bad);
  }
});
