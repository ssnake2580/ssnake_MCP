import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * Thin, safe wrapper around the `gitleaks` binary.
 *
 * Two design rules matter for a security tool exposed to an LLM:
 *  1. Never use a shell - arguments are passed as an array to execFile.
 *  2. Never return secret material. We always pass --redact AND we drop the
 *     `Match` / `Secret` fields from the report before it leaves this module.
 */

export interface Finding {
  rule: string;
  description: string;
  file: string;
  startLine: number;
  endLine: number;
  commit?: string;
  author?: string;
  date?: string;
  fingerprint: string;
}

export interface ScanResult {
  findingsCount: number;
  truncated: boolean;
  findings: Finding[];
}

const BIN = process.env.GITLEAKS_BIN ?? "gitleaks";
const MAX_BUFFER = 64 * 1024 * 1024;
const TIMEOUT_MS = 120_000;

function exec(args: string[], stdin?: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((res, rej) => {
    const child = execFile(
      BIN,
      args,
      { maxBuffer: MAX_BUFFER, timeout: TIMEOUT_MS },
      (err, stdout, stderr) => {
        if (err) {
          const e = err as NodeJS.ErrnoException;
          if (e.code === "ENOENT") {
            return rej(new Error(`gitleaks binary not found ("${BIN}"). Install it (brew install gitleaks) or set GITLEAKS_BIN.`));
          }
          return rej(new Error(`gitleaks failed: ${stderr.trim() || e.message}`));
        }
        res({ stdout, stderr });
      },
    );
    if (stdin !== undefined) child.stdin?.end(stdin);
  });
}

export async function gitleaksVersion(): Promise<string> {
  const { stdout } = await exec(["version"]);
  return stdout.trim();
}

async function assertDir(path: string): Promise<string> {
  const abs = resolve(path);
  let s;
  try {
    s = await stat(abs);
  } catch {
    throw new Error(`Path does not exist: ${abs}`);
  }
  if (!s.isDirectory() && !s.isFile()) throw new Error(`Not a file or directory: ${abs}`);
  return abs;
}

interface RawFinding {
  RuleID: string;
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  Commit?: string;
  Author?: string;
  Date?: string;
  Fingerprint: string;
  // Match and Secret exist in the raw report but are intentionally never read.
}

function sanitize(raw: RawFinding[], maxFindings: number): ScanResult {
  const findings = raw.slice(0, maxFindings).map((f): Finding => ({
    rule: f.RuleID,
    description: f.Description,
    file: f.File,
    startLine: f.StartLine,
    endLine: f.EndLine,
    ...(f.Commit ? { commit: f.Commit } : {}),
    ...(f.Author ? { author: f.Author } : {}),
    ...(f.Date ? { date: f.Date } : {}),
    fingerprint: f.Fingerprint,
  }));
  return { findingsCount: raw.length, truncated: raw.length > maxFindings, findings };
}

/** Run a gitleaks scan subcommand and return sanitized findings. */
async function scan(subArgs: string[], opts: { stdin?: string; maxFindings: number }): Promise<ScanResult> {
  const dir = await mkdtemp(join(tmpdir(), "gitleaks-mcp-"));
  const report = join(dir, "report.json");
  try {
    await exec(
      [
        ...subArgs,
        "--report-format", "json",
        "--report-path", report,
        "--redact",
        "--no-banner",
        "--no-color",
        "--exit-code", "0", // leaks are a result, not an error
      ],
      opts.stdin,
    );
    const text = (await readFile(report, "utf8")).trim();
    const raw: RawFinding[] = text ? JSON.parse(text) : [];
    return sanitize(raw, opts.maxFindings);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * log_opts is forwarded to `git log`, which has flags that write files
 * (--output) or run programs (--ext-diff, --textconv, --exec). Because the
 * value comes from an LLM, it is validated against an allowlist: revisions and
 * ranges are fine, and only a few harmless flags are permitted.
 */
const SAFE_FLAGS = new Set([
  "--since", "--until", "--after", "--before", "--max-count", "-n",
  "--author", "--committer", "--all", "--branches", "--tags", "--remotes",
  "--no-merges", "--first-parent", "--reverse", "--skip",
]);
const SAFE_TOKEN = /^[A-Za-z0-9@{}^~:.\/_+,-]+(=[A-Za-z0-9@{}^~:.\/_+,:-]+)?$/;

export function validateLogOpts(logOpts: string): string {
  const tokens = logOpts.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0 || tokens.length > 20) throw new Error("log_opts must contain 1-20 tokens.");
  for (const t of tokens) {
    if (!SAFE_TOKEN.test(t)) throw new Error(`log_opts: disallowed characters in "${t}".`);
    if (t.startsWith("-")) {
      const flag = t.split("=")[0];
      if (!SAFE_FLAGS.has(flag)) throw new Error(`log_opts: flag "${flag}" is not allowed.`);
    }
  }
  return tokens.join(" ");
}

export async function scanRepo(path: string, opts: { logOpts?: string; maxFindings: number }) {
  const abs = await assertDir(path);
  const args = ["git", abs];
  if (opts.logOpts) args.push(`--log-opts=${validateLogOpts(opts.logOpts)}`);
  return scan(args, opts);
}

export async function scanStaged(path: string, opts: { maxFindings: number }) {
  const abs = await assertDir(path);
  return scan(["git", "--staged", abs], opts);
}

export async function scanPath(path: string, opts: { maxFindings: number }) {
  const abs = await assertDir(path);
  return scan(["dir", abs], opts);
}

export async function scanText(text: string, opts: { maxFindings: number }) {
  return scan(["stdin"], { stdin: text, maxFindings: opts.maxFindings });
}

/**
 * The seam that keeps the MCP tool contract independent of the scanner binary.
 * gitleaks is in maintenance mode (its author moved on to Betterleaks), so a
 * second implementation of this interface can be added once Betterleaks v2 is
 * stable - without touching tool names or schemas.
 */
export interface Engine {
  name: string;
  version(): Promise<string>;
  scanRepo(path: string, o: { logOpts?: string; maxFindings: number }): Promise<ScanResult>;
  scanStaged(path: string, o: { maxFindings: number }): Promise<ScanResult>;
  scanPath(path: string, o: { maxFindings: number }): Promise<ScanResult>;
  scanText(text: string, o: { maxFindings: number }): Promise<ScanResult>;
}

export const engine: Engine = {
  name: "gitleaks",
  version: gitleaksVersion,
  scanRepo,
  scanStaged,
  scanPath,
  scanText,
};
