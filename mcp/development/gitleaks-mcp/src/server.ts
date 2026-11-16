import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as gl from "./gitleaks.js";

/**
 * MCP has three primitives. This server uses all of them:
 *  - TOOLS     : actions the model can call (scan_*)
 *  - RESOURCES : read-only data the client can attach (gitleaks://about)
 *  - PROMPTS   : reusable templates the user can invoke (pre-push-check)
 */
export function createServer(eng: gl.Engine = gl.engine): McpServer {
  const server = new McpServer({ name: "gitleaks-mcp", version: "0.1.0" });

  const maxFindings = z.number().int().min(1).max(500).default(50)
    .describe("Maximum findings to return (the total count is always reported).");

  const asText = (r: gl.ScanResult) => ({
    content: [{
      type: "text" as const,
      text: JSON.stringify(
        {
          summary: r.findingsCount === 0 ? "No secrets found." : `${r.findingsCount} potential secret(s) found. Values are redacted.`,
          ...r,
        },
        null,
        2,
      ),
    }],
  });

  const asError = (e: unknown) => ({
    isError: true,
    content: [{ type: "text" as const, text: e instanceof Error ? e.message : String(e) }],
  });

  const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

  server.registerTool(
    "scan_repo",
    {
      title: "Scan git history",
      description: "Scan a git repository, including its commit history, for hardcoded secrets. Secret values are always redacted.",
      inputSchema: {
        path: z.string().describe("Absolute path to the git repository."),
        log_opts: z.string().optional().describe('Optional `git log` options to limit the scan, e.g. "main..HEAD" or "--since=2024-01-01".'),
        max_findings: maxFindings,
      },
      annotations: readOnly,
    },
    async ({ path, log_opts, max_findings }) => {
      try { return asText(await eng.scanRepo(path, { logOpts: log_opts, maxFindings: max_findings })); }
      catch (e) { return asError(e); }
    },
  );

  server.registerTool(
    "scan_staged",
    {
      title: "Scan staged changes",
      description: "Scan only the changes currently staged in a git repository (what `git commit` would record). Use before committing.",
      inputSchema: {
        path: z.string().describe("Absolute path to the git repository."),
        max_findings: maxFindings,
      },
      annotations: readOnly,
    },
    async ({ path, max_findings }) => {
      try { return asText(await eng.scanStaged(path, { maxFindings: max_findings })); }
      catch (e) { return asError(e); }
    },
  );

  server.registerTool(
    "scan_path",
    {
      title: "Scan files or directory",
      description: "Scan a directory or single file on disk for secrets, without needing git.",
      inputSchema: {
        path: z.string().describe("Absolute path to a file or directory."),
        max_findings: maxFindings,
      },
      annotations: readOnly,
    },
    async ({ path, max_findings }) => {
      try { return asText(await eng.scanPath(path, { maxFindings: max_findings })); }
      catch (e) { return asError(e); }
    },
  );

  server.registerTool(
    "scan_text",
    {
      title: "Scan a text snippet",
      description: "Scan a string (e.g. a snippet, config or diff you are about to write or share) for secrets.",
      inputSchema: {
        text: z.string().min(1).describe("The text to scan."),
        max_findings: maxFindings,
      },
      annotations: readOnly,
    },
    async ({ text, max_findings }) => {
      try { return asText(await eng.scanText(text, { maxFindings: max_findings })); }
      catch (e) { return asError(e); }
    },
  );

  server.registerResource(
    "about",
    "gitleaks://about",
    {
      title: "gitleaks-mcp info",
      description: "Installed gitleaks version and the safety guarantees of this server.",
      mimeType: "text/plain",
    },
    async (uri) => {
      let version = "unknown";
      try { version = await eng.version(); } catch (e) { version = e instanceof Error ? e.message : String(e); }
      return {
        contents: [{
          uri: uri.href,
          text: [
            `engine: ${eng.name} ${version}`,
            "Guarantees: scans run with --redact; Match/Secret fields are dropped; no shell is used; scans are read-only.",
            "Config: gitleaks honours GITLEAKS_CONFIG and a .gitleaks.toml in the scanned path.",
          ].join("\n"),
        }],
      };
    },
  );

  server.registerPrompt(
    "pre-push-check",
    {
      title: "Pre-push secret check",
      description: "Check a repository for secrets before committing or pushing.",
      argsSchema: { path: z.string().describe("Absolute path to the git repository.") },
    },
    ({ path }) => ({
      messages: [{
        role: "user" as const,
        content: {
          type: "text" as const,
          text:
            `Before I push, check the repository at ${path} for secrets.\n` +
            `1. Call scan_staged on it.\n2. Call scan_repo with log_opts "@{upstream}..HEAD" (if no upstream exists, scan the last 20 commits with "-n 20").\n` +
            `3. Summarise findings by rule and file:line. Never ask me to paste secret values.\n` +
            `4. For each finding, say whether it looks real or a false positive, and suggest rotation or a .gitleaksignore entry.`,
        },
      }],
    }),
  );

  return server;
}
