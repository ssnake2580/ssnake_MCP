#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { Scope } from "./scope.js";
import { fuzzPath, fuzzParameter, fuzzVhost } from "./ffuf.js";

const scope = Scope.fromEnv("MCP_FFUF_SCOPE");

const server = new McpServer({
  name: "mcp-ffuf",
  version: "0.1.0",
});

server.tool(
  "check_scope",
  "Return whether a URL's host is within MCP_FFUF_SCOPE. Does not run ffuf.",
  { url: z.string().url() },
  async ({ url }) => json({ url, in_scope: scope.allowsUrl(url), scope_rules: scope.describe() }),
);

server.tool(
  "fuzz_path",
  "Fuzz paths or filenames. URL must contain the literal token 'FUZZ', e.g. 'https://target/FUZZ'.",
  {
    url: z.string().url(),
    wordlist: z.string().describe("Absolute path to a wordlist file on the server."),
    extensions: z.string().regex(/^[\w.,-]+$/).optional().describe("Comma-separated extensions, e.g. '.php,.html'."),
    match_codes: z.string().regex(/^[\d,]+$/).optional(),
    filter_codes: z.string().regex(/^[\d,]+$/).optional(),
  },
  wrap((args) => fuzzPath(args)),
);

server.tool(
  "fuzz_parameter",
  "Fuzz query parameter names. URL must contain 'FUZZ' as the parameter name, e.g. 'https://target/?FUZZ=test'.",
  {
    url: z.string().url(),
    wordlist: z.string(),
    match_codes: z.string().regex(/^[\d,]+$/).optional(),
    filter_codes: z.string().regex(/^[\d,]+$/).optional(),
  },
  wrap((args) => fuzzParameter(args)),
);

server.tool(
  "fuzz_vhost",
  "Fuzz virtual hosts via the Host header. Sends Host: FUZZ.<hostname-of-url> for each wordlist entry.",
  {
    url: z.string().url(),
    wordlist: z.string(),
    match_codes: z.string().regex(/^[\d,]+$/).optional(),
    filter_codes: z.string().regex(/^[\d,]+$/).optional(),
  },
  wrap((args) => fuzzVhost(args)),
);

function wrap(fn) {
  return async (args) => {
    try {
      scope.assertAllowsUrl(args.url);
      return json(await fn(args));
    } catch (err) {
      return json({ error: err.message, code: err.name });
    }
  };
}

function json(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}

const transport = new StdioServerTransport();
await server.connect(transport);

if (scope.isEmpty()) {
  process.stderr.write("mcp-ffuf: WARNING — MCP_FFUF_SCOPE is empty; every run will be refused.\n");
}
process.stderr.write(`mcp-ffuf listening on stdio (scope: ${scope.isEmpty() ? "empty" : scope.describe().join(", ")})\n`);
