#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

// stdio transport: the client launches this process and talks JSON-RPC over
// stdin/stdout. Never console.log here - stdout is the protocol channel.
const server = createServer();
await server.connect(new StdioServerTransport());
console.error("gitleaks-mcp running on stdio");
