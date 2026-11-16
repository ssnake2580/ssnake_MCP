#!/usr/bin/env node
/**
 * securitytrails-mcp — an MCP server exposing the SecurityTrails v1 API.
 *
 * stdout carries the JSON-RPC stream; all diagnostics go to stderr.
 */

import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { VERSION, createServer } from './server.js';

if (!process.env.SECURITYTRAILS_API_KEY) {
    // Start anyway so the host can still list tools; every call then returns an
    // actionable error rather than the server appearing to have crashed.
    console.error(
        'securitytrails-mcp: SECURITYTRAILS_API_KEY is not set — tools will return an error until it is configured.'
    );
}

void serveStdio(() => createServer());
console.error(`securitytrails-mcp v${VERSION} running on stdio`);
