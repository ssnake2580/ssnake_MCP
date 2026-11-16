/** Server construction, kept free of side effects so tests can import it. */

import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/server';
import { SecurityTrailsClient } from './client.js';
import { registerTools } from './tools/index.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

export const VERSION = pkg.version;

function readPositiveInt(name: string, fallback: number): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Build a server instance. Called once per stdio connection by `serveStdio`.
 * Accepts an injected client so tests can drive tools against a stub transport.
 */
export function createServer(client?: SecurityTrailsClient): McpServer {
    const server = new McpServer({ name: 'securitytrails', version: VERSION });
    const apiClient =
        client ??
        new SecurityTrailsClient({
            apiKey: process.env.SECURITYTRAILS_API_KEY ?? '',
            timeoutMs: readPositiveInt('SECURITYTRAILS_TIMEOUT_MS', 30_000),
            maxRetries: readPositiveInt('SECURITYTRAILS_MAX_RETRIES', 2),
            userAgent: `securitytrails-mcp/${VERSION}`
        });
    registerTools(server, apiClient);
    return server;
}
