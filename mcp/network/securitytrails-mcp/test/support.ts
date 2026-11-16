/** Shared test helpers. Not a test file — the runner globs `*.test.ts`. */

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { SecurityTrailsClient } from '../src/client.js';
import { createServer } from '../src/server.js';

export interface StubCall {
    url: string;
    method: string;
    headers: Record<string, string>;
    body: string | undefined;
}

export interface StubResponse {
    status?: number;
    body?: unknown;
    /** Throw instead of responding, to simulate a network failure. */
    throws?: Error;
}

/** A fetch stub that replays queued responses and records every call. */
export function stubFetch(responses: StubResponse[]): { fetch: typeof fetch; calls: StubCall[] } {
    const calls: StubCall[] = [];
    const queue = [...responses];

    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
            headers[key] = value;
        }
        calls.push({
            url: String(input),
            method: init?.method ?? 'GET',
            headers,
            body: typeof init?.body === 'string' ? init.body : undefined
        });

        const next = queue.shift() ?? { status: 200, body: {} };
        if (next.throws) throw next.throws;
        return new Response(next.body === undefined ? '' : JSON.stringify(next.body), {
            status: next.status ?? 200,
            headers: { 'Content-Type': 'application/json' }
        });
    }) as typeof fetch;

    return { fetch: fetchImpl, calls };
}

/** Build a client whose HTTP layer is stubbed and whose backoff is instant. */
export function testClient(responses: StubResponse[], overrides: { apiKey?: string; maxRetries?: number } = {}) {
    const { fetch: fetchImpl, calls } = stubFetch(responses);
    const client = new SecurityTrailsClient({
        apiKey: overrides.apiKey ?? 'test-key',
        maxRetries: overrides.maxRetries ?? 2,
        fetchImpl,
        sleepImpl: async () => {}
    });
    return { client, calls };
}

/** Connect a real MCP Client to the server in-process, over stubbed HTTP. */
export async function connectedClient(responses: StubResponse[]) {
    const { client: apiClient, calls } = testClient(responses);
    const handler = createMcpHandler(() => createServer(apiClient));
    const transport = new StreamableHTTPClientTransport(new URL('http://test.local/mcp'), {
        fetch: (url, init) => handler.fetch(new Request(url, init))
    });
    const client = new Client({ name: 'test-harness', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
    await client.connect(transport);
    return {
        client,
        calls,
        close: async () => {
            await client.close();
        }
    };
}
