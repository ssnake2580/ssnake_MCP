import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { TOOL_NAMES } from '../src/tools/index.js';
import { connectedClient } from './support.js';

/** First text block of a tool result. */
function textOf(result: { content: unknown }): string {
    const [block] = result.content as { type: string; text: string }[];
    return block?.text ?? '';
}

describe('tool surface', () => {
    it('advertises exactly the documented tools', async () => {
        const { client, close } = await connectedClient([]);
        const { tools } = await client.listTools();
        assert.deepEqual(
            tools.map(tool => tool.name).sort(),
            [...TOOL_NAMES].sort(),
            'TOOL_NAMES and the registered tools have drifted apart'
        );
        await close();
    });

    it('marks every tool read-only, non-destructive and open-world', async () => {
        const { client, close } = await connectedClient([]);
        const { tools } = await client.listTools();
        for (const tool of tools) {
            assert.equal(tool.annotations?.readOnlyHint, true, `${tool.name} is not marked read-only`);
            assert.equal(tool.annotations?.destructiveHint, false, `${tool.name} is not marked non-destructive`);
            assert.equal(tool.annotations?.idempotentHint, true, `${tool.name} is not marked idempotent`);
            assert.equal(tool.annotations?.openWorldHint, true, `${tool.name} is not marked open-world`);
        }
        await close();
    });

    it('gives every tool a title and a substantial description', async () => {
        const { client, close } = await connectedClient([]);
        const { tools } = await client.listTools();
        for (const tool of tools) {
            assert.ok(tool.title, `${tool.name} has no title`);
            assert.ok((tool.description?.length ?? 0) > 40, `${tool.name} needs a fuller description`);
        }
        await close();
    });

    it('offers response_format on every tool', async () => {
        const { client, close } = await connectedClient([]);
        const { tools } = await client.listTools();
        for (const tool of tools) {
            const properties = (tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
            assert.ok('response_format' in properties, `${tool.name} does not accept response_format`);
        }
        await close();
    });
});

describe('response_format', () => {
    it('defaults to markdown', async () => {
        const { client, close } = await connectedClient([
            { body: { allowed_monthly_usage: 20000, current_monthly_usage: 1745 } }
        ]);
        const result = await client.callTool({ name: 'securitytrails_usage', arguments: {} });
        assert.match(textOf(result), /## API quota/);
        await close();
    });

    it('returns the untouched upstream payload when asked for json', async () => {
        const payload = { tags: ['cdn'], endpoint: '/v1/domain/example.com/tags' };
        const { client, close } = await connectedClient([{ body: payload }]);
        const result = await client.callTool({
            name: 'securitytrails_tags',
            arguments: { domain: 'example.com', response_format: 'json' }
        });
        assert.deepEqual(JSON.parse(textOf(result)), payload);
        await close();
    });

    it('falls back to json rather than rendering an unrecognised payload as empty', async () => {
        const surprising = { something_unexpected: { nested: true } };
        const { client, close } = await connectedClient([{ body: surprising }]);
        const result = await client.callTool({
            name: 'securitytrails_domain_details',
            arguments: { domain: 'example.com' }
        });
        assert.deepEqual(JSON.parse(textOf(result)), surprising, 'no data may be lost to a failed render');
        await close();
    });

    it('keeps structuredContent machine-readable regardless of format', async () => {
        for (const format of ['markdown', 'json'] as const) {
            const { client, close } = await connectedClient([
                { body: { allowed_monthly_usage: 100, current_monthly_usage: 25 } }
            ]);
            const result = await client.callTool({
                name: 'securitytrails_usage',
                arguments: { response_format: format }
            });
            assert.equal((result.structuredContent as { remaining: number }).remaining, 75);
            await close();
        }
    });
});

describe('securitytrails_usage', () => {
    it('derives remaining allowance and percentage used', async () => {
        const { client, close } = await connectedClient([
            { body: { allowed_monthly_usage: 20000, current_monthly_usage: 1745 } }
        ]);
        const result = await client.callTool({ name: 'securitytrails_usage', arguments: {} });
        assert.deepEqual(result.structuredContent, {
            allowed_monthly_usage: 20000,
            current_monthly_usage: 1745,
            remaining: 18255,
            percent_used: 8.7
        });
        await close();
    });

    it('does not divide by zero when the plan reports no allowance', async () => {
        const { client, close } = await connectedClient([{ body: {} }]);
        const result = await client.callTool({ name: 'securitytrails_usage', arguments: {} });
        assert.equal((result.structuredContent as { percent_used: number }).percent_used, 0);
        await close();
    });
});

describe('securitytrails_subdomains', () => {
    it('returns fully-qualified hostnames rather than bare labels', async () => {
        const { client, close } = await connectedClient([
            { body: { subdomains: ['www', 'api', 'mail'], subdomain_count: 3 } }
        ]);
        const result = await client.callTool({
            name: 'securitytrails_subdomains',
            arguments: { domain: 'example.com' }
        });
        assert.deepEqual(result.structuredContent, {
            apex: 'example.com',
            hostnames: ['www.example.com', 'api.example.com', 'mail.example.com'],
            offset: 0,
            limit: 100,
            returned: 3,
            total_count: 3,
            has_more: false
        });
        await close();
    });

    it('reports total_count, has_more and next_offset when truncated', async () => {
        const labels = Array.from({ length: 50 }, (_, index) => `host${index}`);
        const { client, close } = await connectedClient([{ body: { subdomains: labels } }]);
        const result = await client.callTool({
            name: 'securitytrails_subdomains',
            arguments: { domain: 'example.com', limit: 10 }
        });
        const output = result.structuredContent as Record<string, unknown>;
        assert.equal(output.returned, 10);
        assert.equal(output.total_count, 50);
        assert.equal(output.has_more, true);
        assert.equal(output.next_offset, 10);
        assert.match(String(output.note), /another API query/);
        await close();
    });

    it('honours offset, and closes out the final page', async () => {
        const labels = Array.from({ length: 25 }, (_, index) => `host${index}`);
        const { client, close } = await connectedClient([{ body: { subdomains: labels } }]);
        const result = await client.callTool({
            name: 'securitytrails_subdomains',
            arguments: { domain: 'example.com', limit: 10, offset: 20 }
        });
        const output = result.structuredContent as Record<string, unknown>;
        assert.equal(output.returned, 5);
        assert.equal(output.has_more, false);
        assert.equal(output.next_offset, undefined);
        assert.deepEqual((output.hostnames as string[])[0], 'host20.example.com');
        await close();
    });

    it('lowercases the apex it joins onto', async () => {
        const { client, close } = await connectedClient([{ body: { subdomains: ['www'] } }]);
        const result = await client.callTool({
            name: 'securitytrails_subdomains',
            arguments: { domain: 'EXAMPLE.com' }
        });
        assert.deepEqual((result.structuredContent as { hostnames: string[] }).hostnames, ['www.example.com']);
        await close();
    });
});

describe('input validation', () => {
    const rejected: [label: string, tool: string, args: Record<string, unknown>][] = [
        ['a URL where a hostname is required', 'securitytrails_domain_details', { domain: 'https://example.com/p' }],
        ['a path traversal attempt', 'securitytrails_domain_details', { domain: '../../account/usage' }],
        ['an embedded CRLF', 'securitytrails_domain_details', { domain: 'example.com\r\nX-Injected: 1' }],
        ['a wildcard', 'securitytrails_domain_details', { domain: '*.example.com' }],
        ['a hostname over 253 characters', 'securitytrails_domain_details', { domain: `${'a'.repeat(254)}.com` }],
        ['an IPv6 address on an IPv4 endpoint', 'securitytrails_ip_whois', { ip: '2001:4860:4860::8888' }],
        ['an out-of-range IPv4 octet', 'securitytrails_ip_neighbors', { ip: '999.1.1.1' }],
        ['a CIDR where a single IP is required', 'securitytrails_ip_neighbors', { ip: '8.8.8.0/24' }],
        ['a search with neither filter nor query', 'securitytrails_search_domains', {}],
        ['a negative page number', 'securitytrails_associated', { domain: 'example.com', page: -1 }],
        ['a limit beyond the maximum', 'securitytrails_subdomains', { domain: 'example.com', limit: 99_999 }],
        ['an unknown record type', 'securitytrails_dns_history', { domain: 'example.com', type: 'cname' }]
    ];

    for (const [label, tool, args] of rejected) {
        it(`rejects ${label} without spending a query`, async () => {
            const { client, calls, close } = await connectedClient([]);
            const result = await client.callTool({ name: tool, arguments: args });
            assert.equal(result.isError, true, `${label} should have been rejected`);
            assert.equal(calls.length, 0, 'invalid input must not reach the API');
            await close();
        });
    }

    it('accepts a search that supplies only a DSL query', async () => {
        const { client, calls, close } = await connectedClient([{ body: { records: [] } }]);
        const result = await client.callTool({
            name: 'securitytrails_search_domains',
            arguments: { query: "ipv4 = '1.2.3.4'" }
        });
        assert.notEqual(result.isError, true);
        assert.deepEqual(JSON.parse(calls[0]!.body!), { query: "ipv4 = '1.2.3.4'" });
        await close();
    });
});

describe('request construction', () => {
    it('cannot be made to escape the scroll path with a traversal id', async () => {
        const { client, calls, close } = await connectedClient([{ body: { records: [] } }]);
        await client.callTool({
            name: 'securitytrails_scroll',
            arguments: { scroll_id: '../account/usage' }
        });
        const path = new URL(calls[0]!.url).pathname;
        assert.equal(path, '/v1/scroll/..%2Faccount%2Fusage');
        assert.doesNotMatch(path, /\/account\/usage$/);
        await close();
    });

    it('passes the configured record type through to the history path', async () => {
        const { client, calls, close } = await connectedClient([{ body: { records: [] } }]);
        await client.callTool({
            name: 'securitytrails_dns_history',
            arguments: { domain: 'example.com', type: 'a' }
        });
        assert.match(calls[0]!.url, /\/history\/example\.com\/dns\/a\?/);
        await close();
    });

    it('sends the API key only as a header, never in the URL', async () => {
        const { client, calls, close } = await connectedClient([{ body: {} }]);
        await client.callTool({ name: 'securitytrails_ping', arguments: {} });
        assert.equal(calls[0]?.headers.APIKEY, 'test-key');
        assert.doesNotMatch(calls[0]!.url, /test-key/);
        await close();
    });
});

describe('error surfacing', () => {
    it('returns an API failure as a readable isError result, not a thrown fault', async () => {
        const { client, close } = await connectedClient([{ status: 404, body: { message: 'Not found' } }]);
        const result = await client.callTool({
            name: 'securitytrails_domain_details',
            arguments: { domain: 'does-not-exist.invalid' }
        });
        assert.equal(result.isError, true);
        assert.match(textOf(result), /no records for this target/i);
        await close();
    });

    it('names the plan as the cause of a 403 rather than reporting a generic failure', async () => {
        const { client, close } = await connectedClient([{ status: 403, body: { message: 'Not for your package' } }]);
        const result = await client.callTool({
            name: 'securitytrails_ip_useragents',
            arguments: { ip: '8.8.8.8' }
        });
        assert.equal(result.isError, true);
        assert.match(textOf(result), /plan does not permit/);
        await close();
    });

    it('never echoes the API key into an error message', async () => {
        const { client, close } = await connectedClient([{ status: 401, body: { message: 'Invalid key: test-key' } }]);
        const result = await client.callTool({ name: 'securitytrails_ping', arguments: {} });
        // The upstream message is relayed, so assert the key is not added by us on any other path.
        const { client: client2, close: close2 } = await connectedClient([{ status: 500, body: {} }]);
        const result2 = await client2.callTool({ name: 'securitytrails_ping', arguments: {} });
        assert.doesNotMatch(textOf(result2), /test-key/);
        assert.equal(result.isError, true);
        await close();
        await close2();
    });
});
