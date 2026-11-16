import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SecurityTrailsClient, SecurityTrailsError } from '../src/client.js';
import { stubFetch, testClient } from './support.js';

describe('SecurityTrailsClient', () => {
    it('sends the API key, accept and user-agent headers', async () => {
        const { client, calls } = testClient([{ body: { success: true } }]);
        await client.request('/ping');
        assert.equal(calls.length, 1);
        assert.equal(calls[0]?.headers.APIKEY, 'test-key');
        assert.equal(calls[0]?.headers.Accept, 'application/json');
        assert.equal(calls[0]?.headers['User-Agent'], 'securitytrails-mcp');
    });

    it('omits undefined and empty query parameters', async () => {
        const { client, calls } = testClient([{ body: {} }]);
        await client.request('/domain/example.com/ssl', {
            query: { page: 1, status: undefined, filter: '' }
        });
        const url = new URL(calls[0]!.url);
        assert.equal(url.searchParams.get('page'), '1');
        assert.equal(url.searchParams.has('status'), false);
        assert.equal(url.searchParams.has('filter'), false);
    });

    it('serialises POST bodies and sets the content type', async () => {
        const { client, calls } = testClient([{ body: { records: [] } }]);
        await client.request('/domains/list', { method: 'POST', body: { query: "ipv4 = '1.2.3.4'" } });
        assert.equal(calls[0]?.method, 'POST');
        assert.equal(calls[0]?.headers['Content-Type'], 'application/json');
        assert.deepEqual(JSON.parse(calls[0]!.body!), { query: "ipv4 = '1.2.3.4'" });
    });

    it('refuses to call the API when no key is configured', async () => {
        const { client, calls } = testClient([], { apiKey: '' });
        await assert.rejects(
            () => client.request('/ping'),
            (error: SecurityTrailsError) => {
                assert.match(error.message, /SECURITYTRAILS_API_KEY is not set/);
                return true;
            }
        );
        assert.equal(calls.length, 0, 'must not spend a request without a key');
    });

    it('explains a 401 by naming the env var to fix', async () => {
        const { client } = testClient([{ status: 401, body: { message: 'Bad key' } }]);
        await assert.rejects(
            () => client.request('/ping'),
            (error: SecurityTrailsError) => {
                assert.equal(error.status, 401);
                assert.match(error.message, /SECURITYTRAILS_API_KEY/);
                assert.equal(error.retryable, false);
                return true;
            }
        );
    });

    it('explains a 403 as a plan limitation', async () => {
        const { client } = testClient([{ status: 403, body: {} }]);
        await assert.rejects(() => client.request('/ping'), /plan does not permit/);
    });

    it('explains a 404 as an absent record rather than a broken tool', async () => {
        const { client } = testClient([{ status: 404, body: {} }]);
        await assert.rejects(() => client.request('/domain/nope.invalid'), /no records for this target/i);
    });

    it('points a 429 at the usage tool', async () => {
        const { client } = testClient(
            [
                { status: 429, body: {} },
                { status: 429, body: {} },
                { status: 429, body: {} }
            ],
            { maxRetries: 2 }
        );
        await assert.rejects(() => client.request('/ping'), /securitytrails_usage/);
    });

    it('retries a transient 500 and returns the eventual success', async () => {
        const { client, calls } = testClient([{ status: 500, body: {} }, { body: { success: true } }]);
        const result = await client.request<{ success: boolean }>('/ping');
        assert.deepEqual(result, { success: true });
        assert.equal(calls.length, 2, 'should have retried once');
    });

    it('stops retrying after maxRetries', async () => {
        const { client, calls } = testClient(
            [
                { status: 503, body: {} },
                { status: 503, body: {} },
                { status: 503, body: {} },
                { status: 503, body: {} }
            ],
            { maxRetries: 2 }
        );
        await assert.rejects(() => client.request('/ping'));
        assert.equal(calls.length, 3, 'one initial attempt plus two retries');
    });

    it('does not retry a non-transient 400', async () => {
        const { client, calls } = testClient([{ status: 400, body: {} }, { body: {} }]);
        await assert.rejects(() => client.request('/domains/list'), /malformed/);
        assert.equal(calls.length, 1);
    });

    it('retries a network error and reports it when retries run out', async () => {
        const { client, calls } = testClient([
            { throws: new TypeError('fetch failed') },
            { throws: new TypeError('fetch failed') },
            { throws: new TypeError('fetch failed') }
        ]);
        await assert.rejects(() => client.request('/ping'), /Network error reaching SecurityTrails/);
        assert.equal(calls.length, 3);
    });

    it('tolerates a non-JSON success body', async () => {
        const { client } = testClient([{ body: undefined }]);
        assert.deepEqual(await client.request('/ping'), {});
    });

    it('reports a timeout distinctly from a generic network failure', async () => {
        const timeout = new Error('The operation was aborted due to timeout');
        timeout.name = 'TimeoutError';
        const { client } = testClient([{ throws: timeout }, { throws: timeout }, { throws: timeout }]);
        await assert.rejects(() => client.request('/ping'), /timed out after 30000ms/);
    });

    it('retries a timeout and succeeds if the next attempt is quick', async () => {
        const timeout = new Error('aborted');
        timeout.name = 'TimeoutError';
        const { client, calls } = testClient([{ throws: timeout }, { body: { success: true } }]);
        assert.deepEqual(await client.request('/ping'), { success: true });
        assert.equal(calls.length, 2);
    });

    it('applies exponential backoff between retries', async () => {
        const delays: number[] = [];
        const { fetch: fetchImpl } = stubFetch([{ status: 503, body: {} }, { status: 503, body: {} }, { body: {} }]);
        const client = new SecurityTrailsClient({
            apiKey: 'test-key',
            fetchImpl,
            sleepImpl: async ms => {
                delays.push(ms);
            }
        });
        await client.request('/ping');
        assert.deepEqual(delays, [500, 1000], 'backoff should double between attempts');
    });

    it('honours a configured timeout value in its error message', async () => {
        const timeout = new Error('aborted');
        timeout.name = 'TimeoutError';
        const { fetch: fetchImpl } = stubFetch([{ throws: timeout }]);
        const client = new SecurityTrailsClient({
            apiKey: 'test-key',
            timeoutMs: 1234,
            maxRetries: 0,
            fetchImpl,
            sleepImpl: async () => {}
        });
        await assert.rejects(() => client.request('/ping'), /timed out after 1234ms/);
    });
});
