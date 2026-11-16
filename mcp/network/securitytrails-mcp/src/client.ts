/**
 * Minimal typed client for the SecurityTrails v1 REST API.
 *
 * Adds three things the raw API does not give you: a request timeout, bounded
 * retries on transient failures, and error messages an agent can act on.
 */

export const API_BASE = 'https://api.securitytrails.com/v1';

/** A SecurityTrails API or transport failure, carrying an agent-readable hint. */
export class SecurityTrailsError extends Error {
    readonly status: number | undefined;
    readonly retryable: boolean;

    constructor(message: string, options: { status?: number; retryable?: boolean } = {}) {
        super(message);
        this.name = 'SecurityTrailsError';
        this.status = options.status;
        this.retryable = options.retryable ?? false;
    }
}

export interface SecurityTrailsClientOptions {
    apiKey: string;
    baseUrl?: string;
    /** Per-attempt timeout in milliseconds. Default 30000. */
    timeoutMs?: number;
    /** Retries after the first attempt, for 429/5xx/network errors. Default 2. */
    maxRetries?: number;
    userAgent?: string;
    /** Injectable for tests. */
    fetchImpl?: typeof fetch;
    /** Injectable for tests; receives the delay in ms before each retry. */
    sleepImpl?: (ms: number) => Promise<void>;
}

export interface RequestOptions {
    method?: 'GET' | 'POST';
    query?: Record<string, string | number | boolean | undefined>;
    body?: unknown;
}

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

/** Turn an HTTP status into something the model can actually act on. */
function explain(status: number, apiMessage: string | undefined): string {
    const detail = apiMessage ? `: ${apiMessage}` : '';
    switch (status) {
        case 400:
            return `SecurityTrails rejected the request as malformed (HTTP 400)${detail}. Check the query/filter syntax.`;
        case 401:
            return `SecurityTrails rejected the API key (HTTP 401)${detail}. Verify SECURITYTRAILS_API_KEY is set to a valid key from https://securitytrails.com/app/account/credentials.`;
        case 403:
            return `Your SecurityTrails plan does not permit this endpoint (HTTP 403)${detail}. Several endpoints require a paid tier.`;
        case 404:
            return `SecurityTrails has no records for this target (HTTP 404)${detail}. Confirm the domain or IP is correct, and note that very new or parked assets are often absent.`;
        case 429:
            return `SecurityTrails rate limit or monthly quota exhausted (HTTP 429)${detail}. Call securitytrails_usage to see remaining allowance.`;
        default:
            if (status >= 500) {
                return `SecurityTrails server error (HTTP ${status})${detail}. This is usually transient — retry shortly.`;
            }
            return `SecurityTrails returned HTTP ${status}${detail}.`;
    }
}

const defaultSleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

export class SecurityTrailsClient {
    private readonly apiKey: string;
    private readonly baseUrl: string;
    private readonly timeoutMs: number;
    private readonly maxRetries: number;
    private readonly userAgent: string;
    private readonly fetchImpl: typeof fetch;
    private readonly sleepImpl: (ms: number) => Promise<void>;

    constructor(options: SecurityTrailsClientOptions) {
        this.apiKey = options.apiKey;
        this.baseUrl = options.baseUrl ?? API_BASE;
        this.timeoutMs = options.timeoutMs ?? 30_000;
        this.maxRetries = options.maxRetries ?? 2;
        this.userAgent = options.userAgent ?? 'securitytrails-mcp';
        this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
        this.sleepImpl = options.sleepImpl ?? defaultSleep;
    }

    /** Issue one API request, retrying transient failures. Throws SecurityTrailsError. */
    async request<T = unknown>(path: string, options: RequestOptions = {}): Promise<T> {
        if (!this.apiKey) {
            throw new SecurityTrailsError(
                'SECURITYTRAILS_API_KEY is not set. Add it to the MCP server’s env block — see https://github.com/aqhmal/securitytrails-mcp#configuration.'
            );
        }

        let lastError: SecurityTrailsError | undefined;

        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            if (attempt > 0) {
                // Exponential backoff: 500ms, 1000ms, 2000ms ...
                await this.sleepImpl(500 * 2 ** (attempt - 1));
            }

            try {
                return await this.attempt<T>(path, options);
            } catch (error) {
                const stError =
                    error instanceof SecurityTrailsError
                        ? error
                        : new SecurityTrailsError(`Unexpected client error: ${String(error)}`);
                if (!stError.retryable || attempt === this.maxRetries) throw stError;
                lastError = stError;
            }
        }

        /* c8 ignore next */
        throw lastError ?? new SecurityTrailsError('Request failed for an unknown reason.');
    }

    private async attempt<T>(path: string, options: RequestOptions): Promise<T> {
        const { method = 'GET', query, body } = options;
        const url = new URL(this.baseUrl + path);
        if (query) {
            for (const [key, value] of Object.entries(query)) {
                if (value !== undefined && value !== null && value !== '') {
                    url.searchParams.set(key, String(value));
                }
            }
        }

        let response: Response;
        try {
            response = await this.fetchImpl(url, {
                method,
                headers: {
                    APIKEY: this.apiKey,
                    Accept: 'application/json',
                    'User-Agent': this.userAgent,
                    ...(body ? { 'Content-Type': 'application/json' } : {})
                },
                body: body ? JSON.stringify(body) : undefined,
                signal: AbortSignal.timeout(this.timeoutMs)
            });
        } catch (error) {
            const isTimeout = error instanceof Error && error.name === 'TimeoutError';
            throw new SecurityTrailsError(
                isTimeout
                    ? `SecurityTrails request timed out after ${this.timeoutMs}ms.`
                    : `Network error reaching SecurityTrails: ${error instanceof Error ? error.message : String(error)}`,
                { retryable: true }
            );
        }

        const text = await response.text();
        let payload: unknown;
        try {
            payload = text ? JSON.parse(text) : {};
        } catch {
            payload = { raw: text };
        }

        if (!response.ok) {
            const apiMessage =
                typeof payload === 'object' && payload !== null && 'message' in payload
                    ? String((payload as { message: unknown }).message)
                    : undefined;
            throw new SecurityTrailsError(explain(response.status, apiMessage), {
                status: response.status,
                retryable: RETRYABLE_STATUS.has(response.status)
            });
        }

        return payload as T;
    }
}
