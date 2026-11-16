/** Helpers that turn client results and errors into MCP tool results. */

import type { CallToolResult } from '@modelcontextprotocol/server';
import { SecurityTrailsError } from './client.js';
import type { Renderer } from './render.js';

export type ResponseFormat = 'markdown' | 'json';

/** Any tool argument set carries a response format; every tool schema supplies a default. */
export interface FormatArgs {
    response_format: ResponseFormat;
}

function toJson(value: unknown): string {
    return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

/**
 * Render a payload in the requested format.
 *
 * Markdown rendering is best-effort: if the renderer does not recognise the payload, or throws
 * on an unexpected shape, the raw JSON is returned instead. Returning a partial or empty
 * Markdown document would hide data the caller asked for.
 */
export function render(data: unknown, format: ResponseFormat, renderer?: Renderer): string {
    if (format === 'json' || !renderer) return toJson(data);
    try {
        const markdown = renderer(data);
        return markdown && markdown.trim() !== '' ? markdown : toJson(data);
    } catch {
        return toJson(data);
    }
}

export function errorResult(error: unknown): CallToolResult {
    const message =
        error instanceof SecurityTrailsError
            ? error.message
            : `Unexpected error: ${error instanceof Error ? error.message : String(error)}`;
    return { content: [{ type: 'text', text: message }], isError: true };
}

/**
 * Wrap a handler so a thrown SecurityTrailsError becomes an `isError` result the model can read
 * and retry against, rather than a protocol-level failure, and so the result honours
 * `response_format`.
 */
export function safe<Args extends FormatArgs>(
    run: (args: Args) => Promise<unknown>,
    renderer?: Renderer
): (args: Args) => Promise<CallToolResult> {
    return async (args: Args) => {
        try {
            const data = await run(args);
            return { content: [{ type: 'text', text: render(data, args.response_format, renderer) }] };
        } catch (error) {
            return errorResult(error);
        }
    };
}

/**
 * As {@link safe}, for tools that declare an `outputSchema`. `structuredContent` always carries
 * the machine-readable object; only the text rendering follows `response_format`.
 */
export function safeStructured<Args extends FormatArgs>(
    run: (args: Args) => Promise<Record<string, unknown>>,
    renderer?: Renderer
): (args: Args) => Promise<CallToolResult> {
    return async (args: Args) => {
        try {
            const data = await run(args);
            return {
                content: [{ type: 'text', text: render(data, args.response_format, renderer) }],
                structuredContent: data
            };
        } catch (error) {
            return errorResult(error);
        }
    };
}

/** Shared annotations: every tool in this server is a read-only remote lookup. */
export const READ_ONLY = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true
} as const;
