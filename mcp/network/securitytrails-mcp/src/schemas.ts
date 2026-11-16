/** Reusable input schemas and normalisers shared by the tool modules. */

import * as z from 'zod/v4';

/**
 * A bare hostname. Deliberately strict: a scheme, port or path here would be silently
 * percent-encoded into the request path and come back as a confusing 404 — having spent one of
 * the caller's monthly API queries to get there.
 */
export const DomainSchema = z
    .string()
    .min(1)
    .max(253)
    .regex(
        /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
        'must be a bare hostname such as example.com — no scheme, port, path or wildcard'
    );

const IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** SecurityTrails' IP endpoints are IPv4-only; reject IPv6 up front rather than 404. */
export const IPv4Schema = z
    .string()
    .regex(IPV4, 'must be an IPv4 address such as 8.8.8.8 (SecurityTrails IP endpoints do not accept IPv6)');

export const PageSchema = z
    .number()
    .int()
    .min(1)
    .max(10_000)
    .default(1)
    .describe('1-indexed page number; each page costs one API query');

/**
 * Output format. Markdown is the default because it is markedly cheaper in context and converts
 * the API's raw Unix timestamps into dates; JSON returns the untouched upstream payload.
 */
export const ResponseFormatSchema = z
    .enum(['markdown', 'json'])
    .default('markdown')
    .describe('"markdown" for a compact human-readable summary, "json" for the full raw API payload');

/** Lowercase and percent-encode a hostname or IP for safe interpolation into a path. */
export function normalizeHost(value: string): string {
    return encodeURIComponent(value.trim().toLowerCase());
}
