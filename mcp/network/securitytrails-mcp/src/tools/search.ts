/** Dataset search tools: DSL/filter queries over domains and IPs, plus scrolling. */

import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { SecurityTrailsClient } from '../client.js';
import { renderRecords, renderSearchDomains } from '../render.js';
import { READ_ONLY, safe } from '../result.js';
import { PageSchema, ResponseFormatSchema } from '../schemas.js';

const REQUIRE_ONE = 'Provide either `filter` or `query`.';

export function registerSearchTools(server: McpServer, client: SecurityTrailsClient): void {
    server.registerTool(
        'securitytrails_search_domains',
        {
            title: 'Search domains',
            description:
                'Search the domain dataset by structured filter or DSL query. Valid fields include apex_domain, ' +
                'keyword, tld, mx, ns, cname, ipv4, ipv6 and whois_email — for example ' +
                '{"apex_domain": "example.com"} or "whois_email = \'admin@example.com\'". Note that the domain and ' +
                'IP datasets accept different field names: IP-only fields such as ptr_part or open_port_80 are a ' +
                'syntax error here, and belong in securitytrails_search_ips. Exactly one of `filter` or `query` is ' +
                'required. Each page costs one API query.',
            annotations: READ_ONLY,
            inputSchema: z
                .object({
                    filter: z
                        .record(z.string(), z.unknown())
                        .optional()
                        .describe('structured filter object, e.g. {"apex_domain": "example.com"}'),
                    query: z.string().optional().describe('DSL query string, e.g. "ipv4 = \'1.2.3.4\'"'),
                    include_ips: z.boolean().default(false).describe('include resolved IPs for each domain'),
                    page: PageSchema,
                    response_format: ResponseFormatSchema
                })
                .refine(input => Boolean(input.filter) || Boolean(input.query), { message: REQUIRE_ONE })
        },
        safe(
            ({ filter, query, include_ips, page }) =>
                client.request('/domains/list', {
                    method: 'POST',
                    query: { include_ips, page },
                    body: { ...(filter ? { filter } : {}), ...(query ? { query } : {}) }
                }),
            renderSearchDomains
        )
    );

    server.registerTool(
        'securitytrails_search_ips',
        {
            title: 'Search IPs',
            description:
                'Search the IP dataset by DSL query or structured filter — for example "ptr_part = \'example\'" ' +
                'or "open_port_80 = true". These IP-dataset fields are distinct from the domain-dataset fields used ' +
                'by securitytrails_search_domains. Exactly one of `query` or `filter` is required. Each page costs ' +
                'one API query.',
            annotations: READ_ONLY,
            inputSchema: z
                .object({
                    query: z.string().optional().describe('DSL query, e.g. "ptr_part = \'example\'"'),
                    filter: z.record(z.string(), z.unknown()).optional().describe('structured filter object'),
                    page: PageSchema,
                    response_format: ResponseFormatSchema
                })
                .refine(input => Boolean(input.filter) || Boolean(input.query), { message: REQUIRE_ONE })
        },
        safe(
            ({ query, filter, page }) =>
                client.request('/ips/list', {
                    method: 'POST',
                    query: { page },
                    body: { ...(query ? { query } : {}), ...(filter ? { filter } : {}) }
                }),
            renderRecords
        )
    );

    server.registerTool(
        'securitytrails_scroll',
        {
            title: 'Scroll search results',
            description:
                'Fetch the next batch of a large search using a scroll id. Only usable when a previous ' +
                'securitytrails_search_domains or securitytrails_search_ips response included `meta.scroll_id` — ' +
                'scrolling is not enabled on every plan or every query. When no scroll id is offered, page with the ' +
                '`page` argument instead.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                scroll_id: z.string().min(1).describe('scroll id from a previous search response’s meta block'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ scroll_id }) => client.request(`/scroll/${encodeURIComponent(scroll_id)}`), renderRecords)
    );
}
