/** Domain-oriented tools: records, subdomains, WHOIS, certificates, history. */

import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { SecurityTrailsClient } from '../client.js';
import {
    renderAssociated,
    renderDnsHistory,
    renderDomainDetails,
    renderSsl,
    renderSubdomains,
    renderTags,
    renderWhoisCurrent,
    renderWhoisHistory
} from '../render.js';
import { READ_ONLY, safe, safeStructured } from '../result.js';
import { DomainSchema, PageSchema, ResponseFormatSchema, normalizeHost } from '../schemas.js';

/**
 * Page size for subdomain results.
 *
 * The MCP guidance suggests 20–50 for list tools. This deliberately sits higher: SecurityTrails
 * returns the entire subdomain set in a single billed query, so paging costs a further query
 * each time rather than being free. 100 keeps a typical result inside a reasonable context
 * budget while letting most domains resolve in one call.
 */
const SUBDOMAIN_LIMIT_DEFAULT = 100;
const SUBDOMAIN_LIMIT_MAX = 10_000;

interface SubdomainsResponse {
    subdomains?: string[];
    subdomain_count?: number;
}

export function registerDomainTools(server: McpServer, client: SecurityTrailsClient): void {
    server.registerTool(
        'securitytrails_domain_details',
        {
            title: 'Domain details',
            description:
                'Fetch the current DNS records (A, AAAA, MX, NS, SOA, TXT), hostname counts and registrar metadata ' +
                'for one domain. The best first call when profiling an unfamiliar domain.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain or hostname, e.g. example.com'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ domain }) => client.request(`/domain/${normalizeHost(domain)}`), renderDomainDetails)
    );

    server.registerTool(
        'securitytrails_subdomains',
        {
            title: 'Enumerate subdomains',
            description:
                'List known subdomains of a domain as fully-qualified hostnames, ready to feed into resolution or ' +
                'scanning. Costs one API query regardless of how many hostnames exist, so prefer a single call with ' +
                'a high `limit` over paging with `offset` — each page is separately billed. The response always ' +
                'reports `total_count` and `has_more` so a truncated result is never mistaken for a complete one.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain, e.g. example.com'),
                children_only: z
                    .boolean()
                    .default(false)
                    .describe('only direct children (one label deep) rather than the full tree'),
                include_inactive: z
                    .boolean()
                    .default(true)
                    .describe('include subdomains with no current DNS resolution'),
                limit: z
                    .number()
                    .int()
                    .min(1)
                    .max(SUBDOMAIN_LIMIT_MAX)
                    .default(SUBDOMAIN_LIMIT_DEFAULT)
                    .describe(`maximum hostnames to return (default ${SUBDOMAIN_LIMIT_DEFAULT})`),
                offset: z.number().int().min(0).default(0).describe('number of hostnames to skip before returning'),
                response_format: ResponseFormatSchema
            }),
            outputSchema: z.object({
                apex: z.string(),
                hostnames: z.array(z.string()).describe('fully-qualified hostnames'),
                offset: z.number(),
                limit: z.number(),
                returned: z.number(),
                total_count: z.number().describe('total subdomains SecurityTrails holds for this apex'),
                has_more: z.boolean(),
                next_offset: z.number().optional().describe('offset to pass for the next page, when has_more'),
                note: z.string().optional()
            })
        },
        safeStructured(async ({ domain, children_only, include_inactive, limit, offset }) => {
            const apex = domain.trim().toLowerCase();
            const data = await client.request<SubdomainsResponse>(`/domain/${normalizeHost(domain)}/subdomains`, {
                query: { children_only, include_inactive }
            });

            const labels = data.subdomains ?? [];
            const total = labels.length;
            const page = labels.slice(offset, offset + limit);
            const hasMore = offset + page.length < total;

            return {
                apex,
                hostnames: page.map(label => `${label}.${apex}`),
                offset,
                limit,
                returned: page.length,
                total_count: total,
                has_more: hasMore,
                ...(hasMore ? { next_offset: offset + page.length } : {}),
                ...(hasMore
                    ? {
                          note:
                              `Showing ${page.length} of ${total} hostnames. Raise \`limit\` to get more in one ` +
                              `call, or pass \`offset: ${offset + page.length}\` — note that either way a second ` +
                              `call costs another API query.`
                      }
                    : {})
            };
        }, renderSubdomains)
    );

    server.registerTool(
        'securitytrails_associated',
        {
            title: 'Associated domains',
            description:
                'Find other domains associated with this one through shared registrant details or infrastructure. ' +
                'Useful for expanding scope from a single known domain to an organisation’s wider estate.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain'),
                page: PageSchema,
                response_format: ResponseFormatSchema
            })
        },
        safe(
            ({ domain, page }) => client.request(`/domain/${normalizeHost(domain)}/associated`, { query: { page } }),
            renderAssociated
        )
    );

    server.registerTool(
        'securitytrails_dns_history',
        {
            title: 'Historical DNS records',
            description:
                'Retrieve historical values of one DNS record type for a domain, with the date range each value was ' +
                'observed. The primary tool for spotting infrastructure migrations and origin IPs that predate a CDN.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain or hostname'),
                type: z
                    .enum(['a', 'aaaa', 'mx', 'ns', 'soa', 'txt'])
                    .describe('DNS record type to retrieve history for'),
                page: PageSchema,
                response_format: ResponseFormatSchema
            })
        },
        safe(
            ({ domain, type, page }) =>
                client.request(`/history/${normalizeHost(domain)}/dns/${type}`, { query: { page } }),
            renderDnsHistory
        )
    );

    server.registerTool(
        'securitytrails_whois_current',
        {
            title: 'Current WHOIS',
            description:
                'Fetch the current WHOIS record for a domain: registrar, registrant contacts where not redacted, ' +
                'nameservers, and creation/expiry dates.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ domain }) => client.request(`/domain/${normalizeHost(domain)}/whois`), renderWhoisCurrent)
    );

    server.registerTool(
        'securitytrails_whois_history',
        {
            title: 'Historical WHOIS',
            description:
                'Retrieve past WHOIS records for a domain, each with the window it was observed in. Historical ' +
                'records often expose registrant details that have since been redacted behind privacy services.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ domain }) => client.request(`/history/${normalizeHost(domain)}/whois`), renderWhoisHistory)
    );

    server.registerTool(
        'securitytrails_ssl',
        {
            title: 'SSL/TLS certificates',
            description:
                'List SSL/TLS certificates issued for a hostname. Subject alternative names in the results ' +
                'frequently reveal hostnames that subdomain enumeration alone misses. Pass `status: "all"` to ' +
                'include expired certificates, which are often the more interesting ones historically.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('domain or subdomain'),
                include_subdomains: z
                    .boolean()
                    .default(false)
                    .describe('also return certificates issued for subdomains of this host'),
                status: z
                    .enum(['valid', 'all', 'expired'])
                    .default('valid')
                    .describe('certificate validity filter; use "all" when hunting historical hostnames'),
                page: PageSchema,
                response_format: ResponseFormatSchema
            })
        },
        safe(
            ({ domain, include_subdomains, status, page }) =>
                client.request(`/domain/${normalizeHost(domain)}/ssl`, {
                    query: { include_subdomains, status, page }
                }),
            renderSsl
        )
    );

    server.registerTool(
        'securitytrails_tags',
        {
            title: 'Domain tags',
            description: 'Return SecurityTrails’ classification tags for a domain. Many domains carry no tags at all.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                domain: DomainSchema.describe('apex domain or hostname'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ domain }) => client.request(`/domain/${normalizeHost(domain)}/tags`), renderTags)
    );
}
