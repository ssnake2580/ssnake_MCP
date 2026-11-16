/** IPv4-oriented tools: neighbours, WHOIS, observed user agents, company ranges. */

import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { SecurityTrailsClient } from '../client.js';
import { renderIpNeighbors, renderIpWhois, renderRecords } from '../render.js';
import { READ_ONLY, safe } from '../result.js';
import { DomainSchema, IPv4Schema, PageSchema, ResponseFormatSchema, normalizeHost } from '../schemas.js';

export function registerIpTools(server: McpServer, client: SecurityTrailsClient): void {
    server.registerTool(
        'securitytrails_ip_neighbors',
        {
            title: 'List neighbouring IPs',
            description:
                'List IP blocks adjacent to the given IPv4 address, with the number of sites and sample hostnames ' +
                'seen on each. Useful for finding sibling infrastructure in the same allocation.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                ip: IPv4Schema.describe('IPv4 address, e.g. 8.8.8.8'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ ip }) => client.request(`/ips/nearby/${normalizeHost(ip)}`), renderIpNeighbors)
    );

    server.registerTool(
        'securitytrails_ip_whois',
        {
            title: 'IP WHOIS',
            description:
                'Fetch WHOIS and network-block registration data for one IPv4 address — owning organisation, ' +
                'allocation, and abuse contacts.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                ip: IPv4Schema.describe('IPv4 address, e.g. 8.8.8.8'),
                response_format: ResponseFormatSchema
            })
        },
        safe(({ ip }) => client.request(`/ips/${normalizeHost(ip)}/whois`), renderIpWhois)
    );

    server.registerTool(
        'securitytrails_ip_useragents',
        {
            title: 'User agents seen on an IP',
            description:
                'List user-agent strings SecurityTrails has observed originating from one IPv4 address, with first ' +
                'and last seen dates. Paginated. Requires a paid SecurityTrails plan — returns a plan error on ' +
                'the free tier.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                ip: IPv4Schema.describe('IPv4 address'),
                page: PageSchema,
                response_format: ResponseFormatSchema
            })
        },
        safe(
            ({ ip, page }) => client.request(`/ips/${normalizeHost(ip)}/useragents`, { query: { page } }),
            renderRecords
        )
    );

    server.registerTool(
        'securitytrails_company_associated_ips',
        {
            title: 'Company IP ranges',
            description:
                'Look up IP addresses and ranges attributed to the organisation that owns a domain. Takes the ' +
                'company’s primary domain, not a company name. Requires a paid SecurityTrails plan — ' +
                'returns a plan error on the free tier.',
            annotations: READ_ONLY,
            inputSchema: z.object({
                company_domain: DomainSchema.describe('the company’s primary domain, e.g. example.com'),
                response_format: ResponseFormatSchema
            })
        },
        safe(
            ({ company_domain }) => client.request(`/company/${normalizeHost(company_domain)}/associated-ips`),
            renderRecords
        )
    );
}
