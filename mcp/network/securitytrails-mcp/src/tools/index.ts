/** Registers every tool this server exposes. */

import type { McpServer } from '@modelcontextprotocol/server';
import type { SecurityTrailsClient } from '../client.js';
import { registerAccountTools } from './account.js';
import { registerDomainTools } from './domain.js';
import { registerIpTools } from './ip.js';
import { registerSearchTools } from './search.js';

/** Every tool name this server registers, for tests and documentation. */
export const TOOL_NAMES = [
    'securitytrails_ping',
    'securitytrails_usage',
    'securitytrails_domain_details',
    'securitytrails_subdomains',
    'securitytrails_associated',
    'securitytrails_dns_history',
    'securitytrails_whois_current',
    'securitytrails_whois_history',
    'securitytrails_ssl',
    'securitytrails_tags',
    'securitytrails_ip_neighbors',
    'securitytrails_ip_whois',
    'securitytrails_ip_useragents',
    'securitytrails_company_associated_ips',
    'securitytrails_search_domains',
    'securitytrails_search_ips',
    'securitytrails_scroll'
] as const;

export function registerTools(server: McpServer, client: SecurityTrailsClient): void {
    registerAccountTools(server, client);
    registerDomainTools(server, client);
    registerIpTools(server, client);
    registerSearchTools(server, client);
}
