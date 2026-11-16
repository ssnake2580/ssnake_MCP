#!/usr/bin/env node
import { FastMCP } from "fastmcp";
import dotenv from "dotenv";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { registerIpLookup } from "./tools/ip-lookup.js";
import { registerShodanSearch } from "./tools/shodan-search.js";
import { registerCveLookup } from "./tools/cve-lookup.js";
import { registerDnsLookup } from "./tools/dns-lookup.js";
import { registerReverseDnsLookup } from "./tools/reverse-dns-lookup.js";
import { registerCpeLookup } from "./tools/cpe-lookup.js";
import { registerCvesByProduct } from "./tools/cves-by-product.js";
import { registerShodanCount } from "./tools/shodan-count.js";
import { registerDomainInfo } from "./tools/domain-info.js";
import { registerApiInfo } from "./tools/api-info.js";
import { registerSearchFilters } from "./tools/search-filters.js";

dotenv.config();

if (!process.env.SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is required.");
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, "..", "package.json"), "utf8")
) as { version: string };

const server = new FastMCP({
  name: "shodan-mcp",
  version: pkg.version as `${number}.${number}.${number}`,
  instructions: `This MCP server provides comprehensive access to Shodan's network intelligence and security services:

- Network Reconnaissance: Query detailed information about IP addresses, including open ports, services, and vulnerabilities
- DNS Operations: Forward and reverse DNS lookups for domains and IP addresses
- Vulnerability Intelligence: Access to Shodan's CVEDB for detailed vulnerability information, CPE lookups, and product-specific CVE tracking
- Device Discovery: Search Shodan's database of internet-connected devices with advanced filtering and facets (shodan_search), or get result totals and facet breakdowns without using credits (shodan_count)
- Domain Intelligence: Enumerate subdomains and DNS records for a domain (domain_info)
- Account and Query Help: Check plan and credits (api_info) and list valid search filters and facets (search_filters)

Credit usage: shodan_search costs 1 query credit when the query uses filters (plus 1 per page beyond the first), and domain_info costs 1 query credit per lookup. shodan_count, api_info, search_filters, ip_lookup, dns_lookup, reverse_dns_lookup and the CVE/CPE tools do not consume query credits.

Each tool provides structured, formatted output for easy analysis and integration.`,
});

registerIpLookup(server);
registerShodanSearch(server);
registerCveLookup(server);
registerDnsLookup(server);
registerReverseDnsLookup(server);
registerCpeLookup(server);
registerCvesByProduct(server);
registerShodanCount(server);
registerDomainInfo(server);
registerApiInfo(server);
registerSearchFilters(server);

const transport = process.env.MCP_TRANSPORT || "stdio";

async function main() {
  if (transport === "httpStream") {
    const port = parseInt(process.env.MCP_PORT || "3000", 10);
    const host = process.env.MCP_HOST || "localhost";
    const endpoint = (process.env.MCP_ENDPOINT || "/mcp") as `/${string}`;
    await server.start({
      transportType: "httpStream",
      httpStream: { host, port, endpoint },
    });
    console.error(`Shodan MCP server listening on ${host}:${port} at ${endpoint}`);
  } else {
    await server.start({ transportType: "stdio" });
  }
}

main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  process.exit(1);
});
