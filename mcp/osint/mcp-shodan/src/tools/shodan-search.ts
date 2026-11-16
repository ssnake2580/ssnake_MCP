import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan, facetsSchema, formatFacets, sortedCveIds } from "../helpers.js";
import type { SearchResponse } from "../types.js";

export function registerShodanSearch(server: FastMCP) {
  server.addTool({
    name: "shodan_search",
    description:
      "Search Shodan's database of internet-connected devices. Returns detailed information about matching devices including services, vulnerabilities, and geographic distribution. Supports advanced search filters and returns facet statistics (default: by country). Costs 1 query credit when the query uses filters, plus 1 per page beyond the first. Use shodan_count (free) to get totals and facets without results.",
    parameters: z.object({
      query: z.string().describe("Search query for Shodan."),
      max_results: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .default(10)
        .describe("Maximum results to return (1-100; one Shodan page)."),
      page: z
        .number()
        .int()
        .min(1)
        .optional()
        .default(1)
        .describe("Result page number (100 results per page). Pages past the first cost 1 query credit each."),
      facets: facetsSchema
        .optional()
        .default("country")
        .describe(
          "Comma-separated facets for summary statistics, optionally with a count, e.g. 'country:10,org,port'. Use search_filters to list valid facets."
        ),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const result: SearchResponse = await queryShodan(
        "/shodan/host/search",
        {
          query: args.query,
          facets: args.facets,
          ...(args.page > 1 ? { page: args.page } : {}),
        }
      );

      const matches = (result.matches || []).slice(0, args.max_results);

      const formattedResult = {
        "Search Summary": {
          Query: args.query,
          "Total Results": result.total,
          "Results Returned": matches.length,
          Page: args.page,
        },
        Facets: formatFacets(result.facets, result.total),
        ...(result.facets?.country
          ? {
              "Country Distribution": result.facets.country.map((country) => ({
                Country: country.value,
                Count: country.count,
                Percentage: `${(result.total > 0 ? (country.count / result.total) * 100 : 0).toFixed(2)}%`,
              })),
            }
          : {}),
        Matches: matches.map((match) => {
          const vulns = sortedCveIds(match.vulns);
          return {
          "Basic Information": {
            "IP Address": match.ip_str,
            Organization: match.org,
            ISP: match.isp,
            ASN: match.asn,
            "Last Update": match.timestamp,
          },
          Location: {
            Country: match.location?.country_name,
            City: match.location?.city || "Unknown",
            Region: match.location?.region_code || "Unknown",
            Coordinates: `${match.location?.latitude}, ${match.location?.longitude}`,
          },
          "Service Details": {
            Port: match.port,
            Transport: match.transport,
            Product: match.product || "Unknown",
            Version: match.version || "Unknown",
            CPE: match.cpe || [],
          },
          "Web Information": match.http
            ? {
                Server: match.http.server,
                Title: match.http.title,
                "Robots.txt": match.http.robots ? "Present" : "Not found",
                Sitemap: match.http.sitemap ? "Present" : "Not found",
              }
            : "No HTTP information",
          OS: match.os || "Unknown",
          ...(vulns.length ? { Vulnerabilities: vulns } : {}),
          Hostnames: match.hostnames,
          Domains: match.domains,
          };
        }),
      };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
