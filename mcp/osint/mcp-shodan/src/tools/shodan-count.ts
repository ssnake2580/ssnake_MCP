import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan, facetsSchema, formatFacets } from "../helpers.js";
import type { ShodanFacets } from "../types.js";

export function registerShodanCount(server: FastMCP) {
  server.addTool({
    name: "shodan_count",
    description:
      "Get the total number of Shodan results for a query, with optional facet breakdowns (e.g. by country, org, port). Free: does not consume query credits. Use search_filters to list valid filters and facets.",
    parameters: z.object({
      query: z.string().describe("Search query for Shodan."),
      facets: facetsSchema
        .optional()
        .describe(
          "Comma-separated facets, optionally with a count, e.g. 'country:10,org,port'."
        ),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const result: { total?: number; facets?: ShodanFacets } = await queryShodan(
        "/shodan/host/count",
        { query: args.query, ...(args.facets ? { facets: args.facets } : {}) }
      );

      return JSON.stringify(
        {
          "Search Summary": { Query: args.query, "Total Results": result.total ?? 0 },
          Facets: formatFacets(result.facets, result.total),
        },
        null,
        2
      );
    },
  });
}
