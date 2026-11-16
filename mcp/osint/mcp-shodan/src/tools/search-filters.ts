import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";

export function registerSearchFilters(server: FastMCP) {
  server.addTool({
    name: "search_filters",
    description:
      "List the search filters and facets Shodan supports. Use this to build valid shodan_search and shodan_count queries and facets. Free: does not consume credits.",
    parameters: z.object({}),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async () => {
      const [filters, facets] = await Promise.all([
        queryShodan("/shodan/host/search/filters", {}),
        queryShodan("/shodan/host/search/facets", {}),
      ]);
      const f: string[] = Array.isArray(filters) ? [...filters].sort() : [];
      const c: string[] = Array.isArray(facets) ? [...facets].sort() : [];
      return JSON.stringify(
        {
          Filters: { Count: f.length, Names: f },
          Facets: { Count: c.length, Names: c },
        },
        null,
        2
      );
    },
  });
}
