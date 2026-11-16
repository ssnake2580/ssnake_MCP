import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";

const HOSTNAME_REGEX =
  /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;

interface DomainRecord {
  subdomain?: string;
  type?: string;
  value?: string;
  last_seen?: string;
  ports?: number[];
}

export function registerDomainInfo(server: FastMCP) {
  server.addTool({
    name: "domain_info",
    description:
      "Get subdomains and DNS records for a domain from Shodan. Costs 1 query credit per lookup.",
    parameters: z.object({
      domain: z
        .string()
        .regex(HOSTNAME_REGEX, "Invalid domain name.")
        .describe("The domain to look up, e.g. example.com."),
      history: z
        .boolean()
        .optional()
        .default(false)
        .describe("Include historical DNS data."),
      type: z
        .enum(["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"])
        .optional()
        .describe("Only return DNS records of this type."),
      page: z
        .number()
        .int()
        .min(1)
        .optional()
        .default(1)
        .describe("Result page number."),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const params: Record<string, any> = {};
      if (args.history) params.history = true;
      if (args.type) params.type = args.type;
      if (args.page > 1) params.page = args.page;

      const result = await queryShodan(
        `/dns/domain/${encodeURIComponent(args.domain)}`,
        params
      );

      const subdomains: string[] = result.subdomains || [];
      const records: DomainRecord[] = result.data || [];

      return JSON.stringify(
        {
          Domain: result.domain || args.domain,
          Tags: result.tags || [],
          Subdomains: { Count: subdomains.length, Names: subdomains },
          "DNS Records": records.map((r) => ({
            Subdomain: r.subdomain || "@",
            Type: r.type,
            Value: r.value,
            "Last Seen": r.last_seen,
          })),
          "More Results": result.more
            ? `Yes — request page ${args.page + 1}`
            : "No",
        },
        null,
        2
      );
    },
  });
}
