import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";

export function registerApiInfo(server: FastMCP) {
  server.addTool({
    name: "api_info",
    description:
      "Show the Shodan API plan, remaining query and scan credits, monitored IPs, and usage limits for the configured API key. Free: does not consume credits.",
    parameters: z.object({}),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async () => {
      const r = await queryShodan("/api-info", {});
      return JSON.stringify(
        {
          Plan: r.plan ?? "Unknown",
          "Query Credits": r.query_credits ?? "Unknown",
          "Scan Credits": r.scan_credits ?? "Unknown",
          "Monitored IPs": r.monitored_ips ?? "Unknown",
          "Usage Limits": r.usage_limits ?? {},
          Unlocked: r.unlocked ?? "Unknown",
          "Unlocked Left": r.unlocked_left ?? "Unknown",
          HTTPS: r.https ?? "Unknown",
          Telnet: r.telnet ?? "Unknown",
        },
        null,
        2
      );
    },
  });
}
