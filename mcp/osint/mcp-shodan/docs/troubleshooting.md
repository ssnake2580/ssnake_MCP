# Troubleshooting

## 401 errors or "Invalid API key"

1. Copy the key from your [Shodan account page](https://account.shodan.io/). It is 32 characters, with no spaces or quotes around it.
2. After changing client config, save it and restart the client.
3. Test the key outside the server:

    ```sh
    curl "https://api.shodan.io/api-info?key=$SHODAN_API_KEY"
    ```

    This shows your plan and remaining query credits.

## 403 errors or "Access denied" from `shodan_search`

Search filters (`country:`, `port:`, `product:` and so on) need a Shodan membership or paid API plan, and each filtered search costs one query credit. Ask the agent to run `api_info` to see your plan and remaining credits. On a free account, `ip_lookup`, `dns_lookup`, `reverse_dns_lookup` and the CVE tools still work.

## Running out of query credits

`shodan_search` (with filters or past page 1) and `domain_info` spend credits. `shodan_count` gives totals and breakdowns for free; use it first, then search only for the hosts you need.

## 429 errors or rate limiting

Shodan allows about one request per second. Agents that fire many lookups in parallel can hit this; ask the agent to run lookups one at a time, or retry after a moment.

## `ip_lookup` says "No information available"

Shodan hasn't scanned that address, or it has nothing open. That is a normal result, not a server fault.

## Very large `cves_by_product` or `cpe_lookup` responses

The default `limit` is 1000. Use `count: true` first, then set `limit` to a small number and page with `skip`.

## The client doesn't list the tools

- Run `npx -y @burtthecoder/mcp-shodan` in a terminal. A missing `SHODAN_API_KEY` or an old Node (below 20) fails at startup with a clear error.
- Desktop clients may not inherit your shell `PATH`. Use the absolute path to `npx` or `node`.

## HTTP mode in Docker isn't reachable

The image binds to `0.0.0.0` inside the container. Publish the port with `-p 127.0.0.1:3000:3000` and set `-e MCP_TRANSPORT=httpStream`. `curl http://127.0.0.1:3000/health` should return `200`.
