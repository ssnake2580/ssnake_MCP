# Contributing

Thanks for taking a look. Issues and pull requests are welcome.

## Getting set up

```sh
npm install
npm test
npm run build
```

To try your build against a real MCP host, point the host's config at the built entrypoint:

```json
{
  "mcpServers": {
    "securitytrails-dev": {
      "command": "node",
      "args": ["/absolute/path/to/securitytrails-mcp/dist/index.js"],
      "env": { "SECURITYTRAILS_API_KEY": "your_key" }
    }
  }
}
```

Or drive it without a host at all: `npm run inspect`.

`npm test` needs no API key — the HTTP layer is stubbed. Please keep it that way, so contributors
without a paid SecurityTrails plan can still run the full suite.

## Layout

| Path              | Responsibility                                                          |
| ----------------- | ----------------------------------------------------------------------- |
| `src/client.ts`   | HTTP, timeout, retry, and turning status codes into actionable messages |
| `src/schemas.ts`  | Reusable Zod schemas and host normalisation                             |
| `src/markdown.ts` | Generic Markdown primitives and timestamp handling                      |
| `src/render.ts`   | One Markdown renderer per response shape                                |
| `src/result.ts`   | Wrapping handlers, applying `response_format`, error results            |
| `src/tools/`      | Tool registration, grouped by resource                                  |

## Adding a tool

1. Add the handler to the relevant module in `src/tools/`.
2. Register the name in `TOOL_NAMES` in `src/tools/index.ts` — a test asserts that list and the
   registered tools stay in sync.
3. Include `response_format: ResponseFormatSchema` in the input schema. A test asserts every tool
   accepts it.
4. Wrap the handler in `safe()`, or `safeStructured()` if it declares an `outputSchema`.
5. Reuse `DomainSchema` / `IPv4Schema` / `PageSchema` rather than a loose `z.string()`. Rejecting
   bad input locally costs the user nothing; a bad request costs them a query from their monthly
   allowance.
6. Add a renderer in `src/render.ts`, or pass `renderRecords` if the payload is a plain
   `{ records: [...] }` list.
7. Add the tool to the table in `README.md`, including its plan tier.

## Writing a renderer

Renderers return `string | undefined`. **Return `undefined` when the payload is not the shape you
expect** — the caller then falls back to raw JSON. Never render a partial document: a rendering
gap should cost tokens, never data. A test asserts this fallback holds.

Two things to watch:

- **Timestamps arrive in mixed units.** A single `search_domains` record carries
  `whois.createdDate` in milliseconds and `first_seen` in seconds. Always use `asDate()`, which
  infers the unit — a naive `value * 1000` renders 1995 dates as the year 27400.
- **Zero is meaningful.** `bit_length: 0` means "unknown", but `sites: 0` is a real count. `cell()`
  preserves `0` and `false`; only `null`, `undefined` and `''` become a dash.

## Tool descriptions

The description is the only documentation the model gets. Say precisely what the tool returns and
what it does not — an overstated description is worse than a terse one, because the model will
call the tool expecting data that never arrives. If an endpoint is plan-gated, say so in the
description; that turns a repeated 403 into a single informed decision.

## Deliberate deviations from the MCP best-practice guidance

Both are intentional. Please don't "fix" them without discussion:

- **Subdomain page size defaults to 100, not the suggested 20–50.** SecurityTrails returns the
  entire subdomain set in one billed query, so paging costs a further query rather than being
  free. A larger default resolves most domains in a single call.
- **The API key is not validated on startup.** Doing so would spend a query every time a host
  restarts the server. It is validated by first use instead, and a missing key is reported at
  startup on stderr and in every tool result.

## Style

Formatting is handled by Prettier — don't hand-align anything.

```sh
npm run format        # rewrite files in place
npm run format:check  # verify without writing (this is what CI runs)
```

Before pushing:

```sh
npm run typecheck && npm run format:check && npm test
```

CI runs all three plus the build on Node 20, 22 and 24, and verifies the published tarball
contents. An `.editorconfig` is included so most editors pick up the indent settings
automatically.
