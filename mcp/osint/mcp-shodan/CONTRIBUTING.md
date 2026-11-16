# Contributing to mcp-shodan

## Development setup

Requires Node.js 20 or later.

```sh
git clone https://github.com/w0h1v/mcp-shodan && cd mcp-shodan
npm ci
npm test
```

Run the server against your own MCP client with `node build/index.js` and `SHODAN_API_KEY` set. `npm run dev` rebuilds on change, and `npx fastmcp dev build/index.js` gives an interactive tool tester.

## Checks

Before opening a pull request:

1. `npm test` passes (TypeScript strict build, then the unit tests in `tests/`). No API key or network is needed; tests mock the Shodan API.
2. If you changed an API call or a tool's output, try it against the real API with your own key.
3. `npm audit --omit=dev --audit-level=high` is clean.

## Guidelines

- **Treat tool input as hostile.** Validate new parameters in the tool's zod schema. Never interpolate unvalidated input into a request path.
- **One file per tool.** Tools live in `src/tools/` and register themselves from `src/index.ts`; shared API calls live in `src/helpers.ts`.
- **Add a test for new behaviour.** See `tests/` for the fake-server and mocked-HTTP pattern.
- **Keep docs in step with code.** Update the README, `docs/` and `CHANGELOG.md` when tools, parameters or requirements change.
- **No secrets or private data.** Use public targets (for example 8.8.8.8) in code, docs, tests and issues.

## Pull requests

Keep changes focused, fill in the pull request template, and describe how you tested.

## Security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By contributing, you agree that your contribution is licensed under the MIT license.
