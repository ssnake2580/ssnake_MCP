# Contributing to pd-mcp 🔭

## The contract

- **No shell spawns.** Every executor goes through `src/tools/runner.ts`. `execFile`, never `exec`.
- **Every new tool gets**: zod input validation at the boundary, a timeout in the runner, and a `driver.ts` case that proves it live.
- **Binary resolution**: absolute paths via `PD_TOOLS_DIR` / `PD_<NAME>_BIN` — never `$PATH` guessing.

## Workflow

```sh
bun install
bun src/index.ts    # iterate against the stdio server
bun driver.ts       # full verification — must exit 0
```

Keep commits small and imperative: `httpx: add techDetect flag`.
