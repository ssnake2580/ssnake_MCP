# Changelog

## 2026-09-30

- Maximalize hardening graft: nuclei destructive gate (`confirm: true` required), heavy-scan 2-slot semaphore (naabu/nuclei/shuffledns), startup binary check

- Estate-hardened fork: absolute binary paths (`PD_TOOLS_DIR`/`SHUFFLEDNS_BIN`/`PD_<NAME>_BIN`), no-shell timeout-guarded runner, input validation at every tool boundary
- New tools: `tlsx` (TLS probing), `shuffledns` (active subdomain brute-force with wordlist)
- `naabu`: `scanType` param (`"c"` connect scan default, `"s"` SYN scan)
- `nuclei`: `-id` template selection, `-duc` always on, findings no longer reported as errors
- `httpx`: `screenshot` flag replaced with `techDetect` (wappalyzer)
- `driver.ts`: verification driver — `tools/list` + one live `tools/call` per binary, exits non-zero on failure

## Earlier

- Configurable rate limiting
- Upstream baseline: `intelligent-ears/pd-tools-mcp`
