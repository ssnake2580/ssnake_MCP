# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-09-26

### Added

- Add Claude Code plugin manifest

### Fixed

- scapy-mcp: Enforce pcap byte cap and AsyncSniffer fallback
- scapy-mcp: Make the published wheel actually start the server

### Removed

- docs+code: drop Bodai/Vishnu references from source comments

### Documentation

- Add docs/assets/images/ + .scratch/ convention
- Drop Bodai integration framing and add substrate note
- scapy-mcp: Rewrite README to match archive-org/medium convention
- Update FastMCP badge URL to PrefectHQ org (canonical since v3.0 GA)

### Internal

- deps: Bump mcp-common floor to >=0.26.0,<0.27.0 (Phase 2.5)
- plugin: Rebadge from Bodai + drop stale dev comment
- scapy-mcp: Add Bodai .gitignore snippet
- scapy-mcp: Pre-bump fix (httpx2 to dev deps, mdformat)
- scapy-mcp: Refresh uv.lock for mcp-common 0.30.1

## [0.1.1] - 2026-09-08

### Added

- auth: Wire BearerTokenMiddleware into Runtime lifespan
- Call validate_auth_config at startup
- scapy-mcp: Capture start/stop/read with /dev/bpf\* probe
- scapy-mcp: Craft + dissect tools with malformed-input typed errors
- scapy-mcp: Deterministic PCAP fixture generator + 6 fixtures
- scapy-mcp: Emission controller (4 controls + probe cap) and LayerSpec union
- scapy-mcp: Feed registry (3 required, 2 optional) and wiring-discipline signals
- scapy-mcp: Initialize git repo, flat layout, packaging test
- scapy-mcp: Pcap read/write with path-containment guard
- scapy-mcp: ScapySettings with all §13.4 keys
- scapy-mcp: Server.py with profile-gated transmit, /readyz, baseline tools
- scapy-mcp: Transmit + probe tools, four-control + probe-target gate
- scapy-mcp: Typed exception hierarchy

### Fixed

- scapy-mcp: Cli hosts build_asgi_app via uvicorn so /readyz route mounts
- scapy-mcp: Env_nested_delimiter for nested AuthConfig env vars
- scapy-mcp: Phase 1 prep — gitignore fixtures, server __main__ guard

### Testing

- scapy-mcp: Per-tool e2e tests; transmit asserts refusal
- scapy-mcp: Phase 0b known-layers gate for http_get fixture

### Internal

- scapy-mcp: README, ratchet coverage to 85, e2e + capture/transmit extras
- scapy-mcp: Satisfy crackerjack gate for flat layout
