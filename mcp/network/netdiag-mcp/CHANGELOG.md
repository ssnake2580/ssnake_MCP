# Changelog

## [0.8.1](https://github.com/shigechika/netdiag-mcp/compare/v0.8.0...v0.8.1) (2026-10-26)


### Bug Fixes

* **deps:** bump certifi and opentelemetry-api (security) ([#26](https://github.com/shigechika/netdiag-mcp/issues/26)) ([5f3c73a](https://github.com/shigechika/netdiag-mcp/commit/5f3c73a3886ae17a97a3043e8be4d4e1a5033489))

## [0.8.0](https://github.com/shigechika/netdiag-mcp/compare/v0.7.0...v0.8.0) (2026-10-12)


### Features

* optional per-prefix Authorization header for http_get (NETDIAG_HTTP_AUTH) ([#22](https://github.com/shigechika/netdiag-mcp/issues/22)) ([3529eda](https://github.com/shigechika/netdiag-mcp/commit/3529eda02d29ef09123c038da96a527d5fc1effc))

## [0.7.0](https://github.com/shigechika/netdiag-mcp/compare/v0.6.1...v0.7.0) (2026-09-29)


### Features

* require mcp 2.x (MCPServer) and drop 1.x support ([#19](https://github.com/shigechika/netdiag-mcp/issues/19)) ([f983ad9](https://github.com/shigechika/netdiag-mcp/commit/f983ad9a422a532684da2962d19547b942d86e6b))

## [0.6.1](https://github.com/shigechika/netdiag-mcp/compare/v0.6.0...v0.6.1) (2026-09-16)


### Bug Fixes

* **smoke:** current_time probe must waive the row count (flat dict, no list) ([#16](https://github.com/shigechika/netdiag-mcp/issues/16)) ([9d0f06f](https://github.com/shigechika/netdiag-mcp/commit/9d0f06f16723b01dbd7c635befa58831f59f5295))

## [0.6.0](https://github.com/shigechika/netdiag-mcp/compare/v0.5.0...v0.6.0) (2026-09-11)


### Features

* add http_get to return a response body ([#14](https://github.com/shigechika/netdiag-mcp/issues/14)) ([6bd0356](https://github.com/shigechika/netdiag-mcp/commit/6bd03569ceffa380d00df380bc33d6acf9ab47fd))

## [0.5.0](https://github.com/shigechika/netdiag-mcp/compare/v0.4.0...v0.5.0) (2026-09-09)


### Features

* add current_time so nobody has to calculate a weekday ([#13](https://github.com/shigechika/netdiag-mcp/issues/13)) ([2e612b2](https://github.com/shigechika/netdiag-mcp/commit/2e612b2e62027f1145899c7e793c445434d632bb))


### Bug Fixes

* set explicit TLS minimum version in tls_cert_check ([#11](https://github.com/shigechika/netdiag-mcp/issues/11)) ([41cf6cd](https://github.com/shigechika/netdiag-mcp/commit/41cf6cdaf5a005cbbaadff1c7c6d7d2bb76ddf3f))

## [0.4.0](https://github.com/shigechika/netdiag-mcp/compare/v0.3.0...v0.4.0) (2026-08-20)


### Features

* package the server as a Claude Code plugin ([#7](https://github.com/shigechika/netdiag-mcp/issues/7)) ([9d56cfa](https://github.com/shigechika/netdiag-mcp/commit/9d56cfa73144765ca6d6e7b64b4cca2ebb793be6))

## [0.3.0](https://github.com/shigechika/netdiag-mcp/compare/v0.2.0...v0.3.0) (2026-08-19)


### Features

* add live smoke test (scripts/smoke_test.py) ([#5](https://github.com/shigechika/netdiag-mcp/issues/5)) ([1f78da7](https://github.com/shigechika/netdiag-mcp/commit/1f78da7200d14ffcfb4963b2412850c9713c7361))

## [0.2.0](https://github.com/shigechika/netdiag-mcp/compare/v0.1.0...v0.2.0) (2026-08-19)


### Features

* add DNS-over-TLS and DNS-over-HTTPS support to dns_lookup/dnssec_check ([61d10b4](https://github.com/shigechika/netdiag-mcp/commit/61d10b497fb4521f98ad008a543fd4c7ffd637e9))
* initial netdiag-mcp scaffold ([62ecbdf](https://github.com/shigechika/netdiag-mcp/commit/62ecbdfe3048279239f50264d92f3f98d8dfc8f8))


### Bug Fixes

* ping_host deadline handling, IPv6 ping on macOS; add asn_lookup ([624a055](https://github.com/shigechika/netdiag-mcp/commit/624a055b0e024638f118ae2460244732cf893fab))
* use [project.optional-dependencies] instead of [dependency-groups] ([#3](https://github.com/shigechika/netdiag-mcp/issues/3)) ([0e56227](https://github.com/shigechika/netdiag-mcp/commit/0e562277b6aaf87cf80a87840c6d8adcadbc51a6))
