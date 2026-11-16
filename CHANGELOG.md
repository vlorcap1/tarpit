# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Complete rewrite in Go, focused on detection. Telaraña is now a forward-auth
  service for nginx (`auth_request`), Caddy (`forward_auth`) and Traefik
  (`ForwardAuth`) that reports a verdict (`clean`, `verified-bot`, `suspect`,
  `trapped`) with a score and reasons. The proxy decides what to do.

### Added
- Per-visitor HMAC-signed robots.txt traps, double-door decoy, detection of
  trap paths shared between addresses, and an optional hidden link trap.
- Visitors keyed by address + User-Agent (IPv6 grouped by /64).
- Background forward-confirmed reverse-DNS verification of search engines;
  verified crawlers are never penalised.
- `observe` (default) and `enforce` modes; secret rotation.
- Trusted-proxy handling of `X-Forwarded-For`.
- Prometheus metrics and health on a separate admin listener; JSON logs.
- Tested integration examples and end-to-end tests for nginx (fail-open),
  Caddy and Traefik.
- Container image (distroless, non-root) and multi-platform binaries.

### Removed
- The learning model, proof-of-work, drip-fed maze, compressed-response
  payload and self-play simulation of v0.1.0. Challenges and tarpits are left
  to dedicated tools; route to them with the verdict header.

## [0.1.0] - 2026-11-15

Educational prototype in Python (aiohttp): robots.txt traps, online learning
model, proof-of-work, drip-fed maze and self-play simulation.

[Unreleased]: https://github.com/vlorcap1/telarana/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vlorcap1/telarana/releases/tag/v0.1.0
