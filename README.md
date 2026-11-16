# Telaraña

[![CI](https://github.com/vlorcap1/telarana/actions/workflows/ci.yml/badge.svg)](https://github.com/vlorcap1/telarana/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Trap-based bot detection for your reverse proxy.**
[Leer en español](README.es.md)

Telaraña (Spanish for *spider web*) catches crawlers that read your
`robots.txt` and go exactly where it tells them not to, or that follow links
no human can see. It plugs into nginx, Caddy or Traefik as a forward-auth
service and tells your proxy, per request, whether the visitor is `clean`,
`suspect` or `trapped`. Your proxy decides what to do.

- **Low false positives by design.** Every visitor gets its own signed trap
  paths. A human never requests them; a compliant crawler never does either.
  Search engines verified by DNS are never penalised.
- **Explainable.** Every verdict comes with a score and the reasons behind it,
  in response headers, logs and metrics.
- **Safe to roll out.** Starts in observe-only mode. With nginx, a Telaraña
  outage never takes your site down (fail-open).
- **Small and self-hosted.** A single static Go binary (14 MB container
  image), no dependencies, no data sent anywhere.

## How it works

```
                     ┌────────────────────────────────────────────┐
  visitor ──► proxy ─┤ /robots.txt, /restricted/*  ──► Telaraña    │
                     │ everything else: ask /check ──► Telaraña    │
                     │      verdict headers ◄───────┘              │
                     │ then serve, block, or route ──► your site   │
                     └────────────────────────────────────────────┘
```

1. **robots.txt traps.** Telaraña serves your `robots.txt` with your own rules
   plus a `Disallow` for the trap area and three tempting paths
   (`/restricted/db-dump.sql-3f9a…`) that are unique to each visitor and signed
   with HMAC.
2. **Double door.** The first request to a trap returns a believable decoy page
   that links to a second trap. A curious human who typed a path from
   `robots.txt` stops there (verdict `suspect`); a crawler that follows every
   link requests the second one and is `trapped`.
3. **Shared-list detection.** A trap path signed for a *different* address
   means the crawler got it from somewhere else (shared or replayed crawl
   lists): `trapped` immediately.
4. **Link trap (optional).** Add a hidden link to the trap area in your pages,
   e.g. `<a href="/restricted/archive" hidden>archive</a>`. It is invisible to
   people and screen readers, disallowed for compliant crawlers, and catches
   link-following scrapers that never read `robots.txt`.
5. **Verdicts.** On every `/check`, Telaraña combines trap state with softer
   signals (claimed search engine that fails DNS verification, request rate,
   HTTP-library User-Agent) into a score. Only traps can produce `trapped`.

A visitor is the pair *address + User-Agent* (IPv6 addresses grouped by /64),
so a bot caught behind a shared IP (office, university, mobile carrier) does
not drag its neighbours with it.

## Where it fits

Telaraña is a **detection signal**, not a complete defence. It complements:

| Tool | What it does | With Telaraña |
|---|---|---|
| Challenges (e.g. Anubis) | Proof-of-work to slow down mass scraping | Send only `suspect`/`trapped` visitors to the challenge instead of everyone |
| Tarpits (e.g. Iocaine, Nepenthes) | Feed bots endless generated content | Route `trapped` visitors there |
| Rate limiting | Caps request volume | Catches the slow, polite-looking crawler that rate limits miss |
| Hosted bot management (e.g. Cloudflare) | Global reputation and ML | A self-hosted, explainable signal under your control |

What it does **not** catch: a bot that never reads `robots.txt` and never
follows a trap link. Pair it with rate limiting or a challenge for those.

## Quick start

Requires Docker. This runs nginx in front of a sample app that echoes the
headers it receives:

```sh
git clone https://github.com/vlorcap1/telarana && cd telarana/examples/nginx
export TELARANA_SECRET=$(openssl rand -hex 32)
docker compose up --build
```

Then, in another terminal:

```sh
curl -s localhost:8080/ | grep -i telarana          # X-Telarana-Verdict: clean
curl -s localhost:8080/robots.txt                   # your rules + trap paths
curl -s localhost:8080/restricted/db-dump.sql       # decoy page
```

## Integrations

Complete, tested configurations are in [`examples/`](examples). Each one is
exercised end to end in CI by [`scripts/e2e.sh`](scripts/e2e.sh).

| Proxy | Mechanism | Example | If Telaraña is down |
|---|---|---|---|
| nginx | `auth_request` | [examples/nginx](examples/nginx) | **Fail-open** (site keeps working; verdict `unavailable`) |
| Caddy | `forward_auth` | [examples/caddy](examples/caddy) | Requests fail (502) |
| Traefik | `ForwardAuth` middleware | [examples/traefik](examples/traefik) | Requests fail |

With Caddy and Traefik, run Telaraña with a restart policy and its health
check, and monitor it like any other dependency of your site.

In every case the proxy must:

1. Send `/robots.txt` and the trap area (`/restricted`, `/restricted/*`) to
   Telaraña, passing the client address in `X-Forwarded-For`.
2. Ask `/check` before serving anything else, passing the original path in
   `X-Original-URI` (nginx) or `X-Forwarded-Uri` (Caddy, Traefik, automatic).

## Verdicts

`/check` always answers with these headers:

| Header | Example | Meaning |
|---|---|---|
| `X-Telarana-Verdict` | `clean`, `verified-bot`, `suspect`, `trapped` | The verdict |
| `X-Telarana-Score` | `0`–`100` | 100 only for confirmed traps |
| `X-Telarana-Reasons` | `trap:first-hit,ua:tool` | Why |

| Reason | Points | |
|---|---|---|
| `trap:repeat` / `trap:shared` | — | Confirmed: verdict `trapped`, score 100 |
| `trap:first-hit` | 60 | Requested one trap (the decoy) |
| `goodbot:impostor` | 50 | Claims to be a search engine; DNS says otherwise |
| `rate:high` | up to 30 | Above `TELARANA_RATE_MAX` requests per window |
| `ua:tool` | 15 | Empty or HTTP-library User-Agent (curl, python-requests…) |
| `goodbot:verified` | — | DNS-verified search engine: never penalised |

A score of `TELARANA_SUSPECT_SCORE` (default 50) or more is `suspect`. Rate and
User-Agent together reach 45 at most, so a fast `curl` script alone is never
suspect.

The status code is `200` except in `enforce` mode for `trapped` visitors, which
get `TELARANA_ENFORCE_STATUS` (default `403`). Suspects are always `200`: route
them with the verdict header if you want (for example, to a challenge).

## Rolling out

1. **Observe** (default). Deploy, then watch `visitor trapped` log lines,
   the `X-Telarana-Verdict` in your access logs and the metrics for a week or
   two. Check who is trapped.
2. **Add your crawlers.** If a crawler you care about shows up as an impostor,
   or verifies by IP lists rather than DNS, see `TELARANA_GOOD_BOTS`.
3. **Enforce.** Set `TELARANA_MODE=enforce`, or keep observing and act on the
   verdict header in your proxy (route `trapped` to a tarpit, `suspect` to a
   challenge).

## Configuration

All configuration is through environment variables. Invalid values stop the
program with a message that lists every problem.

| Variable | Default | Description |
|---|---|---|
| `TELARANA_SECRET` | *(required)* | At least 32 characters. Signs trap paths. `openssl rand -hex 32` |
| `TELARANA_SECRET_PREVIOUS` | | Previous secret, still accepted for trap paths while rotating |
| `TELARANA_MODE` | `observe` | `observe` or `enforce` |
| `TELARANA_ENFORCE_STATUS` | `403` | Status for `trapped` visitors in enforce mode (400–599) |
| `TELARANA_TRAP_PREFIX` | `/restricted` | Trap area. Pick something plausible that your site does not use |
| `TELARANA_ROBOTS_FILE` | | Your site's `robots.txt`, served before the trap rules |
| `TELARANA_TRUSTED_PROXIES` | loopback + private ranges | Comma-separated IPs/CIDRs allowed to set `X-Forwarded-For` |
| `TELARANA_GOOD_BOTS` | | Extra DNS-verifiable crawlers: `name:.domain1\|.domain2;name2:.domain3` |
| `TELARANA_SUSPECT_SCORE` | `50` | Score at which a visitor becomes `suspect` |
| `TELARANA_RATE_MAX` | `60` | Requests per window before `rate:high` |
| `TELARANA_RATE_WINDOW` | `10s` | Rate window |
| `TELARANA_VISITOR_TTL` | `24h` | Idle time after which a visitor is forgotten |
| `TELARANA_MAX_VISITORS` | `100000` | Memory cap for tracked visitors |
| `TELARANA_DNS_TIMEOUT` | `2s` | Timeout for crawler verification |
| `TELARANA_LISTEN` | `:8080` | Public listener (behind your proxy) |
| `TELARANA_ADMIN_LISTEN` | `:9090` | Metrics and health; `off` to disable. Keep it private |
| `TELARANA_LOG_LEVEL` | `info` | `debug` logs every non-clean check |
| `TELARANA_LOG_FORMAT` | `json` | `json` or `text` |

Built-in verified crawlers: Googlebot, Bingbot, Applebot and YandexBot. Only
crawlers that document reverse-DNS verification belong in this list; one that
publishes IP ranges instead would be wrongly flagged as an impostor.

## Operations

- **Health:** `GET /healthz` on both listeners; `telarana healthcheck` for
  container health checks (used by the image).
- **Metrics:** `GET /metrics` on the admin listener, Prometheus format:
  `telarana_checks_total{verdict}`, `telarana_trap_hits_total{kind}`,
  `telarana_trapped_total{cause}`, `telarana_robots_served_total`,
  `telarana_goodbot_verifications_total{result}`,
  `telarana_enforcements_total`, `telarana_visitors_tracked`.
- **Logs:** structured JSON on stdout. `trap hit` and `visitor trapped`
  include address, User-Agent and path.
- **Secret rotation:** set the new value in `TELARANA_SECRET` and the old one in
  `TELARANA_SECRET_PREVIOUS`, restart, and remove the old one a day later.
- **State:** kept in memory, per instance. Run a single instance, or route each
  client to the same instance. A shared backend is on the roadmap.

## Security notes

- **Never let a shared cache store `/robots.txt`.** Its content differs per
  visitor; Telaraña sends `Cache-Control: private, no-store`. If a CDN sits in
  front, make sure it honours that header or bypasses that path.
- **Trusted proxies.** `X-Forwarded-For` is only believed from
  `TELARANA_TRUSTED_PROXIES`, walking the chain from the right. Do not expose
  Telaraña directly to the internet; keep the admin port private.
- **Decoys.** The decoy page and trap responses never contain real data.

## Responsible use

Use Telaraña on infrastructure you operate. It is built to defend sites without
closing off the open web: it never penalises verified search engines, keeps
trap paths out of reach of people and compliant crawlers, and starts in
observe mode. Review who you trap, and remember that research crawlers,
archives and accessibility tools crawl too.

## Building from source

Go 1.23 or later:

```sh
go build -o telarana ./cmd/telarana
TELARANA_SECRET=$(openssl rand -hex 32) ./telarana
```

No Go installed? `scripts/go.sh` runs the toolchain in Docker
(`scripts/go.sh test ./...`).

## Project status

Version 1 is a rewrite in Go of an earlier Python prototype (kept as
[v0.1.0](https://github.com/vlorcap1/telarana/releases/tag/v0.1.0)). See the
[changelog](CHANGELOG.md). Contributions are welcome: read
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
