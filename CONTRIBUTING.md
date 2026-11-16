# Contributing

Thanks for helping! Issues and pull requests are welcome in English or
Spanish.

## Principles

- **False positives are worse than misses.** A visitor wrongly blocked is a
  real person or a useful crawler hurt. New signals must be explainable and
  must never, on their own, produce `trapped`.
- **Detection, not punishment.** Telaraña reports a verdict; proxies and
  dedicated tools act on it.
- **Small and dependency-free.** The standard library is enough so far. Adding
  a dependency needs a good reason.

## Development

Go 1.23+ (or Docker: `scripts/go.sh <go args>` runs the toolchain in a
container).

```sh
go test -race ./...          # unit and HTTP tests
go vet ./...
gofmt -l .                   # must print nothing
scripts/e2e.sh nginx         # end to end through a real proxy (needs Docker)
scripts/e2e.sh caddy
scripts/e2e.sh traefik
```

CI runs all of the above, plus `staticcheck` and `govulncheck`, on every pull
request.

## Pull requests

1. Open an issue first for anything beyond a small fix, so we can agree on the
   approach.
2. Add tests: behaviour changes need a test that fails without your change.
   Integration changes need `scripts/e2e.sh` to pass.
3. Update the README (both languages if you can; otherwise say so and someone
   will translate) and the `Unreleased` section of the changelog.
4. Keep commits focused, with messages that explain why.

## Releases (maintainers)

Update `CHANGELOG.md`, then tag: `git tag -a v1.2.3 -m v1.2.3 && git push origin v1.2.3`.
The release workflow publishes binaries and the `ghcr.io/vlorcap1/telarana`
image.
