#!/usr/bin/env bash
# End-to-end test of an integration example, in enforce mode.
# Usage: scripts/e2e.sh nginx|caddy|traefik
set -euo pipefail

name=${1:?usage: scripts/e2e.sh nginx|caddy|traefik}
dir="$(cd "$(dirname "$0")/.." && pwd)/examples/$name"
project="telarana-e2e-$name"
port=${PORT:-18080}
base="http://127.0.0.1:$port"
browser="Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
other="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15"

export TELARANA_SECRET=${TELARANA_SECRET:-$(openssl rand -hex 32)}
export TELARANA_MODE=enforce PORT=$port
compose() { docker compose -p "$project" -f "$dir/docker-compose.yml" "$@"; }

pass=0
fail=0
ok()  { echo "  ok   $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }
expect() { # description, condition...
  local d=$1; shift
  if "$@"; then ok "$d"; else bad "$d"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' -A "${2:-$browser}" "$base$1"; }
body()   { curl -s -A "${2:-$browser}" "$base$1"; }

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== $name: starting"
compose up -d --build --quiet-pull >/dev/null 2>&1 || { compose logs; exit 1; }
for _ in $(seq 1 60); do
  [ "$(status /)" = "200" ] && break
  sleep 1
done

echo "== $name: checks"
home=$(body /)
expect "a browser reaches the site" grep -q "Hostname" <<<"$home"
expect "the site receives the verdict header" grep -qi "X-Telarana-Verdict: clean" <<<"$home"

robots=$(body /robots.txt)
expect "robots.txt keeps the site's own rules" grep -q "Disallow: /private/" <<<"$robots"
expect "robots.txt disallows the trap area" grep -q '^Disallow: /restricted/$' <<<"$robots"
expect "robots.txt lists 3 trap paths" test "$(grep -c '^Disallow: /restricted/.' <<<"$robots" || true)" -eq 3

trap1=$(grep '^Disallow: /restricted/.' <<<"$robots" | head -1 | cut -d' ' -f2 || true)
decoy=$(body "${trap1:-/restricted/none}")
next=$(grep -o 'href="[^"]*"' <<<"$decoy" | cut -d'"' -f2 || true)
expect "first trap shows a decoy linking to another trap" test -n "$next"
expect "second trap answers 404" test "$(status "${next:-/restricted/none}")" = "404"
expect "the trapped visitor is now blocked (enforce)" test "$(status /)" = "403"
expect "another browser on the same IP is not" test "$(status / "$other")" = "200"

if [ "$name" = "nginx" ]; then
  compose stop telarana >/dev/null 2>&1
  expect "fail-open: site still served with Telaraña down" test "$(status / "$other")" = "200"
  expect "fail-open is visible to the site" grep -qi "X-Telarana-Verdict: unavailable" <<<"$(body / "$other")"
fi

echo "== $name: $pass passed, $fail failed"
if [ "$fail" -ne 0 ]; then
  compose logs --tail=50
  exit 1
fi
