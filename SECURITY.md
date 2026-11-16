# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub:
[Report a vulnerability](https://github.com/vlorcap1/telarana/security/advisories/new)
(Security tab → "Report a vulnerability").

Include what you found, how to reproduce it and its impact. You will get an
acknowledgement within 7 days. Once a fix is released, the advisory is
published with credit to you unless you prefer otherwise.

## Supported versions

Security fixes go into the latest release. The Python prototype (v0.1.x) is
not maintained.

## Scope

In scope: anything that lets a remote party bypass detection in a way the
documentation says is prevented, frame another address (for example by
spoofing `X-Forwarded-For` through a correctly configured proxy), crash or
exhaust Telaraña, or read the secret.

Out of scope: bots that never request trap paths (a documented limitation),
and deployments that ignore the security notes in the README (for example, a
shared cache storing `/robots.txt`, or Telaraña exposed without a proxy).
