#!/bin/sh
# Runs the Go toolchain in Docker, for machines without Go installed.
# Usage: scripts/go.sh test ./...   |   scripts/go.sh vet ./...
set -eu
exec docker run --rm -v "$(pwd)":/src -w /src \
  -v telarana-gomod:/go/pkg/mod -v telarana-gocache:/root/.cache/go-build \
  golang:1.25 go "$@"
