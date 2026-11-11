#!/usr/bin/env bash
# Run the GuardFil web playground from a checkout or worktree in the CI-pinned Go image.
# Usage: playground.sh [<repo-path>] [<host-port>] [<tool-set: demo|claude-code>]   -> http://127.0.0.1:<host-port>
# Detached container named gf-playground; stop with: docker rm -f gf-playground
set -eu
REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
PORT="${2:-8787}"
TOOLS_ARGS=""; [ -n "${3:-}" ] && TOOLS_ARGS="-tools $3"
IMAGE='golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
docker rm -f gf-playground >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker run -d --name gf-playground -p "127.0.0.1:$PORT:8787" \
  -v "$REPO:/src:ro" -w /src -v guardfil-gomod:/go/pkg/mod -v guardfil-gocache:/root/.cache/go-build \
  -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -buildvcs=false" \
  "$IMAGE" go run ./cmd/guardfil-playground -addr 0.0.0.0:8787 -allow-non-loopback $TOOLS_ARGS >/dev/null
for i in $(seq 1 60); do curl -fs -o /dev/null "http://127.0.0.1:$PORT/" && { echo "playground: http://127.0.0.1:$PORT"; exit 0; }; sleep 1; done
docker logs gf-playground; exit 1
