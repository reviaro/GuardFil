#!/usr/bin/env bash
# Run GuardFil's ordinary checks for a committed ref inside the CI-pinned Go image.
# Clones the repo inside the container so the tree is LF and clean (the Windows
# checkout uses core.autocrlf=true, which makes gofmt report every file).
#
# Usage: ci-docker.sh [<ref>] [<repo-path>]   (default ref: HEAD, repo: the checkout containing this script)
# Only committed changes are tested; commit before running.
set -eu
REF="${1:-HEAD}"
REPO="${2:-$(cd "$(dirname "$0")/.." && pwd)}"
SHA="$(git -C "$REPO" rev-parse --verify "$REF^{commit}")"
GITDIR="$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)"
IMAGE='golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
echo "ci-docker: testing $SHA"

MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$GITDIR:/repo.git:ro" \
  -v guardfil-gomod:/go/pkg/mod \
  -v guardfil-gocache:/root/.cache/go-build \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e SHA="$SHA" \
  "$IMAGE" bash -euo pipefail -c '
    set -euo pipefail
    git config --global --add safe.directory "*"
    git config --global core.autocrlf false
    git clone -q --no-checkout /repo.git /work && cd /work && git checkout -q "$SHA"
    step() { echo "== $*"; "$@"; }
    step go version
    step go mod verify
    if [ -x ./scripts/check-format.sh ]; then
      step ./scripts/check-format.sh
    else
      echo "== gofmt -l ."; out="$(gofmt -l .)"; [ -z "$out" ] || { echo "$out"; exit 1; }
    fi
    step go vet ./...
    step go test ./tests/security -run "^TestP11ProcessShellBuilds$" -count=1
    step go test -count=1 ./...
    step go test -race -count=1 ./...
    if [ -x ./scripts/test-failclosed-verification.sh ]; then
      step ./scripts/test-failclosed-verification.sh
    fi
    step go build -trimpath -buildvcs=true -o /tmp/guardfil ./cmd/guardfil
    echo "== advisory demo"; go run ./cmd/guardfil-advisory-demo | tail -3
    echo "ci-docker: ALL CHECKS PASSED for $SHA"
  '
