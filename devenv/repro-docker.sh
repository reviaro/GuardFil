#!/usr/bin/env bash
# Run GuardFil's two-clean-worktree reproducibility build inside the CI-pinned Go container.
# Clones the repo inside the container to guarantee LF line endings and cleanliness.
# Uses --network none and mounts the verified module cache read-only.
#
# Retains build artifacts, SHA256SUMS, manifests, and buildinfo outside the source checkout,
# bound to the exact source commit SHA in a dedicated private directory.
#
# Usage: repro-docker.sh [<ref>] [<repo-path>] [<output-dir>]
#   default ref:        HEAD
#   default repo-path:  the checkout containing this script
#   default output-dir: unique fresh directory via mktemp -d
set -eu

REF="${1:-HEAD}"
REPO_ARG="${2:-$(cd "$(dirname "$0")/.." && pwd -P)}"
if [ ! -d "$REPO_ARG" ]; then
  echo "repro-docker: error: repo directory does not exist: $REPO_ARG" >&2
  exit 64
fi
REPO_RAW="$(CDPATH= cd -- "$REPO_ARG" && pwd -P)"
# Standalone checked assignment; fails closed immediately under set -e on Git error
REPO_TOP="$(git -C "$REPO_RAW" rev-parse --show-toplevel)"
test -n "$REPO_TOP"
REPO="$(CDPATH= cd -- "$REPO_TOP" && pwd -P)"
SHA="$(git -C "$REPO" rev-parse --verify "$REF^{commit}")"
GITDIR="$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)"
GITDIR="$(CDPATH= cd -- "$GITDIR" && pwd -P)"
IMAGE='golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'

# Validate destination path
if [ $# -ge 3 ] && [ -n "${3:-}" ]; then
  REQ_TARGET="$3"
  case "$REQ_TARGET" in
    .|..)
      echo "repro-docker: error: invalid destination '$REQ_TARGET'" >&2
      exit 64
      ;;
  esac

  # Reject existing paths, including regular files, directories, and dangling symlinks
  if [ -e "$REQ_TARGET" ] || [ -L "$REQ_TARGET" ]; then
    echo "repro-docker: error: destination path already exists: $REQ_TARGET" >&2
    echo "repro-docker: existing evidence or user paths must never be overwritten" >&2
    exit 64
  fi

  PARENT_DIR="$(dirname -- "$REQ_TARGET")"
  BASE_NAME="$(basename -- "$REQ_TARGET")"
  if [ ! -d "$PARENT_DIR" ]; then
    echo "repro-docker: error: destination parent directory does not exist: $PARENT_DIR" >&2
    exit 64
  fi
  PARENT_DIR="$(CDPATH= cd -- "$PARENT_DIR" && pwd -P)"
  OUT_DIR="$PARENT_DIR/$BASE_NAME"

  # Validate that physical destination is strictly outside the source checkout and git directory
  case "$OUT_DIR/" in
    "$GITDIR/"*)
      echo "repro-docker: error: destination must not be inside git directory: $OUT_DIR" >&2
      exit 64
      ;;
    "$REPO/"*)
      echo "repro-docker: error: destination must be outside the source checkout: $OUT_DIR" >&2
      exit 64
      ;;
  esac

  mkdir -m 0700 "$OUT_DIR"
else
  # Default: allocate a unique private fresh directory per run
  # Validate that TMPDIR is outside source checkout and git directory before creating anything
  BASE_TMP="${TMPDIR:-/tmp}"
  if [ ! -d "$BASE_TMP" ]; then
    echo "repro-docker: error: TMPDIR directory does not exist: $BASE_TMP" >&2
    exit 64
  fi
  CANON_TMP="$(CDPATH= cd -- "$BASE_TMP" && pwd -P)"
  case "$CANON_TMP/" in
    "$GITDIR/"*)
      echo "repro-docker: error: TMPDIR must not be inside git directory: $CANON_TMP" >&2
      exit 64
      ;;
    "$REPO/"*)
      echo "repro-docker: error: TMPDIR must be outside the source checkout: $CANON_TMP" >&2
      exit 64
      ;;
  esac

  OUT_DIR="$(mktemp -d "$CANON_TMP/guardfil-repro-$SHA.XXXXXX")"
  chmod 0700 "$OUT_DIR"
  OUT_DIR="$(CDPATH= cd -- "$OUT_DIR" && pwd -P)"
fi

echo "repro-docker: running two-worktree reproducibility for $SHA"
echo "repro-docker: dedicated private output directory $OUT_DIR"

UID_GID="$(id -u):$(id -g)"

# Run container with:
#  - dedicated mount of $OUT_DIR to /out (no parent exposure)
#  - module cache mounted read-only (:ro)
#  - network disabled (--network none)
#  - partial evidence preserved on failure (no deletion trap)
MSYS_NO_PATHCONV=1 docker run --rm \
  --network none \
  -v "$GITDIR:/repo.git:ro" \
  -v guardfil-gomod:/go/pkg/mod:ro \
  -v "$OUT_DIR:/out" \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e GOPROXY=off -e GOSUMDB=off -e SHA="$SHA" -e UID_GID="$UID_GID" \
  "$IMAGE" bash -euc '
    git config --global --add safe.directory "*"
    git config --global core.autocrlf false
    git clone -q --no-checkout /repo.git /work && cd /work && git checkout -q "$SHA"
    export REPRO_OUTPUT_DIR="/out/artifacts"
    ./scripts/reproducibility.sh
    # Ensure required ownership without following untrusted symlinks and without error masking
    if [ ! -d /out/artifacts ]; then
      echo "repro-docker: error: /out/artifacts was not created" >&2
      exit 1
    fi
    chown -h "$UID_GID" /out/artifacts
    for f in /out/artifacts/*; do
      if [ -e "$f" ] || [ -L "$f" ]; then
        chown -h "$UID_GID" "$f"
      fi
    done
  '

echo "repro-docker: SUCCESS for $SHA"
echo "repro-docker: reproducible artifacts retained at: $OUT_DIR/artifacts"
