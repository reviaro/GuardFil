#!/usr/bin/env bash
# The same native Codex and helpers used by the scripted alpha regression.
# Release digests: https://github.com/openai/codex/releases/tag/rust-v0.166.0
set -euo pipefail
dest=${1:?usage: install-ci-codex.sh DESTINATION}
mkdir -p "$dest"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
while read -r binary digest; do
  asset="$binary-x86_64-unknown-linux-musl"
  archive="$scratch/$asset.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "https://github.com/openai/codex/releases/download/rust-v0.166.0/$asset.tar.gz" -o "$archive"
  printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
  # Extract only the named executable, never archive paths or permissions.
  tar -xOzf "$archive" "$asset" > "$dest/$binary"
  chmod 0755 "$dest/$binary"
done <<'INPUTS'
codex a0bf572d2f93f056c6712a6da348e96078dc84f3885fd7be67807ef389cb3978
codex-code-mode-host 7588334fd47bc4003d970b70dfd4d1e4578491b1e9baa72976a4c2d7e97590da
codex-exec-server 16f698d576fcd1d94e5e38b5c6ce48168afad1d95737b1eb2d84b3f0219ea6e3
INPUTS
