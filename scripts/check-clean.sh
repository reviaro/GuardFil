#!/usr/bin/env sh
# Fail-closed git cleanliness check.
# Rejects tracked modifications, staged changes, untracked files, and ignored files.
# Preserves git exit status on command failure.
set -eu

target="${1:-.}"
status_out=$(git -C "$target" status --porcelain --untracked-files=all --ignored=matching)
if test -n "$status_out"; then
	echo "source modification detected in $target:" >&2
	git -C "$target" status --short --untracked-files=all --ignored=matching >&2
	exit 1
fi
