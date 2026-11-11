#!/usr/bin/env sh
# Fail-closed formatting check for Go source files.
# Preserves gofmt exit status on failure and rejects unformatted files.
set -eu

unformatted=$(gofmt -l .)
if test -n "$unformatted"; then
	echo "gofmt found unformatted files:" >&2
	echo "$unformatted" >&2
	exit 1
fi
