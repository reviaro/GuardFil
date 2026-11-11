#!/usr/bin/env sh
set -eu
mkdir -p dist
go test -run '^$' -bench '^BenchmarkServerShell$' -benchmem ./internal/server | tee dist/server-shell-benchmark.txt
echo 'This is server-shell overhead only; it makes no policy, end-to-end, or SLO claim.' >> dist/server-shell-benchmark.txt
