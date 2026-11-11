#!/usr/bin/env sh
# Build twice from separate clean worktrees. Never write build evidence into the
# checkout: -buildvcs=true would otherwise mark the second build as modified.
set -eu

source_root=$(git rev-parse --show-toplevel)
source_root=$(CDPATH= cd -- "$source_root" && pwd -P)
source_commit=$(git -C "$source_root" rev-parse HEAD)
# Go records vcs.time as a UTC RFC3339 instant. Git's %cI retains the commit's
# original numeric offset, so normalize before comparing equivalent instants.
raw_time=$(git -C "$source_root" show -s --format=%cI "$source_commit")
test -n "$raw_time"
source_time=$(TZ=UTC0 date -d "$raw_time" '+%Y-%m-%dT%H:%M:%SZ')
test -n "$source_time"

if test -n "${REPRO_OUTPUT_DIR:-}"; then
	# A caller-supplied path must be new, so stale evidence cannot be mistaken for
	# this run's output. Resolve and reject an in-checkout path before mkdir so a
	# bad argument cannot make the source tree dirty.
	output_parent=$(dirname -- "$REPRO_OUTPUT_DIR")
	output_name=$(basename -- "$REPRO_OUTPUT_DIR")
	output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
	output_dir=$output_parent/$output_name
	case "$output_dir/" in
	"$source_root/"*) echo "REPRO_OUTPUT_DIR must be outside the source checkout" >&2; exit 64 ;;
	esac
	mkdir "$output_dir"
else
	output_dir=$(mktemp -d "${TMPDIR:-/tmp}/guardfil-repro.XXXXXX")
fi
output_dir=$(CDPATH= cd -- "$output_dir" && pwd -P)
case "$output_dir/" in
"$source_root/"*) echo "REPRO_OUTPUT_DIR must be outside the source checkout" >&2; exit 64 ;;
esac

staging=$(mktemp -d "${TMPDIR:-/tmp}/guardfil-repro-worktrees.XXXXXX")
build_a=$staging/build-a
build_b=$staging/build-b
gocache_a=$staging/gocache-a
gocache_b=$staging/gocache-b
cleanup() {
	git -C "$source_root" worktree remove --force "$build_a" 2>/dev/null || true
	git -C "$source_root" worktree remove --force "$build_b" 2>/dev/null || true
	rm -rf "$staging"
}
trap cleanup EXIT HUP INT TERM

assert_clean() {
	"$source_root/scripts/check-clean.sh" "$1"
}
assert_clean "$source_root"

export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export GOPROXY=off
export GOSUMDB=off
export GONOSUMDB='*'
raw_go_version=$(go version)
test -n "$raw_go_version"
test "$(printf '%s\n' "$raw_go_version" | awk '{print $3}')" = go1.27.1
git -C "$source_root" diff --quiet
git -C "$source_root" diff --cached --quiet
go -C "$source_root" mod verify

git -C "$source_root" worktree add --detach "$build_a" "$source_commit"
git -C "$source_root" worktree add --detach "$build_b" "$source_commit"
assert_clean "$build_a"
assert_clean "$build_b"
build_a_commit=$(git -C "$build_a" rev-parse HEAD)
test "$build_a_commit" = "$source_commit"
build_b_commit=$(git -C "$build_b" rev-parse HEAD)
test "$build_b_commit" = "$source_commit"

flags='-trimpath -buildvcs=true'
# A and B must not share compiled package objects. -mod=readonly and network-
# off resolution prevent dependency changes/resolution; the private build cache
# is fresh per comparison build. The CI dependency-preparation job supplies the
# separately verified module-cache input.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE="$gocache_a" go -C "$build_a" build $flags -o "$output_dir/guardfil-a" ./cmd/guardfil
assert_clean "$source_root"
assert_clean "$build_a"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE="$gocache_b" go -C "$build_b" build $flags -o "$output_dir/guardfil-b" ./cmd/guardfil
assert_clean "$source_root"
assert_clean "$build_b"

for name in a b; do
	go version -m "$output_dir/guardfil-$name" > "$output_dir/guardfil-$name.buildinfo.txt"
	test "$(awk -F= '/vcs\.revision=/{print $2}' "$output_dir/guardfil-$name.buildinfo.txt")" = "$source_commit"
	test "$(awk -F= '/vcs\.time=/{print $2}' "$output_dir/guardfil-$name.buildinfo.txt")" = "$source_time"
	test "$(awk -F= '/vcs\.modified=/{print $2}' "$output_dir/guardfil-$name.buildinfo.txt")" = false
done
sha256sum "$output_dir/guardfil-a" "$output_dir/guardfil-b" > "$output_dir/SHA256SUMS"
cmp -s "$output_dir/guardfil-a" "$output_dir/guardfil-b"

{
	echo "source_commit=$source_commit"
	echo "source_time=$source_time"
	echo "go_version=$raw_go_version"
	echo "goos=linux"
	echo "goarch=amd64"
	echo "module_inputs=preverified cache required; GOFLAGS=-mod=readonly and GOPROXY=off prevent resolution or go.mod/go.sum changes"
	echo "commands=GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE=<fresh-private-per-build> go build -trimpath -buildvcs=true"
	echo "cleanliness=pre-build and after each build; includes ignored and untracked paths"
	echo "artifacts=separate detached worktrees and fresh GOCACHE directories at the pinned source commit; outputs outside checkout"
} > "$output_dir/reproducibility-manifest.txt"
go -C "$source_root" list -m -json all > "$output_dir/module-graph.json"
assert_clean "$source_root"
printf 'reproducible amd64 evidence: %s\n' "$output_dir"
