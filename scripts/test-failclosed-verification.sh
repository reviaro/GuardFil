#!/usr/bin/env bash
# Offline executable regression suite for fail-closed verification.
# Exercises scripts/reproducibility.sh, scripts/check-format.sh, and scripts/check-clean.sh
# against clean/dirty checkouts, synthetic error injections, and mutant checks.
#
# No network access, no credentials, zero external dependencies beyond bash, git, and python3.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
GUARD_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

record_result() {
    local name="$1"
    local status="$2"
    local details="$3"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    if [ "$status" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  [PASS] %s\n" "$name"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        printf "  [FAIL] %s: %s\n" "$name" "$details" >&2
    fi
}

TMP_TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/guardfil-failclosed-test.XXXXXX")
cleanup() {
    rm -rf "$TMP_TEST_DIR"
}
trap cleanup EXIT INT TERM

SHIM_BIN="$TMP_TEST_DIR/bin"
mkdir -p "$SHIM_BIN"

REAL_GIT="$(command -v git)"
export TEST_REAL_GIT="$REAL_GIT"

# Synthetic hermetic go shim
cat << 'EOF' > "$SHIM_BIN/go"
#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
if args[:1] == ['-C']:
    args = args[2:]
if args == ['version']:
    if os.environ.get('INJECT_GO_VERSION_ERROR_EMPTY') == '1':
        print('go: forced toolchain failure empty', file=sys.stderr)
        sys.exit(73)
    if os.environ.get('INJECT_GO_VERSION_ERROR_MISLEADING') == '1':
        print('go version go1.27.1 linux/amd64')
        print('go: forced toolchain failure after output', file=sys.stderr)
        sys.exit(73)
    print('go version go1.27.1 linux/amd64')
elif args[:2] == ['version', '-m']:
    print('build\tvcs.revision=' + os.environ.get('TEST_COMMIT', ''))
    print('build\tvcs.time=' + os.environ.get('TEST_TIME', ''))
    print('build\tvcs.modified=false')
elif args[:1] == ['build']:
    out_idx = args.index('-o') + 1
    pathlib.Path(args[out_idx]).write_bytes(b'reproducible-offline-binary\n')
elif args[:2] == ['mod', 'verify']:
    print('synthetic module verification')
elif args[:1] == ['list']:
    print('{}')
else:
    print('unexpected fake-go invocation', args, file=sys.stderr)
    sys.exit(70)
EOF
chmod +x "$SHIM_BIN/go"

# Synthetic git wrapper shim for injected failures
cat << 'EOF' > "$SHIM_BIN/git"
#!/usr/bin/env python3
import os, subprocess, sys
args = sys.argv[1:]
real_git = os.environ['TEST_REAL_GIT']

if 'status' in args and os.environ.get('INJECT_GIT_STATUS_ERROR') == '1':
    print('QA synthetic git status failure', file=sys.stderr)
    sys.exit(128)

if 'status' in args and os.environ.get('INJECT_GIT_STATUS_ERROR_MISLEADING') == '1':
    print('?? untracked-file.txt')
    print('QA synthetic git status failure with output', file=sys.stderr)
    sys.exit(128)

if 'show' in args and os.environ.get('INJECT_GIT_SHOW_ERROR_AFTER_OUTPUT') == '1':
    subprocess.run([real_git, *args], check=True)
    print('QA synthetic git show failure after output', file=sys.stderr)
    sys.exit(128)

if 'show' in args and os.environ.get('INJECT_GIT_SHOW_ERROR_EMPTY') == '1':
    print('QA synthetic git show failure empty', file=sys.stderr)
    sys.exit(128)

if '--show-toplevel' in args and os.environ.get('INJECT_GIT_TOPLEVEL_ERROR_AFTER_OUTPUT') == '1':
    subprocess.run([real_git, *args], check=True)
    print('QA synthetic git toplevel failure after output', file=sys.stderr)
    sys.exit(128)

if '--show-toplevel' in args and os.environ.get('INJECT_GIT_TOPLEVEL_ERROR_EMPTY') == '1':
    print('QA synthetic git toplevel failure empty', file=sys.stderr)
    sys.exit(128)

os.execv(real_git, [real_git, *args])
EOF
chmod +x "$SHIM_BIN/git"

# ---------------------------------------------------------------------------
# Section 1: Formatter Fail-Closed Tests (scripts/check-format.sh)
# ---------------------------------------------------------------------------
echo "=== 1. Go Formatter Fail-Closed Tests (scripts/check-format.sh) ==="

FORMAT_WORK="$TMP_TEST_DIR/format-work"
mkdir -p "$FORMAT_WORK/scripts"
cp "$GUARD_ROOT/scripts/check-format.sh" "$FORMAT_WORK/scripts/check-format.sh"
chmod +x "$FORMAT_WORK/scripts/check-format.sh"

# Case 1: All files formatted
(
    cat << 'EOF' > "$SHIM_BIN/gofmt"
#!/usr/bin/env sh
exit 0
EOF
    chmod +x "$SHIM_BIN/gofmt"
    cd "$FORMAT_WORK"
    set +e
    out=$(PATH="$SHIM_BIN:$PATH" ./scripts/check-format.sh 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 0 ] && [ -z "$out" ]
) && record_result "check-format: clean formatting exits 0 with empty output" "PASS" "" \
  || record_result "check-format: clean formatting exits 0 with empty output" "FAIL" "expected exit 0 and empty output"

# Case 2: Unformatted file detected (strictly assert rc=1 AND exact file output; no || true)
(
    cat << 'EOF' > "$SHIM_BIN/gofmt"
#!/usr/bin/env sh
echo "internal/dirty.go"
exit 0
EOF
    chmod +x "$SHIM_BIN/gofmt"
    cd "$FORMAT_WORK"
    set +e
    out=$(PATH="$SHIM_BIN:$PATH" ./scripts/check-format.sh 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 1 ] && echo "$out" | grep -q "internal/dirty.go"
) && record_result "check-format: unformatted file exits 1 and lists file" "PASS" "" \
  || record_result "check-format: unformatted file exits 1 and lists file" "FAIL" "expected exit 1 with file listed"

# Case 3: gofmt fails with exit 2 and empty stdout (error masking regression check)
(
    cat << 'EOF' > "$SHIM_BIN/gofmt"
#!/usr/bin/env sh
echo "gofmt: syntax error in file.go" >&2
exit 2
EOF
    chmod +x "$SHIM_BIN/gofmt"
    cd "$FORMAT_WORK"
    set +e
    out=$(PATH="$SHIM_BIN:$PATH" ./scripts/check-format.sh 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 2 ] && echo "$out" | grep -q "syntax error"
) && record_result "check-format: gofmt exit 2 with empty stdout fails closed (exit 2)" "PASS" "" \
  || record_result "check-format: gofmt exit 2 with empty stdout fails closed (exit 2)" "FAIL" "expected exit 2"

# Case 4: gofmt fails with exit 2 and misleading stdout
(
    cat << 'EOF' > "$SHIM_BIN/gofmt"
#!/usr/bin/env sh
echo "internal/file.go"
echo "gofmt: internal error" >&2
exit 2
EOF
    chmod +x "$SHIM_BIN/gofmt"
    cd "$FORMAT_WORK"
    set +e
    out=$(PATH="$SHIM_BIN:$PATH" ./scripts/check-format.sh 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 2 ]
) && record_result "check-format: gofmt exit 2 with misleading stdout fails closed (exit 2)" "PASS" "" \
  || record_result "check-format: gofmt exit 2 with misleading stdout fails closed (exit 2)" "FAIL" "expected exit 2"

# ---------------------------------------------------------------------------
# Section 2: Shared Git Cleanliness Tests (scripts/check-clean.sh)
# ---------------------------------------------------------------------------
echo "=== 2. Git Cleanliness Fail-Closed Tests (scripts/check-clean.sh) ==="

init_clean_repo() {
    local target="$1"
    rm -rf "$target"
    mkdir -p "$target"
    "$REAL_GIT" -C "$target" init -q
    "$REAL_GIT" -C "$target" config user.email "test@example.com"
    "$REAL_GIT" -C "$target" config user.name "Test Runner"
    echo "*.ignored" > "$target/.gitignore"
    echo "initial" > "$target/tracked.txt"
    "$REAL_GIT" -C "$target" add .
    "$REAL_GIT" -C "$target" commit -q -m "initial commit"
}

CLEAN_REPO="$TMP_TEST_DIR/clean-repo"
init_clean_repo "$CLEAN_REPO"

# Case 5: Clean repo passes check-clean.sh
(
    set +e
    out=$("$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 0 ] && [ -z "$out" ]
) && record_result "check-clean: clean repo exits 0 with empty output" "PASS" "" \
  || record_result "check-clean: clean repo exits 0 with empty output" "FAIL" "expected exit 0"

# Case 6: Tracked modification rejected
(
    init_clean_repo "$CLEAN_REPO"
    echo "dirty modification" >> "$CLEAN_REPO/tracked.txt"
    set +e
    out=$("$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 1 ] && echo "$out" | grep -q "source modification detected"
) && record_result "check-clean: tracked modification exits 1" "PASS" "" \
  || record_result "check-clean: tracked modification exits 1" "FAIL" "expected exit 1 on tracked modification"

# Case 7: Staged modification rejected
(
    init_clean_repo "$CLEAN_REPO"
    echo "staged mod" >> "$CLEAN_REPO/tracked.txt"
    "$REAL_GIT" -C "$CLEAN_REPO" add "$CLEAN_REPO/tracked.txt"
    set +e
    out=$("$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 1 ] && echo "$out" | grep -q "source modification detected"
) && record_result "check-clean: staged modification exits 1" "PASS" "" \
  || record_result "check-clean: staged modification exits 1" "FAIL" "expected exit 1 on staged modification"

# Case 8: Untracked file rejected
(
    init_clean_repo "$CLEAN_REPO"
    echo "untracked content" > "$CLEAN_REPO/untracked.txt"
    set +e
    out=$("$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 1 ] && echo "$out" | grep -q "source modification detected"
) && record_result "check-clean: untracked file exits 1" "PASS" "" \
  || record_result "check-clean: untracked file exits 1" "FAIL" "expected exit 1 on untracked file"

# Case 9: Ignored file rejected
(
    init_clean_repo "$CLEAN_REPO"
    echo "ignored content" > "$CLEAN_REPO/sample.ignored"
    set +e
    out=$("$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 1 ] && echo "$out" | grep -q "source modification detected"
) && record_result "check-clean: ignored file exits 1" "PASS" "" \
  || record_result "check-clean: ignored file exits 1" "FAIL" "expected exit 1 on ignored file"

# Case 10: git status failure with empty stdout fails closed
(
    init_clean_repo "$CLEAN_REPO"
    set +e
    out=$(
        export PATH="$SHIM_BIN:$PATH"
        export INJECT_GIT_STATUS_ERROR=1
        "$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1
    )
    rc=$?
    set -e
    [ "$rc" -eq 128 ]
) && record_result "check-clean: git status error (empty stdout) fails closed (exit 128)" "PASS" "" \
  || record_result "check-clean: git status error (empty stdout) fails closed (exit 128)" "FAIL" "expected exit 128"

# Case 11: git status failure with misleading stdout fails closed
(
    init_clean_repo "$CLEAN_REPO"
    set +e
    out=$(
        export PATH="$SHIM_BIN:$PATH"
        export INJECT_GIT_STATUS_ERROR_MISLEADING=1
        "$GUARD_ROOT/scripts/check-clean.sh" "$CLEAN_REPO" 2>&1
    )
    rc=$?
    set -e
    [ "$rc" -eq 128 ]
) && record_result "check-clean: git status error (misleading stdout) fails closed (exit 128)" "PASS" "" \
  || record_result "check-clean: git status error (misleading stdout) fails closed (exit 128)" "FAIL" "expected exit 128"

# ---------------------------------------------------------------------------
# Section 3: Reproducibility Script Fail-Closed & Evidence Verification
# ---------------------------------------------------------------------------
echo "=== 3. Reproducibility Fail-Closed Tests (scripts/reproducibility.sh) ==="

init_repro_repo() {
    local target="$1"
    rm -rf "$target"
    mkdir -p "$target/scripts" "$target/cmd/guardfil"
    "$REAL_GIT" -C "$target" init -q
    "$REAL_GIT" -C "$target" config user.email "test@example.com"
    "$REAL_GIT" -C "$target" config user.name "Test Runner"
    echo "*.ignored" > "$target/.gitignore"
    echo "initial" > "$target/tracked.txt"
    echo "package main" > "$target/cmd/guardfil/main.go"
    cp "$GUARD_ROOT/scripts/reproducibility.sh" "$target/scripts/reproducibility.sh"
    cp "$GUARD_ROOT/scripts/check-clean.sh" "$target/scripts/check-clean.sh"
    chmod +x "$target/scripts/reproducibility.sh" "$target/scripts/check-clean.sh"
    "$REAL_GIT" -C "$target" add .
    "$REAL_GIT" -C "$target" commit -q -m "initial commit"

    # Refresh commit identity and timestamp dynamically on each fixture initialization
    COMMIT="$("$REAL_GIT" -C "$target" rev-parse HEAD)"
    RAW_TIME="$("$REAL_GIT" -C "$target" show -s --format=%cI "$COMMIT")"
    NORM_TIME="$(TZ=UTC0 date -d "$RAW_TIME" '+%Y-%m-%dT%H:%M:%SZ')"
    export TEST_COMMIT="$COMMIT"
    export TEST_TIME="$NORM_TIME"
}

REPRO_REPO="$TMP_TEST_DIR/repro-repo"
init_repro_repo "$REPRO_REPO"

run_repro() {
    local repo="$1"
    local out_dir="$2"
    (
        cd "$repo"
        export REPRO_OUTPUT_DIR="$out_dir"
        export PATH="$SHIM_BIN:$PATH"
        ./scripts/reproducibility.sh
    )
}

# Case 12: Clean repository reproducibility with strict rc=0 AND evidence verification
(
    out_dir="$TMP_TEST_DIR/repro-clean-out-$$"
    rm -rf "$out_dir"
    set +e
    out=$(run_repro "$REPRO_REPO" "$out_dir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 0 ] && \
    echo "$out" | grep -q "reproducible amd64 evidence:" && \
    [ -f "$out_dir/guardfil-a" ] && \
    [ -f "$out_dir/guardfil-b" ] && \
    [ -f "$out_dir/SHA256SUMS" ] && \
    [ -f "$out_dir/reproducibility-manifest.txt" ] && \
    cmp -s "$out_dir/guardfil-a" "$out_dir/guardfil-b" && \
    grep -q "vcs.modified=false" "$out_dir/guardfil-a.buildinfo.txt"
) && record_result "reproducibility: clean repo exits 0 with verified matching artifacts" "PASS" "" \
  || record_result "reproducibility: clean repo exits 0 with verified matching artifacts" "FAIL" "clean build failed verification"

# Case 13: Tracked dirt rejected
(
    init_repro_repo "$REPRO_REPO"
    echo "dirty modification" >> "$REPRO_REPO/tracked.txt"
    out_dir="$TMP_TEST_DIR/repro-dirty-out-$$"
    set +e
    out=$(run_repro "$REPRO_REPO" "$out_dir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 1 ] && echo "$out" | grep -q "source modification detected"
) && record_result "reproducibility: tracked file dirt rejected (exit 1)" "PASS" "" \
  || record_result "reproducibility: tracked file dirt rejected (exit 1)" "FAIL" "expected exit 1 on tracked modification"

# Case 14: Git show timestamp query exits 128 after valid timestamp output (Defect 2)
(
    init_repro_repo "$REPRO_REPO"
    out_dir="$TMP_TEST_DIR/repro-show-err-out-$$"
    set +e
    out=$(INJECT_GIT_SHOW_ERROR_AFTER_OUTPUT=1 run_repro "$REPRO_REPO" "$out_dir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 128 ]
) && record_result "reproducibility: git show failure after timestamp fails closed (exit 128)" "PASS" "" \
  || record_result "reproducibility: git show failure after timestamp fails closed (exit 128)" "FAIL" "expected exit 128"

# Case 15: Git show timestamp query exits 128 with empty stdout
(
    init_repro_repo "$REPRO_REPO"
    out_dir="$TMP_TEST_DIR/repro-show-empty-out-$$"
    set +e
    out=$(INJECT_GIT_SHOW_ERROR_EMPTY=1 run_repro "$REPRO_REPO" "$out_dir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 128 ]
) && record_result "reproducibility: git show failure with empty stdout fails closed (exit 128)" "PASS" "" \
  || record_result "reproducibility: git show failure with empty stdout fails closed (exit 128)" "FAIL" "expected exit 128"

# Case 16: Go version failure with empty stdout fails closed (exit 73)
(
    init_repro_repo "$REPRO_REPO"
    out_dir="$TMP_TEST_DIR/repro-gover-empty-out-$$"
    set +e
    out=$(INJECT_GO_VERSION_ERROR_EMPTY=1 run_repro "$REPRO_REPO" "$out_dir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 73 ] && echo "$out" | grep -q "go: forced toolchain failure empty"
) && record_result "reproducibility: go version failure with empty stdout fails closed (exit 73)" "PASS" "" \
  || record_result "reproducibility: go version failure with empty stdout fails closed (exit 73)" "FAIL" "expected exit 73 and toolchain diagnostic"

# Case 17: Go version failure after misleading valid stdout fails closed (exit 73)
(
    init_repro_repo "$REPRO_REPO"
    out_dir="$TMP_TEST_DIR/repro-gover-misleading-out-$$"
    set +e
    out=$(INJECT_GO_VERSION_ERROR_MISLEADING=1 run_repro "$REPRO_REPO" "$out_dir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 73 ] && echo "$out" | grep -q "go: forced toolchain failure after output"
) && record_result "reproducibility: go version failure with misleading stdout fails closed (exit 73)" "PASS" "" \
  || record_result "reproducibility: go version failure with misleading stdout fails closed (exit 73)" "FAIL" "expected exit 73 and toolchain diagnostic"

# ---------------------------------------------------------------------------
# Section 4: Historical Defect Reproductions (Pre-Fix Failure Demonstration)
# ---------------------------------------------------------------------------
echo "=== 4. Historical Defect Reproductions (Pre-Fix Failure Demonstration) ==="

# Case 18: Old broken assert_clean (if ! test -z "$(git status)")
(
    set +e
    mutant_out=$(
        sh -c '
            export PATH="'"$SHIM_BIN"':$PATH"
            export INJECT_GIT_STATUS_ERROR=1
            assert_clean_mutant() {
                if ! test -z "$(git -C "'"$CLEAN_REPO"'" status --porcelain --untracked-files=all --ignored=matching)"; then
                    echo "dirty" >&2
                    exit 1
                fi
            }
            assert_clean_mutant
        ' 2>&1
    )
    mutant_rc=$?
    set -e
    # The pre-fix construct wrongly returns 0 (masks git status error)
    [ "$mutant_rc" -eq 0 ]
) && record_result "defect-repro: old assert_clean masks git-status error (exit 0 reproduced)" "PASS" "" \
  || record_result "defect-repro: old assert_clean masks git-status error (exit 0 reproduced)" "FAIL" "pre-fix defect did not reproduce"

# Case 19: Old broken timestamp extraction (source_time=$(date -d "$(git show ...)"))
(
    set +e
    mutant_out=$(
        sh -c '
            export PATH="'"$SHIM_BIN"':$PATH"
            export INJECT_GIT_SHOW_ERROR_AFTER_OUTPUT=1
            source_time=$(TZ=UTC0 date -d "$(git -C "'"$REPRO_REPO"'" show -s --format=%cI "'"$COMMIT"'")" "+%Y-%m-%dT%H:%M:%SZ")
            test -n "$source_time"
        ' 2>&1
    )
    mutant_rc=$?
    set -e
    # The pre-fix construct wrongly returns 0 (masks git show exit 128)
    [ "$mutant_rc" -eq 0 ]
) && record_result "defect-repro: old nested git-show masks timestamp query error (exit 0 reproduced)" "PASS" "" \
  || record_result "defect-repro: old nested git-show masks timestamp query error (exit 0 reproduced)" "FAIL" "pre-fix defect did not reproduce"

# Case 20: Old broken formatter mask (test -z "$(gofmt -l .)")
(
    cat << 'EOF' > "$SHIM_BIN/gofmt"
#!/usr/bin/env sh
echo "syntax error" >&2
exit 2
EOF
    chmod +x "$SHIM_BIN/gofmt"
    set +e
    mutant_out=$(
        sh -c '
            export PATH="'"$SHIM_BIN"':$PATH"
            test -z "$(gofmt -l .)"
        ' 2>&1
    )
    mutant_rc=$?
    set -e
    # The pre-fix construct wrongly returns 0 (masks gofmt exit 2)
    [ "$mutant_rc" -eq 0 ]
) && record_result "defect-repro: old test -z gofmt masks formatter failure (exit 0 reproduced)" "PASS" "" \
  || record_result "defect-repro: old test -z gofmt masks formatter failure (exit 0 reproduced)" "FAIL" "pre-fix defect did not reproduce"

# Case 21: Old broken go version pipeline mask (test "$(go version | awk ...)" = go1.27.1)
(
    set +e
    mutant_out=$(
        sh -c '
            export PATH="'"$SHIM_BIN"':$PATH"
            export INJECT_GO_VERSION_ERROR_MISLEADING=1
            test "$(go version | awk "{print \$3}")" = go1.27.1
        ' 2>&1
    )
    mutant_rc=$?
    set -e
    # The pre-fix construct wrongly returns 0 (masks go version failure because awk succeeds)
    [ "$mutant_rc" -eq 0 ]
) && record_result "defect-repro: old go version pipeline masks toolchain error (exit 0 reproduced)" "PASS" "" \
  || record_result "defect-repro: old go version pipeline masks toolchain error (exit 0 reproduced)" "FAIL" "pre-fix defect did not reproduce"

# ---------------------------------------------------------------------------
# Section 5: Repro Path Validation, Confinement & Permissions (devenv/repro-docker.sh)
# ---------------------------------------------------------------------------
echo "=== 5. Repro Runner Path Validation & Confinement (devenv/repro-docker.sh) ==="

# Dedicated fixture repository inside TMP_TEST_DIR so tests are strictly self-contained
FIXTURE_REPO="$TMP_TEST_DIR/repro-fixture-repo"
init_clean_repo "$FIXTURE_REPO"
mkdir -p "$FIXTURE_REPO/scripts"
cp "$GUARD_ROOT/scripts/reproducibility.sh" "$FIXTURE_REPO/scripts/reproducibility.sh"
cp "$GUARD_ROOT/scripts/check-clean.sh" "$FIXTURE_REPO/scripts/check-clean.sh"
chmod +x "$FIXTURE_REPO/scripts/reproducibility.sh" "$FIXTURE_REPO/scripts/check-clean.sh"
"$REAL_GIT" -C "$FIXTURE_REPO" add .
"$REAL_GIT" -C "$FIXTURE_REPO" commit -q -m "add scripts"

# Install Docker recording stub BEFORE all Section 5 cases; reject-path cases must verify zero Docker calls
DOCKER_CALL_LOG="$TMP_TEST_DIR/docker-calls.log"
export TEST_DOCKER_CALL_LOG="$DOCKER_CALL_LOG"
cat << 'EOF' > "$SHIM_BIN/docker"
#!/usr/bin/env sh
echo "docker $*" >> "$TEST_DOCKER_CALL_LOG"
exit 0
EOF
chmod +x "$SHIM_BIN/docker"

run_repro_fixture() {
    : > "$DOCKER_CALL_LOG"
    PATH="$SHIM_BIN:$PATH" "$GUARD_ROOT/devenv/repro-docker.sh" "$@"
}

# Case 22: Reject '.'
(
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" . 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && echo "$out" | grep -q "invalid destination" && [ ! -s "$DOCKER_CALL_LOG" ]
) && record_result "repro-docker: rejects '.' destination (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: rejects '.' destination (exit 64, zero docker calls)" "FAIL" "expected exit 64 with zero docker calls"

# Case 23: Reject '..'
(
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" .. 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && echo "$out" | grep -q "invalid destination" && [ ! -s "$DOCKER_CALL_LOG" ]
) && record_result "repro-docker: rejects '..' destination (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: rejects '..' destination (exit 64, zero docker calls)" "FAIL" "expected exit 64 with zero docker calls"

# Case 24: Existing sentinel file survives untouched after rejection
(
    existing_sentinel="$TMP_TEST_DIR/sentinel-file"
    echo "sentinel-file-payload" > "$existing_sentinel"
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" "$existing_sentinel" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "destination path already exists" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ -f "$existing_sentinel" ] && \
    [ "$(cat "$existing_sentinel")" = "sentinel-file-payload" ]
) && record_result "repro-docker: existing file sentinel survives untouched (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: existing file sentinel survives untouched (exit 64, zero docker calls)" "FAIL" "sentinel was modified or deleted"

# Case 25: Existing sentinel directory survives untouched after rejection
(
    existing_dir_sentinel="$TMP_TEST_DIR/sentinel-directory"
    mkdir -p "$existing_dir_sentinel"
    echo "sentinel-dir-payload" > "$existing_dir_sentinel/child.txt"
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" "$existing_dir_sentinel" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "destination path already exists" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ -d "$existing_dir_sentinel" ] && \
    [ -f "$existing_dir_sentinel/child.txt" ] && \
    [ "$(cat "$existing_dir_sentinel/child.txt")" = "sentinel-dir-payload" ]
) && record_result "repro-docker: existing directory sentinel survives untouched (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: existing directory sentinel survives untouched (exit 64, zero docker calls)" "FAIL" "directory sentinel modified or deleted"

# Case 26: Dangling symlink sentinel survives untouched after rejection
(
    dangling_sentinel="$TMP_TEST_DIR/sentinel-dangling-link"
    ln -s "$TMP_TEST_DIR/nonexistent-sentinel-target" "$dangling_sentinel"
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" "$dangling_sentinel" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "destination path already exists" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ -L "$dangling_sentinel" ] && \
    [ "$(readlink "$dangling_sentinel")" = "$TMP_TEST_DIR/nonexistent-sentinel-target" ]
) && record_result "repro-docker: dangling symlink sentinel survives untouched (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: dangling symlink sentinel survives untouched (exit 64, zero docker calls)" "FAIL" "symlink was modified or deleted"

# Case 27: Reject inside-source destination
(
    inside_dest="$FIXTURE_REPO/bad-subpath"
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" "$inside_dest" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "must be outside the source checkout" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ ! -e "$inside_dest" ]
) && record_result "repro-docker: rejects inside-checkout destination (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: rejects inside-checkout destination (exit 64, zero docker calls)" "FAIL" "expected exit 64 with zero docker calls"

# Case 28: Reject git metadata (.git) destination
(
    gitdir_dest="$FIXTURE_REPO/.git/evidence-dest"
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" "$gitdir_dest" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "must not be inside git directory" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ ! -e "$gitdir_dest" ]
) && record_result "repro-docker: rejects git-metadata destination (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: rejects git-metadata destination (exit 64, zero docker calls)" "FAIL" "expected exit 64 with zero docker calls"

# Case 29: Reject default TMPDIR inside source checkout before any creation
(
    bad_tmp="$FIXTURE_REPO/scratch-tmp"
    mkdir -p "$bad_tmp"
    set +e
    out=$(TMPDIR="$bad_tmp" run_repro_fixture HEAD "$FIXTURE_REPO" 2>&1)
    rc=$?
    set -e
    child_count=$(find "$bad_tmp" -mindepth 1 | wc -l)
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "TMPDIR must be outside the source checkout" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ "$child_count" -eq 0 ]
) && record_result "repro-docker: rejects TMPDIR inside source before creation (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: rejects TMPDIR inside source before creation (exit 64, zero docker calls)" "FAIL" "expected exit 64 with no child creation"

# Case 30: Explicit destination directory created with mode 0700 (Docker stub recording verified)
(
    dest_0700="$TMP_TEST_DIR/repro-0700-dest"
    set +e
    out=$(run_repro_fixture HEAD "$FIXTURE_REPO" "$dest_0700" 2>&1)
    rc=$?
    set -e
    perms=$(stat -c %a "$dest_0700" 2>/dev/null || stat -f %Lp "$dest_0700" 2>/dev/null)
    [ "$rc" -eq 0 ] && [ "$perms" = "700" ] && [ -s "$DOCKER_CALL_LOG" ]
) && record_result "repro-docker: explicit output created with mode 0700 (Docker called)" "PASS" "" \
  || record_result "repro-docker: explicit output created with mode 0700 (Docker called)" "FAIL" "expected mode 0700"

# Case 31: Reject inside-checkout destination when repo-path is a subdirectory
(
    nested_subdir="$FIXTURE_REPO/nested"
    mkdir -p "$nested_subdir"
    inside_dest="$FIXTURE_REPO/inside-actual-checkout"
    set +e
    out=$(run_repro_fixture HEAD "$nested_subdir" "$inside_dest" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "must be outside the source checkout" && \
    [ ! -s "$DOCKER_CALL_LOG" ] && \
    [ ! -e "$inside_dest" ]
) && record_result "repro-docker: repo subdir with explicit inside-checkout output rejected (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: repo subdir with explicit inside-checkout output rejected (exit 64, zero docker calls)" "FAIL" "expected exit 64 with zero docker calls and no destination creation"

# Case 32: Reject default TMPDIR at actual checkout root when repo-path is a subdirectory
(
    nested_subdir="$FIXTURE_REPO/nested"
    mkdir -p "$nested_subdir"
    set +e
    out=$(TMPDIR="$FIXTURE_REPO" run_repro_fixture HEAD "$nested_subdir" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 64 ] && \
    echo "$out" | grep -q "TMPDIR must be outside the source checkout" && \
    [ ! -s "$DOCKER_CALL_LOG" ]
) && record_result "repro-docker: repo subdir with default TMPDIR at checkout root rejected (exit 64, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: repo subdir with default TMPDIR at checkout root rejected (exit 64, zero docker calls)" "FAIL" "expected exit 64 with zero docker calls"

# Case 33: Git show-toplevel failure after output fails closed (exit 128, zero docker calls)
(
    set +e
    out=$(INJECT_GIT_TOPLEVEL_ERROR_AFTER_OUTPUT=1 run_repro_fixture HEAD "$FIXTURE_REPO" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq 128 ] && \
    echo "$out" | grep -q "QA synthetic git toplevel failure after output" && \
    [ ! -s "$DOCKER_CALL_LOG" ]
) && record_result "repro-docker: git toplevel failure after output fails closed (exit 128, zero docker calls)" "PASS" "" \
  || record_result "repro-docker: git toplevel failure after output fails closed (exit 128, zero docker calls)" "FAIL" "expected exit 128 with zero docker calls"

# ---------------------------------------------------------------------------
# Section 6: CI Immutable Input Fail-Closed Verification
# ---------------------------------------------------------------------------
echo "=== 6. CI Immutable Input Verification ==="

# Case 34: Failing go version fails closed under set -eu (exit 73)
(
    set +e
    out=$(
        sh -c '
            set -eu
            export PATH="'"$SHIM_BIN"':$PATH"
            # Create failing go version shim
            cat << "GOVER" > "'"$SHIM_BIN"'/go"
#!/usr/bin/env sh
echo "go: toolchain crashed" >&2
exit 73
GOVER
            chmod +x "'"$SHIM_BIN"'/go"
            raw_go_version=$(go version)
            test -n "$raw_go_version"
            test "$(printf "%s\n" "$raw_go_version" | awk "{print \$3}")" = "go1.27.1"
        ' 2>&1
    )
    rc=$?
    set -e
    [ "$rc" -eq 73 ] && echo "$out" | grep -q "go: toolchain crashed"
) && record_result "ci-workflow: failing go version fails closed (exit 73)" "PASS" "" \
  || record_result "ci-workflow: failing go version fails closed (exit 73)" "FAIL" "expected exit 73 and toolchain crash diagnostic"

# Case 35: Failing git rev-parse HEAD fails closed under set -eu
(
    set +e
    out=$(
        sh -c '
            set -eu
            export PATH="'"$SHIM_BIN"':$PATH"
            export TEST_REAL_GIT="'"$REAL_GIT"'"
            # Create git shim that fails rev-parse HEAD
            cat << "GITRP" > "'"$SHIM_BIN"'/git"
#!/usr/bin/env sh
if [ "$1" = "-C" ] && [ "$3" = "rev-parse" ] && [ "$4" = "HEAD" ]; then
    echo "git: corrupted commit graph" >&2
    exit 128
fi
exec "$TEST_REAL_GIT" "$@"
GITRP
            chmod +x "'"$SHIM_BIN"'/git"
            workspace_commit=$(git -C "'"$CLEAN_REPO"'" rev-parse HEAD)
            test -n "$workspace_commit"
            test "$workspace_commit" = "nonexistent_sha"
        ' 2>&1
    )
    rc=$?
    set -e
    [ "$rc" -eq 128 ]
) && record_result "ci-workflow: failing git rev-parse fails closed (exit 128)" "PASS" "" \
  || record_result "ci-workflow: failing git rev-parse fails closed (exit 128)" "FAIL" "expected exit 128"

echo ""
echo "=== Test Summary ==="
printf "Total tests: %d | Passed: %d | Failed: %d\n" "$TOTAL_COUNT" "$PASS_COUNT" "$FAIL_COUNT"

if [ "$FAIL_COUNT" -ne 0 ]; then
    echo "REGRESSION SUITE FAILED" >&2
    exit 1
fi

echo "ALL FAIL-CLOSED VERIFICATION & DEFECT REPRODUCTION TESTS PASSED"
exit 0
