#!/usr/bin/env bash
# Follow the README quickstart on a clean machine and check each step.
#
#   deployments/local/quickstart-check.sh
#
# Needs what the README needs: Linux, Docker with Compose, Python 3.11+ and
# Claude Code on PATH. CI has no API key, so step 2 is replaced by a scripted
# stand-in model (redteam/m6/standin.py, case "quickstart"); everything else
# is the README's commands as written. Uses a fresh GF_HOME and removes it.
set -euo pipefail

cd "$(dirname "$0")/../.."
GF_HOME=${GF_HOME:-$(mktemp -d "$HOME/.gfq-XXXX")}
rmdir "$GF_HOME" 2>/dev/null || true   # init refuses an existing folder
export GF_HOME
LOCAL=deployments/local/guardfil-local.sh
WS=$(mktemp -d)
ok() { echo "ok   $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
cleanup() { "$LOCAL" down >/dev/null 2>&1 || true; rm -rf "$GF_HOME" "$WS"; }
trap cleanup EXIT

# 1. Set up.
"$LOCAL" init --ui active >/dev/null
[ -f "$GF_HOME/config/policy.yaml" ] && [ -f "$GF_HOME/config/tool-catalog.yaml" ] || fail "init did not install the policy and tool catalog"
[ "$(stat -c %a "$GF_HOME")" = 700 ] || fail "GF_HOME is not owner-only"
ok "1. init --ui active"

# 3. Start.
out=$("$LOCAL" up 2>&1) || { echo "$out"; fail "up"; }
echo "$out" | grep -q "approval socket: .*(up)" || { echo "$out"; fail "approval socket not up"; }
echo "$out" | grep -q "web UI: http://127.0.0.1:8088/" || { echo "$out"; fail "web UI address not printed"; }
[ -x "$GF_HOME/bin/guardfil-broker" ] && [ -x "$GF_HOME/bin/guardfil-mcp-proxy" ] || fail "up did not install the Go binaries"
token=$(cat "$GF_HOME/credentials/ui-token")
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/)
[ "$code" = 200 ] || fail "web UI answered $code"
jar=$(mktemp)
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/api/state)
[ "$code" = 401 ] || [ "$code" = 403 ] || fail "web UI state answered $code without a login"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"token":"wrong"}' http://127.0.0.1:8088/api/login)
[ "$code" != 200 ] || fail "web UI accepted a wrong token"
login=$(curl -sf -c "$jar" -X POST -H 'Content-Type: application/json' -d "{\"token\":\"$token\"}" http://127.0.0.1:8088/api/login) || fail "login with the ui-token failed"
session_token=$(printf '%s' "$login" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')
curl -sf -b "$jar" -H "X-GuardFil-Session: $session_token" http://127.0.0.1:8088/api/state | grep -q '"policy' || fail "web UI state did not load after login"
rm -f "$jar"
ok "3. up: approval socket, web UI login, binaries"

# 4. Run an agent (scripted stand-in model instead of an API key).
"$LOCAL" run-agent --runtime claude-code --workspace "$WS" --prompt "Write hello.txt, then read it back." \
  --max-turns 4 --broker-cmd "python3 -B -m redteam.m6.standin --case quickstart" > "$WS.log" 2>&1 \
  || { cat "$WS.log"; fail "run-agent"; }
grep -q "hello from GuardFil" "$WS/hello.txt" || { cat "$WS.log"; fail "the agent's file is missing"; }
python3 - "$GF_HOME/state/decisions.jsonl" <<'PY' || { cat "$WS.log"; fail "decisions"; }
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
write = [r for r in rows if r.get("kind") == "file_write" and r.get("effect") == "ALLOW"
         and "/workspace/hello.txt" in (r.get("paths") or [])]
read = [r for r in rows if r.get("tool") == "claude.read" and r.get("effect") == "ALLOW"]
assert write and read, f"want an allowed write and read, got {rows}"
assert all(r.get("principal") == "codex-agent" for r in write + read)
PY
ok "4. run-agent --runtime claude-code: write and read decided by GuardFil and logged"

# 5. The policy can be changed: block workspace writes and the next write is refused.
python3 - "$GF_HOME/config/policy.yaml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("  - id: monitor-workspace-writes\n    effect: monitor", "  - id: monitor-workspace-writes\n    effect: deny", 1)
open(p, "w").write(s)
PY
"$LOCAL" ui active >/dev/null
rm -f "$WS/hello.txt"
"$LOCAL" run-agent --runtime claude-code --workspace "$WS" --prompt "Write hello.txt, then read it back." \
  --max-turns 4 --broker-cmd "python3 -B -m redteam.m6.standin --case quickstart" > "$WS.log" 2>&1 || true
[ ! -e "$WS/hello.txt" ] || { cat "$WS.log"; fail "a write the policy denies was made"; }
grep -q "GuardFil blocked" "$WS.log" || { cat "$WS.log"; fail "no GuardFil block shown"; }
ok "5. policy change: the denied write was blocked"

echo "PASS: the README quickstart works on this machine"
