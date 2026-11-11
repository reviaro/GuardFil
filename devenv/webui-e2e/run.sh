#!/bin/bash
# Browser click-through of the GuardFil control UI against a real guardfil.
# usage: devenv/webui-e2e/run.sh <guardfil-binary>
# Needs docker and the pinned Playwright image; run `npm install` here once (inside that image).
set -u
S=$(cd "$(dirname "$0")" && pwd); BIN=$1; REPO=$(cd "$S/../.." && pwd)
W=$(mktemp -d /tmp/gfe-XXXX); chmod 700 $W; mkdir -m 700 $W/config $W/credentials $W/state $W/run
cp $REPO/deployments/example/approval/allow-canary-shell.yaml $W/config/policy.yaml; chmod 600 $W/config/policy.yaml
cp $REPO/deployments/example/approval/stockapp-catalog.yaml $W/config/tool-catalog.yaml; chmod 600 $W/config/tool-catalog.yaml
printf '\n---\n' >> $W/config/tool-catalog.yaml
cat $REPO/deployments/local/executor-catalog.yaml >> $W/config/tool-catalog.yaml
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > $W/credentials/metrics
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > $W/credentials/ui-token
chmod 600 $W/credentials/*
cat > $W/config/guardfil.yaml <<EOF
{"config_root":"$W/config","credentials_root":"$W/credentials","data":{"address":"127.0.0.1:18080"},"management":{"address":"127.0.0.1:19090","metrics_token_file":"$W/credentials/metrics"},"state_dir":"$W/state","approval":{"socket":"$W/run/a.sock","approver_socket":"$W/run/owner.sock","policy_file":"$W/config/policy.yaml","decision_log":"$W/state/decisions.jsonl","tool_catalog":"$W/config/tool-catalog.yaml","ask_timeout_seconds":30},"ui":{"active":true,"address":"127.0.0.1:18088","token_file":"$W/credentials/ui-token"}}
EOF
chmod 600 $W/config/guardfil.yaml
$BIN --config $W/config/guardfil.yaml 2>$W/log & PID=$!
sleep 1
rm -rf $S/shots; mkdir -p $S/shots
docker run --rm --network host --user $(id -u):$(id -g) -e HOME=/tmp -e CHROME=/ms-playwright/chromium-1148/chrome-linux/chrome \
  -v $S:/e2e -v $W/run:$W/run -w /e2e mcr.microsoft.com/playwright:v1.49.1-noble \
  node run.js http://127.0.0.1:18088/ "$(cat $W/credentials/ui-token)" $W/run/a.sock /e2e/shots
RC=$?
kill $PID; wait $PID; echo "guardfil exit=$? e2e rc=$RC"
if [ "$RC" = 0 ]; then
  # Policies/content saved through the browser must also load with UI removed.
  python3 -I -B - "$W/config/guardfil.yaml" <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p)); c.pop("ui")
c["approval"].pop("ask_timeout_seconds")
with open(p, "w") as f: json.dump(c, f)
PY
  $BIN --config $W/config/guardfil.yaml 2>>$W/log & PID=$!
  sleep 1
  python3 -I -B - "$W/run/a.sock" "$S/shots/results.json" <<'PY' || RC=1
import json, socket, sys
def decide(req):
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(sys.argv[1]); s.sendall((json.dumps(req) + "\n").encode()); s.shutdown(socket.SHUT_WR)
        return json.load(s.makefile())
checks = [
    {"name": "Browser-saved policy survives restart with UI removed", "ok": decide({"server":"claude","tool":"read","arguments":{"file_path":"/workspace/public/key"}})["effect"] == "ALLOW"},
    {"name": "Browser-saved content survives restart with UI removed", "ok": "orchid" not in decide({"kind":"filter","tool":"stockapp.get_news","content":"orchid report"})["content"]},
]
for c in checks: print(("PASS " if c["ok"] else "FAIL ") + c["name"])
path = sys.argv[2]
results = json.load(open(path)) + checks
with open(path, "w") as f: json.dump(results, f)
sys.exit(0 if all(c["ok"] for c in checks) else 1)
PY
  kill $PID; wait $PID
fi
rm -rf $W
exit $RC
