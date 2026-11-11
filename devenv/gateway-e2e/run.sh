#!/bin/bash
# End-to-end check of GuardFil's HTTP API gateway with a real guardfil binary,
# a fake app API and the example stock-app catalog and policy.
# usage: devenv/gateway-e2e/run.sh <guardfil-binary>
set -u
S=$(cd "$(dirname "$0")" && pwd); BIN=$1; REPO=$(cd "$S/../.." && pwd)
W=$(mktemp -d /tmp/gfg-XXXX); chmod 700 $W; mkdir -m 700 $W/config $W/credentials $W/state $W/run
cp $REPO/deployments/example/approval/stockapp-policy.yaml $W/config/policy.yaml
cp $REPO/deployments/example/approval/stockapp-catalog.yaml $W/config/tool-catalog.yaml
for f in metrics ui-token gateway-agent-token stockapp-key; do head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > $W/credentials/$f; done
chmod 600 $W/config/* $W/credentials/*
cat > $W/config/guardfil.yaml <<JSON
{"config_root":"$W/config","credentials_root":"$W/credentials","data":{"address":"127.0.0.1:18080"},
 "management":{"address":"127.0.0.1:19090","metrics_token_file":"$W/credentials/metrics"},"state_dir":"$W/state",
 "approval":{"socket":"$W/run/a.sock","policy_file":"$W/config/policy.yaml","decision_log":"$W/state/decisions.jsonl",
             "tool_catalog":"$W/config/tool-catalog.yaml","ask_timeout_seconds":30},
 "ui":{"active":true,"address":"127.0.0.1:18088","token_file":"$W/credentials/ui-token"},
 "gateway":{"address":"127.0.0.1:18090","socket":"$W/run/gateway.sock","agent_token_file":"$W/credentials/gateway-agent-token",
   "upstreams":[{"name":"stockapp","base_url":"http://127.0.0.1:18100","credential_file":"$W/credentials/stockapp-key",
     "credential_header":"Authorization","credential_prefix":"Bearer ",
     "routes":[{"method":"GET","path":"/api/quote/{symbol}","tool":"stockapp.get_quote"},
               {"method":"GET","path":"/api/portfolio","tool":"stockapp.get_portfolio"},
               {"method":"POST","path":"/api/orders","tool":"stockapp.place_order"},
               {"method":"DELETE","path":"/api/orders/{order_id}","tool":"stockapp.cancel_order"},
               {"method":"POST","path":"/api/withdrawals","tool":"stockapp.withdraw_funds"}]}]}}
JSON
chmod 600 $W/config/guardfil.yaml
python3 -I -B $S/fake_app.py 18100 $W/credentials/stockapp-key $W/app.jsonl & APP=$!
$BIN --config $W/config/guardfil.yaml 2>$W/log & PID=$!
sleep 1
python3 -I -B $S/check.py 18090 18088 "$(cat $W/credentials/gateway-agent-token)" $W/credentials/ui-token $W/app.jsonl \
  $W/credentials/stockapp-key $W/state/decisions.jsonl $W/run/a.sock
RC=$?
# The same gateway over its Unix socket (how a networkless executor reaches it).
python3 -I -B - "$W/run/gateway.sock" "$(cat $W/credentials/gateway-agent-token)" <<'PY' || RC=1
import http.client, socket, sys
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect(sys.argv[1])
def get(tok):
    c = C("localhost", timeout=30); c.request("GET", "/stockapp/api/quote/ACME", headers={"Authorization": "Bearer " + tok} if tok else {})
    r = c.getresponse(); r.read(); return r.status
ok, noauth = get(sys.argv[2]), get("")
print(f"unix socket: quote {ok}, no token {noauth}")
sys.exit(0 if ok == 200 and noauth == 401 else 1)
PY
kill $PID $APP; wait $PID 2>/dev/null
grep -c . $W/log >/dev/null && grep -i "gateway" $W/log
rm -rf $W
exit $RC
