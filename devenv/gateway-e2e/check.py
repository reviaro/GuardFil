"""Gateway end-to-end: an 'agent' calls the fake app only through GuardFil's
gateway; a script stands in for the owner in the web UI (allows held orders
worth under 2,000).  Prints one line per case and exits non-zero on a failure."""
import http.client, json, sys, threading, time

gw_port, ui_port, token, ui_token, applog, key = sys.argv[1:7]
APP_KEY = open(key).read().strip()
fails = []


def http_json(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", int(port), timeout=90)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else body.encode()
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    return r.status, r.read().decode(), r.getheader("Set-Cookie")


def agent(method, path, body=None, tok=None):
    st, b, _ = http_json(gw_port, method, path, body, {"Authorization": "Bearer " + (tok or token)})
    return st, b


cookie = None
session_token = None
def owner_api(method, path, body=None):
    global cookie, session_token
    headers = {"Cookie": cookie} if cookie else {}
    if session_token:
        headers["X-GuardFil-Session"] = session_token
    st, b, sc = http_json(ui_port, method, path, json.dumps(body) if body is not None else None,
                          headers)
    if sc and sc.startswith("gf_session="):
        cookie = sc.split(";", 1)[0]
    result = json.loads(b) if b else None
    if path == "/api/login" and st == 200:
        session_token = result["session_token"]
    return st, result


owner_api("POST", "/api/login", {"token": open(ui_token).read().strip()})
shown = []
def owner():
    seen = set()
    while True:
        for p in owner_api("GET", "/api/state")[1]["pending"]:
            if p["id"] in seen:
                continue
            seen.add(p["id"])
            detail = p["detail"]
            # Gateway approval previews now bind and display the actual
            # destination as well as the tool arguments.
            if detail.startswith("URL: "):
                target, _, detail = detail.partition("; arguments: ")
                if target != "URL: http://127.0.0.1:18100/api/orders":
                    fails.append("owner preview has wrong gateway URL")
            else:
                fails.append("owner preview omitted gateway URL")
            a = json.loads(detail)
            from decimal import Decimal
            v = Decimal(str(a.get("quantity", 0))) * Decimal(str(a.get("limit_price", "Infinity")))
            d = "allow" if v < 2000 else "deny"
            shown.append((p["tool"], p["detail"], d))
            owner_api("POST", "/api/approvals/" + p["id"], {"decision": d})
        time.sleep(0.2)
threading.Thread(target=owner, daemon=True).start()


def app_requests():
    return [json.loads(l) for l in open(applog)]


def case(name, want_status, method, path, body=None, tok=None, reaches_app=None, check=None):
    before = len(app_requests())
    st, b = agent(method, path, body, tok)
    after = app_requests()[before:]
    ok = st == want_status
    if reaches_app is not None:
        ok = ok and (len(after) == 1) == reaches_app
    if APP_KEY in b:
        ok = False
        b = "KEY LEAKED " + b
    if check:
        ok = ok and check(b, after)
    print(("PASS " if ok else "FAIL ") + f"{name}: {st} {b[:150]}" + (f"  | app got {after[0]['method']} {after[0]['path']} {after[0]['body']}" if after else "  | app got nothing"))
    if not ok:
        fails.append(name)


case("quote allowed, forwarded with the app key", 200, "GET", "/stockapp/api/quote/ACME", reaches_app=True,
     check=lambda b, a: a[0]["authed"])
case("portfolio (Filter rule): app key, password and AWS key removed, cash kept", 200, "GET", "/stockapp/api/portfolio",
     reaches_app=True, check=lambda b, a: "REDACTED-BY-GUARDFIL" in b and "hunter2" not in b and "AKIA" not in b
     and "1000.00" in b)
case("order 10 @ 12.50 = 125: monitored, forwarded exactly", 200, "POST", "/stockapp/api/orders",
     '{"symbol":"ACME","side":"buy","quantity":10,"limit_price":12.50}', reaches_app=True,
     check=lambda b, a: '"limit_price":12.50' in a[0]["body"])
case("order 100 @ 12.50 = 1250: held, owner allows, forwarded", 200, "POST", "/stockapp/api/orders",
     '{"symbol":"ACME","side":"buy","quantity":100,"limit_price":12.50}', reaches_app=True)
case("order 500 @ 12.50 = 6250: held, owner denies, never reaches app", 403, "POST", "/stockapp/api/orders",
     '{"symbol":"ACME","side":"buy","quantity":500,"limit_price":12.50}', reaches_app=False,
     check=lambda b, a: "APPROVAL_REJECTED" in b)
case("withdrawal: blocked by policy", 403, "POST", "/stockapp/api/withdrawals",
     '{"amount":100.00,"destination":"acct-9"}', reaches_app=False, check=lambda b, a: "block-withdrawals" in b)
case("cancel order: monitored", 200, "DELETE", "/stockapp/api/orders/o-17", reaches_app=True)
case("no gateway token", 401, "GET", "/stockapp/api/portfolio", tok="x" * 20, reaches_app=False)
case("app key used as gateway token", 401, "GET", "/stockapp/api/portfolio", tok=APP_KEY, reaches_app=False)
case("unmapped admin path", 403, "GET", "/stockapp/admin/users", reaches_app=False)
case("path traversal", 403, "GET", "/stockapp/api/quote/..%2Fadmin", reaches_app=False)
case("duplicate key smuggling a bigger quantity", 403, "POST", "/stockapp/api/orders",
     '{"symbol":"ACME","side":"buy","quantity":1,"limit_price":1,"quantity":100000}', reaches_app=False)

# The same Filter rule for an app's built-in agent, through the Python client.
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "../../clients/python"))
from guardfil_client import GuardFil, Blocked
gf = GuardFil(sys.argv[8], timeout=30)

@gf.guard("stockapp.get_portfolio")
def get_portfolio():
    return {"cash": "1000.00", "broker_login": {"user": "owner", "password": "hunter2-broker"},
            "note": "backup key AKIAIOSFODNN7EXAMPLE"}

res = get_portfolio()
ok = "hunter2" not in json.dumps(res) and "AKIA" not in json.dumps(res) and res["cash"] == "1000.00"
print(("PASS " if ok else "FAIL ") + "client @guard get_portfolio: result filtered: " + json.dumps(res))
if not ok:
    fails.append("client filter")
d = gf.check("stockapp.get_portfolio", {})
ok = not d.allowed and "TRANSFORM_UNAVAILABLE" in d.reasons
print(("PASS " if ok else "FAIL ") + f"client check() without can_filter: {d}")
if not ok:
    fails.append("client no can_filter")

decisions = [json.loads(l) for l in open(sys.argv[7])]
print("decision log entries:", len(decisions), "| tools:", sorted({d["tool"] for d in decisions}),
      "| filter entries:", [(d["tool"], d.get("redactions", 0)) for d in decisions if d["kind"] == "filter"])
if any("hunter2" in json.dumps(d) or "AKIA" in json.dumps(d) for d in decisions):
    print("FAIL secret in the decision log"); fails.append("log")
print("owner was shown:")
for s in shown:
    print("  ", s)
print("RESULT", "FAIL " + ", ".join(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
