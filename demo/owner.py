"""Stands in for the owner during the demo: answers held calls on GuardFil's
owner-only approver socket.  Rule of thumb: allow held orders worth under
2,000; deny everything else (withdrawals, shell, unknown).  Prints each answer
with the arguments the owner saw.  usage: owner.py APPROVER_SOCK SECONDS"""
import http.client
import json
import socket
import sys
import time
from decimal import Decimal


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("owner")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


def req(path, method, url, body=None):
    c = UnixHTTP(path)
    c.request(method, url, body=json.dumps(body) if body else None, headers={"Content-Type": "application/json"})
    r = c.getresponse()
    return r.status, r.read()


def judge(p):
    if p.get("tool") != "stockapp.place_order":
        return "deny", "not an order"
    try:
        a = json.loads(p.get("detail") or "{}", parse_float=Decimal)
        value = Decimal(str(a["quantity"])) * Decimal(str(a["limit_price"]))
    except Exception:
        return "deny", "order value unknown"
    return ("allow", f"value {value} < 2000") if value < 2000 else ("deny", f"value {value} >= 2000")


sock, end = sys.argv[1], time.time() + float(sys.argv[2])
seen = set()
while time.time() < end:
    try:
        st, body = req(sock, "GET", "/v1/approvals")
        for p in json.loads(body) if st == 200 else []:
            if p["id"] in seen:
                continue
            seen.add(p["id"])
            d, why = judge(p)
            req(sock, "POST", "/v1/approvals/" + p["id"], {"decision": d})
            print(f"owner: {p.get('tool')} {p.get('detail', '')[:160]} -> {d} ({why})", flush=True)
    except (OSError, ValueError):
        pass
    time.sleep(0.3)
