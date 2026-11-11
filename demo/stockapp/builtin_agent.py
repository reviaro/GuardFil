"""The app's built-in agent.  It runs inside the app, with the app's key, and
asks GuardFil before every tool it runs (the Python decision client).  A Filter
rule's obligation is honored by @guard; a refused call is reported to the model.

usage: builtin_agent.py TASK   (env: MODEL, BROKER_SOCK, GUARDFIL_SOCK, APP_URL, APP_KEY_FILE)
"""
import http.client
import json
import os
import sys
from decimal import Decimal

sys.path[:0] = ["/demo", "/clients"]
from agent_loop import run  # noqa: E402
from guardfil_client import Blocked, GuardFil  # noqa: E402
from guardfil_model import ask_model  # noqa: E402

KEY = open(os.environ["APP_KEY_FILE"]).read().strip()
HOST, PORT = os.environ.get("APP_URL", "127.0.0.1:8000").split(":")
gf = GuardFil(os.environ["GUARDFIL_SOCK"], timeout=120)


def dec_body(d):
    """JSON body with exact decimal literals."""
    return "{" + ",".join(json.dumps(k) + ":" + (format(v, "f") if isinstance(v, Decimal) else json.dumps(v))
                          for k, v in d.items()) + "}"


def call(method, path, body=None):
    c = http.client.HTTPConnection(HOST, int(PORT), timeout=10)
    c.request(method, path, body=dec_body(body).encode() if body is not None else None,
              headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
    return json.loads(c.getresponse().read() or b"{}", parse_float=Decimal)


@gf.guard("stockapp.get_quote")
def get_quote(symbol):
    return call("GET", "/api/quote/" + symbol)


@gf.guard("stockapp.get_portfolio")
def get_portfolio():
    return call("GET", "/api/portfolio")


@gf.guard("stockapp.place_order")
def place_order(symbol, side, quantity, limit_price=None):
    body = {"symbol": symbol, "side": side, "quantity": quantity}
    if limit_price is not None:
        body["limit_price"] = limit_price
    return call("POST", "/api/orders", body)


@gf.guard("stockapp.cancel_order")
def cancel_order(order_id):
    return call("DELETE", "/api/orders/" + order_id)


@gf.guard("stockapp.withdraw_funds")
def withdraw_funds(amount, destination):
    return call("POST", "/api/withdrawals", {"amount": amount, "destination": destination})


@gf.guard("stockapp.get_news")
def get_news(symbol):
    return call("GET", "/api/news/" + symbol)


@gf.guard("stockapp.send_message")
def send_message(text):
    return call("POST", "/api/messages", {"text": text})


FUNCS = {f.__name__: f for f in (get_quote, get_portfolio, place_order, cancel_order, withdraw_funds, get_news, send_message)}


def execute(name, args):
    f = FUNCS.get(name)
    if f is None:
        return "error: unknown tool"
    try:
        out = f(**args)
    except Blocked as b:
        return f"refused by GuardFil: {b.decision}"
    except TypeError as e:
        return f"error: bad arguments ({e})"
    return json.dumps(out, default=lambda o: format(o, "f") if isinstance(o, Decimal) else str(o))


if __name__ == "__main__":
    print("task:", sys.argv[1], flush=True)
    answer = run(sys.argv[1], os.environ.get("MODEL", "openai:gpt-6-luna"),
                 lambda r: ask_model(os.environ["BROKER_SOCK"], r), execute,
                 log=lambda s: print(s, flush=True))
    print("final:", answer.strip(), flush=True)
