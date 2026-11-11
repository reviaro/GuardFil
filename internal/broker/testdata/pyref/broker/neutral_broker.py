"""GuardFil's model-neutral broker (host side).

Agents (in networkless containers) send one provider-neutral request per
connection on a Unix socket; the broker holds the provider keys, charges the
single cumulative $2 ledger, calls the provider through its adapter and
returns a neutral reply.  The agent never sees a key or a provider format.

    python3 -m broker.neutral_broker --sockdir DIR --label demo-1 --max-requests 20

Only providers in LIVE_PROVIDERS are ever called, and only their models in
PROVIDER_MODELS that the ledger prices (MODEL_RATES).  Each provider has its
own $2 ledger; OpenAI keeps the original one.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import signal
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from broker.adapters import ADAPTERS, HTTPRequest, NeutralError, encode_arguments, validate
from research.t2a.openai_broker.smoke import DEFAULT_EXPERIMENT_ROOT, load_key, open_or_init_ledger
from research.t2a.openai_budget import (
    MAX_OUTPUT_TOKENS,
    MIN_RESERVATION_MICROS,
    MODEL_RATES,
    RESERVATION_AMOUNT_MICROS,
    Receipt,
)

LIVE_PROVIDERS = frozenset({"openai", "gemini", "anthropic"})
# Models each provider may be called with (each must also be priced in MODEL_RATES).
PROVIDER_MODELS = {"openai": frozenset({"gpt-6-luna"}), "gemini": frozenset({"gemini-3.6-flash", "gemini-3.5-flash-lite"}),
                   "anthropic": frozenset({"claude-sonnet-5-5"})}
STATE_ROOT = Path("~/.local/state/guardfil").expanduser()
# provider -> (ledger root, experiment id).  OpenAI keeps the original $2 ledger.
LEDGER_ROOTS = {"openai": (DEFAULT_EXPERIMENT_ROOT, None),
                "gemini": (STATE_ROOT / "gemini-experiment-6", "guardfil-m4-gemini-6"),
                "anthropic": (STATE_ROOT / "anthropic-experiment", "guardfil-m4-anthropic")}
# Halted ledgers a provider used before its current one.  Their counted spend
# (settled plus retained), in micro-USD, still counts toward that provider's
# single $2: the broker refuses a reservation that would take the sum over $2.
# Empty by default: a new installation has none.
RETIRED_LEDGER_SPEND: dict = {}
PROVIDER_CEILING_MICROS = 2_000_000
KEY_DIR = Path("~/.config/guardfil/credentials.d").expanduser()
KEY_FILES = {"openai": "openai-api-key", "anthropic": "anthropic-api-key", "gemini": "gemini-api-key"}
MAX_REQUEST_BYTES = 1 << 20
MAX_REPLY_BYTES = 4 << 20
MAX_SESSION_REQUESTS = 64
INPUT_MARGIN_TOKENS = 512
PROVIDER_TIMEOUT_SEC = 150   # thinking models under load can take over a minute
# Provider statuses that mean "not processed, not billed; try again" (rate limit, overload).
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRY_DELAYS_SEC = (5, 15, 30, 65)   # >60 s in total so a per-minute quota resets; the client waits up to 600 s
# Broker evidence code -> the ledger's allowed failure code.
LEDGER_FAILURE_CODES = {"REQUEST_TRANSPORT_FAILURE": "REQUEST_TRANSPORT_FAILURE",
                        "INVALID_PROVIDER_REPLY": "RECEIPT_SCHEMA_VIOLATION",
                        "SETTLEMENT_FAILED": "TERMINAL_UNCERTAINTY"}

Transport = Callable[[HTTPRequest, Mapping[str, str]], Tuple[int, bytes]]


def https_transport(req: HTTPRequest, auth: Mapping[str, str]) -> Tuple[int, bytes]:
    conn = http.client.HTTPSConnection(req.host, 443, timeout=PROVIDER_TIMEOUT_SEC, context=ssl.create_default_context())
    try:
        headers = dict(req.headers, **auth, Accept="application/json")
        conn.request("POST", req.path, body=req.body, headers=headers)
        resp = conn.getresponse()
        body = resp.read(MAX_REPLY_BYTES + 1)
        if len(body) > MAX_REPLY_BYTES:
            raise IOError("provider reply too large")
        return resp.status, body
    finally:
        conn.close()


def reservation_micros(model: str, body: bytes, max_output_tokens: int) -> int:
    """Worst case for one request: every input byte a token (an upper bound for these
    providers' tokenizers on UTF-8 text) plus a margin, and the whole output cap."""
    rin, rout, _ = MODEL_RATES[model]
    amount = (len(body) + INPUT_MARGIN_TOKENS) * rin + max_output_tokens * rout
    return max(MIN_RESERVATION_MICROS, amount)


class NeutralBroker:
    def __init__(self, ledgers: Any, label: str, max_requests: int, keys: Mapping[str, str],
                 transport: Transport = https_transport, evidence: Optional[Path] = None,
                 live_providers: frozenset = LIVE_PROVIDERS, provider_models: Optional[Mapping[str, frozenset]] = PROVIDER_MODELS,
                 prior_spend: Optional[Mapping[str, int]] = None):
        if not 1 <= max_requests <= MAX_SESSION_REQUESTS:
            raise ValueError("max_requests out of range")
        # provider -> ledger; a single ledger object (tests) serves every provider.
        self.ledgers = dict(ledgers) if isinstance(ledgers, Mapping) else {p: ledgers for p in ADAPTERS}
        self.label, self.max_requests = label, max_requests
        self.keys = dict(keys)
        self.transport = transport
        self.evidence = evidence
        self.live = live_providers
        self.models = provider_models   # None (tests only): any priced model
        self.prior = dict(prior_spend or {})   # provider -> counted spend on its retired ledgers
        self.count = 0
        self.stopped = False
        self.sleep = time.sleep
        self.busy = False          # a request is in flight: a stop waits for it
        self.stop_requested = False

    def request_stop(self) -> None:
        """SIGTERM: stop now if idle, else after the request in flight settles
        (stopping mid-request would leave an unsettled reservation, which halts the ledger)."""
        self.stop_requested = True
        if not self.busy:
            raise KeyboardInterrupt()

    def _record(self, **fields: Any) -> None:
        if self.evidence is None:
            return
        fields["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(self.evidence, "a", encoding="utf-8") as f:
            f.write(json.dumps(fields, sort_keys=True) + "\n")

    def handle(self, raw: bytes) -> Dict[str, Any]:
        """One neutral request -> {"ok": true, "reply": {...}} or {"ok": false, "error": "..."}."""
        if self.stopped:
            return {"ok": False, "error": "broker stopped after a ledger or provider failure"}
        try:
            req = json.loads(raw, parse_float=__import__("decimal").Decimal)
            provider, model = validate(req)
        except (ValueError, NeutralError) as e:
            return {"ok": False, "error": f"bad request: {e}"}
        if provider not in self.live:
            return {"ok": False, "error": f"provider {provider} is not enabled for live calls"}
        if model not in MODEL_RATES or (self.models is not None and model not in self.models.get(provider, ())):
            return {"ok": False, "error": f"model {model} is not priced in the ledger"}
        ledger = self.ledgers.get(provider)
        if ledger is None:
            return {"ok": False, "error": f"no ledger for {provider}"}
        if provider not in self.keys:
            return {"ok": False, "error": f"no key for {provider}"}
        if self.count >= self.max_requests:
            return {"ok": False, "error": "this session's request limit is reached"}
        adapter = ADAPTERS[provider]
        out = adapter.build(model, req)
        digest = "sha256:" + hashlib.sha256(out.body).hexdigest()
        if hasattr(adapter, "preflight"):
            try:
                status, body = self._send(adapter.preflight(model, out), adapter.auth(self.keys[provider]))
            except Exception:
                return {"ok": False, "error": "provider unreachable (preflight; nothing was spent)"}
            if status != 200:
                detail = _provider_message(body)
                self._record(model=model, provider=provider, outcome="PREFLIGHT_REFUSED", status=status, detail=detail)
                return {"ok": False, "error": f"provider refused the request before any spend (HTTP {status}): {detail}"}
        self.count += 1
        request_id = f"neutral-{self.label}-{self.count}"
        amount = reservation_micros(model, out.body, req.get("max_output_tokens", MAX_OUTPUT_TOKENS))
        if amount > RESERVATION_AMOUNT_MICROS:
            return {"ok": False, "error": "request too large for one reservation"}
        if self.prior.get(provider):
            try:
                st = ledger.get_status()
                over = self.prior[provider] + st.total_encumbered_micros + amount > PROVIDER_CEILING_MICROS
            except Exception:
                over = True
            if over:
                self._record(request_id=request_id, model=model, outcome="PROVIDER_CEILING", prior_micros=self.prior[provider])
                return {"ok": False, "error": f"{provider}'s $2 across all its ledgers would be exceeded"}
        try:
            permit = ledger.reserve(request_id, digest, amount)
        except Exception as e:  # budget exhausted, halted, ...
            self.stopped = True
            self._record(request_id=request_id, model=model, outcome="RESERVE_FAILED", detail=type(e).__name__)
            return {"ok": False, "error": "the $2 ledger refused the request (budget or ledger state)"}
        try:
            status, body = self._send(out, adapter.auth(self.keys[provider]), request_id)
        except Exception:
            self._fail(ledger, permit, request_id, model, "REQUEST_TRANSPORT_FAILURE")
            return {"ok": False, "error": "provider unreachable"}
        if status in RETRY_STATUSES:
            # Still overloaded or rate-limited after every retry.  The provider bills
            # nothing for such a reply, so the reservation is closed at zero tokens
            # (the response id names the status) instead of halting this provider's ledger.
            unbilled = Receipt(status="completed", response_id=f"unbilled-{status}-{request_id}", request_id=request_id,
                               request_digest=digest, model=model, service_tier=MODEL_RATES[model][2],
                               input_tokens=0, output_tokens=0, total_tokens=0)
            try:
                ledger.settle(permit, unbilled)
            except Exception as e:
                self._fail(ledger, permit, request_id, model, "SETTLEMENT_FAILED", detail=type(e).__name__)
                return {"ok": False, "error": "the ledger could not settle the request"}
            self._record(request_id=request_id, model=model, provider=provider, outcome="UNBILLED_PROVIDER_ERROR",
                         status=status, detail=_provider_message(body), reserved_micros=amount, cost_micros=0)
            return {"ok": False, "error": f"provider busy (HTTP {status}) after retries; nothing was billed, try again later"}
        try:
            reply = adapter.parse(status, body)
        except (NeutralError, ValueError, KeyError, TypeError) as e:
            self._fail(ledger, permit, request_id, model, "INVALID_PROVIDER_REPLY", status=status)
            return {"ok": False, "error": f"provider reply unusable ({e})"}
        u = reply["usage"]
        reported = reply["model"]
        # Gemini reports a dated version ("gemini-3.8-flash-001"); it is priced as the model asked for.
        priced = model if provider == "gemini" and reported.startswith(model) else reported
        receipt = Receipt(status="completed", response_id=reply["response_id"], request_id=request_id,
                          request_digest=digest, model=priced, service_tier=reply.get("service_tier") or "",
                          input_tokens=u["input_tokens"], output_tokens=u["output_tokens"],
                          total_tokens=u["input_tokens"] + u["output_tokens"])
        try:
            settled = ledger.settle(permit, receipt)
        except Exception as e:
            self._fail(ledger, permit, request_id, model, "SETTLEMENT_FAILED", detail=type(e).__name__)
            return {"ok": False, "error": "the ledger could not settle the request"}
        self._record(request_id=request_id, model=reported, provider=provider, outcome="SETTLED",
                     input_tokens=u["input_tokens"], output_tokens=u["output_tokens"],
                     reserved_micros=amount, cost_micros=getattr(settled, "accounted_cost_micros", None),
                     tool_calls=[c["name"] for c in reply["tool_calls"]])
        reply.pop("service_tier", None)
        return {"ok": True, "reply": reply}

    def _send(self, out: HTTPRequest, auth: Mapping[str, str], request_id: str = "") -> Tuple[int, bytes]:
        """One provider call, retried while the provider answers with a transient
        error.  Such a reply is not billed, so the one reservation covers every try."""
        status, body = self.transport(out, auth)
        for delay in RETRY_DELAYS_SEC:
            if status not in RETRY_STATUSES:
                break
            self._record(request_id=request_id, outcome="RETRY", status=status, path=out.path.rsplit(":", 1)[-1],
                         detail=_provider_message(body))
            self.sleep(delay)
            status, body = self.transport(out, auth)
        return status, body

    def _fail(self, ledger: Any, permit: Any, request_id: str, model: str, code: str, **extra: Any) -> None:
        try:
            ledger.record_failure(permit, LEDGER_FAILURE_CODES.get(code, "TERMINAL_UNCERTAINTY"))
        except Exception:
            pass
        self.stopped = True
        self._record(request_id=request_id, model=model, outcome=code, **extra)

    def serve(self, sock_path: Path) -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if sock_path.exists():
            sock_path.unlink()
        old = os.umask(0o077)
        try:
            srv.bind(str(sock_path))
        finally:
            os.umask(old)
        srv.listen(8)
        print("NEUTRAL_BROKER_READY", flush=True)
        try:
            while True:  # serial: the ledger allows one request in flight
                conn, _ = srv.accept()
                self.busy = True
                with conn:
                    conn.settimeout(30)
                    data = b""
                    try:
                        while b"\n" not in data and len(data) <= MAX_REQUEST_BYTES:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                    except OSError:
                        continue
                    if len(data) > MAX_REQUEST_BYTES:
                        res = {"ok": False, "error": "request too large"}
                    else:
                        res = self.handle(data.split(b"\n", 1)[0])
                    conn.settimeout(PROVIDER_TIMEOUT_SEC)
                    try:
                        conn.sendall(_dump(res).encode() + b"\n")
                    except OSError:
                        pass
                self.busy = False
                if self.stop_requested:
                    break
        finally:
            srv.close()
            if sock_path.exists():
                sock_path.unlink()


def _provider_message(body: bytes) -> str:
    """The provider's error message (never contains the key), shortened."""
    try:
        msg = json.loads(body)["error"]["message"]
    except Exception:
        msg = body[:200].decode("utf-8", "replace")
    return str(msg)[:300]


def _dump(obj: Any) -> str:
    """JSON with exact decimals in tool call arguments."""
    if isinstance(obj, dict) and isinstance(obj.get("reply"), dict):
        reply = dict(obj["reply"])
        calls = reply.pop("tool_calls", [])
        head = json.dumps(dict(obj, reply=reply), ensure_ascii=False)
        enc = "[" + ",".join('{"id":%s,"name":%s,"arguments":%s}' % (json.dumps(c["id"]), json.dumps(c["name"]),
                                                                       encode_arguments(c["arguments"])) for c in calls) + "]"
        # insert tool_calls into the reply object
        return head[:-2] + ',"tool_calls":' + enc + "}}"
    return json.dumps(obj, ensure_ascii=False)


def load_keys(providers: frozenset, key_dir: Path = KEY_DIR) -> Dict[str, str]:
    keys = {}
    for p in providers:
        path = key_dir / KEY_FILES[p]
        if path.exists():
            keys[p] = load_key(path)
    return keys


CHECK_PATHS = {"openai": ("api.openai.com", "/v1/models/{m}"), "gemini": ("generativelanguage.googleapis.com", "/v1beta/models/{m}"),
               "anthropic": ("api.anthropic.com", "/v1/models/{m}")}


def check(keys: Mapping[str, str]) -> int:
    """Free check (no ledger, no spend): each keyed provider's models endpoint
    knows the allowed model.  Prints the HTTP status and the model's name only."""
    bad = 0
    for p in sorted(keys):
        for m in sorted(PROVIDER_MODELS[p]):
            host, path = CHECK_PATHS[p]
            headers = dict(ADAPTERS[p].auth(keys[p]), Accept="application/json")
            if p == "anthropic":
                headers["anthropic-version"] = "2023-06-01"
            conn = http.client.HTTPSConnection(host, 443, timeout=30, context=ssl.create_default_context())
            try:
                conn.request("GET", path.format(m=m), headers=headers)
                r = conn.getresponse()
                body = r.read(1 << 20)
            finally:
                conn.close()
            info = {}
            try:
                d = json.loads(body)
                info = {k: d[k] for k in ("name", "id", "displayName", "version", "outputTokenLimit", "thinking") if k in d}
            except ValueError:
                pass
            print(f"CHECK {p}:{m} HTTP {r.status} {json.dumps(info) if r.status == 200 else _provider_message(body)}")
            bad += r.status != 200
    return 1 if bad else 0


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="GuardFil model-neutral broker")
    ap.add_argument("--check", action="store_true", help="free key and model check, then exit (no spend)")
    ap.add_argument("--sockdir")
    ap.add_argument("--label")
    ap.add_argument("--max-requests", type=int, default=16)
    a = ap.parse_args(argv)
    if a.check:
        return check(load_keys(LIVE_PROVIDERS))
    if not a.sockdir or not a.label:
        ap.error("--sockdir and --label are required")
    if not a.label.replace("-", "").isalnum() or len(a.label) > 48:
        ap.error("label: letters, digits and -")
    sockdir = Path(a.sockdir)
    sockdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sockdir, 0o700)
    keys = load_keys(LIVE_PROVIDERS)
    ledgers = {}
    for provider in sorted(keys):
        root, experiment_id = LEDGER_ROOTS[provider]
        ledger = (open_or_init_ledger(root) if experiment_id is None else
                  open_or_init_ledger(root, initialize=True, experiment_id=experiment_id))
        if ledger.get_status().can_reserve:
            ledgers[provider] = ledger
        else:
            print(f"{provider} ledger cannot reserve; {provider} disabled", file=sys.stderr)
            ledger.close()
    prior = {p: RETIRED_LEDGER_SPEND[p] for p in ledgers if p in RETIRED_LEDGER_SPEND}
    if prior:
        print("NEUTRAL_BROKER_PRIOR_SPEND " + json.dumps(prior, sort_keys=True), file=sys.stderr, flush=True)
    if not ledgers:
        print("no provider has a key and a usable ledger", file=sys.stderr)
        return 1
    print("NEUTRAL_BROKER_PROVIDERS " + ",".join(sorted(ledgers)), file=sys.stderr, flush=True)
    b = NeutralBroker(ledgers, a.label, a.max_requests, {p: keys[p] for p in ledgers}, prior_spend=prior,
                      evidence=Path(DEFAULT_EXPERIMENT_ROOT) / f"neutral-broker-{a.label}.jsonl")
    signal.signal(signal.SIGTERM, lambda *_: b.request_stop())
    signal.signal(signal.SIGINT, lambda *_: b.request_stop())
    try:
        b.serve(sockdir / "broker.sock")
    except KeyboardInterrupt:
        pass
    finally:
        for ledger in ledgers.values():
            ledger.close()
        print(f"NEUTRAL_BROKER_DONE requests={b.count}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
