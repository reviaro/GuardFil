"""Anthropic Messages passthrough broker for Claude Code inside the executor.

    python3 -m broker.messages_broker --sockdir DIR --label NAME [--max-requests N]

Claude Code talks to the relay in its executor (ANTHROPIC_BASE_URL on
127.0.0.1); the relay hands each POST /v1/messages body to this broker as one
frame (4-byte length + body) and gets back one frame (4-byte status, 4-byte
length, body).  The broker holds the Anthropic key and the Anthropic $2 ledger.
The key never leaves this process.

Each request is checked, then billed under one reservation:

- **Only listed top-level fields** are passed on.  Anything else is refused,
  including ``mcp_servers`` (Anthropic's server-side MCP connector) and
  ``container`` (code execution).
- **Only client tools.** A tool with a ``type`` other than ``custom`` is a
  provider-side tool (web search, web fetch, code execution) that would reach
  the internet from Anthropic's side, around the executor, so it is refused.
  Server-tool content blocks are refused too.
- **Only the priced model** (``claude-sonnet-5-5``).
- ``max_tokens`` is capped at the ledger's output limit, and extended thinking
  is removed (it needs a larger budget than that limit), with the tuning
  fields that depend on it (``context_management``, ``output_config``).
- The free ``count_tokens`` call sizes the reservation.  Prompt-cache writes
  are counted at 1.25x (5-minute) or 2x (1-hour, and any write the reply does
  not break down) and reads at 0.1x, rounded up, so the count never falls
  below Anthropic's bill.  The reservation assumes every input token is a
  1-hour write.
- The broker asks Anthropic without streaming, so a reply is either complete
  or an error that is not billed.  If Claude Code asked for a stream, the
  complete reply is sent back as one SSE body.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import socket
import struct
import sys
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from broker.adapters import HTTPRequest, _exact
from broker.input_boundary import remote_input_error
from broker.neutral_broker import (KEY_DIR, KEY_FILES, LEDGER_FAILURE_CODES, LEDGER_ROOTS, PROVIDER_CEILING_MICROS,
                                   PROVIDER_TIMEOUT_SEC, RETIRED_LEDGER_SPEND, RETRY_DELAYS_SEC, RETRY_STATUSES,
                                   Transport, _provider_message, https_transport)
from research.t2a.openai_broker.smoke import load_key, open_or_init_ledger
from research.t2a.openai_budget import MAX_OUTPUT_TOKENS, MIN_RESERVATION_MICROS, MODEL_RATES, \
    RESERVATION_AMOUNT_MICROS, Receipt

PROVIDER = "anthropic"
MODEL = "claude-sonnet-5-5"
HOST = "api.anthropic.com"
HEADERS = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
ALLOWED_FIELDS = frozenset({"model", "messages", "system", "max_tokens", "metadata", "stop_sequences", "stream",
                            "temperature", "top_p", "top_k", "tools", "tool_choice", "thinking"})
# Client tuning fields removed before sending: they depend on thinking (removed
# here) or on beta headers the relay does not pass, and carry no tools or URLs.
STRIPPED_FIELDS = frozenset({"context_management", "output_config"})
COUNT_FIELDS = ("model", "messages", "system", "tools", "tool_choice")
CONTENT_TYPES = frozenset({"text", "image", "document", "tool_use", "tool_result", "thinking", "redacted_thinking"})
TOOL_CHOICE_TYPES = frozenset({"auto", "any", "tool", "none"})
# Statuses for a request Anthropic refused without processing (not billed).
UNBILLED_STATUSES = frozenset({400, 401, 403, 404, 413, 422}) | RETRY_STATUSES | {529}
CACHE_WRITE_FACTOR = 2
INPUT_MARGIN_TOKENS = 512
MAX_SESSION_REQUESTS = 64
MAX_FRAME_BYTES = 4 << 20


class Refused(ValueError):
    pass


def _error(status: int, kind: str, message: str) -> Tuple[int, bytes]:
    return status, json.dumps({"type": "error", "error": {"type": kind, "message": "GuardFil broker: " + message}}).encode()


def check_request(req: Any) -> Dict[str, Any]:
    """The request as it will be sent, or Refused."""
    if not isinstance(req, dict):
        raise Refused("the body must be a JSON object")
    remote_error = remote_input_error(req)
    if remote_error:
        raise Refused(remote_error)
    extra = sorted(set(req) - ALLOWED_FIELDS - STRIPPED_FIELDS)
    if extra:
        shown = _exact({k: req[k] for k in extra})[:300]
        raise Refused(f"field(s) not allowed: {', '.join(extra)} ({shown})")
    if req.get("model") != MODEL:
        raise Refused(f"only {MODEL} is allowed (got {req.get('model')!r})")
    if not isinstance(req.get("messages"), list) or not req["messages"]:
        raise Refused("messages must be a non-empty list")
    for m in req["messages"]:
        if not isinstance(m, dict) or m.get("role") not in ("user", "assistant", "system"):
            raise Refused("each message needs role user, assistant or system (got "
                          + (repr(sorted(m))[:120] + " role " + repr(m.get("role")) if isinstance(m, dict) else type(m).__name__) + ")")
        content = m.get("content")
        if m["role"] == "system" and isinstance(content, list) and any(
                not isinstance(b, dict) or b.get("type") != "text" for b in content):
            raise Refused("a system message may hold only text")
        if isinstance(content, list):
            for b in content:
                if not isinstance(b, dict) or b.get("type") not in CONTENT_TYPES:
                    raise Refused(f"content block type {b.get('type') if isinstance(b, dict) else b!r} is not allowed")
        elif not isinstance(content, str):
            raise Refused("message content must be text or a list of blocks")
    tools = req.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            raise Refused("tools must be a list")
        for t in tools:
            if not isinstance(t, dict) or t.get("type", "custom") != "custom" or "input_schema" not in t:
                kind = t.get("type") if isinstance(t, dict) else t
                raise Refused(f"only client tools are allowed; provider-side tool {kind!r} refused")
    tc = req.get("tool_choice")
    if tc is not None and (not isinstance(tc, dict) or tc.get("type") not in TOOL_CHOICE_TYPES):
        raise Refused("tool_choice type not allowed")
    out = {k: v for k, v in req.items() if k not in STRIPPED_FIELDS}
    # A message is its role and content; other per-message keys are dropped.
    out["messages"] = [{"role": m["role"], "content": m["content"]} for m in req["messages"]]
    out.pop("thinking", None)
    out.pop("stream", None)
    mt = out.get("max_tokens")
    if type(mt) is not int or mt < 1:
        raise Refused("max_tokens must be a positive integer")
    out["max_tokens"] = min(mt, MAX_OUTPUT_TOKENS)
    return out


def billable_input(usage: Mapping[str, Any]) -> int:
    """Input tokens as the ledger counts them: never below Anthropic's bill."""
    def n(k: str) -> int:
        v = usage.get(k) or 0
        if type(v) is not int or v < 0:
            raise ValueError(f"usage.{k} is not a count")
        return v
    writes = CACHE_WRITE_FACTOR * n("cache_creation_input_tokens")
    split = usage.get("cache_creation")
    if isinstance(split, Mapping):
        m5, h1 = split.get("ephemeral_5m_input_tokens") or 0, split.get("ephemeral_1h_input_tokens") or 0
        if type(m5) is int and type(h1) is int and m5 >= 0 and h1 >= 0 and m5 + h1 == n("cache_creation_input_tokens"):
            writes = math.ceil(m5 * 5 / 4) + 2 * h1   # 5-minute writes 1.25x, 1-hour writes 2x
    return n("input_tokens") + writes + math.ceil(n("cache_read_input_tokens") / 10)


def reservation(counted_input: int, max_tokens: int) -> int:
    rin, rout, _ = MODEL_RATES[MODEL]
    return max(MIN_RESERVATION_MICROS,
               (CACHE_WRITE_FACTOR * counted_input + INPUT_MARGIN_TOKENS) * rin + max_tokens * rout)


def sse(msg: Mapping[str, Any]) -> bytes:
    """A complete Message as the event stream the Messages API would have sent."""
    def ev(name: str, data: Mapping[str, Any]) -> str:
        return f"event: {name}\ndata: {_exact(data)}\n\n"
    usage = dict(msg.get("usage") or {})
    start = {k: v for k, v in msg.items() if k not in ("content", "stop_reason", "stop_sequence")}
    start.update(content=[], stop_reason=None, stop_sequence=None, usage=dict(usage, output_tokens=1))
    parts = [ev("message_start", {"type": "message_start", "message": start})]
    for i, b in enumerate(msg.get("content") or []):
        t = b.get("type")
        if t == "text":
            first, delta = {"type": "text", "text": ""}, {"type": "text_delta", "text": b.get("text", "")}
        elif t == "tool_use":
            first = {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}
            delta = {"type": "input_json_delta", "partial_json": _exact(b.get("input") or {})}
        else:   # thinking / redacted_thinking are removed from requests; pass any other block whole
            first, delta = b, None
        parts.append(ev("content_block_start", {"type": "content_block_start", "index": i, "content_block": first}))
        if delta is not None:
            parts.append(ev("content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta}))
        parts.append(ev("content_block_stop", {"type": "content_block_stop", "index": i}))
    parts.append(ev("message_delta", {"type": "message_delta",
                                      "delta": {"stop_reason": msg.get("stop_reason"),
                                                "stop_sequence": msg.get("stop_sequence")},
                                      "usage": {"output_tokens": usage.get("output_tokens", 0)}}))
    parts.append(ev("message_stop", {"type": "message_stop"}))
    return "".join(parts).encode()


class MessagesBroker:
    def __init__(self, ledger: Any, key: str, label: str, max_requests: int, transport: Transport = https_transport,
                 prior_micros: int = 0, evidence: Optional[Path] = None):
        if not 1 <= max_requests <= MAX_SESSION_REQUESTS:
            raise ValueError("max_requests out of range")
        self.ledger, self.key, self.label, self.max_requests = ledger, key, label, max_requests
        self.transport, self.prior, self.evidence = transport, prior_micros, evidence
        self.count = 0
        self.stopped = False
        self.sleep = time.sleep
        self.busy = False
        self.stop_requested = False

    def _record(self, **fields: Any) -> None:
        fields["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = json.dumps(fields, sort_keys=True)
        print(line, file=sys.stderr, flush=True)
        if self.evidence is not None:
            with open(self.evidence, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _send(self, req: HTTPRequest, request_id: str = "") -> Tuple[int, bytes]:
        auth = {"x-api-key": self.key}
        status, body = self.transport(req, auth)
        for delay in RETRY_DELAYS_SEC:
            if status not in RETRY_STATUSES | {529}:
                break
            self._record(request_id=request_id, outcome="RETRY", status=status, detail=_provider_message(body))
            self.sleep(delay)
            status, body = self.transport(req, auth)
        return status, body

    def _fail(self, permit: Any, request_id: str, code: str, **extra: Any) -> None:
        try:
            self.ledger.record_failure(permit, LEDGER_FAILURE_CODES.get(code, "TERMINAL_UNCERTAINTY"))
        except Exception:
            pass
        self.stopped = True
        self._record(request_id=request_id, outcome=code, **extra)

    def _settle(self, permit: Any, receipt: Receipt, request_id: str) -> Any:
        try:
            return self.ledger.settle(permit, receipt)
        except Exception as e:
            self._fail(permit, request_id, "SETTLEMENT_FAILED", detail=type(e).__name__)
            return None

    def handle(self, raw: bytes) -> Tuple[int, bytes]:
        if self.stopped:
            return _error(503, "api_error", "stopped after a ledger or provider failure")
        try:
            req = json.loads(raw, parse_float=Decimal)
            wants_stream = isinstance(req, dict) and req.get("stream") is True
            out = check_request(req)
        except (ValueError, Refused) as e:
            self._record(outcome="REFUSED", detail=str(e)[:300])
            return _error(400, "invalid_request_error", str(e))
        if self.count >= self.max_requests:
            return _error(429, "rate_limit_error", "this session's request limit is reached")
        body = _exact(out).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        count_body = _exact({k: out[k] for k in COUNT_FIELDS if k in out}).encode()
        try:
            status, cbody = self._send(HTTPRequest(HOST, "/v1/messages/count_tokens", dict(HEADERS), count_body))
        except Exception:
            return _error(502, "api_error", "Anthropic unreachable (count_tokens; nothing was spent)")
        if status != 200:
            self._record(outcome="PREFLIGHT_REFUSED", status=status, detail=_provider_message(cbody))
            return status, cbody
        try:
            counted = json.loads(cbody)["input_tokens"]
            if type(counted) is not int or counted < 0:
                raise ValueError
        except Exception:
            return _error(502, "api_error", "count_tokens reply unusable; nothing was spent")
        amount = reservation(counted, out["max_tokens"])
        if amount > RESERVATION_AMOUNT_MICROS:
            return _error(400, "invalid_request_error", "request too large for one reservation")
        self.count += 1
        request_id = f"messages-{self.label}-{self.count}"
        try:
            st = self.ledger.get_status()
            over = self.prior + st.total_encumbered_micros + amount > PROVIDER_CEILING_MICROS
        except Exception:
            over = True
        if over:
            self._record(request_id=request_id, outcome="PROVIDER_CEILING")
            return _error(429, "rate_limit_error", "Anthropic's $2 would be exceeded")
        try:
            permit = self.ledger.reserve(request_id, digest, amount)
        except Exception as e:
            self.stopped = True
            self._record(request_id=request_id, outcome="RESERVE_FAILED", detail=type(e).__name__)
            return _error(429, "rate_limit_error", "the $2 ledger refused the request")
        try:
            status, rbody = self._send(HTTPRequest(HOST, "/v1/messages", dict(HEADERS), body), request_id)
        except Exception:
            self._fail(permit, request_id, "REQUEST_TRANSPORT_FAILURE")
            return _error(502, "api_error", "Anthropic unreachable")
        if status != 200:
            if status not in UNBILLED_STATUSES:
                self._fail(permit, request_id, "INVALID_PROVIDER_REPLY", status=status)
                return _error(502, "api_error", f"unexpected Anthropic status {status}")
            # Refused or overloaded without processing: not billed, so closed at zero tokens.
            zero = Receipt(status="completed", response_id=f"unbilled-{status}-{request_id}", request_id=request_id,
                           request_digest=digest, model=MODEL, service_tier=MODEL_RATES[MODEL][2],
                           input_tokens=0, output_tokens=0, total_tokens=0)
            if self._settle(permit, zero, request_id) is None:
                return _error(502, "api_error", "the ledger could not settle the request")
            self._record(request_id=request_id, outcome="UNBILLED_PROVIDER_ERROR", status=status,
                         detail=_provider_message(rbody), reserved_micros=amount)
            return status, rbody
        try:
            msg = json.loads(rbody, parse_float=Decimal)
            if msg.get("type") != "message" or not isinstance(msg.get("id"), str):
                raise ValueError("not a message")
            usage = msg.get("usage") or {}
            in_tok, out_tok = billable_input(usage), usage.get("output_tokens")
            if type(out_tok) is not int or out_tok < 0:
                raise ValueError("output_tokens missing")
            tier = usage.get("service_tier") or MODEL_RATES[MODEL][2]
        except (ValueError, TypeError, AttributeError) as e:
            self._fail(permit, request_id, "INVALID_PROVIDER_REPLY", status=status, detail=str(e)[:100])
            return _error(502, "api_error", "Anthropic reply unusable")
        receipt = Receipt(status="completed", response_id=msg["id"], request_id=request_id, request_digest=digest,
                          model=msg.get("model", ""), service_tier=tier, input_tokens=in_tok, output_tokens=out_tok,
                          total_tokens=in_tok + out_tok)
        settled = self._settle(permit, receipt, request_id)
        if settled is None:
            return _error(502, "api_error", "the ledger could not settle the request")
        self._record(request_id=request_id, outcome="SETTLED", counted_input=counted, input_tokens=in_tok,
                     output_tokens=out_tok, reserved_micros=amount,
                     cost_micros=getattr(settled, "accounted_cost_micros", None),
                     tools=[b.get("name") for b in msg.get("content") or [] if b.get("type") == "tool_use"])
        return 200, (sse(msg) if wants_stream else _exact(msg).encode())

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
        print("MESSAGES_BROKER_READY", flush=True)
        try:
            while True:   # serial: the ledger allows one request in flight
                conn, _ = srv.accept()
                self.busy = True
                with conn:
                    conn.settimeout(30)
                    try:
                        head = _recv(conn, 4)
                        n = struct.unpack(">I", head)[0]
                        if n > MAX_FRAME_BYTES:
                            status, body = _error(413, "invalid_request_error", "request too large")
                        else:
                            status, body = self.handle(_recv(conn, n))
                        conn.settimeout(PROVIDER_TIMEOUT_SEC)
                        conn.sendall(struct.pack(">II", status, len(body)) + body)
                    except (OSError, struct.error, EOFError):
                        pass
                self.busy = False
                if self.stop_requested:
                    break
        finally:
            srv.close()
            if sock_path.exists():
                sock_path.unlink()

    def request_stop(self) -> None:
        self.stop_requested = True
        if not self.busy:
            raise KeyboardInterrupt()


def _recv(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(min(65536, n - len(buf)))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m broker.messages_broker")
    ap.add_argument("--sockdir", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--max-requests", type=int, default=24)
    ap.add_argument("--evidence")
    a = ap.parse_args(argv)
    key_path = KEY_DIR / KEY_FILES[PROVIDER]
    if not key_path.exists():
        print(f"no Anthropic key at {key_path}", file=sys.stderr)
        return 1
    root, experiment_id = LEDGER_ROOTS[PROVIDER]
    ledger = open_or_init_ledger(root, initialize=True, experiment_id=experiment_id)
    if not ledger.get_status().can_reserve:
        print("the Anthropic ledger cannot reserve", file=sys.stderr)
        return 1
    b = MessagesBroker(ledger, load_key(key_path), a.label, a.max_requests,
                       prior_micros=RETIRED_LEDGER_SPEND.get(PROVIDER, 0),
                       evidence=Path(a.evidence) if a.evidence else None)
    signal.signal(signal.SIGTERM, lambda *_: b.request_stop())
    try:
        b.serve(Path(a.sockdir) / "broker.sock")
    except KeyboardInterrupt:
        pass
    finally:
        st = ledger.get_status()
        print(f"MESSAGES_BROKER_DONE requests={b.count} anthropic_total_micros={st.total_spend_micros}", flush=True)
        ledger.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
