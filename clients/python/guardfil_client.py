"""Ask GuardFil before an application runs one of its agent's tools.

An app with a built-in AI agent calls GuardFil before executing a tool the agent
chose.  GuardFil decides it with the owner's policy (allow, block, monitor, or
hold it for the owner: "ask me") and logs the decision.  Standard library only.

    from decimal import Decimal
    from guardfil_client import GuardFil, Blocked

    gf = GuardFil("/home/me/.guardfil-local/run/approval.sock")

    d = gf.check("stockapp.place_order",
                 {"symbol": "ACME", "side": "buy", "quantity": 10, "limit_price": Decimal("12.50")})
    if d.allowed:
        place_order(...)

    # or wrap the tool function: it runs only when GuardFil allows the call
    @gf.guard("stockapp.place_order")
    def place_order(symbol, side, quantity, limit_price=None): ...

The tool must be listed in GuardFil's tool catalog (`approval.tool_catalog`),
with its arguments.  Pass exact amounts as `decimal.Decimal` (or int); floats
are refused, because a float cannot carry an exact price.

This is cooperative: it protects only the calls the app sends through it.  For
enforcement, keep the credentials that act (for example the brokerage key)
behind GuardFil's gateway, so nothing reaches them without a decision.
"""
from __future__ import annotations

import functools
import inspect
import json
import re
import socket
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

__all__ = ["GuardFil", "Decision", "Blocked", "FilterError"]

# A held ("ask me") call waits for the owner up to the service's ask timeout (max 600 s).
DEFAULT_TIMEOUT_SEC = 630.0
MAX_REPLY_BYTES = 256 * 1024
_TOOL_ID = re.compile(r"^([A-Za-z0-9_-]{1,64})\.([A-Za-z0-9_-]{1,64})$")
_ASKED = {"APPROVAL_GRANTED": "allowed", "APPROVAL_REJECTED": "denied", "APPROVAL_EXPIRED": "expired"}


@dataclass(frozen=True)
class Decision:
    """GuardFil's answer.  Anything but a clean ALLOW is not allowed."""
    allowed: bool
    reasons: Tuple[str, ...] = ()
    rule_ids: Tuple[str, ...] = ()
    error: Optional[str] = field(default=None)
    # Filter rules whose obligation applies: pass the tool's result through
    # GuardFil.filter before the agent sees it.
    filter: Tuple[str, ...] = ()

    @property
    def monitored(self) -> bool:
        return "POLICY_MONITORED" in self.reasons

    @property
    def asked(self) -> Optional[str]:
        """'allowed', 'denied' or 'expired' when the owner was asked; None otherwise."""
        for r in self.reasons:
            if r in _ASKED:
                return _ASKED[r]
        return None

    def __str__(self) -> str:
        what = "ALLOW" if self.allowed else "BLOCK"
        return f"{what} [{' '.join(self.rule_ids + self.reasons)}]"


class FilterError(Exception):
    """GuardFil could not filter a result; it must not be shown to the agent."""


class Blocked(Exception):
    """Raised by GuardFil.guard when a call is not allowed."""

    def __init__(self, tool: str, decision: Decision):
        super().__init__(f"GuardFil blocked {tool}: {decision}")
        self.tool = tool
        self.decision = decision


def _encode(v: Any, depth: int = 0) -> str:
    """JSON with exact decimals: Decimal becomes a number literal; float is refused."""
    if depth > 8:
        raise ValueError("arguments nested too deeply")
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, Decimal):
        if not v.is_finite():
            raise ValueError("decimal must be finite")
        s = format(v, "f")
        return s if s not in ("-0",) else "0"
    if isinstance(v, float):
        raise TypeError("pass amounts as decimal.Decimal or int, not float")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, Mapping):
        items = []
        for k, x in v.items():
            if not isinstance(k, str):
                raise TypeError("argument names must be strings")
            items.append(json.dumps(k) + ":" + _encode(x, depth + 1))
        return "{" + ",".join(items) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_encode(x, depth + 1) for x in v) + "]"
    raise TypeError(f"unsupported argument type {type(v).__name__}")


class GuardFil:
    """Client for the GuardFil approval service (a Unix socket)."""

    def __init__(self, socket_path: str, timeout: float = DEFAULT_TIMEOUT_SEC,
                 on_decision: Optional[Callable[[str, Decision], None]] = None):
        self.socket_path = socket_path
        self.timeout = timeout
        self.on_decision = on_decision

    def check(self, tool: str, arguments: Optional[Mapping[str, Any]] = None, can_filter: bool = False) -> Decision:
        """Ask GuardFil about one call of `tool` ("app.tool") with these arguments.

        can_filter=True promises to pass the result through `filter` when the
        decision has a `filter` obligation; without it, a Filter rule blocks.
        Blocks while the owner is asked.  Never raises for GuardFil being down or
        replying oddly: that is a BLOCK decision with an `error`."""
        m = _TOOL_ID.match(tool or "")
        if not m:
            raise ValueError("tool must be app.tool, for example stockapp.place_order")
        body = ('{"server":' + json.dumps(m.group(1)) + ',"tool":' + json.dumps(m.group(2)) +
                ',"arguments":' + _encode(dict(arguments or {})) + (',"can_filter":true' if can_filter else "") + "}")
        decision = self._send(body.encode("utf-8"))
        if self.on_decision is not None:
            self.on_decision(tool, decision)
        return decision

    def filter(self, tool: str, result: Any) -> Any:
        """Remove secrets from a tool result before the agent sees it.

        Strings are filtered as text.  Dicts and lists are filtered as one JSON
        document, so a value is judged with its key ("password": ...), and
        decoded again (Decimals stay exact).  Numbers, booleans and None pass
        unchanged.  Anything else raises FilterError, as does GuardFil being
        unable to filter: the caller must not show the unfiltered result."""
        if not _TOOL_ID.match(tool or ""):
            raise ValueError("tool must be app.tool")
        if result is None or isinstance(result, (bool, int, Decimal)):
            return result
        if isinstance(result, str):
            return self._filter_text(tool, result)
        if isinstance(result, (Mapping, list, tuple)):
            try:
                text = _encode(result)
            except (TypeError, ValueError) as e:
                raise FilterError(f"the {tool} result cannot be filtered: {e}") from e
            try:
                return json.loads(self._filter_text(tool, text), parse_float=Decimal)
            except ValueError as e:
                raise FilterError(f"the filtered {tool} result is not valid JSON") from e
        raise FilterError(f"the {tool} result ({type(result).__name__}) cannot be filtered")

    def _filter_text(self, tool: str, text: str) -> str:
        body = json.dumps({"kind": "filter", "tool": tool, "content": text}).encode("utf-8")
        try:
            out = json.loads(self._roundtrip(body))
        except (OSError, ValueError, socket.timeout) as e:
            raise FilterError(f"GuardFil could not filter the {tool} result") from e
        if not isinstance(out, dict) or not isinstance(out.get("content"), str):
            raise FilterError(f"GuardFil could not filter the {tool} result")
        return out["content"]

    def guard(self, tool: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: the function runs only if GuardFil allows the call.

        Its arguments (by parameter name, defaults included, None left out) are
        the tool arguments.  A refused call raises Blocked.  If a Filter rule
        applies, the return value is filtered before it is returned."""
        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def inner(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                call_args = {k: v for k, v in bound.arguments.items() if v is not None}
                d = self.check(tool, call_args, can_filter=True)
                if not d.allowed:
                    raise Blocked(tool, d)
                result = fn(*args, **kwargs)
                return self.filter(tool, result) if d.filter else result
            return inner
        return wrap

    def _send(self, body: bytes) -> Decision:
        def fail(code: str) -> Decision:
            return Decision(False, ("CLIENT_" + code,), (), code.lower())

        try:
            reply = self._roundtrip(body)
        except _ReplyTooLarge:
            return fail("REPLY_TOO_LARGE")
        except socket.timeout:
            return fail("TIMEOUT")
        except OSError:
            return fail("UNAVAILABLE")
        try:
            out: Dict[str, Any] = json.loads(reply.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return fail("BAD_REPLY")
        effect, reasons, rules = out.get("effect"), out.get("reasons"), out.get("rule_ids")
        if (effect not in ("ALLOW", "BLOCK") or not isinstance(reasons, list) or not isinstance(rules, list)
                or not all(isinstance(x, str) for x in reasons + rules)):
            return fail("BAD_REPLY")
        filt = out.get("filter") or []
        if not isinstance(filt, list) or not all(isinstance(x, str) for x in filt):
            return fail("BAD_REPLY")
        return Decision(effect == "ALLOW", tuple(reasons), tuple(rules), None, tuple(filt))

    def _roundtrip(self, body: bytes) -> bytes:
        deadline = time.monotonic() + self.timeout
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(self.timeout)
            s.connect(self.socket_path)
            s.sendall(body + b"\n")
            s.shutdown(socket.SHUT_WR)
            chunks: List[bytes] = []
            total = 0
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout()
                s.settimeout(left)
                b = s.recv(4096)
                if not b:
                    break
                total += len(b)
                if total > MAX_REPLY_BYTES:
                    raise _ReplyTooLarge()
                chunks.append(b)
        finally:
            s.close()
        return b"".join(chunks)


class _ReplyTooLarge(OSError):
    pass
