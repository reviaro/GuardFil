"""Ask a model through GuardFil's model-neutral broker (agent side).

The agent holds no key and names the model as provider:model; the same code
runs on OpenAI, Anthropic or Gemini.  Standard library only.

    from guardfil_model import ask_model
    reply = ask_model("/run/guardfil-broker/broker.sock", {
        "model": "openai:gpt-6-luna", "system": "...",
        "messages": [{"role": "user", "content": "..."}],
        "tools": [{"name": "get_quote", "description": "...", "parameters": {...}}]})
    reply["text"], reply["tool_calls"]   # tool call arguments keep exact decimals
"""
import json
import socket
from decimal import Decimal
from typing import Any, Dict

MAX_REPLY = 4 << 20


class ModelError(Exception):
    pass


def _enc(v: Any) -> str:
    if isinstance(v, Decimal):
        return format(v, "f")
    if isinstance(v, float):
        raise TypeError("use Decimal, not float")
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(str(k)) + ":" + _enc(x) for k, x in v.items()) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_enc(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)


def ask_model(sock_path: str, request: Dict[str, Any], timeout: float = 600) -> Dict[str, Any]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall(_enc(request).encode("utf-8") + b"\n")
        buf = b""
        while b"\n" not in buf:
            b = s.recv(65536)
            if not b:
                break
            buf += b
            if len(buf) > MAX_REPLY:
                raise ModelError("reply too large")
    except OSError as e:
        raise ModelError(f"model broker unavailable: {e}") from e
    finally:
        s.close()
    try:
        out = json.loads(buf, parse_float=Decimal)
    except ValueError as e:
        raise ModelError("bad reply from the model broker") from e
    if not out.get("ok"):
        raise ModelError(out.get("error") or "model request failed")
    return out["reply"]
