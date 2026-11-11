"""Provider adapters for GuardFil's model-neutral broker.

An agent sends the broker one provider-neutral "chat with tools" request; an
adapter turns it into the provider's HTTP request and the provider's reply
back into one neutral reply.  The agent never holds a key and never sees which
wire format was used, so the same agent runs on OpenAI, Anthropic or Gemini.

Neutral request:
    {"model": "openai:gpt-6-luna",                  # provider:model
     "system": "You are ...",                         # optional
     "messages": [
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "...",
         "tool_calls": [{"id": "c1", "name": "get_quote", "arguments": {"symbol": "ACME"}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "get_quote", "content": "..."}],
     "tools": [{"name": "get_quote", "description": "...", "parameters": {JSON schema}}],
     "max_output_tokens": 512}

Neutral reply:
    {"text": "...", "tool_calls": [{"id", "name", "arguments"}], "stop": "end" | "tool_calls" | "max_tokens",
     "usage": {"input_tokens": n, "output_tokens": n}, "model": "...", "response_id": "..."}

Standard library only.  Tool arguments are decoded with exact decimals.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Mapping, Optional, Tuple

MAX_MESSAGES = 200
MAX_TOOLS = 64
MAX_TEXT = 200_000
MAX_OUTPUT_TOKENS = 1024
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MODEL_RE = re.compile(r"^(openai|anthropic|gemini):([A-Za-z0-9._-]{1,64})$")


class NeutralError(ValueError):
    """The neutral request or the provider reply is not acceptable."""


@dataclass(frozen=True)
class HTTPRequest:
    host: str
    path: str
    headers: Dict[str, str]   # without the key; the broker adds it
    body: bytes


def _loads(raw: bytes) -> Any:
    return json.loads(raw, parse_float=Decimal)




def encode_arguments(args: Mapping[str, Any]) -> str:
    """Tool arguments as JSON with exact decimal literals."""
    def enc(v: Any) -> str:
        if isinstance(v, Decimal):
            return format(v, "f")
        if isinstance(v, Mapping):
            return "{" + ",".join(json.dumps(str(k)) + ":" + enc(x) for k, x in v.items()) + "}"
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(enc(x) for x in v) + "]"
        return json.dumps(v, ensure_ascii=False)
    return enc(args)


def validate(req: Any) -> Tuple[str, str]:
    """Check a neutral request; returns (provider, model)."""
    if not isinstance(req, dict) or set(req) - {"model", "system", "messages", "tools", "max_output_tokens"}:
        raise NeutralError("request has unknown fields")
    m = MODEL_RE.match(str(req.get("model", "")))
    if not m:
        raise NeutralError("model must be provider:model with provider openai, anthropic or gemini")
    if not isinstance(req.get("system", ""), str) or len(req.get("system", "")) > MAX_TEXT:
        raise NeutralError("system must be text")
    msgs = req.get("messages")
    if not isinstance(msgs, list) or not 1 <= len(msgs) <= MAX_MESSAGES:
        raise NeutralError(f"messages: 1 to {MAX_MESSAGES}")
    for msg in msgs:
        if not isinstance(msg, dict):
            raise NeutralError("each message is an object")
        role = msg.get("role")
        content = msg.get("content", "")
        if not isinstance(content, str) or len(content) > MAX_TEXT:
            raise NeutralError("message content must be text")
        if role == "user":
            if set(msg) - {"role", "content"}:
                raise NeutralError("user message: role and content only")
        elif role == "assistant":
            if set(msg) - {"role", "content", "tool_calls"}:
                raise NeutralError("assistant message: role, content, tool_calls")
            for c in msg.get("tool_calls") or []:
                if (not isinstance(c, dict) or set(c) != {"id", "name", "arguments"} or not NAME_RE.match(str(c["id"]))
                        or not NAME_RE.match(str(c["name"])) or not isinstance(c["arguments"], dict)):
                    raise NeutralError("tool call: id, name, arguments object")
        elif role == "tool":
            if set(msg) != {"role", "tool_call_id", "name", "content"} or not NAME_RE.match(str(msg["tool_call_id"])) \
                    or not NAME_RE.match(str(msg["name"])):
                raise NeutralError("tool message: role, tool_call_id, name, content")
        else:
            raise NeutralError("role must be user, assistant or tool")
    if msgs[0]["role"] != "user":
        raise NeutralError("the first message must be from the user")
    tools = req.get("tools", [])
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        raise NeutralError(f"tools: at most {MAX_TOOLS}")
    for t in tools:
        if (not isinstance(t, dict) or set(t) - {"name", "description", "parameters"} or not NAME_RE.match(str(t.get("name")))
                or not isinstance(t.get("parameters", {}), dict) or not isinstance(t.get("description", ""), str)):
            raise NeutralError("tool: name, description, parameters (JSON schema)")
    mot = req.get("max_output_tokens", MAX_OUTPUT_TOKENS)
    if type(mot) is not int or not 16 <= mot <= MAX_OUTPUT_TOKENS:
        raise NeutralError(f"max_output_tokens: 16 to {MAX_OUTPUT_TOKENS}")
    return m.group(1), m.group(2)


def _schema(t: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(t.get("parameters") or {"type": "object", "properties": {}})


def _tool_args(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        raw = _loads(raw.encode() or b"{}")
    if not isinstance(raw, dict):
        raise NeutralError("tool call arguments are not an object")
    return raw


def _reply(text: List[str], calls: List[Dict[str, Any]], stop: str, in_tok: Any, out_tok: Any, model: Any,
           rid: Any) -> Dict[str, Any]:
    if type(in_tok) is not int or type(out_tok) is not int or in_tok < 0 or out_tok < 0:
        raise NeutralError("reply has no token usage")
    if not isinstance(model, str) or not isinstance(rid, str) or not rid:
        raise NeutralError("reply has no model or id")
    return {"text": "".join(text), "tool_calls": calls, "stop": stop,
            "usage": {"input_tokens": in_tok, "output_tokens": out_tok}, "model": model, "response_id": rid}


class OpenAIResponses:
    """OpenAI Responses API (POST /v1/responses, non-streaming, store=false)."""
    provider = "openai"
    host = "api.openai.com"
    service_tier = "default"

    def build(self, model: str, req: Mapping[str, Any]) -> HTTPRequest:
        items: List[Dict[str, Any]] = []
        for m in req["messages"]:
            if m["role"] == "user":
                items.append({"role": "user", "content": [{"type": "input_text", "text": m["content"]}]})
            elif m["role"] == "assistant":
                if m.get("content"):
                    items.append({"role": "assistant", "content": [{"type": "output_text", "text": m["content"]}]})
                for c in m.get("tool_calls") or []:
                    items.append({"type": "function_call", "call_id": c["id"], "name": c["name"],
                                  "arguments": encode_arguments(c["arguments"])})
            else:
                items.append({"type": "function_call_output", "call_id": m["tool_call_id"], "output": m["content"]})
        body: Dict[str, Any] = {"model": model, "input": items, "store": False, "stream": False,
                                "service_tier": self.service_tier, "reasoning": {"effort": "none"},
                                "max_output_tokens": req.get("max_output_tokens", MAX_OUTPUT_TOKENS)}
        if req.get("system"):
            body["instructions"] = req["system"]
        if req.get("tools"):
            body["tools"] = [{"type": "function", "name": t["name"], "description": t.get("description", ""),
                              "parameters": _schema(t), "strict": False} for t in req["tools"]]
        return HTTPRequest(self.host, "/v1/responses", {"Content-Type": "application/json"}, _exact(body).encode())

    @staticmethod
    def auth(key: str) -> Dict[str, str]:
        return {"Authorization": "Bearer " + key}

    def parse(self, status: int, raw: bytes) -> Dict[str, Any]:
        if status != 200:
            raise NeutralError(f"provider HTTP {status}")
        r = _loads(raw)
        if r.get("status") not in ("completed", "incomplete"):
            raise NeutralError("response not completed")
        text, calls = [], []
        for item in r.get("output") or []:
            if item.get("type") == "message":
                text += [c.get("text", "") for c in item.get("content") or [] if c.get("type") == "output_text"]
            elif item.get("type") == "function_call":
                calls.append({"id": item["call_id"], "name": item["name"], "arguments": _tool_args(item["arguments"])})
        u = r.get("usage") or {}
        stop = "tool_calls" if calls else ("max_tokens" if r.get("status") == "incomplete" else "end")
        out = _reply(text, calls, stop, u.get("input_tokens"), u.get("output_tokens"), r.get("model"), r.get("id"))
        out["service_tier"] = r.get("service_tier")
        return out


class AnthropicMessages:
    """Anthropic Messages API (POST /v1/messages)."""
    provider = "anthropic"
    host = "api.anthropic.com"
    service_tier = "standard"

    def build(self, model: str, req: Mapping[str, Any]) -> HTTPRequest:
        msgs: List[Dict[str, Any]] = []

        def add(role: str, block: Dict[str, Any]) -> None:
            # Consecutive same-role turns (several tool results) merge into one message.
            if msgs and msgs[-1]["role"] == role:
                msgs[-1]["content"].append(block)
            else:
                msgs.append({"role": role, "content": [block]})
        for m in req["messages"]:
            if m["role"] == "user":
                add("user", {"type": "text", "text": m["content"]})
            elif m["role"] == "assistant":
                if m.get("content"):
                    add("assistant", {"type": "text", "text": m["content"]})
                for c in m.get("tool_calls") or []:
                    add("assistant", {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["arguments"]})
            else:
                add("user", {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]})
        body: Dict[str, Any] = {"model": model, "max_tokens": req.get("max_output_tokens", MAX_OUTPUT_TOKENS),
                                "messages": msgs}
        if req.get("system"):
            body["system"] = req["system"]
        if req.get("tools"):
            body["tools"] = [{"name": t["name"], "description": t.get("description", ""), "input_schema": _schema(t)}
                             for t in req["tools"]]
        return HTTPRequest(self.host, "/v1/messages",
                           {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}, _exact(body).encode())

    @staticmethod
    def auth(key: str) -> Dict[str, str]:
        return {"x-api-key": key}

    def preflight(self, model: str, out: HTTPRequest) -> HTTPRequest:
        """The free count_tokens call with the same messages, system and tools: a
        malformed request is refused there, before anything is reserved."""
        inner = json.loads(out.body, parse_float=Decimal)
        inner.pop("max_tokens", None)
        return HTTPRequest(self.host, "/v1/messages/count_tokens", dict(out.headers), _exact(inner).encode())

    def parse(self, status: int, raw: bytes) -> Dict[str, Any]:
        if status != 200:
            raise NeutralError(f"provider HTTP {status}")
        r = _loads(raw)
        if r.get("type") != "message":
            raise NeutralError("not a message")
        text, calls = [], []
        for b in r.get("content") or []:
            if b.get("type") == "text":
                text.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                calls.append({"id": b["id"], "name": b["name"], "arguments": _tool_args(b.get("input") or {})})
        u = r.get("usage") or {}
        in_tok = u.get("input_tokens")
        if type(in_tok) is int:
            # Cache reads and writes are input too; count them all.
            in_tok += int(u.get("cache_creation_input_tokens") or 0) + int(u.get("cache_read_input_tokens") or 0)
        stop = {"tool_use": "tool_calls", "max_tokens": "max_tokens"}.get(r.get("stop_reason"), "end")
        out = _reply(text, calls, stop, in_tok, u.get("output_tokens"), r.get("model"), r.get("id"))
        out["service_tier"] = u.get("service_tier", self.service_tier)
        return out


def _exact(body: Mapping[str, Any]) -> str:
    """JSON with exact decimals (tool call arguments keep the literal the model wrote)."""
    def enc(v: Any) -> str:
        if isinstance(v, Decimal):
            return format(v, "f")
        if isinstance(v, Mapping):
            return "{" + ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + enc(x) for k, x in v.items()) + "}"
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(enc(x) for x in v) + "]"
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return enc(body)


class GeminiGenerateContent:
    """Google Gemini API (POST /v1beta/models/{model}:generateContent)."""
    provider = "gemini"
    host = "generativelanguage.googleapis.com"
    service_tier = "default"

    def __init__(self) -> None:
        # Gemini 3+ returns a thoughtSignature with each function call and refuses
        # (HTTP 400) a later turn that echoes the call without it.  The agent sees
        # only neutral calls, so the broker keeps the signatures by call id.
        self._signatures: Dict[str, str] = {}

    def build(self, model: str, req: Mapping[str, Any]) -> HTTPRequest:
        contents: List[Dict[str, Any]] = []

        def add(role: str, part: Dict[str, Any]) -> None:
            if contents and contents[-1]["role"] == role:
                contents[-1]["parts"].append(part)
            else:
                contents.append({"role": role, "parts": [part]})
        for m in req["messages"]:
            if m["role"] == "user":
                add("user", {"text": m["content"]})
            elif m["role"] == "assistant":
                if m.get("content"):
                    add("model", {"text": m["content"]})
                for c in m.get("tool_calls") or []:
                    part: Dict[str, Any] = {"functionCall": {"id": c["id"], "name": c["name"], "args": c["arguments"]}}
                    # Unknown call (e.g. history from another broker run): Google's documented
                    # placeholder skips the check instead of failing the request.
                    part["thoughtSignature"] = self._signatures.get(c["id"], "skip_thought_signature_validator")
                    add("model", part)
            else:
                add("user", {"functionResponse": {"id": m["tool_call_id"], "name": m["name"],
                                                  "response": {"content": m["content"]}}})
        body: Dict[str, Any] = {"contents": contents,
                                "generationConfig": {"maxOutputTokens": req.get("max_output_tokens", MAX_OUTPUT_TOKENS)}}
        if req.get("system"):
            body["systemInstruction"] = {"parts": [{"text": req["system"]}]}
        if req.get("tools"):
            body["tools"] = [{"functionDeclarations": [{"name": t["name"], "description": t.get("description", ""),
                                                        "parameters": _schema(t)} for t in req["tools"]]}]
        return HTTPRequest(self.host, f"/v1beta/models/{model}:generateContent",
                           {"Content-Type": "application/json"}, _exact(body).encode())

    @staticmethod
    def auth(key: str) -> Dict[str, str]:
        return {"x-goog-api-key": key}

    def preflight(self, model: str, out: HTTPRequest) -> HTTPRequest:
        """A free countTokens call with the same request: Google rejects a malformed
        request there before anything is reserved (a failed paid call halts the ledger)."""
        inner = json.loads(out.body, parse_float=Decimal)
        inner["model"] = f"models/{model}"
        return HTTPRequest(self.host, f"/v1beta/models/{model}:countTokens", {"Content-Type": "application/json"},
                           _exact({"generateContentRequest": inner}).encode())

    def parse(self, status: int, raw: bytes) -> Dict[str, Any]:
        if status != 200:
            raise NeutralError(f"provider HTTP {status}")
        r = _loads(raw)
        cands = r.get("candidates") or []
        if not cands:
            raise NeutralError("no candidates")
        text, calls = [], []
        for i, p in enumerate((cands[0].get("content") or {}).get("parts") or []):
            if "text" in p and not p.get("thought"):
                text.append(p["text"])
            elif "functionCall" in p:
                fc = p["functionCall"]
                cid = fc.get("id") or "call_" + hashlib.sha256(f"{r.get('responseId')}:{i}".encode()).hexdigest()[:16]
                calls.append({"id": cid, "name": fc["name"], "arguments": _tool_args(fc.get("args") or {})})
                if isinstance(p.get("thoughtSignature"), str) and len(self._signatures) < 4096:
                    self._signatures[cid] = p["thoughtSignature"]
        u = r.get("usageMetadata") or {}
        out_tok = u.get("candidatesTokenCount", 0)
        if type(out_tok) is int:
            out_tok += int(u.get("thoughtsTokenCount") or 0)   # thinking is billed as output
        stop = "tool_calls" if calls else ("max_tokens" if cands[0].get("finishReason") == "MAX_TOKENS" else "end")
        out = _reply(text, calls, stop, u.get("promptTokenCount"), out_tok, r.get("modelVersion"), r.get("responseId"))
        out["service_tier"] = self.service_tier
        return out


ADAPTERS = {a.provider: a for a in (OpenAIResponses(), AnthropicMessages(), GeminiGenerateContent())}


def adapter_for(provider: str):
    return ADAPTERS[provider]
