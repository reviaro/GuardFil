"""The agent loop both demo agents share: ask the model (through GuardFil's
model-neutral broker), run the tools it calls, feed back the results, until it
answers.  Provider-independent: the model is just "provider:model"."""
import json
from decimal import Decimal
from typing import Any, Callable, Dict, List

TOOLS = [
    {"name": "get_quote", "description": "Current price of a stock symbol",
     "parameters": {"type": "object", "properties": {"symbol": {"type": "string"}}, "required": ["symbol"]}},
    {"name": "get_portfolio", "description": "Cash, positions and open orders",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "place_order", "description": "Place a buy or sell order. limit_price is a decimal string like \"12.50\".",
     "parameters": {"type": "object", "properties": {
         "symbol": {"type": "string"}, "side": {"type": "string", "enum": ["buy", "sell"]},
         "quantity": {"type": "integer"}, "limit_price": {"type": "string"}},
         "required": ["symbol", "side", "quantity"]}},
    {"name": "cancel_order", "description": "Cancel an open order",
     "parameters": {"type": "object", "properties": {"order_id": {"type": "string"}}, "required": ["order_id"]}},
    {"name": "get_news", "description": "Latest headlines for a stock symbol",
     "parameters": {"type": "object", "properties": {"symbol": {"type": "string"}}, "required": ["symbol"]}},
    {"name": "send_message", "description": "Send a message to the app's support desk",
     "parameters": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "withdraw_funds", "description": "Withdraw cash to an external account. amount is a decimal string.",
     "parameters": {"type": "object", "properties": {"amount": {"type": "string"}, "destination": {"type": "string"}},
                    "required": ["amount", "destination"]}},
]

SYSTEM = ("You are the trading assistant of a paper-trading app (fake money). Use the tools to do what the user "
          "asks. If a tool call is refused, say so plainly and do not try to get around it. Be brief.")


def to_decimal_args(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Prices and amounts travel as exact decimals."""
    out = dict(args)
    for k in ("limit_price", "amount"):
        if k in out and not isinstance(out[k], Decimal):
            try:
                out[k] = Decimal(str(out[k]))
            except Exception:
                pass
    return out


def run(task: str, model: str, ask: Callable[[Dict[str, Any]], Dict[str, Any]],
        execute: Callable[[str, Dict[str, Any]], str], tools: List[Dict[str, Any]] = TOOLS,
        system: str = SYSTEM, max_steps: int = 6, log: Callable[[str], None] = print) -> str:
    messages: List[Dict[str, Any]] = [{"role": "user", "content": task}]
    for _ in range(max_steps):
        reply = ask({"model": model, "system": system, "messages": messages, "tools": tools,
                     "max_output_tokens": 1024 if model.startswith("gemini:") else 400})  # Gemini thinking counts as output
        if reply.get("text"):
            log("agent: " + reply["text"].strip())
        calls = reply.get("tool_calls") or []
        if not calls:
            return reply.get("text", "")
        messages.append({"role": "assistant", "content": reply.get("text", ""), "tool_calls": calls})
        for c in calls:
            args = to_decimal_args(c["name"], c["arguments"])
            result = execute(c["name"], args)
            log(f"  tool {c['name']}({json.dumps(args, default=str)}) -> {result[:220]}")
            messages.append({"role": "tool", "tool_call_id": c["id"], "name": c["name"], "content": result})
    return "(stopped after the step limit)"
