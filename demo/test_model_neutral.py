"""H7: the demo's agent loop runs unchanged on a second (and third) provider.

Offline: the real NeutralBroker and adapters, with a fake transport that
answers in each provider's own wire format (no network, no spend).  The same
task produces the same tool calls, with the exact decimal price, and the same
final answer on OpenAI, Anthropic and Gemini.
    python3 -m unittest demo.test_model_neutral
"""
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT)]
from agent_loop import run  # noqa: E402
from broker import neutral_broker as nb  # noqa: E402
from broker.test_neutral_broker import FakeLedger  # noqa: E402

CALL = {"symbol": "ACME", "side": "buy", "quantity": 10, "limit_price": "12.50"}


def provider_reply(provider, turn, model):
    """Turn 1: call place_order; turn 2: answer.  In the provider's own format."""
    if provider == "openai":
        out = ([{"type": "function_call", "call_id": "c1", "name": "place_order", "arguments": json.dumps(CALL)}] if turn == 1
               else [{"type": "message", "content": [{"type": "output_text", "text": "Order placed."}]}])
        return {"id": f"resp_{turn}", "status": "completed", "model": model, "service_tier": "default", "output": out,
                "usage": {"input_tokens": 50, "output_tokens": 10, "total_tokens": 60}}
    if provider == "anthropic":
        content = ([{"type": "tool_use", "id": "toolu_1", "name": "place_order", "input": CALL}] if turn == 1
                   else [{"type": "text", "text": "Order placed."}])
        return {"id": f"msg_{turn}", "type": "message", "role": "assistant", "model": model, "content": content,
                "stop_reason": "tool_use" if turn == 1 else "end_turn", "usage": {"input_tokens": 50, "output_tokens": 10}}
    parts = [{"functionCall": {"name": "place_order", "args": CALL}}] if turn == 1 else [{"text": "Order placed."}]
    return {"responseId": f"r_{turn}", "modelVersion": model, "candidates": [{"content": {"role": "model", "parts": parts},
            "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 50, "candidatesTokenCount": 10}}


MODELS = {"openai": ("gpt-6-luna", "default"), "anthropic": ("claude-sonnet-5-5", "standard"),
          "gemini": ("gemini-flash-latest", "default")}


class ModelNeutralTest(unittest.TestCase):
    def run_on(self, provider):
        model, tier = MODELS[provider]
        added = model not in nb.MODEL_RATES
        if added:
            nb.MODEL_RATES[model] = (1, 1, tier)   # test-only price; never live
        sent = []

        def transport(req, auth):
            if req.path.endswith((":countTokens", "/count_tokens")):
                return 200, b'{"totalTokens": 50}'
            sent.append(req)
            return 200, json.dumps(provider_reply(provider, len(sent), model)).encode()
        broker = nb.NeutralBroker(FakeLedger(), "h7", 8, {provider: "k"}, transport=transport,
                                  live_providers=frozenset({provider}), provider_models=None)
        executed = []

        def ask(r):
            out = broker.handle(json.dumps(r, default=str).encode())
            self.assertTrue(out["ok"], out)
            return out["reply"]

        def execute(name, args):
            executed.append((name, args))
            return '{"order_id":"o-1","status":"open"}'
        try:
            answer = run("Buy 10 ACME with a limit price of 12.50.", f"{provider}:{model}", ask, execute, log=lambda s: None)
        finally:
            if added:
                del nb.MODEL_RATES[model]
        return answer, executed, sent

    def test_same_agent_three_providers(self):
        results = {p: self.run_on(p) for p in MODELS}
        for p, (answer, executed, sent) in results.items():
            self.assertEqual(answer, "Order placed.", p)
            self.assertEqual(executed, [("place_order", {"symbol": "ACME", "side": "buy", "quantity": 10,
                                                         "limit_price": Decimal("12.50")})], p)
            self.assertEqual(len(sent), 2, p)
            # The second request carries the tool result back in that provider's format.
            self.assertIn(b"o-1", sent[1].body, p)
        hosts = {p: r[2][0].host for p, r in results.items()}
        self.assertEqual(hosts, {"openai": "api.openai.com", "anthropic": "api.anthropic.com",
                                 "gemini": "generativelanguage.googleapis.com"})


if __name__ == "__main__":
    unittest.main()
