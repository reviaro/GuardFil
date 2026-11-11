import json
import unittest
from decimal import Decimal

from broker.adapters import ADAPTERS, NeutralError, validate

REQ = {
    "model": "x:y",
    "system": "You trade on paper.",
    "messages": [
        {"role": "user", "content": "Buy 10 ACME at 12.50"},
        {"role": "assistant", "content": "Placing it.", "tool_calls": [
            {"id": "c1", "name": "place_order", "arguments": {"symbol": "ACME", "quantity": 10, "limit_price": Decimal("12.50")}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "place_order", "content": "{\"ok\":true}"},
        {"role": "tool", "tool_call_id": "c2", "name": "get_quote", "content": "12.40"},
    ],
    "tools": [{"name": "place_order", "description": "Place an order",
               "parameters": {"type": "object", "properties": {"symbol": {"type": "string"}}}}],
    "max_output_tokens": 256,
}

# Replies as each provider documents them: text plus one tool call with a decimal argument.
REPLIES = {
    "openai": {"id": "resp_1", "status": "completed", "model": "gpt-6-luna", "service_tier": "default",
               "output": [{"type": "message", "content": [{"type": "output_text", "text": "Done."}]},
                          {"type": "function_call", "call_id": "call_9", "name": "place_order",
                           "arguments": "{\"symbol\":\"ACME\",\"quantity\":5,\"limit_price\":9.95}"}],
               "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150}},
    "anthropic": {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
                  "content": [{"type": "text", "text": "Done."},
                              {"type": "tool_use", "id": "toolu_9", "name": "place_order",
                               "input": {"symbol": "ACME", "quantity": 5, "limit_price": 9.95}}],
                  "stop_reason": "tool_use",
                  "usage": {"input_tokens": 100, "cache_read_input_tokens": 20, "output_tokens": 30}},
    "gemini": {"responseId": "r_1", "modelVersion": "gemini-flash-latest",
               "candidates": [{"content": {"role": "model", "parts": [
                   {"text": "Done."},
                   {"functionCall": {"name": "place_order", "args": {"symbol": "ACME", "quantity": 5, "limit_price": 9.95}}}]},
                   "finishReason": "STOP"}],
               "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 25, "thoughtsTokenCount": 5}},
}


class AdapterTest(unittest.TestCase):
    def test_same_reply_from_every_provider(self):
        for name, a in ADAPTERS.items():
            r = a.parse(200, json.dumps(REPLIES[name]).encode())
            self.assertEqual(r["text"], "Done.", name)
            self.assertEqual(r["stop"], "tool_calls", name)
            self.assertEqual(r["usage"], {"input_tokens": 120, "output_tokens": 30}, name)
            call = r["tool_calls"][0]
            self.assertEqual(call["name"], "place_order")
            self.assertEqual(call["arguments"]["limit_price"], Decimal("9.95"), name)   # exact, not float

    def test_openai_request(self):
        body = json.loads(ADAPTERS["openai"].build("gpt-6-luna", REQ).body)
        self.assertEqual(body["instructions"], "You trade on paper.")
        self.assertFalse(body["store"])
        types = [i.get("type", i.get("role")) for i in body["input"]]
        self.assertEqual(types, ["user", "assistant", "function_call", "function_call_output", "function_call_output"])
        self.assertIn('"limit_price":12.50', body["input"][2]["arguments"])
        self.assertEqual(body["tools"][0]["type"], "function")
        self.assertEqual(body["max_output_tokens"], 256)

    def test_anthropic_request(self):
        r = ADAPTERS["anthropic"].build("claude-sonnet-5-5", REQ)
        self.assertEqual(r.path, "/v1/messages")
        self.assertIn(b'"limit_price":12.50', r.body)
        body = json.loads(r.body)
        self.assertEqual([m["role"] for m in body["messages"]], ["user", "assistant", "user"])
        # both tool results merged into one user turn, after the assistant's tool_use
        self.assertEqual([b["type"] for b in body["messages"][2]["content"]], ["tool_result", "tool_result"])
        self.assertEqual(body["messages"][1]["content"][1]["type"], "tool_use")
        self.assertEqual(body["system"], "You trade on paper.")
        self.assertIn("input_schema", body["tools"][0])
        self.assertEqual(body["max_tokens"], 256)

    def test_gemini_request(self):
        r = ADAPTERS["gemini"].build("gemini-flash-latest", REQ)
        self.assertEqual(r.path, "/v1beta/models/gemini-flash-latest:generateContent")
        body = json.loads(r.body)
        self.assertEqual([c["role"] for c in body["contents"]], ["user", "model", "user"])
        self.assertIn("functionCall", body["contents"][1]["parts"][1])
        self.assertEqual(body["contents"][2]["parts"][0]["functionResponse"]["response"], {"content": "{\"ok\":true}"})
        self.assertEqual(body["generationConfig"]["maxOutputTokens"], 256)
        self.assertIn(b'"limit_price":12.50', r.body)

    def test_keys_never_in_body(self):
        for name, a in ADAPTERS.items():
            self.assertTrue(a.auth("SECRETKEY"))
            self.assertNotIn(b"SECRETKEY", a.build("m", REQ).body)

    def test_bad_replies(self):
        for name, a in ADAPTERS.items():
            with self.assertRaises(NeutralError):
                a.parse(500, b"{}")
            bad = dict(REPLIES[name])
            bad.pop({"openai": "usage", "anthropic": "usage", "gemini": "usageMetadata"}[name])
            with self.assertRaises((NeutralError, TypeError)):
                a.parse(200, json.dumps(bad).encode())

    def test_validate(self):
        good = dict(REQ, model="openai:gpt-6-luna")
        self.assertEqual(validate(good), ("openai", "gpt-6-luna"))
        for bad in (dict(good, model="gpt-6-luna"), dict(good, model="azure:x"), dict(good, extra=1),
                    dict(good, max_output_tokens=5000), dict(good, messages=[]),
                    dict(good, messages=[{"role": "system", "content": "x"}]),
                    dict(good, messages=[{"role": "assistant", "content": "x"}]),
                    dict(good, tools=[{"name": "bad name"}])):
            with self.assertRaises(NeutralError):
                validate(bad)


if __name__ == "__main__":
    unittest.main()
