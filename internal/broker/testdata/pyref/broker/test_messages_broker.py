import json
import tempfile
import unittest
from pathlib import Path

from broker import messages_broker as mb
from research.t2a.openai_broker.smoke import open_or_init_ledger

CC_REQ = {"model": mb.MODEL, "max_tokens": 32000, "stream": True, "thinking": {"type": "enabled", "budget_tokens": 8000},
          "system": [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}],
          "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
          "tools": [{"name": "Bash", "description": "run", "input_schema": {"type": "object"}}],
          "metadata": {"user_id": "u"}}
REPLY = {"id": "msg_1", "type": "message", "role": "assistant", "model": mb.MODEL, "stop_reason": "tool_use",
         "stop_sequence": None, "content": [{"type": "text", "text": "ok"},
                                            {"type": "tool_use", "id": "tu1", "name": "Bash", "input": {"command": "ls"}}],
         "usage": {"input_tokens": 10, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 1000,
                   "output_tokens": 20, "service_tier": "standard"}}


class Transport:
    def __init__(self, replies):
        self.replies, self.sent = list(replies), []

    def __call__(self, req, auth):
        assert auth == {"x-api-key": "k"}
        self.sent.append((req.path, json.loads(req.body)))
        if req.path.endswith("count_tokens"):
            return 200, b'{"input_tokens": 1110}'
        return self.replies.pop(0)


class MessagesBrokerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ledger = open_or_init_ledger(Path(self.dir.name), initialize=True, experiment_id="test-messages")

    def tearDown(self):
        self.ledger.close()
        self.dir.cleanup()

    def broker(self, replies, **kw):
        t = Transport(replies)
        b = mb.MessagesBroker(self.ledger, "k", "t", 8, transport=t, **kw)
        b.sleep = lambda s: None
        return b, t

    def test_settles_with_cache_counted_and_streams_back(self):
        b, t = self.broker([(200, json.dumps(REPLY).encode())])
        status, body = b.handle(json.dumps(CC_REQ).encode())
        self.assertEqual(status, 200)
        sent = t.sent[-1][1]
        self.assertEqual(sent["max_tokens"], mb.MAX_OUTPUT_TOKENS)
        self.assertNotIn("thinking", sent)
        self.assertNotIn("stream", sent)
        self.assertEqual([p for p, _ in t.sent], ["/v1/messages/count_tokens", "/v1/messages"])
        text = body.decode()
        self.assertTrue(text.startswith("event: message_start"))
        self.assertIn('"partial_json":"{\\"command\\":\\"ls\\"}"', text)
        self.assertTrue(text.rstrip().endswith('{"type":"message_stop"}'))
        st = self.ledger.get_status()
        # 10 + 2*100 + ceil(1000/10) = 310 input tokens at 2, 20 output at 10.
        self.assertEqual(st.total_spend_micros, 310 * 2 + 20 * 10)

    def test_cache_write_split_counted_by_ttl(self):
        self.assertEqual(mb.billable_input({"input_tokens": 1, "cache_creation_input_tokens": 9,
                                            "cache_creation": {"ephemeral_5m_input_tokens": 4,
                                                               "ephemeral_1h_input_tokens": 5}}), 1 + 5 + 10)
        # a split that does not add up falls back to 2x
        self.assertEqual(mb.billable_input({"input_tokens": 0, "cache_creation_input_tokens": 9,
                                            "cache_creation": {"ephemeral_5m_input_tokens": 1}}), 18)

    def test_json_reply_when_not_streaming(self):
        b, _ = self.broker([(200, json.dumps(REPLY).encode())])
        status, body = b.handle(json.dumps(dict(CC_REQ, stream=False)).encode())
        self.assertEqual((status, json.loads(body)["id"]), (200, "msg_1"))

    def test_provider_side_tools_and_fields_refused_before_spend(self):
        bad = [dict(CC_REQ, tools=[{"type": "web_search_20250305", "name": "web_search"}]),
               dict(CC_REQ, tools=[{"type": "code_execution_20250825", "name": "code_execution"}]),
               dict(CC_REQ, mcp_servers=[{"type": "url", "url": "https://evil.example/mcp"}]),
               dict(CC_REQ, container="c1"),
               dict(CC_REQ, model="claude-opus-5-5"),
               dict(CC_REQ, messages=[{"role": "user", "content": [{"type": "server_tool_use", "id": "x"}]}]),
               dict(CC_REQ, tool_choice={"type": "web_search"})]
        for req in bad:
            b, t = self.broker([])
            status, body = b.handle(json.dumps(req).encode())
            self.assertEqual(status, 400, req)
            self.assertEqual(t.sent, [])
        self.assertEqual(self.ledger.get_status().total_spend_micros, 0)

    def test_overload_retried_then_closed_at_zero(self):
        b, _ = self.broker([(529, b'{"type":"error","error":{"type":"overloaded_error","message":"busy"}}')] * 5)
        status, _ = b.handle(json.dumps(CC_REQ).encode())
        self.assertEqual(status, 529)
        st = self.ledger.get_status()
        self.assertEqual(st.total_spend_micros, 0)
        self.assertTrue(st.can_reserve)
        self.assertFalse(b.stopped)

    def test_bad_reply_halts(self):
        b, _ = self.broker([(200, b'{"type":"message","id":"m","usage":{}}')])
        status, _ = b.handle(json.dumps(CC_REQ).encode())
        self.assertEqual(status, 502)
        self.assertTrue(b.stopped)

    def test_provider_ceiling(self):
        b, t = self.broker([], prior_micros=1_999_000)
        status, _ = b.handle(json.dumps(CC_REQ).encode())
        self.assertEqual(status, 429)
        self.assertEqual([p for p, _ in t.sent], ["/v1/messages/count_tokens"])


if __name__ == "__main__":
    unittest.main()
