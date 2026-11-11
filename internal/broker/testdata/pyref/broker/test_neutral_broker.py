import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from decimal import Decimal
from pathlib import Path

from broker import neutral_broker as nb
from broker.test_adapters import REPLIES

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
from guardfil_model import ModelError, ask_model  # noqa: E402


class FakeLedger:
    def __init__(self, refuse=False):
        self.reserved, self.settled, self.failed, self.refuse = [], [], [], refuse

    def reserve(self, rid, digest, amount):
        if self.refuse:
            raise RuntimeError("budget")
        self.reserved.append((rid, digest, amount))
        return ("permit", rid)

    def settle(self, permit, receipt):
        if receipt.model not in nb.MODEL_RATES:
            raise ValueError("RECEIPT_MODEL_MISMATCH")
        self.settled.append(receipt)

        class R:
            accounted_cost_micros = receipt.input_tokens + receipt.output_tokens
        return R()

    def record_failure(self, permit, code):
        self.failed.append(code)


def req(model="openai:gpt-6-luna"):
    return {"model": model, "messages": [{"role": "user", "content": "Buy 5 ACME at 9.95"}],
            "tools": [{"name": "place_order", "parameters": {"type": "object"}}], "max_output_tokens": 64}


class BrokerTest(unittest.TestCase):
    def broker(self, ledger=None, reply=None, live=nb.LIVE_PROVIDERS, transport=None, models=nb.PROVIDER_MODELS):
        self.ledger = ledger or FakeLedger()
        self.sent = []

        def fake(http_req, auth):
            if http_req.path.endswith((":countTokens", "/count_tokens")):
                self.preflights = getattr(self, "preflights", 0) + 1
                return 200, b'{"totalTokens": 10}'
            self.sent.append((http_req, auth))
            return 200, json.dumps(reply or REPLIES["openai"]).encode()
        return nb.NeutralBroker(self.ledger, "t", 4, {"openai": "sk-test-KEY", "anthropic": "ak", "gemini": "gk"},
                                transport=transport or fake, live_providers=live, provider_models=models)

    def test_openai_round_trip_charges_ledger(self):
        b = self.broker()
        out = b.handle(json.dumps(req()).encode())
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["reply"]["tool_calls"][0]["arguments"]["limit_price"], Decimal("9.95"))
        rid, digest, amount = self.ledger.reserved[0]
        self.assertTrue(digest.startswith("sha256:"))
        self.assertGreaterEqual(amount, len(self.sent[0][0].body) + 64)
        self.assertEqual(self.ledger.settled[0].input_tokens, 120)
        self.assertEqual(self.sent[0][1], {"Authorization": "Bearer sk-test-KEY"})
        self.assertNotIn(b"sk-test-KEY", json.dumps(out, default=str).encode())

    def test_other_providers_not_live(self):
        b = self.broker(live=frozenset({"openai"}))
        for m in ("anthropic:claude-sonnet-5-5", "gemini:gemini-flash-latest"):
            out = b.handle(json.dumps(req(m)).encode())
            self.assertFalse(out["ok"])
            self.assertIn("not enabled for live calls", out["error"])
        self.assertEqual(self.sent, [])
        self.assertEqual(self.ledger.reserved, [])

    def test_gemini_live_model_and_signatures(self):
        sig = "c2lnbmF0dXJl"
        reply = {"responseId": "r1", "modelVersion": "gemini-3.6-flash-001", "candidates": [{"content": {"role": "model",
                 "parts": [{"functionCall": {"name": "place_order", "args": {"symbol": "ACME"}}, "thoughtSignature": sig}]},
                 "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 40, "candidatesTokenCount": 8, "thoughtsTokenCount": 30}}
        b = self.broker(reply=reply)
        out = b.handle(json.dumps(req("gemini:gemini-3.6-flash")).encode())
        self.assertTrue(out["ok"], out)
        self.assertEqual(self.ledger.settled[0].model, "gemini-3.6-flash")
        self.assertEqual(self.ledger.settled[0].output_tokens, 38)
        call = out["reply"]["tool_calls"][0]
        follow = dict(req("gemini:gemini-3.6-flash"), messages=[
            {"role": "user", "content": "Buy"}, {"role": "assistant", "content": "", "tool_calls": [call]},
            {"role": "tool", "tool_call_id": call["id"], "name": "place_order", "content": "ok"}])
        self.assertTrue(b.handle(json.dumps(follow).encode())["ok"])
        sent = json.loads(self.sent[1][0].body)
        self.assertEqual(sent["contents"][1]["parts"][0]["thoughtSignature"], sig)
        self.assertEqual(self.sent[1][1], {"x-goog-api-key": "gk"})
        # A model the provider list does not name is refused before any spend.
        self.assertIn("not priced", b.handle(json.dumps(req("gemini:gemini-flash-latest")).encode())["error"])
        self.assertEqual(len(self.sent), 2)

    def test_gemini_preflight_refusal_spends_nothing(self):
        def t(r, a):
            if r.path.endswith(":countTokens"):
                return 400, b'{"error": {"code": 400, "message": "Invalid JSON payload"}}'
            raise AssertionError("paid call after a refused preflight")
        b = nb.NeutralBroker(FakeLedger(), "t", 4, {"gemini": "g"}, transport=t)
        out = b.handle(json.dumps(req("gemini:gemini-3.6-flash")).encode())
        self.assertIn("before any spend", out["error"])
        self.assertIn("Invalid JSON payload", out["error"])
        self.assertEqual((b.ledgers["gemini"].reserved, b.stopped, b.count), ([], False, 0))

    def test_transient_errors_retried_in_one_reservation(self):
        replies = [(503, b'{"error":{"message":"overloaded"}}'), (429, b"{}"),
                   (200, json.dumps(REPLIES["openai"]).encode())]
        b = nb.NeutralBroker(FakeLedger(), "t", 4, {"openai": "k"}, transport=lambda r, a: replies.pop(0))
        b.sleep = lambda s: None
        self.assertTrue(b.handle(json.dumps(req()).encode())["ok"])
        self.assertEqual(len(b.ledgers["openai"].reserved), 1)
        always = nb.NeutralBroker(FakeLedger(), "t", 4, {"openai": "k"}, transport=lambda r, a: (503, b"{}"))
        always.sleep = lambda s: None
        out = always.handle(json.dumps(req()).encode())
        self.assertIn("nothing was billed", out["error"])
        led = always.ledgers["openai"]
        self.assertEqual((led.failed, led.settled[0].input_tokens, led.settled[0].output_tokens), ([], 0, 0))
        self.assertTrue(led.settled[0].response_id.startswith("unbilled-503-"))
        self.assertFalse(always.stopped)
        bad = nb.NeutralBroker(FakeLedger(), "t", 4, {"openai": "k"}, transport=lambda r, a: (400, b"{}"))
        self.assertFalse(bad.handle(json.dumps(req()).encode())["ok"])
        self.assertEqual(bad.ledgers["openai"].failed, ["RECEIPT_SCHEMA_VIOLATION"])

    def test_retired_ledgers_count_toward_the_provider_ceiling(self):
        class Led(FakeLedger):
            def get_status(self):
                class S:
                    total_encumbered_micros = 10_000
                return S()
        reply = {"responseId": "r1", "modelVersion": "gemini-3.6-flash", "candidates": [{"content": {"role": "model",
                 "parts": [{"text": "hi"}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1}}
        t = lambda r, a: (200, b'{"totalTokens": 4}' if r.path.endswith(":countTokens") else json.dumps(reply).encode())
        ok = nb.NeutralBroker({"gemini": Led()}, "t", 4, {"gemini": "g"}, transport=t, prior_spend={"gemini": 50_000})
        self.assertTrue(ok.handle(json.dumps(req("gemini:gemini-3.6-flash")).encode())["ok"])
        full = nb.NeutralBroker({"gemini": Led()}, "t", 4, {"gemini": "g"}, transport=t, prior_spend={"gemini": 1_989_000})
        out = full.handle(json.dumps(req("gemini:gemini-3.6-flash")).encode())
        self.assertIn("across all its ledgers", out["error"])
        self.assertEqual(full.ledgers["gemini"].reserved, [])

    def test_one_ledger_per_provider(self):
        oa, gm = FakeLedger(), FakeLedger()
        reply = {"responseId": "r1", "modelVersion": "gemini-3.6-flash", "candidates": [{"content": {"role": "model",
                 "parts": [{"text": "hi"}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1}}
        b = nb.NeutralBroker({"openai": oa, "gemini": gm}, "t", 4, {"openai": "k", "gemini": "g"},
                             transport=lambda r, a: (200, b'{"totalTokens": 4}' if r.path.endswith(":countTokens")
                                                     else json.dumps(reply).encode()))
        self.assertTrue(b.handle(json.dumps(req("gemini:gemini-3.6-flash")).encode())["ok"])
        self.assertEqual((len(oa.reserved), len(gm.reserved)), (0, 1))
        b2 = nb.NeutralBroker({"openai": oa}, "t", 4, {"openai": "k", "gemini": "g"})
        self.assertIn("no ledger", b2.handle(json.dumps(req("gemini:gemini-3.6-flash")).encode())["error"])

    def test_unpriced_model_refused_before_spend(self):
        b = self.broker()
        out = b.handle(json.dumps(req("openai:gpt-7-ultra")).encode())
        self.assertIn("not priced", out["error"])
        self.assertEqual(self.sent, [])

    def test_offline_second_provider_through_same_path(self):
        # With a test-only live set and price, the Anthropic adapter runs the same flow offline.
        saved = nb.MODEL_RATES.get("claude-sonnet-5-5")
        nb.MODEL_RATES["claude-sonnet-5-5"] = (3, 15, "standard")
        try:
            b = self.broker(reply=REPLIES["anthropic"], live=frozenset({"anthropic"}), models=None)
            out = b.handle(json.dumps(req("anthropic:claude-sonnet-5-5")).encode())
            self.assertTrue(out["ok"], out)
            self.assertEqual(self.sent[0][1], {"x-api-key": "ak"})
            self.assertEqual(self.sent[0][0].host, "api.anthropic.com")
            self.assertEqual(self.ledger.settled[0].model, "claude-sonnet-5-5")
            _, _, amount = self.ledger.reserved[0]
            self.assertGreaterEqual(amount, 64 * 15)
        finally:
            if saved is None:
                del nb.MODEL_RATES["claude-sonnet-5-5"]
            else:
                nb.MODEL_RATES["claude-sonnet-5-5"] = saved

    def test_failures_stop_the_broker(self):
        b = self.broker(reply={"id": "x", "status": "failed"})
        self.assertFalse(b.handle(json.dumps(req()).encode())["ok"])
        self.assertEqual(self.ledger.failed, ["RECEIPT_SCHEMA_VIOLATION"])
        self.assertIn("stopped", b.handle(json.dumps(req()).encode())["error"])
        b2 = self.broker(ledger=FakeLedger(refuse=True))
        self.assertIn("ledger refused", b2.handle(json.dumps(req()).encode())["error"])

    def test_request_limit(self):
        b = self.broker()
        for _ in range(4):
            self.assertTrue(b.handle(json.dumps(req()).encode())["ok"])
        self.assertIn("limit", b.handle(json.dumps(req()).encode())["error"])

    def test_socket_and_client(self):
        b = self.broker()
        d = tempfile.mkdtemp()
        path = Path(d) / "b.sock"
        threading.Thread(target=b.serve, args=(path,), daemon=True).start()
        for _ in range(50):
            if path.exists():
                break
            time.sleep(0.05)
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)
        reply = ask_model(str(path), dict(req(), messages=[{"role": "user", "content": "x"}]))
        self.assertEqual(reply["tool_calls"][0]["arguments"]["limit_price"], Decimal("9.95"))
        with self.assertRaises(ModelError):
            ask_model(str(path), {"model": "nope"})


if __name__ == "__main__":
    unittest.main()
