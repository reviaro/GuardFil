import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardfil_client import Blocked, Decision, FilterError, GuardFil, _encode  # noqa: E402


class FakeService:
    """One-connection-per-request Unix socket server that records requests."""

    def __init__(self, reply=None):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "a.sock")
        self.requests = []
        self.reply = reply or (lambda req: {"effect": "ALLOW", "reasons": ["POLICY_ALLOWED"], "rule_ids": ["r"],
                                            "policy_digest": "x", "action_digest": "y"})
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(4)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            data = b""
            while True:
                b = c.recv(4096)
                if not b:
                    break
                data += b
            req = json.loads(data)
            self.requests.append((data, req))
            r = self.reply(req)
            c.sendall(r if isinstance(r, bytes) else (json.dumps(r) + "\n").encode())
            c.close()

    def close(self):
        self.srv.close()


class EncodeTest(unittest.TestCase):
    def test_decimal_is_exact_literal(self):
        self.assertEqual(_encode({"p": Decimal("12.50"), "q": 10, "s": "x", "b": True}),
                         '{"p":12.50,"q":10,"s":"x","b":true}')
        self.assertEqual(_encode(Decimal("0.1")), "0.1")
        self.assertEqual(_encode(Decimal("1E+3")), "1000")

    def test_float_refused(self):
        with self.assertRaises(TypeError):
            _encode({"p": 0.1})
        with self.assertRaises(ValueError):
            _encode(Decimal("NaN"))


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.svc = FakeService()
        self.gf = GuardFil(self.svc.path, timeout=5)

    def tearDown(self):
        self.svc.close()

    def test_check_sends_mcp_form(self):
        d = self.gf.check("stockapp.place_order", {"symbol": "ACME", "limit_price": Decimal("12.50")})
        self.assertTrue(d.allowed)
        raw, req = self.svc.requests[0]
        self.assertEqual(req["server"], "stockapp")
        self.assertEqual(req["tool"], "place_order")
        self.assertIn(b'"limit_price":12.50', raw)
        self.assertTrue(raw.endswith(b"\n"))

    def test_bad_tool_name(self):
        with self.assertRaises(ValueError):
            self.gf.check("place_order", {})

    def test_guard_runs_only_when_allowed(self):
        ran = []

        @self.gf.guard("stockapp.place_order")
        def place_order(symbol, side, quantity, limit_price=None):
            ran.append(symbol)
            return "ok"

        self.assertEqual(place_order("ACME", "buy", 3), "ok")
        self.assertEqual(self.svc.requests[-1][1]["arguments"], {"symbol": "ACME", "side": "buy", "quantity": 3})
        self.svc.reply = lambda req: {"effect": "BLOCK", "reasons": ["APPROVAL_REJECTED"], "rule_ids": ["ask-orders"]}
        with self.assertRaises(Blocked) as cm:
            place_order("ACME", "buy", 3000)
        self.assertEqual(cm.exception.decision.asked, "denied")
        self.assertEqual(ran, ["ACME"])

    def test_monitored_and_asked(self):
        self.svc.reply = lambda req: {"effect": "ALLOW", "reasons": ["POLICY_MONITORED"], "rule_ids": ["m"]}
        self.assertTrue(self.gf.check("a.b").monitored)
        self.svc.reply = lambda req: {"effect": "ALLOW", "reasons": ["APPROVAL_GRANTED"], "rule_ids": ["a"]}
        self.assertEqual(self.gf.check("a.b").asked, "allowed")

    def test_bad_reply_is_block(self):
        self.svc.reply = lambda req: b"nonsense"
        d = self.gf.check("a.b")
        self.assertFalse(d.allowed)
        self.assertEqual(d.error, "bad_reply")
        self.svc.reply = lambda req: {"effect": "MAYBE", "reasons": [], "rule_ids": []}
        self.assertFalse(self.gf.check("a.b").allowed)

    def test_unavailable_is_block(self):
        d = GuardFil("/nonexistent/x.sock", timeout=1).check("a.b")
        self.assertEqual((d.allowed, d.error), (False, "unavailable"))

    def test_on_decision_hook(self):
        seen = []
        gf = GuardFil(self.svc.path, timeout=5, on_decision=lambda t, d: seen.append((t, d.allowed)))
        gf.check("a.b")
        self.assertEqual(seen, [("a.b", True)])


class FilterTest(unittest.TestCase):
    def setUp(self):
        def reply(req):
            if req.get("kind") == "filter":
                return {"content": req["content"].replace("hunter2", "[REDACTED:secret_field]"), "redactions": 1}
            return {"effect": "ALLOW", "reasons": ["POLICY_FILTERED"], "rule_ids": ["f"], "filter": ["f"]}
        self.svc = FakeService(reply)
        self.gf = GuardFil(self.svc.path, timeout=5)

    def tearDown(self):
        self.svc.close()

    def test_guard_filters_result_and_declares_can_filter(self):
        @self.gf.guard("stockapp.get_portfolio")
        def get_portfolio():
            return {"cash": Decimal("100.00"), "login": {"password": "hunter2"}, "notes": ["pw hunter2"]}

        out = get_portfolio()
        self.assertEqual(out["cash"], Decimal("100.00"))
        self.assertNotIn("hunter2", repr(out))
        self.assertTrue(self.svc.requests[0][1]["can_filter"])

    def test_check_without_can_filter(self):
        self.gf.check("a.b", {})
        self.assertNotIn("can_filter", self.svc.requests[0][1])
        self.assertEqual(self.gf.check("a.b").filter, ("f",))

    def test_filter_refuses_opaque_objects(self):
        with self.assertRaises(FilterError):
            self.gf.filter("a.b", object())
        with self.assertRaises(FilterError):
            self.gf.filter("a.b", {"x": 0.5})

    def test_filter_fails_closed(self):
        with self.assertRaises(FilterError):
            GuardFil("/nonexistent/x.sock", timeout=1).filter("a.b", "secret")
        self.svc.reply = lambda req: b"nonsense"
        with self.assertRaises(FilterError):
            self.gf.filter("a.b", "x")


if __name__ == "__main__":
    unittest.main()
