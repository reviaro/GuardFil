"""Offline tests for run_codex (no Docker, no broker, no model)."""
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_codex as rc  # noqa: E402


class FakeAsk:
    def __init__(self, effect="ALLOW"):
        self.effect = effect
        self.calls = []

    def __call__(self, sock, req):
        self.calls.append(req)
        return {"effect": self.effect, "reasons": ["POLICY_ALLOWED" if self.effect == "ALLOW" else "POLICY_DENIED"],
                "rule_ids": ["r1"]}


class GateTest(unittest.TestCase):
    def gate(self, effect="ALLOW"):
        ask = FakeAsk(effect)
        return rc.Gate("/nonexistent", ask=ask), ask

    def test_shell_string_is_split(self):
        g, ask = self.gate()
        res = g.decide("item/commandExecution/requestApproval",
                       {"command": "/bin/bash -lc 'echo hi > a.txt'", "cwd": "/workspace"})
        self.assertEqual(res, {"decision": "accept"})
        self.assertEqual(ask.calls, [{"kind": "shell", "command": ["/bin/bash", "-lc", "echo hi > a.txt"],
                                      "cwd": "/workspace"}])

    def test_shell_block_declines(self):
        g, _ = self.gate("BLOCK")
        self.assertEqual(g.decide("item/commandExecution/requestApproval", {"command": "ls", "cwd": "/workspace"}),
                         {"decision": "decline"})

    def test_v1_replies(self):
        g, _ = self.gate("BLOCK")
        self.assertEqual(g.decide("execCommandApproval", {"command": ["ls"], "cwd": "/workspace"}),
                         {"decision": "denied"})
        g, _ = self.gate("ALLOW")
        self.assertEqual(g.decide("execCommandApproval", {"command": ["ls"], "cwd": "/workspace"}),
                         {"decision": "approved"})

    def test_unparseable_command_blocks_without_asking(self):
        g, ask = self.gate()
        self.assertEqual(g.decide("item/commandExecution/requestApproval", {"command": "echo 'open", "cwd": "/w"}),
                         {"decision": "decline"})
        self.assertEqual(ask.calls, [])

    def test_file_change_uses_observed_paths(self):
        g, ask = self.gate()
        g.observe_item({"id": "i1", "type": "fileChange", "changes": [
            {"path": "/workspace/notes/a.md", "kind": {"type": "add"}, "diff": "SECRET CONTENT"},
            {"path": "/workspace/b.md", "kind": {"type": "update", "move_path": "/workspace/c.md"}}]})
        self.assertEqual(g.decide("item/fileChange/requestApproval", {"itemId": "i1"}), {"decision": "accept"})
        self.assertEqual(ask.calls[0], {"kind": "file_write", "changes": [
            {"path": "/workspace/notes/a.md", "change": "add"}, {"path": "/workspace/b.md", "change": "update"},
            {"path": "/workspace/c.md", "change": "add"}]})
        self.assertNotIn("SECRET", json.dumps(ask.calls))

    def test_file_change_unknown_item_blocks(self):
        g, ask = self.gate()
        self.assertEqual(g.decide("item/fileChange/requestApproval", {"itemId": "nope"}), {"decision": "decline"})
        self.assertEqual(ask.calls, [])

    def test_mcp_delegates_only_owner_configured_servers(self):
        ask = FakeAsk()
        g = rc.Gate("/nonexistent", ask=ask, protected_mcp=["stockapp"])
        for params, action in [
            ({"serverName": "stockapp", "_meta": {"codex_approval_kind": "mcp_tool_call"}}, "accept"),
            ({"serverName": "stockapp"}, "decline"),
            ({"serverName": "other", "_meta": {"codex_approval_kind": "mcp_tool_call"}}, "decline")]:
            self.assertEqual(g.decide("mcpServer/elicitation/request", params),
                             {"action": action, "content": None})
        self.assertEqual(ask.calls, [])  # actual admission belongs to the proxy

    def test_legacy_patch_covers_rename_and_refuses_overflow(self):
        g, ask = self.gate()
        self.assertEqual(g.decide("applyPatchApproval", {"fileChanges": {
            "/workspace/a": {"type": "update", "move_path": "/workspace/.git/hooks/pre-commit"}}}),
            {"decision": "approved"})
        self.assertEqual(ask.calls[-1]["changes"], [
            {"path": "/workspace/a", "change": "update"},
            {"path": "/workspace/.git/hooks/pre-commit", "change": "add"}])
        ask.calls.clear()
        for changes in ({str(i): {"type": "add"} for i in range(17)},
                        {"/workspace/a": {"type": "unknown"}},
                        {"/workspace/a": {"type": "update", "move_path": 42}}):
            self.assertEqual(g.decide("applyPatchApproval", {"fileChanges": changes}), {"decision": "denied"})
        self.assertEqual(ask.calls, [])

    def test_completed_patch_cannot_be_reapproved(self):
        g, ask = self.gate()
        item = {"id": "i1", "type": "fileChange", "changes": [
            {"path": "/workspace/a", "kind": {"type": "add"}}]}
        g.observe_item(item)
        g.complete_item(item)
        self.assertEqual(g.decide("item/fileChange/requestApproval", {"itemId": "i1"}), {"decision": "decline"})
        self.assertEqual(ask.calls, [])

    def test_mcp_without_pending_call_declines(self):
        g, _ = self.gate()
        self.assertEqual(g.decide("mcpServer/elicitation/request", {"serverName": "other"}),
                         {"action": "decline", "content": None})

    def test_permissions_never_granted(self):
        g, ask = self.gate()
        self.assertEqual(g.decide("item/permissions/requestApproval", {}), {"permissions": {}, "scope": "turn"})
        self.assertEqual(ask.calls, [])


class AskGuardfilTest(unittest.TestCase):
    def serve(self, reply: bytes):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "s.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        got = {}

        def run():
            c, _ = srv.accept()
            data = b""
            while True:
                b = c.recv(4096)
                if not b:
                    break
                data += b
            got["req"] = data
            c.sendall(reply)
            c.close()
            srv.close()
        threading.Thread(target=run, daemon=True).start()
        return path, got

    def test_allow_round_trip(self):
        path, got = self.serve(b'{"effect":"ALLOW","reasons":["POLICY_ALLOWED"],"rule_ids":["a"],'
                               b'"policy_digest":"x","action_digest":"y"}\n')
        out = rc.ask_guardfil(path, {"kind": "shell", "command": ["ls"], "cwd": "/workspace"}, timeout=5)
        self.assertEqual(out["effect"], "ALLOW")
        self.assertEqual(json.loads(got["req"]), {"kind": "shell", "command": ["ls"], "cwd": "/workspace"})
        self.assertTrue(got["req"].endswith(b"\n"))

    def test_garbage_is_block(self):
        path, _ = self.serve(b"not json")
        self.assertEqual(rc.ask_guardfil(path, {}, timeout=5)["effect"], "BLOCK")

    def test_unreachable_is_block(self):
        out = rc.ask_guardfil("/nonexistent/x.sock", {}, timeout=1)
        self.assertEqual(out, {"effect": "BLOCK", "reasons": ["APPROVAL_SERVICE_UNAVAILABLE"], "rule_ids": []})


class SessionTest(unittest.TestCase):
    def test_requires_running_guardfil(self):
        with tempfile.TemporaryDirectory() as home:
            s = rc.Session(Path(home), Path(home), 4, Path(home), out=lambda m: None)
            with self.assertRaises(rc.RunError):
                s.start()
            self.assertIsNone(s.broker)   # nothing started, no model spend

    def test_config_has_no_network_or_credentials(self):
        cfg = rc.config_toml()
        self.assertIn('base_url = "http://127.0.0.1:8899/v1"', cfg)
        self.assertNotIn("env_key", cfg)
        self.assertIn('trust_level = "untrusted"', cfg)

    def test_mcp_servers_behind_filter_proxy(self):
        import tomllib
        a = rc.parse_args(["--workspace", "/tmp", "--mcp", "notes=demo", "--mcp", "fs=node /w/fs.js --ro"])
        cfg = tomllib.loads(rc.config_toml(a.mcp))
        notes = cfg["mcp_servers"]["notes"]
        self.assertEqual(notes["command"], "/opt/guardfil/guardfil-mcp-proxy")
        self.assertEqual(notes["args"][:5], ["--socket", "/run/guardfil/approval.sock", "--server", "notes", "--"])
        self.assertEqual(notes["args"][-3:], ["python3", "-I", "/guardfil/demo_mcp.py"])
        self.assertEqual(cfg["mcp_servers"]["fs"]["args"][-3:], ["node", "/w/fs.js", "--ro"])
        for bad in (["--mcp", "Notes=demo"], ["--mcp", "notes"], ["--mcp", "a=demo", "--mcp", "a=demo"],
                    ["--mcp", "x="]):
            with self.assertRaises(SystemExit):
                rc.parse_args(["--workspace", "/tmp"] + bad)

    def test_max_requests_bounds(self):
        with self.assertRaises(SystemExit):
            rc.parse_args(["--workspace", "/tmp", "--max-requests", "65"])
        with self.assertRaises(SystemExit):
            rc.parse_args(["--workspace", "/tmp", "--once"])

    def test_optional_gateway_socket_and_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sock_path = base / "gw.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            self.addCleanup(srv.close)
            not_a_sock = base / "regular.txt"
            not_a_sock.write_text("x")

            # Missing or non-socket paths are rejected by CLI and Session
            for bad in (str(base / "missing.sock"), str(not_a_sock)):
                with self.assertRaises(SystemExit):
                    rc.parse_args(["--workspace", tmp, "--gateway-socket", bad])
                with self.assertRaises(rc.RunError):
                    rc.Session(base, base, 4, base, out=lambda m: None, gateway_socket=Path(bad))

            # Omitted gateway_socket leaves mounts and env unchanged
            s_none = rc.Session(base, base, 4, base, out=lambda m: None)
            spec_none = s_none.build_agent_spec(base / "ch", base / "cfg.toml")
            self.assertNotIn("GUARDFIL_GATEWAY_SOCKET", spec_none.env)
            self.assertFalse(any(m.target == "/run/guardfil/gateway.sock" for m in spec_none.mounts))

            # Valid gateway_socket mounts only the socket file (writable) and sets env
            a = rc.parse_args(["--workspace", tmp, "--gateway-socket", str(sock_path),
                               "--transcript", str(base / "t.jsonl")])
            self.assertEqual(a.gateway_socket, sock_path.resolve())
            self.assertEqual(a.transcript, str(base / "t.jsonl"))
            s_gw = rc.Session(base, base, 4, base, out=lambda m: None, gateway_socket=a.gateway_socket)
            spec_gw = s_gw.build_agent_spec(base / "ch", base / "cfg.toml")
            self.assertEqual(spec_gw.env.get("GUARDFIL_GATEWAY_SOCKET"), "/run/guardfil/gateway.sock")
            gw_mounts = [m for m in spec_gw.mounts if m.target == "/run/guardfil/gateway.sock"]
            self.assertEqual(len(gw_mounts), 1)
            self.assertEqual(gw_mounts[0].source, sock_path.resolve())
            self.assertTrue(gw_mounts[0].writable)
            self.assertFalse(any(m.source == base.resolve() and m.target != "/workspace" and m.target != "/usr/local/bin"
                                 for m in spec_gw.mounts))

    def test_model_flag(self):
        import tomllib
        self.assertEqual(tomllib.loads(rc.config_toml())["model"], "gpt-6-luna")
        self.assertEqual(tomllib.loads(rc.config_toml(None, "gpt-6-sol"))["model"], "gpt-6-sol")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rc.parse_args(["--workspace", tmp, "--model", "gpt-6-sol"]).model, "gpt-6-sol")
            self.assertEqual(rc.parse_args(["--workspace", tmp]).model, "gpt-6-luna")
            for bad in ("GPT 6", "../x", "", 'a"b'):
                with self.assertRaises(SystemExit):
                    rc.parse_args(["--workspace", tmp, "--model", bad])

    def test_gateway_from_gf_home_is_mounted_with_token(self):
        # guardfil-local.sh gateway runs the gateway on $GF_HOME/run/gateway.sock;
        # run-agent mounts it without --gateway-socket and passes the agent token.
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "run").mkdir()
            (home / "credentials").mkdir()
            (home / "config").mkdir()
            (home / "config/gateway.yaml").write_text("upstreams: []\n")
            (home / "credentials" / "gateway-agent-token").write_text("tok-123\n")
            (home / "credentials" / "ui-token").write_text("ui-secret")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(home / "run" / "gateway.sock"))
            self.addCleanup(srv.close)
            s = rc.Session(home, home, 4, home, out=lambda m: None)
            spec = s.build_agent_spec(home / "ch", home / "cfg.toml")
            self.assertEqual(spec.env.get("GUARDFIL_GATEWAY_SOCKET"), "/run/guardfil/gateway.sock")
            self.assertEqual(spec.env.get("GUARDFIL_GATEWAY_TOKEN"), "tok-123")
            self.assertNotIn("ui-secret", json.dumps(spec.env))
            self.assertEqual([m.source for m in spec.mounts if m.target == "/run/guardfil/gateway.sock"],
                             [(home / "run" / "gateway.sock")])

    def test_app_server_records_transcript_messages(self):
        import io
        seen = []

        class DummyProc:
            def __init__(self):
                self.stdout = io.BytesIO(
                    b'{"jsonrpc":"2.0","method":"item/completed","params":{"item":{"type":"agentMessage","text":"hi"}}}\n'
                    b'{"jsonrpc":"2.0","method":"turn/completed","params":{"turn":{"status":"completed"}}}\n'
                )
                self.stdin = io.BytesIO()

        proc = DummyProc()
        app = rc.AppServer(proc, rc.Gate("/nonexistent", ask=FakeAsk()), lambda m: None, on_message=seen.append)
        status = app.wait(None, timeout=5.0)
        self.assertEqual(status, {"status": "completed"})
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0]["method"], "item/completed")
        self.assertEqual(seen[1]["method"], "turn/completed")


if __name__ == "__main__":
    unittest.main()
