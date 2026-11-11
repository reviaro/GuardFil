"""Offline tests for per-agent identity and runtime session management."""
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_session import AgentSession, read_approver_socket  # noqa: E402
import run_codex as rc  # noqa: E402
import run_claude as rcc  # noqa: E402
import run_python as rp  # noqa: E402


class MockOwnerServer:
    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self.created = []
        self.deleted = []
        self.session_counter = 0
        self.approval_sock_path = "/tmp/mock-approval.sock"

        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # quiet in test

            def do_POST(self):
                if self.path == "/sessions":
                    content_len = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(content_len).decode("utf-8"))
                    agent = body.get("agent")
                    owner.session_counter += 1
                    sess_id = f"sess{owner.session_counter:04d}"
                    owner.created.append({"session": sess_id, "agent": agent, "default": body.get("default", False)})
                    reply = {
                        "session": sess_id,
                        "principal": "codex-agent" if body.get("default") else f"agent.{agent}",
                        "approval_socket": owner.approval_sock_path,
                        "gateway_token": f"token-{sess_id}",
                    }
                    data = json.dumps(reply).encode("utf-8")
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_DELETE(self):
                if self.path.startswith("/sessions/"):
                    sess_id = self.path.split("/sessions/", 1)[1]
                    owner.deleted.append(sess_id)
                    self.send_response(204)
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler, bind_and_activate=False)
        if hasattr(self.server, "socket") and self.server.socket is not None:
            self.server.socket.close()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sock_path)
        self.sock.listen(5)
        self.server.socket = self.sock
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.sock.close()
        try:
            os.remove(self.sock_path)
        except OSError:
            pass


class ReadApproverSocketTest(unittest.TestCase):
    def test_missing_config_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError) as ctx:
                read_approver_socket(Path(tmp))
            self.assertIn("missing", str(ctx.exception))

    def test_missing_approver_socket_field_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "config"
            cfg_dir.mkdir(parents=True)
            (cfg_dir / "guardfil.yaml").write_text("approval:\n  socket: /tmp/a.sock\n")
            with self.assertRaises(RuntimeError) as ctx:
                read_approver_socket(Path(tmp))
            self.assertIn("approver_socket is not set", str(ctx.exception))

    def test_valid_approver_socket_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "config"
            cfg_dir.mkdir(parents=True)
            (cfg_dir / "guardfil.yaml").write_text("approval:\n  approver_socket: /tmp/owner.sock\n")
            res = read_approver_socket(Path(tmp))
            self.assertEqual(res, "/tmp/owner.sock")


class AgentSessionClientTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.owner_sock = os.path.join(self.tmpdir, "owner.sock")
        self.mock = MockOwnerServer(self.owner_sock)

    def tearDown(self):
        self.mock.close()
        try:
            os.rmdir(self.tmpdir)
        except OSError:
            pass

    def test_open_and_close_session(self):
        sess = AgentSession(self.owner_sock, "test-bot")
        sess.open()
        self.assertEqual(sess.session_id, "sess0001")
        self.assertEqual(sess.principal, "agent.test-bot")
        self.assertEqual(sess.gateway_token, "token-sess0001")
        self.assertEqual(len(self.mock.created), 1)

        sess.close()
        self.assertIn("sess0001", self.mock.deleted)

    def test_context_manager(self):
        with AgentSession(self.owner_sock, "ctx-bot") as sess:
            self.assertEqual(sess.principal, "agent.ctx-bot")
        self.assertIn("sess0001", self.mock.deleted)

    def test_broker_binding_is_host_only_and_requires_an_active_session(self):
        sess = AgentSession(self.owner_sock, None)
        with self.assertRaises(RuntimeError):
            sess.broker_env()
        with sess:
            env = sess.broker_env()
            self.assertEqual(env["GUARDFIL_OWNER_SOCKET"], self.owner_sock)
            self.assertEqual(env["GUARDFIL_SESSION_ID"], sess.session_id)
            self.assertIsNot(env, os.environ)
        with self.assertRaises(RuntimeError):
            sess.broker_env()

    def test_default_identity_has_a_distinct_session(self):
        with AgentSession(self.owner_sock, None) as first, AgentSession(self.owner_sock, None) as second:
            self.assertEqual(first.principal, "codex-agent")
            self.assertEqual(second.principal, "codex-agent")
            self.assertNotEqual(first.session_id, second.session_id)
        self.assertEqual(len(self.mock.deleted), 2)
        self.assertTrue(all(item["default"] for item in self.mock.created))


class RuntimeAgentCleanupTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.home = Path(self.tmpdir)
        self.owner_sock = os.path.join(self.tmpdir, "owner.sock")
        self.mock = MockOwnerServer(self.owner_sock)

        cfg_dir = self.home / "config"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "guardfil.yaml").write_text(f"approval:\n  approver_socket: {self.owner_sock}\n")

    def tearDown(self):
        self.mock.close()

    def test_codex_session_deleted_on_startup_failure(self):
        # The mock server returns approval_socket: /tmp/mock-approval.sock which does not exist,
        # so Session.start() fails when checking if approval_sock is a socket.
        s = rc.Session(self.home, self.home, 4, self.home, out=lambda m: None, agent="codex-worker")
        with self.assertRaises(rc.RunError):
            s.start()
        # Verify session was created on mock server
        self.assertEqual(len(self.mock.created), 1)
        self.assertEqual(self.mock.created[0]["agent"], "codex-worker")
        # Verify session was deleted even though start() failed
        self.assertEqual(len(self.mock.deleted), 1)
        self.assertEqual(self.mock.deleted[0], self.mock.created[0]["session"])

    def test_claude_session_deleted_on_startup_failure(self):
        s = rcc.Session(self.home, self.home, 4, self.home, out=lambda m: None, agent="claude-worker")
        with self.assertRaises(RuntimeError):
            s.start(prompt="hi", max_turns=1)
        self.assertEqual(len(self.mock.created), 1)
        self.assertEqual(self.mock.created[0]["agent"], "claude-worker")
        self.assertEqual(len(self.mock.deleted), 1)
        self.assertEqual(self.mock.deleted[0], self.mock.created[0]["session"])

    def test_python_session_deleted_on_startup_failure(self):
        s = rp.Session(self.home, self.home, 4, out=lambda m: None, agent="py-worker")
        with self.assertRaises(RuntimeError):
            s.start(agent=self.home / "agent.py", model="test-model", task="do stuff")
        self.assertEqual(len(self.mock.created), 1)
        self.assertEqual(self.mock.created[0]["agent"], "py-worker")
        self.assertEqual(len(self.mock.deleted), 1)
        self.assertEqual(self.mock.deleted[0], self.mock.created[0]["session"])

    def test_missing_approver_socket_config_refuses_to_start(self):
        # Empty config without approver_socket
        (self.home / "config" / "guardfil.yaml").write_text("approval:\n  socket: /tmp/s.sock\n")
        s = rc.Session(self.home, self.home, 4, self.home, out=lambda m: None, agent="codex-worker")
        with self.assertRaises(RuntimeError) as ctx:
            s.start()
        self.assertIn("approval.approver_socket is not set", str(ctx.exception))
        self.assertEqual(len(self.mock.created), 0)

    def test_default_session_is_created_and_cleaned_up_on_failure(self):
        s = rc.Session(self.home, self.home, 4, self.home, out=lambda m: None, agent=None)
        with self.assertRaises(rc.RunError):
            s.start()
        self.assertEqual(len(self.mock.created), 1)
        self.assertTrue(self.mock.created[0]["default"])
        self.assertEqual(self.mock.deleted, [self.mock.created[0]["session"]])


class HostPathTest(unittest.TestCase):
    """GuardFil runs in a container; the paths it reports are mapped to $GF_HOME."""

    def test_container_paths_map_to_gf_home(self):
        from deployments.local.agent_session import host_path
        home = Path("/h/gf")
        self.assertEqual(host_path(home, "/run/guardfil/agents/ab.sock"), "/h/gf/run/agents/ab.sock")
        self.assertEqual(host_path(home, "/run/guardfil-owner/owner.sock"), "/h/gf/owner/owner.sock")
        self.assertEqual(host_path(home, "/other/x.sock"), "/other/x.sock")


if __name__ == "__main__":
    unittest.main()
