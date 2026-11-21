"""Offline tests for per-agent identity and runtime session management."""
import http.server
import io
import json
import os
import socket
import sys
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_session import AgentSession, read_approver_socket  # noqa: E402
import run_codex as rc  # noqa: E402
import run_claude as rcc  # noqa: E402
import run_python as rp  # noqa: E402
from deployments.local.runtime_cleanup import CleanupError, finish_cli_cleanup  # noqa: E402


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

    def test_failed_delete_retains_identity_for_retry_and_closes_connection(self):
        for failure in (500, OSError("synthetic transport failure")):
            with self.subTest(failure=failure):
                sess = AgentSession(self.owner_sock, None)
                sess.session_id, sess.gateway_token = "synthetic-session", "synthetic-token"
                first, second = Mock(), Mock()
                if isinstance(failure, int):
                    first.getresponse.return_value.status = failure
                else:
                    first.request.side_effect = failure
                second.getresponse.return_value.status = 204
                with patch("agent_session._UnixHTTPConnection", side_effect=[first, second]):
                    with self.assertRaises((RuntimeError, OSError)):
                        sess.close()
                    self.assertEqual(sess.session_id, "synthetic-session")
                    self.assertEqual(sess.gateway_token, "synthetic-token")
                    first.close.assert_called_once()
                    sess.close()
                    second.request.assert_called_once_with("DELETE", "/sessions/synthetic-session")
                self.assertIsNone(sess.session_id)
                self.assertIsNone(sess.gateway_token)

    def test_delete_of_already_absent_session_is_successful(self):
        sess = AgentSession(self.owner_sock, None)
        sess.session_id = "synthetic-session"
        conn = Mock()
        conn.getresponse.return_value.status = 404
        with patch("agent_session._UnixHTTPConnection", return_value=conn):
            sess.close()
        self.assertIsNone(sess.session_id)
        conn.close.assert_called_once()


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


class RuntimeShutdownFailuresTest(unittest.TestCase):
    runtimes = (rc, rcc, rp)

    def session(self, runtime):
        session = runtime.Session.__new__(runtime.Session)
        session.agent_session = Mock()
        session.executor = Mock(containers_stopped=True)
        session.broker = Mock()
        session.broker.poll.return_value = None
        session.broker.wait.return_value = 0
        session.broker.communicate.return_value = ("", None)
        session.broker_log = Mock()
        session.sockdir = None
        session.out = Mock()
        return session

    def test_all_runtimes_attempt_every_independent_step_and_aggregate_failures(self):
        for runtime in self.runtimes:
            with self.subTest(runtime=runtime.__name__):
                session = self.session(runtime)
                authority, broker, log = session.agent_session, session.broker, session.broker_log
                authority.close.side_effect = OSError("owner unavailable")
                broker.terminate.side_effect = OSError("terminate rejected")
                broker.wait.side_effect = subprocess.TimeoutExpired("synthetic broker", 5)
                broker.kill.side_effect = OSError("kill rejected")
                log.close.side_effect = OSError("log close failed")
                session.executor.stop.side_effect = RuntimeError("Docker failed")
                with self.assertRaises(CleanupError) as error:
                    session.stop()
                for message in ("owner unavailable", "terminate rejected", "kill rejected",
                                "exit after kill", "log close failed", "Docker failed"):
                    self.assertIn(message, str(error.exception))
                authority.close.assert_called_once()
                broker.kill.assert_called_once()
                self.assertEqual(broker.wait.call_count, 2)
                log.close.assert_called_once()
                session.executor.stop.assert_called_once()
                self.assertIs(session.agent_session, authority)
                self.assertIs(session.broker, broker)
                self.assertIs(session.broker_log, log)

    def test_all_runtimes_await_kill_and_retry_failed_authority_revocation(self):
        for runtime in self.runtimes:
            with self.subTest(runtime=runtime.__name__):
                session = self.session(runtime)
                authority, broker = session.agent_session, session.broker
                authority.close.side_effect = [OSError("owner temporarily unavailable"), None]
                broker.wait.side_effect = [subprocess.TimeoutExpired("synthetic broker", 1), 0]
                with self.assertRaisesRegex(CleanupError, "owner temporarily unavailable"):
                    session.stop()
                broker.kill.assert_called_once()
                self.assertEqual(broker.wait.call_count, 2)
                self.assertEqual(broker.wait.call_args.kwargs, {"timeout": 5})
                broker.stdout.read.assert_not_called()
                self.assertIsNone(session.broker)
                self.assertIsNone(session.broker_log)
                self.assertIs(session.agent_session, authority)
                session.stop()
                self.assertIsNone(session.agent_session)
                self.assertEqual(authority.close.call_count, 2)
                self.assertEqual(broker.kill.call_count, 1)

    def test_all_runtimes_retain_socket_directory_until_processes_stop(self):
        for runtime in self.runtimes:
            for live in ("broker", "container"):
                with self.subTest(runtime=runtime.__name__, live=live), tempfile.TemporaryDirectory() as tmp:
                    session = self.session(runtime)
                    session.sockdir = Path(tmp) / "sockets"
                    session.sockdir.mkdir()
                    if live == "broker":
                        session.broker.wait.side_effect = subprocess.TimeoutExpired("synthetic broker", 1)
                    else:
                        session.executor.containers_stopped = False
                    with self.assertRaisesRegex(CleanupError, "retain broker directory"):
                        session.stop()
                    self.assertTrue(session.sockdir.exists())
                    if session.broker is not None:
                        session.broker.wait.side_effect = None
                    session.executor.containers_stopped = True
                    session.stop()
                    self.assertIsNone(session.sockdir)
                    self.assertFalse((Path(tmp) / "sockets").exists())

    def test_all_runtimes_attempt_broker_cleanup_after_docker_failure(self):
        for runtime in self.runtimes:
            with self.subTest(runtime=runtime.__name__):
                session = self.session(runtime)
                authority, broker = session.agent_session, session.broker
                session.executor.stop.side_effect = RuntimeError("Docker removal failure")
                with self.assertRaisesRegex(CleanupError, "Docker removal failure"):
                    session.stop()
                authority.close.assert_called_once()
                broker.terminate.assert_called_once()
                broker.wait.assert_called_once()
                self.assertIsNone(session.agent_session)
                self.assertIsNone(session.broker)

    def test_broker_summary_timeout_does_not_skip_executor_cleanup(self):
        for runtime in (rc, rcc):
            with self.subTest(runtime=runtime.__name__):
                session = self.session(runtime)
                broker = session.broker
                broker.communicate.side_effect = subprocess.TimeoutExpired("synthetic summary", 1)
                with self.assertRaisesRegex(CleanupError, "collect broker summary"):
                    session.stop()
                broker.communicate.assert_called_once_with(timeout=1)
                broker.stdout.close.assert_called_once()
                session.executor.stop.assert_called_once()
                self.assertIsNone(session.broker)

    def test_all_runtimes_preserve_startup_context_when_cleanup_fails(self):
        for runtime in self.runtimes:
            with self.subTest(runtime=runtime.__name__):
                session = self.session(runtime)
                session.gf_home = Path("/synthetic/home")
                original = RuntimeError("original owner startup error")
                with patch.object(runtime, "read_approver_socket", side_effect=original), \
                        patch.object(session, "stop", side_effect=RuntimeError("rollback failed")):
                    with self.assertRaisesRegex(RuntimeError, "original owner startup error.*rollback failed") as error:
                        if runtime is rc:
                            session.start()
                        elif runtime is rcc:
                            session.start("synthetic prompt", 1)
                        else:
                            session.start(Path("/synthetic/agent.py"), "synthetic-model", "synthetic task")
                chain = error.exception
                while chain is not None and chain is not original:
                    chain = chain.__cause__
                self.assertIs(chain, original)

    def test_cli_cleanup_reports_both_failures_and_preserves_existing_exit_status(self):
        for status, expected in ((0, 1), (1, 1), (130, 130)):
            with self.subTest(status=status):
                session, transcript = Mock(), Mock()
                session.stop.side_effect = RuntimeError("session cleanup failed")
                transcript.close.side_effect = OSError("transcript close failed")
                with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    self.assertEqual(finish_cli_cleanup(session, transcript, status), expected)
                self.assertIn("session cleanup failed", stderr.getvalue())
                self.assertIn("transcript close failed", stderr.getvalue())
                session.stop.assert_called_once()

    def test_each_cli_reports_successful_run_but_failed_cleanup_as_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "codex").write_text("synthetic binary placeholder")
            script = base / "agent.py"
            script.write_text("# synthetic script placeholder")
            for runtime in self.runtimes:
                with self.subTest(runtime=runtime.__name__):
                    session = Mock(gf_home=base, dir=base)
                    proc = session.start.return_value
                    proc.stdout = []
                    proc.returncode = 0
                    session.stop.side_effect = RuntimeError("synthetic cleanup failure")
                    args = ["--workspace", tmp]
                    if runtime is rc:
                        args += ["--codex-bin-dir", tmp, "--prompt", "synthetic", "--once"]
                    elif runtime is rcc:
                        args += ["--prompt", "synthetic"]
                    else:
                        args += ["--agent-file", str(script), "--task", "synthetic"]
                    with patch.object(runtime, "Session", return_value=session), \
                            patch.object(rc, "run_turns", return_value=1), \
                            patch("signal.signal"), \
                            patch("sys.stdout", new_callable=io.StringIO), \
                            patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        self.assertEqual(runtime.main(args), 1)
                    self.assertIn("synthetic cleanup failure", stderr.getvalue())
                    session.stop.assert_called_once()


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
