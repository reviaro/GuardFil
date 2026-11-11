import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claude_hook as ch  # noqa: E402
import run_claude as rcl  # noqa: E402


def ev(name, inp, cwd="/workspace"):
    return {"hook_event_name": "PreToolUse", "tool_name": name, "tool_input": inp, "cwd": cwd}


class MappingTest(unittest.TestCase):
    def test_bash_is_shell(self):
        self.assertEqual(ch.request_for(ev("Bash", {"command": "ls -la"})),
                         {"kind": "shell", "command": ["bash", "-c", "ls -la"], "cwd": "/workspace"})

    def test_writes_are_file_writes_with_normalized_paths(self):
        r = ch.request_for(ev("Edit", {"file_path": "sub/../x.txt", "old_string": "a", "new_string": "b"}))
        self.assertEqual(r, {"kind": "file_write", "changes": [{"path": "/workspace/x.txt", "change": "add"}]})
        r = ch.request_for(ev("Write", {"file_path": "/etc/passwd", "content": "x"}))
        self.assertEqual(r["changes"][0], {"path": "/etc/passwd", "change": "update"})

    def test_builtin_tools_projected_and_lower_cased(self):
        r = ch.request_for(ev("Read", {"file_path": "/workspace/a", "offset": 3}))
        self.assertEqual(r, {"server": "claude", "tool": "read", "arguments": {"file_path": "/workspace/a"}})
        r = ch.request_for(ev("WebFetch", {"url": "https://example.com", "prompt": "long"}))
        self.assertEqual(r["arguments"], {"url": "https://example.com"})
        self.assertEqual(ch.request_for(ev("TodoWrite", {"todos": []}))["arguments"], {})

    def test_read_paths_resolved_against_cwd(self):
        r = ch.request_for(ev("Read", {"file_path": "sub/../secrets/k"}))
        self.assertEqual(r["arguments"], {"file_path": "/workspace/secrets/k"})
        r = ch.request_for(ev("Grep", {"pattern": "key"}, cwd="/workspace/app"))
        self.assertEqual(r["arguments"], {"pattern": "key", "path": "/workspace/app"})
        r = ch.request_for(ev("Glob", {"pattern": "*.py", "path": "../x/"}))
        self.assertEqual(r["arguments"], {"pattern": "*.py", "path": "/x"})

    def test_mcp_tools(self):
        r = ch.request_for(ev("mcp__notes__add_note", {"text": "hi"}))
        self.assertEqual(r, {"server": "notes", "tool": "add_note", "arguments": {"text": "hi"}, "can_filter": True})

    def test_unreadable_calls_raise(self):
        for bad in (ev("Bash", {}), ev("Write", {"content": "x"}), {"tool_name": 3, "tool_input": {}}):
            with self.assertRaises(Exception):
                ch.request_for(bad)


class FailClosedTest(unittest.TestCase):
    def run_hook(self, event, sock, argv=()):
        ch.SOCK = sock
        sys.stdin = io.StringIO(json.dumps(event))
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = ch.main(list(argv))
        finally:
            sys.stdin = sys.__stdin__
        return code, out.getvalue(), err.getvalue()

    def serve(self, reply):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "s")
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(path)
        srv.listen(1)

        def one():
            c, _ = srv.accept()
            c.recv(65536)
            c.sendall(reply)
            c.close()
            srv.close()
        threading.Thread(target=one, daemon=True).start()
        return path

    def test_no_guardfil_blocks(self):
        code, out, err = self.run_hook(ev("Bash", {"command": "id"}), "/nonexistent/approval.sock")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("blocked", err)

    def test_garbage_reply_blocks(self):
        code, out, _ = self.run_hook(ev("Bash", {"command": "id"}), self.serve(b"not json"))
        self.assertEqual((code, out), (2, ""))

    def test_block_verdict_blocks(self):
        code, _, err = self.run_hook(ev("Bash", {"command": "id"}),
                                     self.serve(b'{"effect":"BLOCK","reasons":["POLICY_DENIED"],"rule_ids":["r"]}'))
        self.assertEqual(code, 2)
        self.assertIn("POLICY_DENIED", err)

    def test_allow_verdict_allows(self):
        code, out, _ = self.run_hook(ev("Bash", {"command": "id"}),
                                     self.serve(b'{"effect":"ALLOW","reasons":["POLICY_ALLOWED"],"rule_ids":["r"]}'))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_unreadable_event_blocks(self):
        sys.stdin = io.StringIO("{")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ch.main([]), 2)
        sys.stdin = sys.__stdin__

    def test_only_managed_proxy_servers_can_delegate(self):
        for server, expected in (("notes", 0), ("other", 2)):
            code, out, _ = self.run_hook(ev(f"mcp__{server}__write", {"text": "hi"}),
                                         "/nonexistent/approval.sock", ["--proxy-server", "notes"])
            self.assertEqual(code, expected)
            if code == 0:
                self.assertIn("PROXY_DECIDES_ACTUAL_CALL", out)


class ManagedSettingsTest(unittest.TestCase):
    def test_hook_is_managed_and_blocks_on_failure(self):
        s = rcl.managed_settings()
        hook = s["hooks"]["PreToolUse"][0]
        self.assertEqual(hook["matcher"], "*")
        self.assertEqual(hook["hooks"][0]["onFailure"], "block")
        self.assertTrue(s["allowManagedHooksOnly"])
        self.assertEqual(s["permissions"]["disableBypassPermissionsMode"], "disable")
        command = rcl.managed_settings(["notes"])["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn("--proxy-server notes", command)

    def test_model_flag(self):
        env = rcl.claude_env("claude-opus-5-5")
        self.assertEqual({env[k] for k in env if k.endswith("_MODEL")}, {"claude-opus-5-5"})
        self.assertEqual(rcl.claude_env()["ANTHROPIC_MODEL"], "claude-sonnet-5-5")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rcl.parse_args(["--workspace", tmp, "--prompt", "x", "--model", "claude-opus-5-5"]).model,
                             "claude-opus-5-5")
            with self.assertRaises(SystemExit):
                rcl.parse_args(["--workspace", tmp, "--prompt", "x", "--model", "Opus 5"])

    def test_no_real_key_in_the_environment(self):
        env = rcl.claude_env()
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "guardfil-broker")
        self.assertTrue(env["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:"))

    def test_optional_gateway_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            claude_bin = base / "claude"
            claude_bin.write_text("#!/bin/sh\n")
            sock_path = base / "gw.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            self.addCleanup(srv.close)
            not_a_sock = base / "regular.txt"
            not_a_sock.write_text("x")

            for bad in (str(base / "missing.sock"), str(not_a_sock)):
                with self.assertRaises(SystemExit):
                    rcl.parse_args(["--workspace", tmp, "--prompt", "hi", "--gateway-socket", bad])
                with self.assertRaises(RuntimeError):
                    rcl.Session(base, base, 4, claude_bin, out=lambda m: None, gateway_socket=Path(bad))

            s_none = rcl.Session(base, base, 4, claude_bin, out=lambda m: None)
            spec_none = s_none.build_agent_spec("hi", 4, base / "h", base / "s.json", base / "a.sock")
            self.assertNotIn("GUARDFIL_GATEWAY_SOCKET", spec_none.env)
            # Claude Code may use only the MCP servers GuardFil configured (none here),
            # never a workspace .mcp.json or a config the agent wrote in /claude_home.
            self.assertIn("--strict-mcp-config", spec_none.command)
            self.assertEqual(spec_none.command[spec_none.command.index("--setting-sources") + 1], "")
            self.assertNotIn("--mcp-config", spec_none.command)
            self.assertFalse(any(m.target == "/run/guardfil/gateway.sock" for m in spec_none.mounts))

            a = rcl.parse_args(["--workspace", tmp, "--prompt", "hi", "--gateway-socket", str(sock_path)])
            self.assertEqual(a.gateway_socket, sock_path.resolve())
            s_gw = rcl.Session(base, base, 4, claude_bin, out=lambda m: None, gateway_socket=a.gateway_socket)
            spec_gw = s_gw.build_agent_spec("hi", 4, base / "h", base / "s.json", base / "a.sock")
            self.assertEqual(spec_gw.env.get("GUARDFIL_GATEWAY_SOCKET"), "/run/guardfil/gateway.sock")
            gw_mounts = [m for m in spec_gw.mounts if m.target == "/run/guardfil/gateway.sock"]
            self.assertEqual(len(gw_mounts), 1)
            self.assertEqual(gw_mounts[0].source, sock_path.resolve())
            self.assertTrue(gw_mounts[0].writable)

    def test_claude_mcp_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            claude_bin = base / "claude"
            claude_bin.write_text("#!/bin/sh\n")
            filter_sock = base / "run" / "filter.sock"
            filter_sock.parent.mkdir(parents=True)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(filter_sock))
            self.addCleanup(srv.close)
            proxy_bin = base / "bin" / "guardfil-mcp-proxy"
            proxy_bin.parent.mkdir(parents=True)
            proxy_bin.write_text("#!/bin/sh\n")
            proxy_bin.chmod(0o755)

            a = rcl.parse_args(["--workspace", tmp, "--prompt", "hi", "--mcp", "notes=demo"])
            self.assertEqual(len(a.mcp), 1)
            self.assertEqual(a.mcp[0][0], "notes")

            s = rcl.Session(base, base, 4, claude_bin, out=lambda m: None, mcp=a.mcp)
            spec = s.build_agent_spec("hi", 4, base / "h", base / "s.json", base / "a.sock")
            self.assertIn("--mcp-config", spec.command)
            mcp_mounts = [m for m in spec.mounts if m.target == "/claude_home/mcp-config.json"]
            self.assertEqual(len(mcp_mounts), 1)
            cfg = json.loads(Path(mcp_mounts[0].source).read_text())
            self.assertIn("notes", cfg["mcpServers"])
            self.assertEqual(cfg["mcpServers"]["notes"]["command"], "/opt/guardfil/guardfil-mcp-proxy")
            self.assertEqual(cfg["mcpServers"]["notes"]["args"][:2], ["--socket", "/run/guardfil/approval.sock"])


if __name__ == "__main__":
    unittest.main()
