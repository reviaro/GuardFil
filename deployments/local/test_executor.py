import sys
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deployments.local.executor import AgentSpec, Executor, Mount, RelaySpec  # noqa: E402


def flag_value(args, flag):
    return args[args.index(flag) + 1]


class ExecutorArgsTest(unittest.TestCase):
    def setUp(self):
        self.ex = Executor("t1", "guardfil.run-agent=t1")
        self.relay = RelaySpec("img", Path("/r/relay.py"), Path("/tmp/gfcx-x"), ["python3", "/srv/relay.py"])
        self.spec = AgentSpec("img", ["agent"], Path("/w"), mounts=[Mount(Path("/bin-dir"), "/usr/local/bin")])
        self.ex.workspace = Mock(ready=True, view=Path("/private/view"))

    def check_hardened(self, args):
        for flag in ("--read-only", "--cap-drop=ALL"):
            self.assertIn(flag, args)
        self.assertEqual(flag_value(args, "--security-opt"), "no-new-privileges")
        self.assertEqual(flag_value(args, "--pids-limit"), "256")
        self.assertEqual(flag_value(args, "--memory"), flag_value(args, "--memory-swap"))
        self.assertEqual(flag_value(args, "--ipc"), "private")
        self.assertRegex(flag_value(args, "--user"), r"^\d+:\d+$")
        self.assertNotIn("--privileged", args)
        self.assertFalse(any("docker.sock" in a for a in args))

    def test_anchor_has_no_network(self):
        args = self.ex.anchor_args(self.relay)
        self.check_hardened(args)
        self.assertEqual(flag_value(args, "--network"), "none")

    def test_agent_shares_only_the_anchor_namespace(self):
        args = self.ex.agent_args(self.spec)
        self.check_hardened(args)
        self.assertEqual(flag_value(args, "--network"), "container:gf-exec-anchor-t1")
        mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
        self.assertEqual(mounts, ["/private/view:/workspace:rw", "/bin-dir:/usr/local/bin:ro"])
        self.assertIn("nosuid", flag_value(args, "--tmpfs"))

    def test_without_relay_the_agent_has_no_network(self):
        args = self.ex.agent_args(self.spec, relay=False)
        self.check_hardened(args)
        self.assertEqual(flag_value(args, "--network"), "none")

    def test_no_guardfil_paths_by_default(self):
        args = self.ex.agent_args(self.spec) + self.ex.anchor_args(self.relay)
        for bad in ("credentials", "approval.sock", "owner", "/var/lib/guardfil", "/etc/guardfil"):
            self.assertFalse(any(bad in a for a in args), bad)

    def test_cannot_mount_raw_workspace_without_helper(self):
        self.ex.workspace = None
        with self.assertRaisesRegex(RuntimeError, "mediated workspace"):
            self.ex.agent_args(self.spec)
        with patch("deployments.local.executor.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "requires a workspace helper"):
                self.ex.start(None, self.spec)
            spawn.assert_not_called()

    def test_additional_mount_cannot_alias_raw_workspace(self):
        for source in (Path("/w"), Path("/w/secret"), Path("/")):
            with self.subTest(source=source):
                self.spec.mounts = [Mount(source, "/alternate")]
                with self.assertRaisesRegex(RuntimeError, "raw workspace"):
                    self.ex.agent_args(self.spec)

    def test_shell_startup_does_not_use_writable_home_or_path(self):
        self.spec.env = {"HOME": "/tmp", "BASH_ENV": "/workspace/evil", "PATH": "/workspace"}
        args = self.ex.agent_args(self.spec)
        env = [args[i+1] for i, arg in enumerate(args) if arg == "-e"]
        self.assertIn("HOME=/guardfil-home", env)
        self.assertIn("PATH=/usr/local/bin:/usr/bin:/bin", env)
        self.assertIn("BASH_ENV=/dev/null", env)
        self.assertNotIn("HOME=/tmp", env)

    def test_mount_failure_starts_no_container(self):
        self.spec.workspace_socket = Path("/approval.sock")
        self.spec.workspace_binary = Path("/guardfil-workspace")
        with patch("deployments.local.executor.WorkspaceMount") as mount, \
                patch("deployments.local.executor.docker") as docker, \
                patch("deployments.local.executor.subprocess.Popen") as spawn:
            mount.return_value.start.side_effect = RuntimeError("mount refused")
            docker.return_value.stdout = ""
            with self.assertRaisesRegex(RuntimeError, "mount refused"):
                self.ex.start(self.relay, self.spec)
            spawn.assert_not_called()
            self.assertFalse(any(c.args[0] == "run" for c in docker.call_args_list))
            mount.return_value.stop.assert_called_once()

    def test_containers_stop_before_workspace_unmount(self):
        calls = Mock()
        calls.attach_mock(self.ex.workspace.stop, "unmount")
        with patch("deployments.local.executor.docker", return_value=Mock(stdout="agent123")) as docker:
            calls.attach_mock(docker, "docker")
            self.ex.stop()
        self.assertEqual(calls.mock_calls[-2].args, ("rm", "-f", "agent123"))
        self.assertEqual(calls.mock_calls[-1][0], "unmount")


if __name__ == "__main__":
    unittest.main()
