import sys
import os
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deployments.local.executor import AgentSpec, Executor, Mount, RelaySpec, check_mount_hardlinks, check_storage_bind_alias  # noqa: E402
import deployments.local.gfbin as gfbin  # noqa: E402
from deployments.local.runtime_cleanup import Cleanup, CleanupError, close_streams, stop_process  # noqa: E402


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
        self.ex.containers_stopped = False
        calls = Mock()
        calls.attach_mock(self.ex.workspace.stop, "unmount")
        with patch("deployments.local.executor.docker", side_effect=[
                Mock(stdout="agent123"), Mock(), Mock(stdout="")]) as docker:
            calls.attach_mock(docker, "docker")
            self.ex.stop()
        self.assertEqual(calls.mock_calls[-3].args, ("rm", "-f", "agent123"))
        self.assertEqual(calls.mock_calls[-2].args[0], "ps")
        self.assertEqual(calls.mock_calls[-1][0], "unmount")
        self.assertTrue(self.ex.containers_stopped)

    def test_list_failure_still_removes_both_names_and_retains_unconfirmed_view(self):
        self.ex.containers_stopped = False
        view = self.ex.workspace
        def failing_docker(*args):
            if args[0] == "ps":
                raise OSError("synthetic daemon unavailable")
            return Mock()
        with patch("deployments.local.executor.docker", side_effect=failing_docker) as docker:
            with self.assertRaises(CleanupError) as error:
                self.ex.stop()
        self.assertIn(call("rm", "-f", self.ex.agent_name), docker.call_args_list)
        self.assertIn(call("rm", "-f", self.ex.anchor), docker.call_args_list)
        self.assertIn("confirm executor shutdown", str(error.exception))
        self.assertIn("retain workspace", str(error.exception))
        self.assertFalse(self.ex.containers_stopped)
        view.stop.assert_not_called()

    def test_remove_failure_does_not_skip_other_container_or_final_confirmation(self):
        self.ex.containers_stopped = False
        view = self.ex.workspace
        with patch("deployments.local.executor.docker", side_effect=[
                Mock(stdout="a b"), OSError("cannot remove a"), Mock(), Mock(stdout="a")]) as docker:
            with self.assertRaisesRegex(CleanupError, "cannot remove a"):
                self.ex.stop()
        self.assertIn(call("rm", "-f", "b"), docker.call_args_list)
        self.assertEqual(docker.call_count, 4)
        view.stop.assert_not_called()
        # A later cleanup can finish without discarding ownership of the view.
        with patch("deployments.local.executor.docker", side_effect=[Mock(stdout="a"), Mock(), Mock(stdout="")]):
            self.ex.stop()
        view.stop.assert_called_once()
        self.assertIsNone(self.ex.workspace)

    def test_unmount_failure_keeps_view_retryable(self):
        view = self.ex.workspace
        view.stop.side_effect = [OSError("unmount failed"), None]
        with self.assertRaisesRegex(CleanupError, "unmount failed"):
            self.ex.stop()
        self.assertIs(self.ex.workspace, view)
        self.ex.stop()
        self.assertIsNone(self.ex.workspace)

    def test_positive_shutdown_check_resolves_a_lost_remove_response(self):
        self.ex.containers_stopped = False
        view = self.ex.workspace
        with patch("deployments.local.executor.docker", side_effect=[
                Mock(stdout="agent123"), OSError("lost removal response"), Mock(stdout="")]):
            self.ex.stop()
        self.assertTrue(self.ex.containers_stopped)
        view.stop.assert_called_once()

    def test_client_kill_is_awaited_and_failed_exit_keeps_view(self):
        self.ex.containers_stopped = False
        view = self.ex.workspace
        client = self.ex.agent = Mock()
        client.poll.return_value = None
        client.wait.side_effect = subprocess.TimeoutExpired("synthetic docker client", 5)
        with patch("deployments.local.executor.docker", return_value=Mock(stdout="")):
            with self.assertRaisesRegex(CleanupError, "exit after kill"):
                self.ex.stop()
        client.kill.assert_called_once()
        self.assertEqual(client.wait.call_count, 2)
        client.stdout.close.assert_not_called()  # An active reader must not block cleanup.
        view.stop.assert_not_called()
        self.assertIs(self.ex.agent, client)

    def test_failed_start_keeps_original_error_when_rollback_fails(self):
        self.spec.workspace_socket = Path("/approval.sock")
        self.spec.workspace_binary = Path("/guardfil-workspace")
        original = RuntimeError("original mount startup error")
        with patch("deployments.local.executor.WorkspaceMount") as mount, \
                patch.object(self.ex, "stop", side_effect=RuntimeError("rollback error")):
            mount.return_value.start.side_effect = original
            with self.assertRaisesRegex(RuntimeError, "original mount startup error.*rollback error") as error:
                self.ex.start(None, self.spec)
        self.assertIs(error.exception.__cause__, original)

    def test_kill_fallback_reaps_a_real_synthetic_process(self):
        child = subprocess.Popen([sys.executable, "-I", "-c",
                                  "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                                  "print('READY', flush=True); time.sleep(30)"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        cleanup = Cleanup()
        try:
            self.assertEqual(child.stdout.readline().strip(), "READY")
            self.assertTrue(stop_process(child, cleanup, "synthetic child", 0.02))
            cleanup.finish()
            self.assertIsNotNone(child.returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            close_streams(child, cleanup, "synthetic child")

    def test_hard_link_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = tmp_path / "workspace"
            ws.mkdir()
            runtime = tmp_path / "runtime"
            runtime.mkdir()
            f1 = ws / "secret.txt"
            f1.write_text("secret")
            neighbor = runtime / "neighbor.txt"
            neighbor.hardlink_to(f1)
            self.assertEqual(neighbor.stat().st_nlink, 2)

            # Refused when directory contains hard link
            with self.assertRaisesRegex(RuntimeError, "hard link"):
                check_mount_hardlinks(runtime)

            self.spec.workspace = ws
            self.spec.mounts = [Mount(runtime, "/usr/local/bin")]
            with self.assertRaisesRegex(RuntimeError, "hard link"):
                self.ex.agent_args(self.spec)

            # Refused when regular file mount directly has nlink > 1
            self.spec.mounts = [Mount(neighbor, "/usr/local/bin/neighbor.txt")]
            with self.assertRaisesRegex(RuntimeError, "hard link"):
                self.ex.agent_args(self.spec)

    def test_bind_alias_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = base / "ws"
            alias = base / "alias"
            other = base / "other"
            disjoint = base / "disjoint"
            for p in (ws, alias, other, disjoint):
                p.mkdir()

            mock_mountinfo = f"""
1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw
2 1 8:1 {ws} {ws} rw,relatime - ext4 /dev/sda1 rw
3 1 8:1 {ws}/sub {alias} rw,relatime - ext4 /dev/sda1 rw
4 1 8:1 {other} {other} rw,relatime - ext4 /dev/sda1 rw
5 1 8:2 {disjoint} {disjoint} rw,relatime - ext4 /dev/sda2 rw
"""
            # Bind alias of workspace storage (shares major:minor and root relative) is refused
            with self.assertRaisesRegex(RuntimeError, "bind alias of workspace storage"):
                check_storage_bind_alias(ws, alias, mountinfo_text=mock_mountinfo)

            # Disjoint filesystem (different major:minor) is accepted
            check_storage_bind_alias(ws, disjoint, mountinfo_text=mock_mountinfo)

            # Disjoint directory on same device (neither is ancestor/descendant in fs root) is accepted
            check_storage_bind_alias(ws, other, mountinfo_text=mock_mountinfo)

    def test_storage_mounted_beneath_workspace_is_workspace_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            ws, runtime, other = base / "ws", base / "runtime", base / "other"
            for p in (ws / "nested", runtime, other):
                p.mkdir(parents=True)
            # The same data directory is bound beneath the workspace and at the runtime path.
            mountinfo = f"""
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:2 /data {ws}/nested rw - ext4 /dev/sda2 rw
3 1 8:2 /data {runtime} rw - ext4 /dev/sda2 rw
4 1 8:2 /unrelated {other} rw - ext4 /dev/sda2 rw
"""
            with self.assertRaisesRegex(RuntimeError, "bind alias of workspace storage mounted at"):
                check_storage_bind_alias(ws, runtime, mountinfo_text=mountinfo)
            check_storage_bind_alias(ws, other, mountinfo_text=mountinfo)

    def test_agent_args_and_start_apply_bind_alias_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            ws, runtime = base / "ws", base / "runtime"
            ws.mkdir()
            runtime.mkdir()
            self.spec.workspace = ws
            self.spec.mounts = [Mount(runtime, "/usr/local/bin")]
            refusal = RuntimeError("bind alias of workspace storage")
            with patch("deployments.local.executor.check_storage_bind_alias", side_effect=refusal) as check:
                with self.assertRaisesRegex(RuntimeError, "bind alias"):
                    self.ex.agent_args(self.spec)
                check.assert_called_with(ws, runtime)
                # start() refuses before the workspace view or any container exists.
                self.spec.workspace_socket = Path("/approval.sock")
                self.spec.workspace_binary = Path("/guardfil-workspace")
                with patch("deployments.local.executor.WorkspaceMount") as mount, \
                        patch("deployments.local.executor.docker") as docker, \
                        patch("deployments.local.executor.subprocess.Popen") as popen:
                    with self.assertRaisesRegex(RuntimeError, "bind alias"):
                        self.ex.start(self.relay, self.spec)
                mount.assert_not_called()
                docker.assert_not_called()
                popen.assert_not_called()

    def test_snapshot_swapped_source_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fifo = base / "fifo"
            os.mkfifo(fifo)
            for index, source in enumerate((fifo, base / "missing", base)):
                session = base / f"s{index}"
                session.mkdir()
                with self.assertRaisesRegex(RuntimeError, "regular file"):
                    gfbin.runtime_executables(session, {"codex": source})

    def test_sweep_removes_only_abandoned_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions = Path(tmp) / "sessions"
            names = ("abandoned", "starting", "container-alive", "docker-down", "current", "no-snapshot")
            for name in names:
                (sessions / name).mkdir(parents=True)
                if name != "no-snapshot":
                    (sessions / name / "runtime_bin").mkdir()
                    (sessions / name / "runtime_bin" / "codex").write_bytes(b"bin")
            (sessions / "linked").symlink_to(sessions / "starting")
            held = gfbin.hold_runtime_lock(sessions / "starting")
            self.addCleanup(held.close)
            with self.assertRaisesRegex(RuntimeError, "in use by another launcher"):
                gfbin.hold_runtime_lock(sessions / "starting")
            asked = []

            def containers(session_id):
                asked.append(session_id)
                if session_id == "docker-down":
                    raise subprocess.CalledProcessError(1, "docker")
                return ["c1"] if session_id == "container-alive" else []

            removed = gfbin.sweep_stale_runtime(sessions, sessions / "current", containers)
            self.assertEqual(removed, [sessions / "abandoned" / "runtime_bin"])
            # A locked or current session is never even looked up in Docker.
            self.assertEqual(sorted(asked), ["abandoned", "container-alive", "docker-down"])
            for name in ("starting", "container-alive", "docker-down", "current"):
                self.assertTrue((sessions / name / "runtime_bin" / "codex").is_file(), name)
            self.assertEqual(gfbin.sweep_stale_runtime(sessions / "missing", sessions / "current", containers), [])

    def test_stop_session_releases_snapshot_lock_only_when_snapshot_is_gone(self):
        from deployments.local import runtime_cleanup

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "s1"
            (session_dir / "runtime_bin").mkdir(parents=True)
            session = Mock(dir=session_dir, agent_session=None, broker=None, broker_log=None, sockdir=None)
            session.runtime_lock = gfbin.hold_runtime_lock(session_dir)
            self.addCleanup(lambda: session.runtime_lock and session.runtime_lock.close())
            session.executor.containers_stopped = False
            with self.assertRaises(runtime_cleanup.CleanupError):
                runtime_cleanup.stop_session(session, broker_timeout=1)
            self.assertIsNotNone(session.runtime_lock)
            self.assertEqual(gfbin.sweep_stale_runtime(Path(tmp), Path(tmp) / "other", lambda _id: []), [])
            session.executor.containers_stopped = True
            runtime_cleanup.stop_session(session, broker_timeout=1)
            self.assertIsNone(session.runtime_lock)
            self.assertFalse((session_dir / "runtime_bin").exists())

    def test_snapshot_executables(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            session_dir = base / "session"
            session_dir.mkdir()
            bin_dir = base / "orig_bin"
            bin_dir.mkdir()
            codex_bin = bin_dir / "codex"
            codex_bin.write_bytes(b"#!/bin/sh\necho codex\n")
            codex_bin.chmod(0o755)

            # Unrelated neighbor in the original directory with hard link
            secret = base / "secret"
            secret.write_text("secret")
            neighbor = bin_dir / "neighbor.txt"
            neighbor.hardlink_to(secret)
            self.assertEqual(neighbor.stat().st_nlink, 2)

            snapshot = gfbin.runtime_executables(session_dir, {"codex": codex_bin})
            self.assertTrue(snapshot.is_dir())
            entries = sorted(p.name for p in snapshot.iterdir())
            self.assertEqual(entries, ["codex"])

            snap_codex = snapshot / "codex"
            self.assertEqual(snap_codex.read_bytes(), b"#!/bin/sh\necho codex\n")
            self.assertEqual(snap_codex.stat().st_nlink, 1)
            self.assertTrue(os.access(snap_codex, os.X_OK))
            self.assertFalse((snapshot / "neighbor.txt").exists())

            # Pre-existing runtime_bin is refused
            with self.assertRaisesRegex(RuntimeError, "refusing pre-existing runtime_bin"):
                gfbin.runtime_executables(session_dir, {"codex": codex_bin})

            # Symlink executable source is refused
            sym_session = base / "sym_session"
            sym_session.mkdir()
            sym_bin = bin_dir / "codex-sym"
            sym_bin.symlink_to(codex_bin)
            with self.assertRaisesRegex(RuntimeError, "regular file"):
                gfbin.runtime_executables(sym_session, {"codex": sym_bin})

    def test_bind_alias_fail_closed_and_nested(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = base / "ws"
            src = base / "src"
            nested = src / "sub" / "nested_alias"
            disjoint = base / "disjoint"
            for p in (ws, src, nested, disjoint):
                p.mkdir(parents=True)

            # Unreadable /proc/self/mountinfo -> refused
            with mock.patch("pathlib.Path.read_text", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(RuntimeError, "cannot read /proc/self/mountinfo"):
                    check_storage_bind_alias(ws, disjoint)

            # Missing mountinfo match for path -> refused
            with self.assertRaisesRegex(RuntimeError, "no mountinfo entry"):
                check_storage_bind_alias(ws, disjoint, mountinfo_text="")

            # Nested mount under mount_source aliasing workspace storage -> refused
            nested_mountinfo = f"""
1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw
2 1 8:2 /ws_root {ws.resolve()} rw,relatime - ext4 /dev/sda2 rw
3 1 8:3 /src_root {src.resolve()} rw,relatime - ext4 /dev/sda3 rw
4 3 8:2 /ws_root/sub {nested.resolve()} rw,relatime - ext4 /dev/sda2 rw
5 1 8:4 /disjoint_root {disjoint.resolve()} rw,relatime - ext4 /dev/sda4 rw
"""
            with self.assertRaisesRegex(RuntimeError, "nested mount"):
                check_storage_bind_alias(ws, src, mountinfo_text=nested_mountinfo)

            # Disjoint mount -> admitted
            check_storage_bind_alias(ws, disjoint, mountinfo_text=nested_mountinfo)

    def test_check_mount_hardlinks_lstat_and_fail_closed(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = base / "ws"
            ws.mkdir()
            secret = ws / "secret.txt"
            secret.write_text("secret")
            hard = ws / "hard.txt"
            hard.hardlink_to(secret)

            mount_dir = base / "mount"
            mount_dir.mkdir()
            sym = mount_dir / "link_to_hard"
            sym.symlink_to(hard)

            # lstat does not follow symlinks
            check_mount_hardlinks(sym)
            check_mount_hardlinks(mount_dir)

            # Non-ENOENT lstat error fails closed
            (mount_dir / "regular.txt").write_text("ok")
            with mock.patch("os.lstat", side_effect=PermissionError("EACCES")):
                with self.assertRaises(PermissionError):
                    check_mount_hardlinks(mount_dir)

            # Unreadable subdirectory in os.walk also fails closed
            (mount_dir / "subdir").mkdir()
            with mock.patch("os.scandir", side_effect=PermissionError("EACCES")):
                with self.assertRaises(PermissionError):
                    check_mount_hardlinks(mount_dir)

    def test_stop_session_removes_runtime_bin(self):
        from deployments.local import runtime_cleanup

        class DummyExecutor:
            def __init__(self, stopped: bool):
                self.containers_stopped = stopped
                self.stop_called = False

            def stop(self):
                self.stop_called = True

        class DummySession:
            def __init__(self, session_dir: Path, stopped: bool):
                self.dir = session_dir
                self.agent_session = None
                self.broker = None
                self.sockdir = None
                self.executor = DummyExecutor(stopped)

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / "session"
            session_dir.mkdir()
            runtime_bin = session_dir / "runtime_bin"
            runtime_bin.mkdir()
            (runtime_bin / "codex").write_bytes(b"bin")

            # Unconfirmed container shutdown retains runtime_bin and raises CleanupError
            s_unconfirmed = DummySession(session_dir, stopped=False)
            with self.assertRaises(runtime_cleanup.CleanupError):
                runtime_cleanup.stop_session(s_unconfirmed, broker_timeout=1)
            self.assertTrue(runtime_bin.exists())

            # Confirmed container shutdown removes runtime_bin
            s_ok = DummySession(session_dir, stopped=True)
            runtime_cleanup.stop_session(s_ok, broker_timeout=1)
            self.assertFalse(runtime_bin.exists())
            self.assertTrue(s_ok.executor.stop_called)


if __name__ == "__main__":
    unittest.main()
