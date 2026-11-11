"""Fail-closed startup and teardown checks without a privileged host change."""
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from deployments.local.workspace import WorkspaceMount, host_problem
from deployments.local.gfbin import runtime_files


class WorkspaceLifecycleTest(unittest.TestCase):
    def test_helper_snapshot_excludes_neighboring_files_and_cannot_change_with_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, session = root / "workspace", root / "session"
            source.mkdir()
            session.mkdir()
            helper = source / "hook.py"
            helper.write_text("trusted hook")
            (source / "secret").write_text("not a runtime asset")
            frozen = runtime_files(session, {"hook.py": helper})
            helper.write_text("changed after session started")
            self.assertEqual((frozen / "hook.py").read_text(), "trusted hook")
            self.assertFalse((frozen / "secret").exists())
            self.assertFalse(frozen.is_relative_to(source))

    def test_missing_helper_never_launches(self):
        mount = WorkspaceMount(Path("/no-such-guardfil-workspace"), Path("/tmp"), Path("/a.sock"), "/workspace")
        with patch("deployments.local.workspace.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "missing"):
                mount.start()
            spawn.assert_not_called()
        mount.stop()

    def test_host_check_names_the_missing_setting_and_its_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "fuse.conf"
            real = Path

            def path(arg):
                return conf if arg == "/etc/fuse.conf" else real(arg)

            with patch("deployments.local.workspace.os.access", return_value=True), \
                    patch("deployments.local.workspace.shutil.which", return_value="/usr/bin/fusermount3"), \
                    patch("deployments.local.workspace.os.geteuid", return_value=1000), \
                    patch("deployments.local.workspace.Path", side_effect=path):
                conf.write_text("#user_allow_other\n")
                self.assertIn("sudo tee -a /etc/fuse.conf", host_problem())
                conf.write_text("user_allow_other  # for Docker\n")
                self.assertIsNone(host_problem())
                conf.unlink()
                self.assertIn("user_allow_other", host_problem())
            with patch("deployments.local.workspace.shutil.which", return_value=None):
                self.assertIn("fusermount3", host_problem())

    def test_unmount_does_not_recursively_delete_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            (source / "keep").write_text("owner data")
            private = base / "private"
            private.mkdir()
            view = private / "view"
            view.symlink_to(source, target_is_directory=True)
            mount = WorkspaceMount(Path("/unused"), source, Path("/a.sock"), "/workspace")
            mount.directory, mount.view = private, view
            with patch("deployments.local.workspace.is_mounted", return_value=False):
                with self.assertRaises(OSError):
                    mount.stop()
            self.assertEqual((source / "keep").read_text(), "owner data")

    def test_disconnected_mount_detaches_before_directory_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "private"
            private.mkdir()
            view = private / "view"
            view.mkdir()
            mount = WorkspaceMount(Path("/unused"), Path("/source"), Path("/a.sock"), "/workspace")
            mount.directory, mount.view = private, view
            mount.proc = Mock(stdout=io.StringIO(""))
            mount.proc.poll.return_value = 1
            with patch("deployments.local.workspace.is_mounted", side_effect=[True, False]), \
                    patch("deployments.local.workspace.subprocess.run") as unmount:
                mount.stop()
                self.assertEqual(unmount.call_args.args[0], ["fusermount3", "-uz", str(view)])
            self.assertFalse(private.exists())
            mount.stop()


if __name__ == "__main__":
    unittest.main()
