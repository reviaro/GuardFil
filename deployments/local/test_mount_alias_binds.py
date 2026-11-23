"""Raw-mount admission against real bind mounts.

The unit tests feed the admission check hand-written mount tables. This
module checks it against the kernel's own table, using bind mounts that
Docker creates inside a disposable, networkless container; nothing is
mounted on the host and no privilege is needed beyond running Docker.

    python3 -B deployments/local/test_mount_alias_binds.py --docker

builds the fixture and runs the tests in the pinned executor image. Run
through unittest directly, the tests skip unless GUARDFIL_BIND_FIXTURE names
a prepared fixture root.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deployments.local.executor import AgentSpec, Executor, Mount, check_storage_bind_alias  # noqa: E402

IMAGE = "golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea"
FIXTURE = os.environ.get("GUARDFIL_BIND_FIXTURE")
MARKER = "synthetic bind marker"


@unittest.skipUnless(FIXTURE, "real bind mounts: run this file with --docker")
class RealBindAliasTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(FIXTURE or "/")
        self.workspace = self.root / "workspace"

    def admit(self, source: Path):
        executor = Executor("bind-fixture", "guardfil.test=bind-fixture")
        executor.workspace = Mock(ready=True, view=self.root / "view")
        spec = AgentSpec("unused-image", ["unused"], self.workspace, mounts=[Mount(source, "/raw")])
        return executor.agent_args(spec, relay=False)

    def test_fixture_really_aliases(self):
        # Each refused case below exposes the same inode outside the workspace,
        # with a single link, so only the mount table can reveal it.
        for inside, outside in (("sub/marker", "direct/marker"), ("nested/marker", "runtime/marker"),
                                ("sub/marker", "outer/inner/marker")):
            protected, raw = self.workspace / inside, self.root / outside
            self.assertTrue(protected.samefile(raw), outside)
            self.assertEqual(raw.stat().st_nlink, 1)
            self.assertEqual(raw.read_text(), MARKER)

    def test_direct_alias_of_workspace_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "bind alias of workspace storage"):
            self.admit(self.root / "direct")

    def test_alias_of_storage_mounted_beneath_workspace_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "bind alias of workspace storage mounted at"):
            self.admit(self.root / "runtime")

    def test_alias_nested_beneath_the_mount_source_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "nested mount"):
            self.admit(self.root / "outer")

    def test_unrelated_directory_is_admitted(self):
        source = self.root / "disjoint"
        check_storage_bind_alias(self.workspace, source)
        self.assertIn(f"{source}:/raw:ro", self.admit(source))


def run_in_docker() -> int:
    with tempfile.TemporaryDirectory(prefix="gf-bind-fixture-") as tmp:
        base = Path(tmp)
        workspace, data, outer, disjoint = (base / n for n in ("workspace", "data", "outer", "disjoint"))
        for path in (workspace / "sub", workspace / "nested", data, outer / "inner", disjoint):
            path.mkdir(parents=True)
        (workspace / "sub" / "marker").write_text(MARKER)
        (data / "marker").write_text(MARKER)
        (disjoint / "control").write_text("public control")
        binds = [(REPO_ROOT, "/work", "ro"), (workspace, "/fixture/workspace", "ro"),
                 (workspace / "sub", "/fixture/direct", "ro"),
                 (data, "/fixture/workspace/nested", "ro"), (data, "/fixture/runtime", "ro"),
                 (outer, "/fixture/outer", "ro"), (workspace / "sub", "/fixture/outer/inner", "ro"),
                 (disjoint, "/fixture/disjoint", "ro")]
        args = ["docker", "run", "--rm", "--pull=never", "--network", "none", "--cap-drop=ALL",
                "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
                "-e", "GUARDFIL_BIND_FIXTURE=/fixture", "-e", "HOME=/tmp", "-w", "/work"]
        for source, target, mode in binds:
            args += ["-v", f"{source}:{target}:{mode}"]
        args += [IMAGE, "python3", "-B", "-m", "unittest", "-v", "deployments.local.test_mount_alias_binds"]
        return subprocess.run(args).returncode


if __name__ == "__main__":
    if sys.argv[1:] == ["--docker"]:
        raise SystemExit(run_in_docker())
    unittest.main()
