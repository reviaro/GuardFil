"""Host storage identity; these tests use no Docker, FUSE or provider API."""
import tempfile
import unittest
from pathlib import Path

from deployments.local.workspace_scope import workspace_scope


class WorkspaceScopeTest(unittest.TestCase):
    def test_nested_roots_share_storage_coordinates(self):
        with tempfile.TemporaryDirectory(prefix="gf privacy ") as directory:
            parent = Path(directory)
            child = parent / "private"
            child.mkdir()
            a = workspace_scope(parent)["mounts"][0]
            b = workspace_scope(child)["mounts"][0]
            self.assertEqual(a["filesystem"], b["filesystem"])
            self.assertEqual(b["root"], a["root"] + "/private")
            self.assertEqual(a["virtual"], "/workspace")
            self.assertEqual(b["virtual"], "/workspace")

    def test_owner_selected_symlink_resolves_to_same_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            alias = root / "alias"
            alias.symlink_to(source, target_is_directory=True)
            self.assertEqual(workspace_scope(source), workspace_scope(alias))
