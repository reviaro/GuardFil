"""Offline CLI transaction tests; Docker is a stub, parser checks live in bootstrap tests."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

from deployments.local.gfbin import gateway_socket


SCRIPT = Path(__file__).with_name("guardfil-local.sh")
DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
a = sys.argv[1:]
home = Path(os.environ['GF_HOME'])
with (home / 'docker-calls').open('a') as f:
    f.write(json.dumps(a) + '\n')
if a[:2] == ['image', 'inspect']:
    sys.exit(int(os.environ.get('NO_IMAGE', '0')))
if a[0] == 'run':
    assert '--read-only' in a and a[a.index('--network')+1] == 'none'
    assert '-validate-config' in a
    stage = next(v.rsplit(':', 2)[0] for v in a if v.endswith(':/etc/guardfil:ro'))
    assert Path(stage, 'guardfil.yaml').is_file()
    (home / 'at-validation').write_bytes((home / 'config/guardfil.yaml').read_bytes())
    sys.exit(int(os.environ.get('REJECT_CONFIG', '0')))
if 'ps' in a:
    count = home / 'ps-calls'
    n = int(count.read_text()) + 1 if count.exists() else 1
    count.write_text(str(n))
    if n == 1 and os.environ.get('FAIL_FIRST_PS') == '1': sys.exit(1)
    if os.environ.get('RUNNING') == '1': print('fake-service')
elif 'restart' in a:
    count = home / 'restarts'
    n = int(count.read_text()) + 1 if count.exists() else 1
    count.write_text(str(n))
    if n == 1 and os.environ.get('FAIL_FIRST_RESTART') == '1': sys.exit(1)
'''


class LocalConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gf-cli-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        bindir = self.base / "bin"
        bindir.mkdir()
        for name, body in (("docker", DOCKER), ("sleep", "#!/bin/sh\nexit 0\n")):
            p = bindir / name
            p.write_text(body)
            p.chmod(0o700)
        self.env = dict(os.environ, GF_HOME=str(self.home), PATH=str(bindir)+os.pathsep+os.environ["PATH"])
        self.run_cli("init", "--ui", "inactive")

    def run_cli(self, *args, ok=True, **env):
        result = subprocess.run(["bash", str(SCRIPT), *args], env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result

    def snapshot(self):
        return {p.name: p.read_bytes() for p in (self.home / "config").iterdir() if p.is_file()}

    def candidate(self, text):
        p = self.base / "candidate.yaml"
        p.write_text(text)
        return str(p)

    def test_invalid_catalog_leaves_stopped_config_unchanged(self):
        before = self.snapshot()
        self.run_cli("catalog", self.candidate("invalid: yaml\n"), ok=False, REJECT_CONFIG="1")
        self.assertEqual(before, self.snapshot())
        self.assertFalse(list(self.home.glob(".config-*")))

    def test_valid_catalog_installed_after_validation(self):
        before = self.snapshot()["guardfil.yaml"]
        self.run_cli("catalog", self.candidate("catalog_version: 1\ntools: [{id: app.read}]\n"))
        self.assertEqual((self.home / "at-validation").read_bytes(), before)
        self.assertIn(b"app.read", self.snapshot()["tool-catalog.yaml"])
        self.assertFalse((self.home / "restarts").exists())

    def test_restart_failure_restores_all_config_and_ui_mode(self):
        before = self.snapshot()
        self.run_cli("ui", "active", ok=False, RUNNING="1", FAIL_FIRST_RESTART="1")
        self.assertEqual(before, self.snapshot())
        self.assertEqual((self.home / "restarts").read_text(), "2")

    def test_docker_status_failure_rolls_back(self):
        before = self.snapshot()
        self.run_cli("ui", "active", ok=False, RUNNING="1", FAIL_FIRST_PS="1")
        self.assertEqual(before, self.snapshot())
        self.assertEqual((self.home / "restarts").read_text(), "1")

    def test_ui_mode_is_installed_on_success(self):
        self.run_cli("ui", "active")
        self.assertEqual(self.snapshot()[".ui-mode"], b"active\n")

    def test_missing_validator_leaves_config_unchanged(self):
        before = self.snapshot()
        self.run_cli("catalog", self.candidate("catalog_version: 1\ntools: []\n"), ok=False, NO_IMAGE="1")
        self.assertEqual(before, self.snapshot())

    def test_gateway_validation_failure_and_restart_rollback(self):
        # Quoted credential paths and flow YAML reach the real YAML validator.
        candidate = self.candidate('upstreams: [{name: app, base_url: "https://example.invalid", credential_file: "/etc/guardfil/credentials.d/test"}]\n')
        before = self.snapshot()
        self.run_cli("gateway", candidate, ok=False, REJECT_CONFIG="1")
        self.assertEqual(before, self.snapshot())
        self.run_cli("gateway", candidate, ok=False, RUNNING="1", FAIL_FIRST_RESTART="1")
        self.assertEqual(before, self.snapshot())

    def test_gateway_removal_unlinks_stale_socket_and_stops_autodetection(self):
        self.run_cli("gateway", self.candidate("upstreams: []\n"))
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        path = self.home / "run/gateway.sock"
        sock.bind(str(path))
        self.assertEqual(gateway_socket(self.home), path)
        self.run_cli("gateway", "--remove")
        self.assertFalse(path.exists())
        self.assertIsNone(gateway_socket(self.home))
        sock.close()
        stale = socket.socket(socket.AF_UNIX)
        self.addCleanup(stale.close)
        stale.bind(str(path))
        self.assertIsNone(gateway_socket(self.home))
        self.assertEqual(gateway_socket(self.home, path), path)


if __name__ == "__main__":
    unittest.main()
