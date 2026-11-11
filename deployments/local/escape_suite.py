#!/usr/bin/env python3
"""The executor escape suite.  Needs Docker; runs in hosted CI.

    python3 -I deployments/local/escape_suite.py [--json OUT]

It starts a real executor session: the anchor running the real relay, and an
agent container running escape_probe.py in place of an agent.  Before that it
plants a random marker on the host, in places an agent must never reach:

- fake provider keys in a fake ~/.config/guardfil/credentials.d,
- a fake GuardFil home (UI token, policy, decision log) and a live owner socket,
- an environment variable of this process.

A fake broker listens on the relay's socket and counts frames.  The suite
fails if any attempt escaped, if any planted place was found, or if the broker
saw anything other than the one valid model request.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import struct
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from deployments.local import gfbin  # noqa: E402
from deployments.local.executor import AgentSpec, Executor, Mount, RelaySpec  # noqa: E402

PROBE = Path(__file__).resolve().parent / "escape_probe.py"
RELAY_PORT = 8899
# The image every runtime's executor uses today (pinned by digest).
IMAGE = "golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
EXPECTED = {
    "net.interfaces_only_loopback", "net.tcp_public", "net.tcp_ipv6", "net.udp_dns_query", "net.dns_resolve",
    "net.cloud_metadata", "net.docker_host_gateway", "net.raw_icmp_socket", "net.packet_socket",
    "net.loopback_ports_only_relay", "net.abstract_unix_sockets", "relay.other_paths_and_methods",
    "relay.model_path_reaches_only_broker", "host.docker_socket", "host.write_outside_workspace",
    "host.no_root", "host.setuid_root", "host.mount", "host.unshare_user_namespace", "host.ptrace",
    "host.mknod_block_device", "host.devices", "host.proc_1_is_the_container", "host.pids_limited",
    "secrets.environment", "secrets.marker_anywhere_on_disk", "secrets.unix_sockets_on_disk",
}


class FakeBroker(threading.Thread):
    """Answers every frame with status 418, and counts them."""

    def __init__(self, path: Path):
        super().__init__(daemon=True)
        self.frames = []
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(path))
        self.srv.listen(8)

    def run(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                try:
                    n = struct.unpack(">I", conn.recv(4))[0]
                    body = b""
                    while len(body) < n:
                        chunk = conn.recv(n - len(body))
                        if not chunk:
                            break
                        body += chunk
                    self.frames.append(body)
                    conn.sendall(struct.pack(">II", 418, 2) + b"{}")
                except Exception:
                    pass


class WorkspaceApprover(threading.Thread):
    """Synthetic filesystem authority for the container isolation fixture.

    Policy allow/deny and service-loss behavior use the real decision service
    in the workspace integration tests. This fixture grants workspace access
    so the escape attempts exercise the same mediated mount as real agents.
    """
    def __init__(self, path: Path):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(path))
        self.srv.listen(8)

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                try:
                    req = json.loads(conn.makefile("rb").readline(65536))
                    paths = req.get("paths", []) if req.get("kind") == "file_read" else [
                        c["path"] for c in req.get("changes", [])] if req.get("kind") == "file_write" else []
                    allowed = bool(paths) and all(p == "/workspace" or p.startswith("/workspace/") for p in paths)
                    conn.sendall((json.dumps({"effect": "ALLOW" if allowed else "BLOCK",
                                              "policy_digest": "synthetic-escape-workspace"}) + "\n").encode())
                except (OSError, ValueError, KeyError, TypeError):
                    pass


def plant(base: Path, marker: str) -> None:
    keys = base / "home" / ".config" / "guardfil" / "credentials.d"
    keys.mkdir(parents=True, mode=0o700)
    for name in ("openai-api-key", "anthropic-api-key", "gemini-api-key"):
        (keys / name).write_text(f"sk-{marker}\n")
    gf = base / "gf"
    for sub in ("credentials", "state", "config", "owner"):
        (gf / sub).mkdir(parents=True, mode=0o700)
    (gf / "credentials" / "ui-token").write_text(marker)
    (gf / "config" / "policy.yaml").write_text(f"# {marker}\n")
    (gf / "state" / "decisions.jsonl").write_text(json.dumps({"marker": marker}) + "\n")
    owner = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    owner.bind(str(gf / "owner" / "owner.sock"))
    owner.listen(1)
    os.environ["GUARDFIL_FAKE_PROVIDER_KEY"] = marker


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write the results here too")
    ap.add_argument("--gf-home", default=os.environ.get("GF_HOME", str(Path.home() / ".guardfil-local")),
                    help="where guardfil-broker is (bin/); GUARDFIL_BROKER_BIN overrides")
    a = ap.parse_args()
    marker = "gfmark" + secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="gfesc-") as tmp:
        base = Path(tmp)
        plant(base, marker)
        sockdir = base / "s"
        sockdir.mkdir(mode=0o700)
        workspace = base / "ws"
        workspace.mkdir(mode=0o700)
        broker = FakeBroker(sockdir / "broker.sock")
        broker.start()
        approval_socket = sockdir / "approval.sock"
        approver = WorkspaceApprover(approval_socket)
        approver.start()
        sid = secrets.token_hex(4)
        ex = Executor(sid, f"guardfil.escape-suite={sid}")
        relay = RelaySpec(IMAGE, gfbin.broker_bin(Path(a.gf_home)), sockdir, gfbin.relay_command(RELAY_PORT),
                          target=gfbin.RELAY_IN_CONTAINER)
        spec = AgentSpec(IMAGE, ["python3", "-I", "/probe/escape_probe.py", marker, str(RELAY_PORT)], workspace,
                         mounts=[Mount(PROBE, "/probe/escape_probe.py")], env={"HOME": "/tmp"}, interactive=False,
                         workspace_socket=approval_socket, workspace_binary=gfbin.workspace_bin(Path(a.gf_home)))
        try:
            proc = ex.start(relay, spec)
            out, _ = proc.communicate(timeout=600)
        finally:
            ex.stop()
            approver.srv.close()
            broker.srv.close()
        results = [json.loads(line) for line in out.decode().splitlines() if line.startswith("{")]
    names = {r["name"] for r in results}
    failures = [r for r in results if r["escaped"]]
    if names != EXPECTED:
        failures.append({"name": "suite.all_attempts_ran", "escaped": True,
                         "detail": f"missing {sorted(EXPECTED - names)} extra {sorted(names - EXPECTED)}"})
    if len(broker.frames) != 1:
        failures.append({"name": "suite.broker_saw_only_the_valid_request", "escaped": True,
                         "detail": f"{len(broker.frames)} frames"})
    for r in results:
        print(f"{'ESCAPED' if r['escaped'] else 'held   '}  {r['name']:40s} {r['detail']}")
    print(f"broker frames: {len(broker.frames)} (expected 1)")
    if a.json:
        Path(a.json).write_text(json.dumps({"results": results, "broker_frames": len(broker.frames),
                                            "failures": failures}, indent=1))
    if failures:
        print(f"\nFAIL: {len(failures)} attempt(s) got through: " + ", ".join(f["name"] for f in failures))
        return 1
    print(f"\nPASS: all {len(results)} escape attempts held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
