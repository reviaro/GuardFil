#!/usr/bin/env python3
"""Exercise the shipped Python agent in the real executor, with a fake model.

Usage: python3 -B devenv/headless-e2e/python_runtime.py /path/to/guardfil
Requires Docker and the pinned executor image. No provider keys or API calls.
"""
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]


def run_cli(args, env):
    runner = subprocess.Popen(args, env=env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = runner.communicate(timeout=90)
        return runner.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        os.killpg(runner.pid, signal.SIGTERM)
        try:
            runner.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(runner.pid, signal.SIGKILL)
            runner.communicate()
        raise


def broker():
    """Stand in for the host neutral broker; answer only this scripted test."""
    sockdir = Path(sys.argv[sys.argv.index("--sockdir") + 1])
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(sockdir / "broker.sock"))
        server.listen()
        print("NEUTRAL_BROKER_READY", flush=True)
        calls = [
            {"id": "write-allowed", "name": "write_note", "arguments": {"name": "allowed", "text": "positive control"}},
            {"id": "write-denied", "name": "write_note", "arguments": {"name": "blocked", "text": "BLOCKME"}},
            {"id": "read-allowed", "name": "read_note", "arguments": {"name": "allowed"}},
        ]
        for reply in ({"tool_calls": calls}, {"text": "scripted run complete"}):
            conn, _ = server.accept()
            with conn:
                json.loads(conn.makefile("rb").readline())
                conn.sendall((json.dumps({"ok": True, "reply": reply}) + "\n").encode())
        # run_python owns shutdown and cleans up this fixture process.
        while True:
            time.sleep(1)


def main(binary):
    from run import port, write, check
    with tempfile.TemporaryDirectory(prefix="gfpr-", dir="/tmp") as tmp:
        root = Path(tmp)
        for d in ("config", "credentials", "state", "run", "workspace", "home"):
            (root / d).mkdir(mode=0o700)
        policy = write(root / "config/policy.yaml", """schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: workspace-access
    effect: allow
    match:
      principals: [codex-agent]
      operations: [filesystem.read, filesystem.write]
      resources: [{kind: path, value: /workspace/**}]
  - id: workspace-secret
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.read]
      resources: [{kind: path, value: /workspace/secrets/**}]
  - id: workspace-protected
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources: [{kind: path, value: /workspace/protected/**}]
  - id: notes
    effect: allow
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: notes.write_note}, {kind: tool, value: notes.read_note}]
""")
        catalog = write(root / "config/catalog.yaml", (REPO / "deployments/local/executor-catalog.yaml").read_text())
        content = write(root / "config/content.json", {"schema_version": 1, "lists": [{
            "id": "blocked-word", "name": "Blocked word", "action": "block", "direction": "request",
            "tools": ["notes.write_note"], "words": ["BLOCKME"]}]})
        token = write(root / "credentials/metrics", "synthetic-metrics-token-0123456789")
        approval = root / "run/approval.sock"
        cfg = write(root / "config/guardfil.yaml", {
            "config_root": str(root / "config"), "credentials_root": str(root / "credentials"),
            "state_dir": str(root / "state"), "data": {"address": f"127.0.0.1:{port()}"},
            "management": {"address": f"127.0.0.1:{port()}", "metrics_token_file": token},
            "approval": {"socket": str(approval), "policy_file": policy, "tool_catalog": catalog,
                         "approver_socket": str(root / "run/owner.sock"),
                         "content_rules_file": content, "decision_log": str(root / "state/decisions.jsonl")}})
        # The override is explicitly a test stand-in, never the real broker.
        fake = root / "fake-broker"
        import shlex
        write(fake, "#!/bin/sh\nexec /usr/bin/python3 -B " + shlex.quote(str(Path(__file__).resolve())) + ' "$@"\n')
        fake.chmod(0o700)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root / "home"),
               "GF_HOME": str(root), "GUARDFIL_BROKER_BIN": str(fake), "PYTHONDONTWRITEBYTECODE": "1"}
        if os.environ.get("GUARDFIL_WORKSPACE_BIN"):
            env["GUARDFIL_WORKSPACE_BIN"] = os.environ["GUARDFIL_WORKSPACE_BIN"]
        with open(root / "server.log", "wb") as log:
            server = subprocess.Popen([binary, "--config", cfg], stdout=log, stderr=log, env=env)
            try:
                deadline = time.monotonic() + 10
                while not approval.exists() and time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError((root / "server.log").read_text())
                    time.sleep(0.05)
                returncode, stdout, stderr = run_cli([str(REPO / "deployments/local/guardfil-local.sh"), "run-agent", "--runtime", "python",
                                    "--workspace", str(root / "workspace"), "--task", "scripted test", "--model", "openai:scripted-test",
                                    "--max-requests", "2"], env)
                print(stdout, end="")
                if returncode:
                    print(stderr)
                check("Python runtime CLI completes inside executor", returncode == 0)
                check("Python agent allowed tool creates file", (root / "workspace/notes/allowed.txt").read_text() == "positive control")
                check("Python agent denied tool has no side effect", not (root / "workspace/notes/blocked.txt").exists())
                check("Python agent allowed read returns content", 'tool read_note({"name": "allowed"}) -> positive control' in stdout)
                records = [json.loads(line) for line in (root / "state/decisions.jsonl").read_text().splitlines()]
                tool_records = [r for r in records if r.get("kind") == "mcp"]
                check("Python runtime logs allow/block/read decisions", len(tool_records) == 3 and [r["effect"] for r in tool_records] == ["ALLOW", "BLOCK", "ALLOW"])
                check("Python workspace IO has independent policy decisions", {"file_read", "file_write"} <= {r.get("kind") for r in records})
                # This second agent deliberately omits GuardFil's client. Its
                # raw Python and shell IO must still meet filesystem policy.
                ws = root / "workspace"
                for name in ("secrets", "protected"):
                    (ws / name).mkdir()
                (ws / "secrets/token").write_text("synthetic-private-marker")
                (ws / "protected/config").write_text("unchanged")
                (ws / "secret-alias").symlink_to("secrets/token")
                (ws / "write-alias").symlink_to("protected/config")
                probe = ws / "raw_probe.py"
                probe.write_text('''from pathlib import Path
import os, subprocess
for name in ("/workspace/secrets/token", "/workspace/secret-alias", "/proc/self/root/workspace/secrets/token"):
    try:
        Path(name).read_text()
    except PermissionError:
        pass
    else:
        raise AssertionError("protected read was permitted")
for name in ("/workspace/protected/config", "/workspace/write-alias"):
    try:
        Path(name).write_text("bad")
    except PermissionError:
        pass
    else:
        raise AssertionError("protected write was permitted")
command = subprocess.run(["/bin/bash", "-lc", "printf bad > /workspace/protected/config"], capture_output=True)
assert command.returncode != 0, "shell bypassed write rule"
Path("/workspace/notes/direct.txt").write_text("raw positive control")
assert Path("/workspace/notes/direct.txt").read_text() == "raw positive control"
Path("/tmp/.bash_profile").write_text("printf injected > /workspace/startup-bypass")
command = subprocess.run(["/bin/bash", "-lc", "printf startup-control"], capture_output=True, text=True)
assert command.returncode == 0 and command.stdout == "startup-control"
assert os.environ["HOME"] == "/guardfil-home" and os.environ["BASH_ENV"] == "/dev/null"
assert not Path("/workspace/startup-bypass").exists(), "writable profile executed"
print("RAW_WORKSPACE_BOUNDARY_PASSED")
''')
                returncode, stdout, stderr = run_cli([str(REPO / "deployments/local/guardfil-local.sh"), "run-agent", "--runtime", "python",
                    "--workspace", str(ws), "--agent-file", str(probe), "--task", "raw filesystem fixture",
                    "--model", "openai:scripted-test", "--max-requests", "2"], env)
                if returncode:
                    print(stdout, stderr)
                check("Raw agent IO and shell aliases cannot bypass workspace policy", returncode == 0 and "RAW_WORKSPACE_BOUNDARY_PASSED" in stdout)
                check("Denied shell writes leave the backing file unchanged", (ws / "protected/config").read_text() == "unchanged")
                check("Raw allowed IO persists through the mediated mount", (ws / "notes/direct.txt").read_text() == "raw positive control")
                check("Writable temporary shell profile is ignored", not (ws / "startup-bypass").exists())
                check("Python session stops its executor", not any(subprocess.check_output(
                    ["docker", "ps", "-aq", "--filter", "label=guardfil.run-agent=" + session.name], env=env, text=True).strip()
                    for session in (root / "sessions").iterdir()))
            finally:
                server.terminate()
                server.wait(timeout=10)
                for session in (root / "sessions").glob("*"):
                    ids = subprocess.check_output(["docker", "ps", "-aq", "--filter", "label=guardfil.run-agent=" + session.name], env=env, text=True).split()
                    if ids:
                        subprocess.run(["docker", "rm", "-f", *ids], env=env, check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    if sys.argv[1] == "neutral":
        broker()
    else:
        main(str(Path(sys.argv[1]).resolve()))
