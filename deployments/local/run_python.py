#!/usr/bin/env python3
"""Run a plain-Python agent inside the GuardFil executor.

    deployments/local/guardfil-local.sh run-agent --runtime python --workspace DIR --task TEXT
        [--agent FILE] [--model PROVIDER:MODEL] [--max-requests N]

The agent (default: python_agent_example.py) runs with no network at all.  It
gets two Unix sockets and its workspace:

- the model-neutral broker's socket (the broker runs on the host and holds the
  provider keys and the per-provider $2 ledgers),
- GuardFil's approval socket, which its tools ask before they run
  (clients/python/guardfil_client.py, GuardFil.guard).

GuardFil's Python clients and the demo agent loop are mounted read-only at
/guardfil-lib.  The agent file is mounted read-only at /agent/agent.py.
"""
from __future__ import annotations

import argparse
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deployments.local import gfbin  # noqa: E402
from deployments.local.agent_session import AgentSession, host_path, read_approver_socket  # noqa: E402
from deployments.local.executor import AgentSpec, Executor, Mount  # noqa: E402

IMAGE = "golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
DEFAULT_AGENT = Path(__file__).resolve().parent / "python_agent_example.py"
DEFAULT_MODEL = "gemini:gemini-3.5-flash-lite"


class Session:
    def __init__(self, gf_home: Path, workspace: Path, max_requests: int, out=print,
                 agent: Optional[str] = None):
        self.gf_home, self.workspace, self.max_requests, self.out = gf_home, workspace, max_requests, out
        self.agent = agent
        self.agent_session: Optional[AgentSession] = None
        self.id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        self.dir = gf_home / "sessions" / self.id
        self.dir.mkdir(mode=0o700, parents=True)
        self.executor = Executor(self.id, f"guardfil.run-agent={self.id}")
        self.broker: Optional[subprocess.Popen] = None
        self.sockdir: Optional[Path] = None

    def start(self, agent: Path, model: str, task: str) -> subprocess.Popen:
        try:
            approver_sock = read_approver_socket(self.gf_home)
            self.agent_session = AgentSession(approver_sock, self.agent, workspace=self.workspace)
            self.agent_session.open()
            approval_sock = Path(host_path(self.gf_home, self.agent_session.approval_socket))
            if not approval_sock.is_socket():
                raise RuntimeError(f"GuardFil is not running ({approval_sock} missing): run guardfil-local.sh up")
            self.sockdir = Path(tempfile.mkdtemp(prefix="gfpy-"))
            os.chmod(self.sockdir, 0o700)
            self.out(f"session {self.id}: starting the model broker (keys stay in the broker)")
            self.broker_log = open(self.dir / "broker.log", "w")
            self.broker = subprocess.Popen(
                [str(gfbin.broker_bin(self.gf_home)), "neutral", "--sockdir", str(self.sockdir),
                 "--label", f"run-python-{self.id}", "--max-requests", str(self.max_requests)],
                env=self.agent_session.broker_env(),
                cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.broker_log, text=True)
            line = self.broker.stdout.readline() if self.broker.stdout else ""
            if "NEUTRAL_BROKER_READY" not in line:
                raise RuntimeError(f"the model broker did not start (see {self.dir}/broker.log)")
            self.out("starting the agent in the executor (no network)")
            helpers = gfbin.runtime_files(self.dir, {
                "clients/guardfil_client.py": REPO_ROOT / "clients/python/guardfil_client.py",
                "clients/guardfil_model.py": REPO_ROOT / "clients/python/guardfil_model.py",
                "demo/agent_loop.py": REPO_ROOT / "demo/agent_loop.py"})
            mounts = [Mount(helpers, "/guardfil-lib"),
                      Mount(self.sockdir, "/run/guardfil-broker", writable=True),
                      Mount(approval_sock, "/run/guardfil/approval.sock", writable=True)]
            agent_path = "/agent/agent.py"
            if agent.resolve().is_relative_to(self.workspace.resolve()):
                agent_path = "/workspace/" + agent.resolve().relative_to(self.workspace.resolve()).as_posix()
            else:
                mounts.append(Mount(agent.resolve(), agent_path))
            env = {"HOME": "/tmp", "BROKER_SOCK": "/run/guardfil-broker/broker.sock",
                   "GUARDFIL_SOCK": "/run/guardfil/approval.sock"}
            gw = gfbin.gateway_socket(self.gf_home)
            if gw is not None:
                mounts.append(Mount(gw, gfbin.GATEWAY_IN_CONTAINER, writable=True))
                env.update(gfbin.gateway_env(self.gf_home, self.agent_session))
            spec = AgentSpec(IMAGE, ["python3", "-I", agent_path, "--model", model, "--task", task],
                             self.workspace, mounts=mounts, env=env, interactive=False, show_stderr=True)
            spec.workspace_socket = approval_sock
            spec.workspace_binary = gfbin.workspace_bin(self.gf_home)
            return self.executor.start(None, spec)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        self.executor.stop()
        if self.agent_session is not None:
            self.agent_session.close()
            self.agent_session = None
        if self.broker is not None:
            if self.broker.poll() is None:
                self.broker.send_signal(signal.SIGTERM)
                try:
                    self.broker.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    self.broker.kill()
            self.broker_log.close()
        if self.sockdir is not None:
            shutil.rmtree(self.sockdir, ignore_errors=True)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="guardfil-local.sh run-agent --runtime python")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--task", required=True)
    ap.add_argument("--agent", metavar="NAME", default=None, help="agent identity name for per-agent session")
    ap.add_argument("--agent-file", default=str(DEFAULT_AGENT), help="agent Python script")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-requests", type=int, default=8)
    ap.add_argument("--gf-home", default=os.environ.get("GF_HOME", str(Path.home() / ".guardfil-local")))
    a = ap.parse_args(argv)
    workspace = Path(a.workspace).expanduser().resolve()
    agent_file = Path(a.agent_file).expanduser()
    if not workspace.is_dir() or not agent_file.is_file():
        print("run-agent: --workspace must be a folder and --agent-file a file", file=sys.stderr)
        return 2
    session = Session(Path(a.gf_home).expanduser(), workspace, a.max_requests, out=lambda s: print(s, flush=True),
                      agent=a.agent)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        proc = session.start(agent_file, a.model, a.task)
        assert proc.stdout is not None
        for raw in proc.stdout:
            print(raw.decode(errors="replace").rstrip(), flush=True)
        proc.wait()
        print(f"decisions are in {session.gf_home}/state/decisions.jsonl")
        return proc.returncode
    except KeyboardInterrupt:
        return 130
    except RuntimeError as e:
        print(f"run-agent: {e}", file=sys.stderr)
        return 1
    finally:
        session.stop()


if __name__ == "__main__":
    sys.exit(main())
