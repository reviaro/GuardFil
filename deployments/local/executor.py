"""The GuardFil executor: the locked-down container pair every agent runtime runs in.

An executor session is two containers:

- the **anchor**, with ``--network none``.  It runs only the relay, which
  listens on 127.0.0.1 and turns model requests into frames on the host
  broker's Unix socket.  The broker holds the provider keys and the ledgers.
- the **agent**, in the anchor's network namespace.  So its only network is
  the anchor's loopback, where it finds the relay and nothing else.

Both containers run as the calling user, with a read-only root, every
capability dropped, ``no-new-privileges``, Docker's default seccomp profile,
and limits on processes, memory and CPU.  The agent's only writable places are
its workspace and a size-limited /tmp.  No GuardFil config, state, credential
or owner socket is ever mounted; a runtime adds only the mounts it lists.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from deployments.local.workspace import WorkspaceMount

PIDS_LIMIT = 256
MEMORY_LIMIT = "2g"
CPU_LIMIT = "2"
TMP_SIZE = "256m"


def docker(*args: str, check: bool = True, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=timeout)


def hardening(label: str, uid: Optional[str] = None) -> List[str]:
    """The flags every executor container gets."""
    uid = uid or f"{os.getuid()}:{os.getgid()}"
    return ["--user", uid, "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(PIDS_LIMIT), "--memory", MEMORY_LIMIT, "--memory-swap", MEMORY_LIMIT,
            "--cpus", CPU_LIMIT, "--ipc", "private", "--label", label]


@dataclass
class Mount:
    source: Path
    target: str
    writable: bool = False

    def args(self) -> List[str]:
        return ["-v", f"{self.source}:{self.target}:{'rw' if self.writable else 'ro'}"]


@dataclass
class AgentSpec:
    """What a runtime runs in the agent container."""
    image: str
    command: Sequence[str]
    workspace: Path
    workspace_target: str = "/workspace"
    mounts: List[Mount] = field(default_factory=list)
    env: dict = field(default_factory=dict)
    interactive: bool = True   # stdin/stdout piped to the runtime's driver
    show_stderr: bool = False  # merge the runtime's stderr into its stdout
    workspace_socket: Optional[Path] = None
    workspace_binary: Optional[Path] = None


@dataclass
class RelaySpec:
    image: str
    relay_path: Path           # relay program on the host, mounted read-only at target
    sockdir: Path              # host dir holding the broker's socket
    command: Sequence[str]     # relay command line, run inside the anchor
    target: str = "/srv/relay.py"


class Executor:
    def __init__(self, session_id: str, label: str):
        self.id = session_id
        self.label = label
        self.anchor = f"gf-exec-anchor-{session_id}"
        self.agent_name = f"gf-exec-agent-{session_id}"
        self.agent: Optional[subprocess.Popen] = None
        self.workspace: Optional[WorkspaceMount] = None

    def anchor_args(self, relay: RelaySpec) -> List[str]:
        return ["run", "-d", "--rm", "--name", self.anchor, "--network", "none", *hardening(self.label),
                "-v", f"{relay.relay_path}:{relay.target}:ro", "-v", f"{relay.sockdir}:/run/guardfil-broker:rw",
                relay.image, *relay.command]

    def agent_args(self, spec: AgentSpec, relay: bool = True) -> List[str]:
        if self.workspace is None or not self.workspace.ready or self.workspace.view is None:
            raise RuntimeError("a mediated workspace must be mounted before starting the agent")
        source = spec.workspace.resolve()
        for mount in spec.mounts:
            mounted = mount.source.resolve()
            if mounted.is_relative_to(source) or source.is_relative_to(mounted):
                raise RuntimeError(f"additional mount {mount.source} would expose the raw workspace")
        # With a relay, the agent shares the anchor's loopback; without one
        # (a runtime that reaches GuardFil only over Unix sockets) it has no network at all.
        network = f"container:{self.anchor}" if relay else "none"
        args = ["run", "--rm", "--name", self.agent_name, "--network", network,
                *hardening(self.label), "--tmpfs", f"/tmp:rw,nosuid,nodev,size={TMP_SIZE}"]
        if spec.interactive:
            args.insert(1, "-i")
        # Writable HOME or PATH entries can replace an approved command with
        # startup code. The image root is read-only; runtimes keep their own
        # state in explicitly mounted CODEX_HOME / CLAUDE_CONFIG_DIR instead.
        env = dict(spec.env)
        env.update(HOME="/guardfil-home", PATH="/usr/local/bin:/usr/bin:/bin", BASH_ENV="/dev/null", ENV="/dev/null")
        for k, v in sorted(env.items()):
            args += ["-e", f"{k}={v}"]
        args += Mount(self.workspace.view, spec.workspace_target, writable=True).args()
        for m in spec.mounts:
            args += m.args()
        return args + ["-w", spec.workspace_target, spec.image, *spec.command]

    def start(self, relay: Optional[RelaySpec], spec: AgentSpec) -> subprocess.Popen:
        if spec.workspace_socket is None or spec.workspace_binary is None:
            raise RuntimeError("executor requires a workspace helper and session approval socket")
        self.workspace = WorkspaceMount(spec.workspace_binary, spec.workspace.resolve(),
                                        spec.workspace_socket, spec.workspace_target)
        try:
            self.workspace.start()
            if relay is not None:
                docker(*self.anchor_args(relay))
                time.sleep(0.5)
            self.agent = subprocess.Popen(["docker", *self.agent_args(spec, relay is not None)], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT if spec.show_stderr else subprocess.DEVNULL)
            return self.agent
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self.agent is not None and self.agent.poll() is None:
            try:
                assert self.agent.stdin is not None
                self.agent.stdin.close()
                self.agent.wait(timeout=5)
            except Exception:
                pass
        ids = docker("ps", "-aq", "--filter", f"label={self.label}").stdout.split()
        if ids:
            docker("rm", "-f", *ids)
        if self.workspace is not None:
            self.workspace.stop()
            self.workspace = None
