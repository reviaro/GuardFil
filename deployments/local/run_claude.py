#!/usr/bin/env python3
"""Run Claude Code inside the GuardFil executor.

    deployments/local/guardfil-local.sh run-agent --runtime claude-code --workspace DIR --prompt TEXT [--max-requests N]

What it starts (all torn down on exit):

- the host Messages broker (holds the Anthropic key and the Anthropic $2
  ledger; refuses provider-side tools such as web search),
- the executor's networkless anchor running the relay for /v1/messages,
- Claude Code (`claude -p`) in the anchor's network namespace, with a managed
  PreToolUse hook that sends every tool call to GuardFil's approval service.
  The hook is managed (``allowManagedHooksOnly``) and blocks on any failure
  (``onFailure: block``); bypass-permissions mode is disabled.

The approval socket is mounted for the hook.  The agent can ask it questions
too, but it can never answer a held call: answers come only from the owner's
socket and the web UI, which are not mounted.
"""
from __future__ import annotations

import argparse
import json
import re
import os
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deployments.local import gfbin  # noqa: E402
from deployments.local.agent_session import AgentSession, host_path, read_approver_socket  # noqa: E402
from deployments.local.executor import AgentSpec, Executor, Mount, RelaySpec  # noqa: E402
from deployments.local.run_codex import parse_mcp  # noqa: E402

IMAGE = "golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
RELAY_PORT = 8899
WORKSPACE = "/workspace"
MODEL = "claude-sonnet-5-5"
HERE_IN_CONTAINER = "/guardfil"
APPROVAL_IN_CONTAINER = "/run/guardfil/approval.sock"
PROXY_IN_CONTAINER = "/opt/guardfil/guardfil-mcp-proxy"
GATEWAY_IN_CONTAINER = "/run/guardfil/gateway.sock"
MANAGED_IN_CONTAINER = "/etc/claude-code/managed-settings.json"
DEFAULT_CLAUDE_BIN = Path(os.environ.get("CLAUDE_BIN", shutil.which("claude") or Path("~/.local/bin/claude").expanduser()))
DEFAULT_MAX_REQUESTS = 16
HOOK_TIMEOUT_SEC = 630


def managed_settings(mcp_servers=()) -> dict:
    command = ["python3", "-I", f"{HERE_IN_CONTAINER}/claude_hook.py"]
    for name in mcp_servers:
        command += ["--proxy-server", name]
    hook = {"type": "command", "command": shlex.join(command),
            "timeout": HOOK_TIMEOUT_SEC, "onFailure": "block"}
    return {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [hook]}]},
            "allowManagedHooksOnly": True,
            "permissions": {"disableBypassPermissionsMode": "disable"}}


def claude_env(model: str = MODEL) -> dict:
    return {"HOME": "/tmp", "CLAUDE_CONFIG_DIR": "/claude_home",
            "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{RELAY_PORT}",
            # Not a key: the broker adds the real one.  Claude Code needs some token to start.
            "ANTHROPIC_AUTH_TOKEN": "guardfil-broker",
            "ANTHROPIC_MODEL": model, "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": model, "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
            "ANTHROPIC_SMALL_FAST_MODEL": model, "MAX_THINKING_TOKENS": "0",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1",
            "DISABLE_AUTOUPDATER": "1", "DISABLE_ERROR_REPORTING": "1",
            "GUARDFIL_SOCK": APPROVAL_IN_CONTAINER}


def describe(event: dict) -> Optional[str]:
    """One line for a stream-json event worth showing."""
    t = event.get("type")
    if t == "assistant":
        out = []
        for b in (event.get("message") or {}).get("content") or []:
            if b.get("type") == "text" and b.get("text", "").strip():
                out.append("claude: " + b["text"].strip())
            elif b.get("type") == "tool_use":
                out.append(f"  tool: {b.get('name')} {json.dumps(b.get('input'))[:160]}")
        return "\n".join(out) or None
    if t == "user":
        for b in (event.get("message") or {}).get("content") or []:
            if isinstance(b, dict) and b.get("type") == "tool_result":
                c = b.get("content")
                text = c if isinstance(c, str) else json.dumps(c)
                return ("  result" + (" (error)" if b.get("is_error") else "") + ": " + text.strip()[:200])
    if t == "result":
        return f"[done: {event.get('subtype')}, {event.get('num_turns')} turns]"
    return None


def model_name(v: str) -> str:
    """A model id as the broker's model list writes it (the broker decides whether it is allowed)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", v):
        raise argparse.ArgumentTypeError(f"{v!r} is not a model id (lower-case letters, digits, . _ -)")
    return v


class Session:
    def __init__(self, gf_home: Path, workspace: Path, max_requests: int, claude_bin: Path,
                 out: Callable[[str], None] = print, gateway_socket: Optional[Path] = None,
                 broker_cmd: Optional[List[str]] = None,
                 agent: Optional[str] = None,
                 mcp: "Optional[List[tuple[str, List[str]]]]" = None, model: str = MODEL):
        self.gf_home, self.workspace, self.max_requests = gf_home, workspace, max_requests
        self.model = model
        self.claude_bin = claude_bin.resolve()
        self.out = out
        self.broker_cmd = list(broker_cmd) if broker_cmd else None
        self.agent = agent
        self.mcp = mcp or []
        self.agent_session: Optional[AgentSession] = None
        try:
            # --gateway-socket, else the gateway guardfil-local.sh runs in $GF_HOME/run (if any).
            self.gateway_socket: Optional[Path] = gfbin.gateway_socket(gf_home, gateway_socket)
        except FileNotFoundError as e:
            raise RuntimeError(str(e))
        self.id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        self.dir = gf_home / "sessions" / self.id
        self.dir.mkdir(mode=0o700, parents=True)
        self.label = f"guardfil.run-agent={self.id}"
        self.executor = Executor(self.id, self.label)
        self.broker: Optional[subprocess.Popen] = None
        self.sockdir: Optional[Path] = None

    def build_agent_spec(self, prompt: str, max_turns: int, home: Path, settings: Path,
                         approval_sock: Path) -> AgentSpec:
        helpers = gfbin.runtime_files(self.dir, {
            name: Path(__file__).resolve().parent / name for name in ("claude_hook.py", "demo_mcp.py")})
        mounts = [Mount(self.claude_bin, "/usr/local/bin/claude"), Mount(home, "/claude_home", writable=True),
                  Mount(settings, MANAGED_IN_CONTAINER), Mount(helpers, HERE_IN_CONTAINER),
                  Mount(approval_sock, APPROVAL_IN_CONTAINER, writable=True)]
        if self.mcp:
            try:
                proxy = gfbin.mcp_proxy_bin(self.gf_home)
            except FileNotFoundError as e:
                raise RuntimeError(f"MCP servers need the filter proxy: {e}")
            mounts += [Mount(proxy, PROXY_IN_CONTAINER)]
            mcp_cfg = {
                "mcpServers": {
                    name: {
                        "command": PROXY_IN_CONTAINER,
                        "args": ["--socket", APPROVAL_IN_CONTAINER, "--server", name, "--"] + argv,
                    }
                    for name, argv in self.mcp
                }
            }
            mcp_cfg_path = self.dir / "mcp-config.json"
            mcp_cfg_path.write_text(json.dumps(mcp_cfg, indent=2))
            mounts.append(Mount(mcp_cfg_path, "/claude_home/mcp-config.json"))
        env = claude_env(self.model)
        if self.gateway_socket is not None:
            mounts.append(Mount(self.gateway_socket, GATEWAY_IN_CONTAINER, writable=True))
            env.update(gfbin.gateway_env(self.gf_home, self.agent_session))
        cmd = ["/usr/local/bin/claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
               "--max-turns", str(max_turns), "--model", self.model]
        # Only the servers GuardFil configured, each behind the filter proxy:
        # Claude Code otherwise also loads a workspace .mcp.json and user config
        # from the writable /claude_home, which the agent could write itself.
        cmd += ["--strict-mcp-config", "--setting-sources", ""]
        if self.mcp:
            cmd += ["--mcp-config", "/claude_home/mcp-config.json"]
        return AgentSpec(IMAGE, cmd, self.workspace, WORKSPACE, mounts, env, interactive=False)

    def start(self, prompt: str, max_turns: int) -> subprocess.Popen:
        try:
            approver_sock = read_approver_socket(self.gf_home)
            self.agent_session = AgentSession(approver_sock, self.agent, workspace=self.workspace)
            self.agent_session.open()
            approval_sock = Path(host_path(self.gf_home, self.agent_session.approval_socket))
            if not approval_sock.is_socket():
                raise RuntimeError(f"GuardFil is not running ({approval_sock} missing): run guardfil-local.sh up")
            if not self.claude_bin.is_file():
                raise RuntimeError(f"no Claude Code binary at {self.claude_bin}")
            if self.gateway_socket is not None and not self.gateway_socket.is_socket():
                raise RuntimeError(f"gateway socket {self.gateway_socket} is not an existing Unix socket")
            self.sockdir = Path(tempfile.mkdtemp(prefix="gfcc-"))
            os.chmod(self.sockdir, 0o700)
            home = self.dir / "claude_home"
            home.mkdir(mode=0o700)
            settings = self.dir / "managed-settings.json"
            settings.write_text(json.dumps(managed_settings(name for name, _ in self.mcp), indent=1))
            os.chmod(settings, 0o644)

            self.out(f"session {self.id}: starting the Messages broker (the Anthropic key stays in the broker)")
            self.broker_log = open(self.dir / "broker.jsonl", "w")
            if self.broker_cmd:
                bcmd = list(self.broker_cmd)
                if "--sockdir" not in bcmd:
                    bcmd.extend(["--sockdir", str(self.sockdir)])
                if "--label" not in bcmd and "--case-label" not in bcmd:
                    bcmd.extend(["--label", f"run-claude-{self.id}"])
                if "--max-requests" not in bcmd:
                    bcmd.extend(["--max-requests", str(self.max_requests)])
            else:
                bcmd = [str(gfbin.broker_bin(self.gf_home)), "messages", "--sockdir", str(self.sockdir),
                        "--label", f"run-claude-{self.id}", "--max-requests", str(self.max_requests)]
            self.broker = subprocess.Popen(
                bcmd, env=self.agent_session.broker_env(), cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.broker_log, text=True)
            line = self.broker.stdout.readline() if self.broker.stdout else ""
            if "MESSAGES_BROKER_READY" not in line and "READY " not in line:
                raise RuntimeError("the Messages broker did not start (see broker.jsonl in the session folder)")

            self.out("starting Claude Code in the networkless executor")
            relay = RelaySpec(IMAGE, gfbin.broker_bin(self.gf_home), self.sockdir,
                              gfbin.relay_command(RELAY_PORT, "/v1/messages"), target=gfbin.RELAY_IN_CONTAINER)
            spec = self.build_agent_spec(prompt, max_turns, home, settings, approval_sock)
            spec.workspace_socket = approval_sock
            spec.workspace_binary = gfbin.workspace_bin(self.gf_home)
            return self.executor.start(relay, spec)
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
            for line in (self.broker.stdout.read() if self.broker.stdout else "").splitlines()[-1:]:
                self.out("broker: " + line[:300])
            self.broker_log.close()
        if self.sockdir is not None:
            shutil.rmtree(self.sockdir, ignore_errors=True)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="guardfil-local.sh run-agent --runtime claude-code")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    ap.add_argument("--max-turns", type=int, default=12)
    ap.add_argument("--gf-home", default=os.environ.get("GF_HOME", str(Path.home() / ".guardfil-local")))
    ap.add_argument("--claude-bin", default=str(DEFAULT_CLAUDE_BIN))
    ap.add_argument("--transcript", help="also write the raw stream-json events here")
    ap.add_argument("--gateway-socket", metavar="PATH",
                    help="optional path to GuardFil gateway Unix socket to mount in container")
    ap.add_argument("--agent", metavar="NAME", help="agent identity name for per-agent session")
    ap.add_argument("--model", default=MODEL, type=model_name,
                    help=f"Anthropic model (default {MODEL}); others must be in ~/.config/guardfil/models.yaml")
    ap.add_argument("--broker-cmd", help="custom broker command to run instead of the default Messages broker")
    ap.add_argument("--mcp", action="append", default=[], metavar="NAME=COMMAND",
                    help="an MCP server for Claude Code, run behind GuardFil's filter; repeatable")
    a = ap.parse_args(argv)
    try:
        a.mcp = [parse_mcp(m) for m in a.mcp]
    except ValueError as e:
        ap.error(str(e))
    if len({n for n, _ in a.mcp}) != len(a.mcp):
        ap.error("--mcp names must differ")
    if a.gateway_socket is not None:
        gw = Path(a.gateway_socket).expanduser().resolve()
        if not gw.is_socket():
            ap.error(f"--gateway-socket {a.gateway_socket} is not an existing Unix socket")
        a.gateway_socket = gw
    return a


def main(argv: Optional[List[str]] = None) -> int:
    a = parse_args(argv)
    workspace = Path(a.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"run-agent: workspace {workspace} is not a folder", file=sys.stderr)
        return 2
    gw_sock = Path(a.gateway_socket).expanduser().resolve() if a.gateway_socket else None
    bcmd = shlex.split(a.broker_cmd) if getattr(a, "broker_cmd", None) else None
    session = Session(Path(a.gf_home).expanduser(), workspace, a.max_requests, Path(a.claude_bin).expanduser(),
                       out=lambda s: print(s, flush=True), gateway_socket=gw_sock, broker_cmd=bcmd,
                       agent=getattr(a, "agent", None), mcp=a.mcp, model=a.model)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    transcript = open(a.transcript, "w") if a.transcript else None
    try:
        proc = session.start(a.prompt, a.max_turns)
        assert proc.stdout is not None
        for raw in proc.stdout:
            if transcript:
                transcript.write(raw.decode(errors="replace"))
            try:
                line = describe(json.loads(raw))
            except ValueError:
                continue
            if line:
                print(line, flush=True)
        proc.wait()
        print(f"decisions are in {session.gf_home}/state/decisions.jsonl; broker log in {session.dir}/broker.jsonl")
        return 0 if proc.returncode == 0 else 1
    except KeyboardInterrupt:
        print("\nstopped")
        return 130
    except RuntimeError as e:
        print(f"run-agent: {e}", file=sys.stderr)
        return 1
    finally:
        if transcript:
            transcript.close()
        session.stop()


if __name__ == "__main__":
    sys.exit(main())
