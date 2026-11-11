#!/usr/bin/env python3
"""Run native Codex inside a GuardFil boundary, day to day.

    deployments/local/guardfil-local.sh run-codex --workspace DIR [--prompt TEXT] [--max-requests N]

What it starts (all torn down on exit):

- the host model broker (holds the OpenAI key and the $2 ledger; the key never
  leaves that process),
- a networkless "anchor" container running the relay, which turns Codex's
  model requests into frames on the broker's Unix socket,
- native Codex (`codex app-server`) in the anchor's network namespace: no
  network except the relay on 127.0.0.1, no credentials, read-only root, all
  capabilities dropped, process, memory and CPU limits, only the workspace
  writable (see executor.py; `run-agent --runtime codex` is the same thing).

Every shell command and file change that Codex asks approval for is decided
by the running local GuardFil approval service
($GF_HOME/run/approval.sock), so the web UI's rules and "ask me" apply live.
Anything other than a clean ALLOW is declined.  Codex runs with the
externalSandbox policy: the container is the sandbox and GuardFil the gate.
MCP tools/call requests are checked at the proxy itself, including calls
Codex does not ask about; results use the same session's filter.

Known limits: Codex's "untrusted" approval policy runs a short list of known
read-only commands (ls, cat, ...) without asking; they can only read the
workspace.  The broker caps each model reply at 1024 output tokens.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deployments.local.agent_session import AgentSession, host_path, read_approver_socket  # noqa: E402
from deployments.local.executor import AgentSpec, Executor, Mount, RelaySpec  # noqa: E402
IMAGE_PIN = "golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
# Codex's standalone release folder (holds the codex binary); CODEX_BIN_DIR overrides.
CODEX_BIN_DIR = os.environ.get("CODEX_BIN_DIR") or str(
    Path.home() / ".codex/packages/standalone/releases/0.166.0-x86_64-unknown-linux-musl/bin")
from deployments.local import gfbin  # noqa: E402

MAX_SESSION_REQUESTS = 64   # the broker's per-session request cap
MODEL = "gpt-6-luna"
RELAY_PORT = 8899
WORKSPACE = "/workspace"
DEFAULT_MAX_REQUESTS = 16
# The service may hold an "ask me" call for up to its ask timeout (max 600 s).
DECISION_TIMEOUT_SEC = 630.0
MAX_DECISION_BYTES = 64 * 1024
RPC_TIMEOUT_SEC = 60.0
TURN_IDLE_TIMEOUT_SEC = 900.0

V1_METHODS = {"execCommandApproval": "command", "applyPatchApproval": "file_change"}
APPROVAL_METHODS = {
    "item/commandExecution/requestApproval": "command",
    "item/fileChange/requestApproval": "file_change",
    "item/permissions/requestApproval": "permissions",
    "mcpServer/elicitation/request": "mcp",
    **V1_METHODS,
}


class RunError(RuntimeError):
    pass


# ---- decisions -------------------------------------------------------------------------------

def ask_guardfil(sock_path: str, request: Dict[str, Any], timeout: float = DECISION_TIMEOUT_SEC) -> Dict[str, Any]:
    """One request per connection to the approval service.  Any failure is a BLOCK."""
    blocked = {"effect": "BLOCK", "reasons": ["APPROVAL_SERVICE_UNAVAILABLE"], "rule_ids": []}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        s.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_DECISION_BYTES:
                return blocked
        out = json.loads(buf.decode("utf-8"))
        if not isinstance(out, dict) or out.get("effect") not in ("ALLOW", "BLOCK"):
            return blocked
        return {"effect": out["effect"], "reasons": list(out.get("reasons") or []),
                "rule_ids": list(out.get("rule_ids") or [])}
    except Exception:
        return blocked
    finally:
        s.close()


def file_write_changes(changes: Any) -> Optional[List[Dict[str, str]]]:
    """A fileChange item's changes as the kernel's file_write form (paths only, never content)."""
    if not isinstance(changes, list) or not changes or len(changes) > 16:
        return None
    out: List[Dict[str, str]] = []
    for ch in changes:
        if not isinstance(ch, dict) or not isinstance(ch.get("path"), str):
            return None
        kind = ch.get("kind")
        ktype = kind.get("type") if isinstance(kind, dict) else None
        if ktype not in ("add", "update", "delete"):
            return None
        out.append({"path": ch["path"], "change": ktype})
        move = kind.get("move_path")
        if ktype == "update" and move is not None:
            if not isinstance(move, str):
                return None
            out.append({"path": move, "change": "add"})
    return out if len(out) <= 16 else None


class Gate:
    """Maps one Codex approval callback to a GuardFil request and the reply Codex expects."""

    def __init__(self, sock_path: str, ask: Callable[..., Dict[str, Any]] = ask_guardfil,
                 log: Callable[[str], None] = lambda s: None, protected_mcp=()):
        self.sock_path = sock_path
        self.ask = ask
        self.log = log
        self.file_changes: Dict[str, Optional[List[Dict[str, str]]]] = {}
        self.protected_mcp = frozenset(protected_mcp)

    def observe_item(self, item: Any) -> None:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            return
        if item.get("type") == "fileChange":
            self.file_changes[item["id"]] = file_write_changes(item.get("changes"))

    def complete_item(self, item: Any) -> None:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            self.file_changes.pop(item["id"], None)

    def request_for(self, kind: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if kind == "command":
            command, cwd = params.get("command"), params.get("cwd") or WORKSPACE
            if isinstance(command, list) and all(isinstance(a, str) for a in command):
                argv = command
            elif isinstance(command, str):
                try:
                    argv = shlex.split(command)
                except ValueError:
                    return None
            else:
                return None
            if not argv or not isinstance(cwd, str):
                return None
            return {"kind": "shell", "command": argv, "cwd": cwd}
        if kind == "file_change":
            changes = None
            if isinstance(params.get("itemId"), str):
                changes = self.file_changes.get(params["itemId"])
            elif isinstance(params.get("fileChanges"), dict):   # v1 applyPatchApproval
                legacy = params["fileChanges"]
                if all(isinstance(p, str) and isinstance(c, dict) for p, c in legacy.items()):
                    changes = file_write_changes([
                        {"path": p, "kind": {"type": c.get("type"), "move_path": c.get("move_path")}}
                        for p, c in legacy.items()])
            return {"kind": "file_write", "changes": changes} if changes else None
        return None

    @staticmethod
    def describe(kind: str, req: Optional[Dict[str, Any]]) -> str:
        if req is None:
            return kind + " (unreadable)"
        if kind == "command":
            return "shell: " + shlex.join(req["command"])[:200]
        if kind == "file_change":
            return "write: " + ", ".join(c["path"] for c in req["changes"])[:200]
        if kind == "mcp":
            return f"tool: {req['server']}.{req['tool']}"
        return kind

    def decide(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """The JSON-RPC result for one approval callback.  Default: decline."""
        kind = APPROVAL_METHODS[method]
        v1 = method in V1_METHODS
        if kind == "mcp":
            # This is permission to reach our proxy, not an authorization for
            # an inferred tool call. The proxy checks the actual request even
            # when Codex skips elicitation (e.g. a readOnlyHint annotation).
            meta = params.get("_meta")
            allowed = (isinstance(params.get("serverName"), str) and params["serverName"] in self.protected_mcp
                       and isinstance(meta, dict) and meta.get("codex_approval_kind") == "mcp_tool_call")
            self.log("GuardFil: MCP call delegated to policy proxy" if allowed else "GuardFil: unknown MCP elicitation blocked")
            return {"action": "accept" if allowed else "decline", "content": None}
        if kind == "permissions":
            self.log("GuardFil: extra permissions requested -> none granted")
            return {"permissions": {}, "scope": "turn"}
        req = self.request_for(kind, params)
        verdict = (self.ask(self.sock_path, req) if req is not None
                   else {"effect": "BLOCK", "reasons": ["REQUEST_UNREADABLE"], "rule_ids": []})
        allowed = verdict["effect"] == "ALLOW"
        why = " ".join(verdict["rule_ids"] + verdict["reasons"])
        self.log(f"GuardFil: {'ALLOW' if allowed else 'BLOCK'} {self.describe(kind, req)}  [{why}]")
        if v1:
            return {"decision": "approved" if allowed else "denied"}
        return {"decision": "accept" if allowed else "decline"}


# ---- app-server JSON-RPC client --------------------------------------------------------------

class AppServer:
    def __init__(self, proc: subprocess.Popen, gate: Gate, out: Callable[[str], None],
                 on_message: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.proc = proc
        self.gate = gate
        self.out = out
        self.on_message = on_message
        self.inbox: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self.next_id = 1
        self._wlock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict):
                if self.on_message is not None:
                    try:
                        self.on_message(msg)
                    except Exception:
                        pass
                self.inbox.put(msg)
        self.inbox.put(None)

    def send(self, msg: Dict[str, Any]) -> None:
        data = json.dumps(msg, separators=(",", ":")) + "\n"
        with self._wlock:
            assert self.proc.stdin is not None
            self.proc.stdin.write(data.encode())
            self.proc.stdin.flush()

    def request(self, method: str, params: Dict[str, Any]) -> int:
        rid = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return rid

    def _handle_server_request(self, msg: Dict[str, Any]) -> None:
        method, rid = msg.get("method"), msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method in APPROVAL_METHODS:
            result = self.gate.decide(method, params)
            self.send({"jsonrpc": "2.0", "id": rid, "result": result})
        else:
            self.send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not supported"}})

    def _handle_notification(self, method: str, params: Dict[str, Any]) -> Optional[str]:
        item = params.get("item")
        if method == "item/started":
            self.gate.observe_item(item)
        elif method == "item/completed" and isinstance(item, dict):
            self.gate.complete_item(item)
            if item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                self.out("\ncodex: " + item["text"].strip() + "\n")
            elif item.get("type") == "commandExecution" and item.get("status") in ("completed", "failed"):
                self.out(f"  (command {item.get('status')}, exit {item.get('exitCode')})")
        elif method == "turn/completed":
            turn = params.get("turn") if isinstance(params.get("turn"), dict) else {}
            return str(turn.get("status") or "completed")
        elif method == "error":
            err = params.get("error") if isinstance(params.get("error"), dict) else {}
            self.out("codex error: " + str(err.get("message") or params)[:300])
        return None

    def wait(self, rid: Optional[int], timeout: float) -> Dict[str, Any]:
        """Pump messages until the response to rid (or, with rid None, until turn/completed)."""
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise RunError("timed out waiting for Codex")
            try:
                msg = self.inbox.get(timeout=min(left, 1.0))
            except queue.Empty:
                continue
            if msg is None:
                raise RunError("Codex exited")
            if "method" in msg and "id" in msg:
                self._handle_server_request(msg)
                deadline = time.monotonic() + timeout   # an "ask me" hold is not idleness
            elif "method" in msg:
                status = self._handle_notification(msg["method"], msg.get("params") or {})
                if rid is None and status is not None:
                    return {"status": status}
            elif rid is not None and msg.get("id") == rid:
                if "error" in msg:
                    raise RunError("Codex refused: " + str((msg["error"] or {}).get("message"))[:300])
                return msg.get("result") or {}


# ---- containers and broker -------------------------------------------------------------------

HERE_IN_CONTAINER = "/guardfil"
APPROVAL_IN_CONTAINER = "/run/guardfil/approval.sock"
GATEWAY_IN_CONTAINER = "/run/guardfil/gateway.sock"
PROXY_IN_CONTAINER = "/opt/guardfil/guardfil-mcp-proxy"
DEMO_MCP = f"python3 -I {HERE_IN_CONTAINER}/demo_mcp.py"


def parse_mcp(spec: str) -> "tuple[str, List[str]]":
    """NAME=COMMAND (run inside the container), or NAME=demo for the demo notes server."""
    name, sep, cmd = spec.partition("=")
    if not sep or not name or not all(c.islower() or c.isdigit() or c in "_-" for c in name) or not name[0].isalpha():
        raise ValueError("--mcp is NAME=COMMAND with a lower-case NAME, for example notes=demo")
    argv = shlex.split(DEMO_MCP if cmd.strip() == "demo" else cmd)
    if not argv:
        raise ValueError("--mcp needs a command")
    return name, argv


def mcp_toml(servers: "List[tuple[str, List[str]]]") -> str:
    """Each MCP server runs behind policy admission and result filtering."""
    out = []
    for name, argv in servers:
        args = ["--socket", APPROVAL_IN_CONTAINER, "--server", name, "--"] + argv
        out.append(f"\n[mcp_servers.{name}]\ncommand = \"{PROXY_IN_CONTAINER}\"\nargs = {json.dumps(args)}\n"
                   "startup_timeout_sec = 20\n")
    return "".join(out)


def config_toml(servers: "Optional[List[tuple[str, List[str]]]]" = None, model: str = MODEL) -> str:
    return f"""model = "{model}"
model_provider = "guardfil"
model_reasoning_effort = "none"

[model_providers.guardfil]
name = "GuardFil broker"
wire_api = "responses"
base_url = "http://127.0.0.1:{RELAY_PORT}/v1"
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false

[projects."{WORKSPACE}"]
trust_level = "untrusted"
""" + mcp_toml(servers or [])


def private_dir(p: Path) -> Path:
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def model_name(v: str) -> str:
    """A model id as the broker's model list writes it (the broker decides whether it is allowed)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", v):
        raise argparse.ArgumentTypeError(f"{v!r} is not a model id (lower-case letters, digits, . _ -)")
    return v


class Session:
    def __init__(self, gf_home: Path, workspace: Path, max_requests: int, bin_dir: Path,
                 out: Callable[[str], None] = print, mcp: "Optional[List[tuple[str, List[str]]]]" = None,
                 gateway_socket: Optional[Path] = None,
                 on_message: Optional[Callable[[Dict[str, Any]], None]] = None,
                 broker_cmd: Optional[List[str]] = None,
                 agent: Optional[str] = None, model: str = MODEL):
        self.gf_home, self.workspace, self.max_requests, self.bin_dir = gf_home, workspace, max_requests, bin_dir
        self.model = model
        self.mcp = mcp or []
        self.out = out
        self.broker_cmd = list(broker_cmd) if broker_cmd else None
        self.agent = agent
        self.agent_session: Optional[AgentSession] = None
        try:
            # --gateway-socket, else the gateway guardfil-local.sh runs in $GF_HOME/run (if any).
            self.gateway_socket: Optional[Path] = gfbin.gateway_socket(gf_home, gateway_socket)
        except FileNotFoundError as e:
            raise RunError(str(e))
        self.on_message = on_message
        self.id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        self.dir = private_dir(gf_home / "sessions" / self.id)
        self.label = f"guardfil.run-agent={self.id}"
        self.broker: Optional[subprocess.Popen] = None
        self.sockdir: Optional[Path] = None
        self.executor = Executor(self.id, self.label)

    def build_agent_spec(self, codex_home: Path, cfg: Path) -> AgentSpec:
        mounts = [Mount(self.bin_dir, "/usr/local/bin"), Mount(codex_home, "/codex_home", writable=True),
                  Mount(cfg, "/codex_home/config.toml")]
        if self.mcp:
            approval_sock = (Path(host_path(self.gf_home, self.agent_session.approval_socket))
                             if self.agent_session else self.gf_home / "run" / "approval.sock")
            if not approval_sock.is_socket():
                raise RunError(f"MCP servers need GuardFil's approval socket ({approval_sock}); "
                               "re-run guardfil-local.sh up with this version")
            try:
                proxy = gfbin.mcp_proxy_bin(self.gf_home)
            except FileNotFoundError as e:
                raise RunError(f"MCP servers need the filter proxy: {e}")
            helpers = gfbin.runtime_files(self.dir, {"demo_mcp.py": Path(__file__).resolve().parent / "demo_mcp.py"})
            mounts += [Mount(helpers, HERE_IN_CONTAINER),
                       Mount(approval_sock, APPROVAL_IN_CONTAINER, writable=True),
                       Mount(proxy, PROXY_IN_CONTAINER)]
        env = {"CODEX_HOME": "/codex_home", "HOME": "/tmp"}
        if self.gateway_socket is not None:
            mounts.append(Mount(self.gateway_socket, GATEWAY_IN_CONTAINER, writable=True))
            env.update(gfbin.gateway_env(self.gf_home, self.agent_session))
        return AgentSpec(IMAGE_PIN, ["/usr/local/bin/codex", "app-server", "--stdio"], self.workspace,
                         WORKSPACE, mounts, env)

    def start(self, on_message: Optional[Callable[[Dict[str, Any]], None]] = None) -> AppServer:
        try:
            try:
                approver_sock = read_approver_socket(self.gf_home)
                self.agent_session = AgentSession(approver_sock, self.agent, workspace=self.workspace)
                self.agent_session.open()
            except (RuntimeError, OSError) as error:
                raise RunError(str(error)) from error
            approval_sock = Path(host_path(self.gf_home, self.agent_session.approval_socket))
            if not approval_sock.is_socket():
                raise RunError(f"GuardFil is not running ({approval_sock} missing): run guardfil-local.sh up")
            if self.gateway_socket is not None and not self.gateway_socket.is_socket():
                raise RunError(f"gateway socket {self.gateway_socket} is not an existing Unix socket")
            # A short private path: Unix socket paths are limited to 108 bytes.
            self.sockdir = Path(tempfile.mkdtemp(prefix="gfcx-"))
            sockdir = private_dir(self.sockdir)
            codex_home = private_dir(self.dir / "codex_home")
            cfg = self.dir / "config.toml"
            cfg.write_text(config_toml(self.mcp, self.model))
            os.chmod(cfg, 0o600)
            spec = self.build_agent_spec(codex_home, cfg)
            spec.workspace_socket = approval_sock
            spec.workspace_binary = gfbin.workspace_bin(self.gf_home)

            self.out(f"session {self.id}: starting the model broker (key stays in the broker)")
            if self.broker_cmd:
                bcmd = list(self.broker_cmd)
                if "--sockdir" not in bcmd:
                    bcmd.extend(["--sockdir", str(sockdir)])
                if "--case-label" not in bcmd and "--label" not in bcmd:
                    bcmd.extend(["--case-label", f"run-codex-{self.id}"])
                if "--max-requests" not in bcmd:
                    bcmd.extend(["--max-requests", str(self.max_requests)])
            else:
                bcmd = [str(gfbin.broker_bin(self.gf_home)), "responses", "--sockdir", str(sockdir),
                        "--case-label", f"run-codex-{self.id}", "--max-requests", str(self.max_requests),
                        # Creates the OpenAI ledger on first use; an existing one is opened as is.
                        "--initialize-ledger"]
            self.broker = subprocess.Popen(
                bcmd,
                env=self.agent_session.broker_env(),
                cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            gfbin.wait_ready(self.broker, "READY")

            self.out("starting the networkless Codex container")
            relay = RelaySpec(IMAGE_PIN, gfbin.broker_bin(self.gf_home), sockdir,
                              gfbin.relay_command(RELAY_PORT, "/v1/responses"), target=gfbin.RELAY_IN_CONTAINER)
            app = self.executor.start(relay, spec)
            gate = Gate(str(approval_sock), log=self.out, protected_mcp=[name for name, _ in self.mcp])
            callback = on_message if on_message is not None else self.on_message
            return AppServer(app, gate, self.out, on_message=callback)
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
                self.broker.terminate()
                try:
                    self.broker.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.broker.kill()
            for line in (self.broker.stdout.read() if self.broker.stdout else "").splitlines()[-1:]:
                self.out("broker: " + line[:300])
        if self.sockdir is not None:
            shutil.rmtree(self.sockdir, ignore_errors=True)


def run_turns(app: AppServer, prompts: Callable[[], Optional[str]], out: Callable[[str], None],
              model: str = MODEL) -> int:
    app.wait(app.request("initialize", {"clientInfo": {"name": "guardfil-run-codex", "version": "1"},
                                         "capabilities": {"experimentalApi": True}}), RPC_TIMEOUT_SEC)
    app.send({"jsonrpc": "2.0", "method": "initialized"})
    res = app.wait(app.request("thread/start", {"model": model, "modelProvider": "guardfil", "cwd": WORKSPACE,
                                                 "approvalPolicy": "untrusted", "approvalsReviewer": "user",
                                                 "ephemeral": True}), RPC_TIMEOUT_SEC)
    thread_id = (res.get("thread") or {}).get("id")
    if not isinstance(thread_id, str):
        raise RunError("Codex did not start a thread")
    turns = 0
    while True:
        text = prompts()
        if text is None:
            return turns
        app.wait(app.request("turn/start", {
            "threadId": thread_id, "input": [{"type": "text", "text": text}],
            "approvalPolicy": "untrusted", "approvalsReviewer": "user",
            "sandboxPolicy": {"type": "externalSandbox", "networkAccess": "restricted"}}), RPC_TIMEOUT_SEC)
        done = app.wait(None, TURN_IDLE_TIMEOUT_SEC)
        turns += 1
        out(f"[turn {turns} {done['status']}]")


def interactive_prompts(first: Optional[str], once: bool) -> Callable[[], Optional[str]]:
    state = {"first": first, "done": False}

    def next_prompt() -> Optional[str]:
        if state["first"] is not None:
            p, state["first"] = state["first"], None
            return p
        if once or state["done"]:
            return None
        try:
            line = input("\nyou (empty line to quit)> ").strip()
        except EOFError:
            line = ""
        if not line:
            state["done"] = True
            return None
        return line
    return next_prompt


DEFAULT_CODEX_BIN_DIR = str(os.environ.get("CODEX_BIN_DIR", (shutil.which("codex") and Path(shutil.which("codex")).resolve().parent) or CODEX_BIN_DIR))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="guardfil-local.sh run-codex", description=__doc__.split("\n\n")[0])
    ap.add_argument("--workspace", required=True, help="host folder Codex may work in (mounted at /workspace)")
    ap.add_argument("--prompt", help="first task; without --once you can continue the conversation")
    ap.add_argument("--once", action="store_true", help="run only --prompt, then exit")
    ap.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                    help=f"model requests this session may make (1-{MAX_SESSION_REQUESTS}, default "
                         f"{DEFAULT_MAX_REQUESTS}); the $2 ledger still applies")
    ap.add_argument("--gf-home", default=os.environ.get("GF_HOME", str(Path.home() / ".guardfil-local")))
    ap.add_argument("--codex-bin-dir", default=DEFAULT_CODEX_BIN_DIR)
    ap.add_argument("--mcp", action="append", default=[], metavar="NAME=COMMAND",
                    help="an MCP server for Codex, run in its container behind GuardFil's filter "
                         "(NAME=demo: the demo notes server); repeatable")
    ap.add_argument("--gateway-socket", metavar="PATH",
                    help="optional path to GuardFil gateway Unix socket to mount in container")
    ap.add_argument("--agent", metavar="NAME", help="agent identity name for per-agent session")
    ap.add_argument("--model", default=MODEL, type=model_name,
                    help=f"OpenAI model (default {MODEL}); others must be in ~/.config/guardfil/models.yaml")
    ap.add_argument("--broker-cmd", help="custom broker command to run instead of the default model broker")
    ap.add_argument("--transcript", metavar="FILE",
                    help="also write the raw JSON-RPC messages here")
    a = ap.parse_args(argv)
    try:
        a.mcp = [parse_mcp(m) for m in a.mcp]
    except ValueError as e:
        ap.error(str(e))
    if len({n for n, _ in a.mcp}) != len(a.mcp):
        ap.error("--mcp names must differ")
    if not 1 <= a.max_requests <= MAX_SESSION_REQUESTS:
        ap.error(f"--max-requests must be 1-{MAX_SESSION_REQUESTS}")
    if a.once and not a.prompt:
        ap.error("--once needs --prompt")
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
        print(f"run-codex: workspace {workspace} is not a folder", file=sys.stderr)
        return 2
    bin_dir = Path(a.codex_bin_dir)
    if not (bin_dir / "codex").is_file():
        print(f"run-codex: no codex binary in {bin_dir}", file=sys.stderr)
        return 2
    gw_sock = Path(a.gateway_socket).expanduser().resolve() if a.gateway_socket else None
    transcript = open(a.transcript, "w") if getattr(a, "transcript", None) else None

    def on_message(msg: Dict[str, Any]) -> None:
        if transcript is not None and not transcript.closed:
            transcript.write(json.dumps(msg) + "\n")
            transcript.flush()

    bcmd = shlex.split(a.broker_cmd) if getattr(a, "broker_cmd", None) else None
    session = Session(Path(a.gf_home).expanduser(), workspace, a.max_requests, bin_dir,
                      out=lambda s: print(s, flush=True), mcp=a.mcp,
                      gateway_socket=gw_sock,
                      on_message=on_message if transcript is not None else None,
                      broker_cmd=bcmd,
                      agent=getattr(a, "agent", None), model=a.model)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        app = session.start()
        turns = run_turns(app, interactive_prompts(a.prompt, a.once), session.out, a.model)
        print(f"done: {turns} turn(s); decisions are in {session.gf_home}/state/decisions.jsonl")
        return 0
    except KeyboardInterrupt:
        print("\nstopped")
        return 130
    except (RunError, RuntimeError, TimeoutError, subprocess.CalledProcessError) as exc:
        print(f"run-codex: {exc}", file=sys.stderr)
        return 1
    finally:
        if transcript:
            transcript.close()
        session.stop()


if __name__ == "__main__":
    sys.exit(main())
