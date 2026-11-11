"""Client helper for GuardFil per-agent identity sessions over the owner socket."""
from __future__ import annotations

import http.client
import json
import os
import socket
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:
    yaml = None


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 10.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


# guardfil-local.sh runs GuardFil in a container; its config and replies name
# paths as the container sees them.  These are the bind mounts back to the host.
CONTAINER_MOUNTS = (("/run/guardfil-owner/", "owner"), ("/run/guardfil/", "run"))


def host_path(gf_home: Path, path: str) -> str:
    """A path GuardFil reports, as the host sees it (unchanged if not under a mount)."""
    for prefix, sub in CONTAINER_MOUNTS:
        if path.startswith(prefix):
            return str(Path(gf_home) / sub / path[len(prefix):])
    return path


def read_approver_socket(gf_home: Path) -> str:
    """Read approval.approver_socket from gf_home/config/guardfil.yaml, or refuse to start."""
    cfg_path = gf_home / "config" / "guardfil.yaml"
    if not cfg_path.is_file():
        raise RuntimeError(f"GuardFil config file missing: {cfg_path}")
    content = cfg_path.read_text(encoding="utf-8")
    data: Optional[Dict[str, Any]] = None
    if yaml is not None:
        try:
            data = yaml.safe_load(content)
        except Exception:
            data = None
    if data is None:
        try:
            data = json.loads(content)
        except Exception:
            # simple fallback parser for standard key: value yaml
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("approver_socket:"):
                    val = line.split(":", 1)[1].strip().strip('"').strip("'")
                    data = {"approval": {"approver_socket": val}}
                    break
    if not isinstance(data, dict):
        raise RuntimeError(f"invalid GuardFil config in {cfg_path}")
    approval = data.get("approval")
    if not isinstance(approval, dict):
        raise RuntimeError("approval section missing in GuardFil config")
    approver_socket = approval.get("approver_socket")
    if not approver_socket:
        raise RuntimeError("approval.approver_socket is not set in GuardFil config")
    return host_path(gf_home, os.path.expanduser(str(approver_socket)))



class AgentSession:
    """Manages an agent session over GuardFil's owner (approver) socket."""

    def __init__(self, approver_socket: str, agent_name: Optional[str], timeout: float = 10.0, workspace: Optional[Path] = None):
        self.approver_socket = approver_socket
        self.agent_name = agent_name
        self.timeout = timeout
        self.workspace = workspace
        self.session_id: Optional[str] = None
        self.principal: Optional[str] = None
        self.approval_socket: Optional[str] = None
        self.gateway_token: Optional[str] = None

    def open(self) -> AgentSession:
        conn = _UnixHTTPConnection(self.approver_socket, timeout=self.timeout)
        try:
            identity = {"default": True} if self.agent_name is None else {"agent": self.agent_name}
            # This owner-only declaration is made by the executor launcher.
            # The agent cannot request it through its approval socket.
            identity["workspace_mediated"] = True
            if self.workspace is not None:
                from deployments.local.workspace_scope import workspace_scope
                identity["workspace"] = workspace_scope(self.workspace)
            body = json.dumps(identity).encode("utf-8")
            conn.request("POST", "/sessions", body=body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp_body = resp.read().decode("utf-8", errors="replace")
            if resp.status not in (200, 201):
                raise RuntimeError(f"GuardFil session creation failed ({resp.status}): {resp_body.strip()}")
            data = json.loads(resp_body)
            self.session_id = data.get("session")
            self.principal = data.get("principal")
            self.approval_socket = data.get("approval_socket")
            self.gateway_token = data.get("gateway_token")
            return self
        finally:
            conn.close()

    def close(self) -> None:
        if not self.session_id:
            return
        sess_id = self.session_id
        self.session_id = None
        try:
            conn = _UnixHTTPConnection(self.approver_socket, timeout=self.timeout)
            conn.request("DELETE", f"/sessions/{sess_id}")
            resp = conn.getresponse()
            resp.read()
            conn.close()
        except Exception:
            pass

    def broker_env(self) -> Dict[str, str]:
        """Host broker binding; never include this environment in AgentSpec."""
        if not self.session_id:
            raise RuntimeError("cannot start a broker without an active GuardFil session")
        return {**os.environ, "GUARDFIL_OWNER_SOCKET": self.approver_socket,
                "GUARDFIL_SESSION_ID": self.session_id}

    def __enter__(self) -> AgentSession:
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
