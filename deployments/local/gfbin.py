"""Where the Go binaries the local runtimes use live.

guardfil-local.sh up copies them out of the GuardFil image into $GF_HOME/bin:
guardfil-broker (the host-side model brokers, and the relay that runs in each
executor's networkless anchor) and guardfil-mcp-proxy (runs inside agent
containers).  GUARDFIL_BROKER_BIN overrides the broker's path (CI builds it).
"""
from __future__ import annotations

import os
from pathlib import Path

RELAY_IN_CONTAINER = "/srv/guardfil-broker"


def runtime_files(session_dir: Path, files: dict[str, Path]) -> Path:
    """Snapshot only the trusted helper files needed by this session.

    Mounting their source directory would expose an unmediated alias when the
    workspace happens to contain the GuardFil checkout itself.
    """
    root = session_dir / "runtime"
    root.mkdir(mode=0o700, exist_ok=True)
    for name, source in files.items():
        target = root / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o600)
    return root


def broker_bin(gf_home: Path) -> Path:
    p = Path(os.environ.get("GUARDFIL_BROKER_BIN") or (Path(gf_home) / "bin" / "guardfil-broker"))
    if not p.is_file() or not os.access(p, os.X_OK):
        raise FileNotFoundError(f"no guardfil-broker at {p}: run guardfil-local.sh up")
    return p.resolve()


def mcp_proxy_bin(gf_home: Path) -> Path:
    p = Path(os.environ.get("GUARDFIL_MCP_PROXY_BIN") or (Path(gf_home) / "bin" / "guardfil-mcp-proxy"))
    if not p.is_file() or not os.access(p, os.X_OK):
        raise FileNotFoundError(f"no guardfil-mcp-proxy at {p}: run guardfil-local.sh up")
    return p.resolve()


def workspace_bin(gf_home: Path) -> Path:
    p = Path(os.environ.get("GUARDFIL_WORKSPACE_BIN") or (Path(gf_home) / "bin" / "guardfil-workspace"))
    if not p.is_file() or not os.access(p, os.X_OK):
        raise FileNotFoundError(f"no guardfil-workspace at {p}: run guardfil-local.sh up")
    return p.resolve()


def relay_command(port: int, path: str = "/v1/responses") -> list:
    return [RELAY_IN_CONTAINER, "relay", "--port", str(port), "--path", path,
            "--socket-path", "/run/guardfil-broker/broker.sock"]


def wait_ready(proc, token: str, timeout_sec: float = 60.0) -> str:
    """Wait for the broker's ready line (a line containing token)."""
    import select
    import time
    deadline = time.monotonic() + timeout_sec
    out = proc.stdout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for the broker's {token} line")
        r, _, _ = select.select([out], [], [], min(0.2, remaining))
        if not r:
            if proc.poll() is not None:
                raise RuntimeError(f"the broker exited early ({proc.returncode})")
            continue
        line = out.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError(f"the broker exited before {token} ({proc.returncode})")
            continue
        if token in line:
            return line.strip()


GATEWAY_IN_CONTAINER = "/run/guardfil/gateway.sock"


def gateway_socket(gf_home: Path, explicit=None):
    """The API gateway socket to mount: --gateway-socket if given, else the one
    guardfil-local.sh's gateway runs in $GF_HOME/run, else None (no gateway)."""
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.is_socket():
            return p
        raise FileNotFoundError(f"gateway socket {explicit} is not an existing Unix socket")
    cfg = Path(gf_home) / "config" / "gateway.yaml"
    if not cfg.is_file():
        return None
    p = Path(gf_home) / "run" / "gateway.sock"
    if p.is_socket():
        return p
    return None


def gateway_env(gf_home: Path, session=None) -> dict:
    """Environment for an agent that may call the gateway: the socket path and
    its session token. Legacy callers without a session use the shared token.
    The token only lets the agent ask the gateway; the app credential
    stays in GuardFil."""
    env = {"GUARDFIL_GATEWAY_SOCKET": GATEWAY_IN_CONTAINER}
    tok = session.gateway_token if session is not None and getattr(session, "gateway_token", None) else None
    if session is not None and tok is None:
        raise RuntimeError("GuardFil did not issue a session-bound gateway token; enable the gateway in the same GuardFil service before starting this agent")
    if tok is None:
        try:
            tok = (Path(gf_home) / "credentials" / "gateway-agent-token").read_text().strip() or None
        except OSError:
            tok = None
    if tok:
        env["GUARDFIL_GATEWAY_TOKEN"] = tok
    return env
