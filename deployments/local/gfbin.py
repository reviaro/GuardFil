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


def runtime_executables(session_dir: Path, executables: dict[str, Path]) -> Path:
    """Snapshot only the trusted runtime executables into a fresh private per-session directory.

    Streams bytes into new inodes (st_nlink == 1) via O_EXCL temp files so pre-existing hard
    links or neighbor files in the original binary directory are never exposed inside the container.
    """
    import os
    import shutil
    import stat

    root = session_dir / "runtime_bin"
    try:
        os.lstat(root)
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError(f"refusing pre-existing runtime_bin: {root}")
    os.mkdir(root, 0o700)
    os.chmod(root, 0o700)

    for idx, (name, source) in enumerate(executables.items()):
        rel = Path(name)
        if not name or rel.is_absolute() or ".." in rel.parts:
            raise RuntimeError(f"invalid runtime executable name: {name!r}")
        src = Path(source)
        # Open first and inspect the descriptor, so the file that was checked
        # is the file that is copied. O_NONBLOCK keeps a FIFO from blocking.
        try:
            src_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as error:
            raise RuntimeError(f"runtime executable must be a regular file: {src} ({error.strerror})") from error
        if not stat.S_ISREG(os.fstat(src_fd).st_mode):
            os.close(src_fd)
            raise RuntimeError(f"runtime executable must be a regular file: {src}")
        target = root / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp_path = root / f".tmp-{os.getpid()}-{idx}-{target.name}"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except BaseException:
            os.close(src_fd)
            raise
        try:
            with os.fdopen(fd, "wb") as dst, os.fdopen(src_fd, "rb") as src_f:
                shutil.copyfileobj(src_f, dst, length=1024 * 1024)
                dst.flush()
                os.fchmod(dst.fileno(), 0o755)
        except BaseException:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
        os.replace(tmp_path, target)
    return root


RUNTIME_LOCK = "runtime_bin.lock"


def hold_runtime_lock(session_dir: Path):
    """Mark this session's executable snapshot as in use for the launcher's lifetime.

    The kernel drops the lock when the launcher exits, however it exits, so a
    later launcher can tell an abandoned snapshot from one still starting.
    """
    import fcntl

    lock = open(Path(session_dir) / RUNTIME_LOCK, "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        lock.close()
        raise RuntimeError(f"session directory {session_dir} is in use by another launcher") from error
    return lock


def _session_containers(session_id: str) -> list[str]:
    import subprocess

    listed = subprocess.run(["docker", "ps", "-aq", "--filter", f"label=guardfil.run-agent={session_id}"],
                            check=True, capture_output=True, text=True, timeout=30)
    return listed.stdout.split()


def sweep_stale_runtime(sessions_dir: Path, current: Path, containers=_session_containers) -> list[Path]:
    """Delete executable snapshots left behind by launchers that were killed.

    A snapshot goes only when its launcher no longer holds the session lock
    and no container of that session exists (a killed launcher's container can
    still be using the mount). Anything uncertain is kept; this never fails a launch.
    """
    import fcntl
    import shutil
    import stat

    removed: list[Path] = []
    try:
        candidates = sorted(Path(sessions_dir).iterdir())
    except OSError:
        return removed
    for session in candidates:
        snapshot = session / "runtime_bin"
        try:
            if session == current or not stat.S_ISDIR(os.lstat(session).st_mode) \
                    or not stat.S_ISDIR(os.lstat(snapshot).st_mode):
                continue
            fd = os.open(session / RUNTIME_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if containers(session.name):
                continue
            shutil.rmtree(snapshot)
            removed.append(snapshot)
        except Exception:
            continue  # Locked, Docker unreachable or removal failed: keep it.
        finally:
            os.close(fd)
    return removed


def session_runtime_executables(session, executables: dict[str, Path]) -> Path:
    """Snapshot a launcher session's executables, clearing abandoned snapshots first."""
    if getattr(session, "runtime_lock", None) is None:
        session.runtime_lock = hold_runtime_lock(session.dir)
    for snapshot in sweep_stale_runtime(session.dir.parent, session.dir):
        session.out(f"removed abandoned runtime snapshot {snapshot}")
    return runtime_executables(session.dir, executables)


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
