"""The GuardFil executor: the locked-down container pair every agent runtime runs in.

An executor session is two containers:

- the **anchor**, with ``--network none``.  It runs only the relay, which
  listens on 127.0.0.1 and turns model requests into frames on the host
  broker's Unix socket.  The broker holds the provider keys and the ledgers.
- the **agent**, in the anchor's network namespace.  So its only network is
  the anchor's loopback, where it finds the relay and nothing else.

Both containers run as the calling user, with a read-only root, every
capability dropped, ``no-new-privileges``, Docker's default seccomp profile,
and limits on processes, memory and CPU.  The agent can write its mediated
workspace, a size-limited /tmp and the explicit state or socket mounts added
by its runtime.  Provider credential directories and the owner socket stay
on the host; session directories outside workspace mediation are untrusted output.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import List, Optional, Sequence, Tuple

from deployments.local.workspace import WorkspaceMount
from deployments.local.runtime_cleanup import Cleanup, cleanup_after_error, close_streams, stop_process

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


MAX_MOUNT_INSPECT_FILES = 1024


def check_mount_hardlinks(path: Path, max_files: int = MAX_MOUNT_INSPECT_FILES) -> None:
    """Refuse mounts containing regular files with st_nlink > 1 to prevent exposing hard links."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        return
    if stat.S_ISREG(st.st_mode):
        if st.st_nlink > 1:
            raise RuntimeError(f"additional mount {path} has multiple hard links ({st.st_nlink})")
        return
    if stat.S_ISDIR(st.st_mode):
        def _raise_walk_error(err: OSError) -> None:
            raise err

        count = 0
        for root, dirs, files in os.walk(path, followlinks=False, onerror=_raise_walk_error):
            for f in sorted(dirs) + sorted(files):
                count += 1
                if count > max_files:
                    raise RuntimeError(f"additional mount {path} exceeds inspection bound of {max_files} files")
                fp = os.path.join(root, f)
                try:
                    st = os.lstat(fp)
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    raise RuntimeError(f"additional mount {path} contains hard link {f} ({st.st_nlink} links)")


def _unescape_mount_path(p: str) -> str:
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), p)


def _parse_mountinfo(mountinfo_text: str) -> list[Tuple[str, PurePosixPath, PurePosixPath]]:
    """Return list of (major_minor, root_posix, mount_point_posix) from mountinfo text."""
    entries: list[Tuple[str, PurePosixPath, PurePosixPath]] = []
    for line in mountinfo_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        major_minor = fields[2]
        root = PurePosixPath(os.path.normpath(_unescape_mount_path(fields[3])))
        mount_point = PurePosixPath(os.path.normpath(_unescape_mount_path(fields[4])))
        entries.append((major_minor, root, mount_point))
    return entries


def _is_subpath(child: PurePosixPath, parent: PurePosixPath) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _paths_alias(dev_a: str, fs_a: PurePosixPath, dev_b: str, fs_b: PurePosixPath) -> bool:
    return dev_a == dev_b and (_is_subpath(fs_a, fs_b) or _is_subpath(fs_b, fs_a))


def _find_mount_for_path(
    resolved_path: Path, entries: list[Tuple[str, PurePosixPath, PurePosixPath]]
) -> Optional[Tuple[str, PurePosixPath]]:
    """Return (major_minor, storage_relative_path) for the given host path based on mountinfo."""
    norm_path = resolved_path.resolve()
    target_posix = PurePosixPath(norm_path)
    best_mount_point: Optional[PurePosixPath] = None
    best_entry: Optional[Tuple[str, PurePosixPath, PurePosixPath]] = None

    for major_minor, root, mp_posix in entries:
        if _is_subpath(target_posix, mp_posix):
            if best_mount_point is None or len(mp_posix.parts) >= len(best_mount_point.parts):
                best_mount_point = mp_posix
                best_entry = (major_minor, root, mp_posix)

    if best_entry is None or best_mount_point is None:
        return None

    major_minor, root, _ = best_entry
    rel = target_posix.relative_to(best_mount_point)
    fs_path = PurePosixPath(os.path.normpath(str(root / rel)))
    return (major_minor, fs_path)


def _storage_regions(
    resolved: PurePosixPath, entries: list[Tuple[str, PurePosixPath, PurePosixPath]]
) -> Optional[list[Tuple[str, PurePosixPath, PurePosixPath]]]:
    """Every (major_minor, storage path, visible path) reachable beneath a host path.

    A recursive bind exposes the path's own storage and every mount nested
    under it, so both count. Returns None when the path has no mount entry.
    """
    own = _find_mount_for_path(Path(resolved), entries)
    if own is None:
        return None
    regions = [(own[0], own[1], resolved)]
    for major_minor, root, mount_point in entries:
        if mount_point != resolved and _is_subpath(mount_point, resolved):
            regions.append((major_minor, root, mount_point))
    return regions


def check_storage_bind_alias(workspace: Path, mount_source: Path, mountinfo_text: Optional[str] = None) -> None:
    """Refuse mounts that are bind aliases of workspace storage.

    Storage mounted beneath the workspace is workspace storage too, and a
    mount nested beneath the source is exposed with it, so every region on
    one side is compared with every region on the other.
    """
    if mountinfo_text is None:
        try:
            mountinfo_text = Path("/proc/self/mountinfo").read_text()
        except OSError as exc:
            raise RuntimeError(f"cannot read /proc/self/mountinfo to verify mount {mount_source}: {exc}") from exc

    entries = _parse_mountinfo(mountinfo_text)
    ws_regions = _storage_regions(PurePosixPath(workspace.resolve()), entries)
    ms_regions = _storage_regions(PurePosixPath(mount_source.resolve()), entries)
    if ws_regions is None:
        raise RuntimeError(f"no mountinfo entry found for workspace {workspace}")
    if ms_regions is None:
        raise RuntimeError(f"no mountinfo entry found for mount source {mount_source}")

    for ms_index, (dev_ms, fs_ms, seen_ms) in enumerate(ms_regions):
        for ws_index, (dev_ws, fs_ws, seen_ws) in enumerate(ws_regions):
            if not _paths_alias(dev_ws, fs_ws, dev_ms, fs_ms):
                continue
            if ms_index:
                raise RuntimeError(
                    f"additional mount {mount_source} contains nested mount {seen_ms} aliasing workspace storage")
            where = f" mounted at {seen_ws}" if ws_index else ""
            raise RuntimeError(f"additional mount {mount_source} is a bind alias of workspace storage{where}")


def check_additional_mounts(spec: "AgentSpec") -> None:
    """Refuse raw mounts that overlap or alias the workspace storage."""
    source = spec.workspace.resolve()
    for mount in spec.mounts:
        mounted = mount.source.resolve()
        if mounted.is_relative_to(source) or source.is_relative_to(mounted):
            raise RuntimeError(f"additional mount {mount.source} would expose the raw workspace")
        check_mount_hardlinks(mounted)
        check_storage_bind_alias(source, mounted)


class Executor:
    def __init__(self, session_id: str, label: str):
        self.id = session_id
        self.label = label
        self.anchor = f"gf-exec-anchor-{session_id}"
        self.agent_name = f"gf-exec-agent-{session_id}"
        self.agent: Optional[subprocess.Popen] = None
        self.workspace: Optional[WorkspaceMount] = None
        self.containers_stopped = True

    def anchor_args(self, relay: RelaySpec) -> List[str]:
        return ["run", "-d", "--rm", "--name", self.anchor, "--network", "none", *hardening(self.label),
                "-v", f"{relay.relay_path}:{relay.target}:ro", "-v", f"{relay.sockdir}:/run/guardfil-broker:rw",
                relay.image, *relay.command]

    def agent_args(self, spec: AgentSpec, relay: bool = True) -> List[str]:
        if self.workspace is None or not self.workspace.ready or self.workspace.view is None:
            raise RuntimeError("a mediated workspace must be mounted before starting the agent")
        check_additional_mounts(spec)
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
        # Refuse an inadmissible mount before the workspace view or any container exists.
        check_additional_mounts(spec)
        self.workspace = WorkspaceMount(spec.workspace_binary, spec.workspace.resolve(),
                                        spec.workspace_socket, spec.workspace_target)
        try:
            self.workspace.start()
            if relay is not None:
                self.containers_stopped = False
                docker(*self.anchor_args(relay))
                time.sleep(0.5)
            self.containers_stopped = False
            self.agent = subprocess.Popen(["docker", *self.agent_args(spec, relay is not None)], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT if spec.show_stderr else subprocess.DEVNULL)
            return self.agent
        except Exception as error:
            cleanup_after_error(error, self.stop)
            raise

    def stop(self) -> None:
        cleanup = Cleanup()
        containers = Cleanup()
        if not self.containers_stopped:
            # A failed list must not prevent attempts to remove the two owned
            # containers. Remove separately so either failure cannot skip the other.
            ids = [self.agent_name, self.anchor]
            try:
                ids = docker("ps", "-aq", "--filter", f"label={self.label}").stdout.split()
            except Exception as error:
                containers.failures.append(("list executor containers", error))
            for container in ids:
                containers.attempt(f"remove container {container}", lambda c=container: docker("rm", "-f", c))
        client_stopped = True
        if self.agent is not None:
            client = self.agent
            client_stopped = stop_process(client, cleanup, "Docker agent client", 5)
            if client_stopped:
                close_streams(client, cleanup, "Docker agent client")
                self.agent = None
        if not self.containers_stopped:
            # Recheck even after removal failures: Docker may have removed a
            # container before the connection failed, or --rm raced with us.
            try:
                remaining = docker("ps", "-aq", "--filter", f"label={self.label}").stdout.split()
                self.containers_stopped = not remaining and client_stopped
                if not self.containers_stopped:
                    raise RuntimeError(f"shutdown unconfirmed for label {self.label}: {remaining}; retry stop")
            except Exception as error:
                containers.failures.append(("confirm executor shutdown", error))
            # A positive final check resolves an earlier lost response or
            # an ordinary --rm race; only unresolved failures mean incomplete cleanup.
            if not self.containers_stopped:
                cleanup.failures.extend(containers.failures)
        if self.workspace is not None:
            if self.containers_stopped:
                if cleanup.attempt("unmount workspace", self.workspace.stop):
                    self.workspace = None
            else:
                cleanup.failures.append((f"retain workspace {self.workspace.view}",
                                         RuntimeError("container shutdown is unconfirmed; retry stop")))
        cleanup.finish()
