"""Shared read-only descriptor primitives for the binding check and recorded report.

Everything here is no-follow, nonblocking-open, descriptor-validated and
borrowed-root safe: the caller's experiment-root descriptor is never closed,
duplicated or owned. Failures are reduced to three fixed kinds ("invalid",
"io", "busy") that each public API maps to its own fixed error code.
"""

import errno
import fcntl
import os
import stat
from typing import List, Optional, Tuple

LEDGER_ENTRY = "ledger"
LEDGER_LOCK_ENTRY = "ledger.lock"
LEDGER_STATE_ENTRY = "ledger.json"
MAX_REPORT_JSON_DEPTH = 4

_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_INVALID_ERRNOS = frozenset({errno.ENOENT, errno.ELOOP, errno.ENOTDIR, errno.ENXIO, errno.EISDIR})


class IoFailure(Exception):
    """Internal: kind is "invalid", "io" or "busy". Carries no payload."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class OwnedFds:
    """Descriptors owned by one call. Each is closed exactly once; no close retry."""

    def __init__(self) -> None:
        self._fds: List[int] = []

    def add(self, fd: int) -> int:
        self._fds.append(fd)
        return fd

    def close_all(self) -> bool:
        """Close every owned descriptor once (reverse order). Returns True if any close failed.

        An interruption (KeyboardInterrupt/SystemExit) during one close never skips the
        remaining descriptors and never retries a descriptor whose number may already
        be reused; the first interruption is re-raised after all resources were visited.
        """
        failed = False
        pending: Optional[BaseException] = None
        fds, self._fds = self._fds, []
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                failed = True
            except BaseException as exc:  # noqa: BLE001 - termination exceptions
                failed = True
                if pending is None:
                    pending = exc
        if pending is not None:
            raise pending
        return failed


def cleanup_after_failure(owned: "OwnedFds", locked_fd: Optional[int]) -> Optional[BaseException]:
    """Unconditional bounded cleanup: unlock once, close every owned fd once.

    Never raises; returns the first termination exception seen (if any) so the caller can
    re-raise it AFTER every resource was visited. No close is ever retried.
    """
    pending: Optional[BaseException] = None
    if locked_fd is not None:
        try:
            fcntl.flock(locked_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        except BaseException as exc:  # noqa: BLE001
            pending = exc
    try:
        owned.close_all()
    except BaseException as exc:  # noqa: BLE001
        if pending is None:
            pending = exc
    return pending


def _kind_of(err: OSError) -> str:
    return "invalid" if err.errno in _INVALID_ERRNOS else "io"


def open_entry(name: str, dir_fd: int, owned: OwnedFds, *, directory: bool) -> int:
    flags = _OPEN_FLAGS | (os.O_DIRECTORY if directory else 0)
    try:
        return owned.add(os.open(name, flags, dir_fd=dir_fd))
    except OSError as err:
        raise IoFailure(_kind_of(err)) from None


def validate_dir(fd: int) -> Tuple[int, int]:
    try:
        st = os.fstat(fd)
    except OSError:
        raise IoFailure("io") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise IoFailure("invalid")
    return (st.st_dev, st.st_ino)


def validate_regular(fd: int) -> Tuple[Tuple[int, int], os.stat_result]:
    try:
        st = os.fstat(fd)
    except OSError:
        raise IoFailure("io") from None
    if (
        not stat.S_ISREG(st.st_mode)
        or st.st_uid != os.getuid()
        or stat.S_IMODE(st.st_mode) != 0o600
        or st.st_nlink != 1
    ):
        raise IoFailure("invalid")
    return (st.st_dev, st.st_ino), st


def entry_identity(name: str, dir_fd: int, *, directory: bool) -> Tuple[int, int]:
    """Identity of the CURRENT no-follow directory entry (not of an old descriptor)."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as err:
        raise IoFailure(_kind_of(err)) from None
    if directory and (
        not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700
    ):
        raise IoFailure("invalid")
    if not directory and (
        not stat.S_ISREG(st.st_mode)
        or st.st_nlink != 1
        or st.st_uid != os.getuid()
        or stat.S_IMODE(st.st_mode) != 0o600
    ):
        raise IoFailure("invalid")
    return (st.st_dev, st.st_ino)


def open_ledger_and_lock(
    root_fd: int, owned: OwnedFds, flock_op: int
) -> Tuple[int, Tuple[int, int], int, Tuple[int, int]]:
    """Validate the borrowed root, open fixed `ledger` and `ledger.lock`, take the lock nonblockingly."""
    validate_dir(root_fd)
    ledger_fd = open_entry(LEDGER_ENTRY, root_fd, owned, directory=True)
    dir_id = validate_dir(ledger_fd)
    lock_fd = open_entry(LEDGER_LOCK_ENTRY, ledger_fd, owned, directory=False)
    lock_id, _ = validate_regular(lock_fd)
    try:
        fcntl.flock(lock_fd, flock_op | fcntl.LOCK_NB)
    except BlockingIOError:
        raise IoFailure("busy") from None
    except OSError as err:
        raise IoFailure("busy" if err.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES) else "io") from None
    return ledger_fd, dir_id, lock_fd, lock_id


def final_entry_checks(
    root_fd: int,
    ledger_fd: int,
    lock_fd: int,
    dir_id: Tuple[int, int],
    lock_id: Tuple[int, int],
) -> None:
    """Under the held lock: re-validate descriptors AND current entries (identity, type, owner,
    mode, link count). This is an observation at one instant, not atomic protection afterwards."""
    validate_dir(root_fd)
    if validate_regular(lock_fd)[0] != lock_id:
        raise IoFailure("invalid")
    if validate_dir(ledger_fd) != dir_id:
        raise IoFailure("invalid")
    if entry_identity(LEDGER_ENTRY, root_fd, directory=True) != dir_id:
        raise IoFailure("invalid")
    if entry_identity(LEDGER_LOCK_ENTRY, ledger_fd, directory=False) != lock_id:
        raise IoFailure("invalid")


def unlock(lock_fd: int) -> None:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    except OSError:
        raise IoFailure("io") from None


def check_json_depth(text: str, max_depth: int = MAX_REPORT_JSON_DEPTH) -> None:
    """Reject JSON nesting deeper than max_depth (root container is depth one)."""
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                raise IoFailure("invalid")
        elif ch in "]}":
            depth -= 1
