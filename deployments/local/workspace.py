"""Host lifecycle for the filesystem view mounted into an executor.

The source directory is never a fallback. A missing helper, failed mount or
lost decision service must leave the agent unable to access the source.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from deployments.local import gfbin


def is_mounted(path: Path) -> bool:
    # Do not stat a disconnected FUSE mount: that can wait on the dead server.
    target = str(path)
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mounted = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
        if mounted == target:
            return True
    return False


def host_problem() -> Optional[str]:
    """Why this host cannot serve a mediated workspace, or None if it can."""
    if not os.access("/dev/fuse", os.R_OK | os.W_OK) or not shutil.which("fusermount3"):
        return ("workspace mediation needs /dev/fuse and fusermount3 on the Linux host "
                "(Debian/Ubuntu: sudo apt-get install fuse3).")
    try:
        configured = any(line.split("#", 1)[0].strip() == "user_allow_other"
                         for line in Path("/etc/fuse.conf").read_text().splitlines())
    except OSError:
        configured = False
    if os.geteuid() != 0 and not configured:
        return ("workspace mediation needs user_allow_other in /etc/fuse.conf so Docker can "
                "bind the view. A host administrator enables it once with: "
                "echo user_allow_other | sudo tee -a /etc/fuse.conf")
    return None


class WorkspaceMount:
    def __init__(self, binary: Path, source: Path, socket: Path, virtual: str):
        self.binary, self.source, self.socket, self.virtual = binary, source, socket, virtual
        self.directory: Optional[Path] = None
        self.view: Optional[Path] = None
        self.proc: Optional[subprocess.Popen] = None
        self.log = None
        self.ready = False

    def start(self) -> Path:
        if self.directory is not None:
            raise RuntimeError("workspace view has already been started")
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise RuntimeError("guardfil-workspace is missing; run guardfil-local.sh up")
        if not self.source.is_dir() or not self.socket.is_socket():
            raise RuntimeError("workspace source and session approval socket must exist")
        problem = host_problem()
        if problem:
            raise RuntimeError(problem + " The raw workspace will not be mounted.")
        self.directory = Path(tempfile.mkdtemp(prefix="gfws-"))
        self.view = self.directory / "view"
        self.view.mkdir(mode=0o700)
        self.log = tempfile.TemporaryFile(mode="w+t")
        try:
            self.proc = subprocess.Popen(
                [str(self.binary), "--source", str(self.source), "--mount", str(self.view),
                 "--socket", str(self.socket), "--virtual-root", self.virtual],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.log, text=True)
            gfbin.wait_ready(self.proc, "GUARDFIL_WORKSPACE_READY", timeout_sec=15)
            if self.proc.poll() is not None or not is_mounted(self.view):
                raise RuntimeError("workspace helper did not establish its filesystem mount")
            self.ready = True
            return self.view
        except Exception as error:
            self.log.seek(0)
            detail = self.log.read(4096).strip()
            self.stop()
            raise RuntimeError(f"workspace mediation failed: {error}" + (f"; {detail}" if detail else "")) from error

    def stop(self) -> None:
        """Call only after all agent containers have stopped."""
        self.ready = False
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            if self.proc.stdout is not None:
                self.proc.stdout.close()
            self.proc = None
        if self.view is not None and is_mounted(self.view):
            # The process may have crashed before unmounting. Detach this exact
            # owned mount; never walk it or recursively delete its contents.
            subprocess.run(["fusermount3", "-uz", str(self.view)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
        if self.view is not None:
            if is_mounted(self.view):
                raise RuntimeError(f"workspace view is still mounted at {self.view}")
            self.view.rmdir()
            self.view = None
        if self.directory is not None:
            self.directory.rmdir()
            self.directory = None
        if self.log is not None:
            self.log.close()
            self.log = None

