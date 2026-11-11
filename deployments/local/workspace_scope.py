"""Owner-side storage mappings for privacy across workspace and bind aliases."""
from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path


def _decode(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def _mount_id(path: str) -> int:
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
            if line.startswith("mnt_id:"):
                return int(line.split()[1])
        raise RuntimeError("Linux did not report the workspace mount identity")
    finally:
        os.close(fd)


def workspace_scope(source: Path) -> dict:
    """Map the selected source using the host's mount namespace, not the agent's."""
    root = str(source.resolve(strict=True))
    entries = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise RuntimeError("invalid Linux mount information")
        entries.append((int(fields[0]), _decode(fields[3]), _decode(fields[4])))
    identity = _mount_id(root)
    entry = next((entry for entry in entries if entry[0] == identity), None)
    if entry is None:
        raise RuntimeError("workspace mount changed while preparing privacy controls; retry the run")
    _, physical_root, mountpoint = entry
    filesystem_root = posixpath.normpath(posixpath.join(physical_root, posixpath.relpath(root, mountpoint)))
    mappings = [{"virtual": "/workspace", "filesystem": format(os.statvfs(root).f_fsid, "x"), "root": filesystem_root}]
    for mount_id, physical_root, point in entries:
        if point == root or not point.startswith(root.rstrip("/") + "/"):
            continue
        # Stacked mounts can share a name. Only the mount actually visible
        # through the host's namespace describes what the mediator will open.
        if _mount_id(point) != mount_id:
            continue
        relative = posixpath.relpath(point, root)
        mappings.append({"virtual": "/workspace/" + relative,
                         "filesystem": format(os.statvfs(point).f_fsid, "x"), "root": physical_root})
    if len(mappings) > 256:
        raise RuntimeError("workspace contains more than 256 mounted locations")
    return {"mounts": sorted(mappings, key=lambda m: m["virtual"])}
