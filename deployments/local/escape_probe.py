#!/usr/bin/env python3
"""Escape attempts, run inside an executor agent container (stdlib only).

    python3 -I escape_probe.py MARKER RELAY_PORT

Prints one JSON line per attempt: {"name", "escaped", "detail"}.  "escaped" is
true when the forbidden thing worked.  An attempt that cannot be classified
reports escaped=true, so the suite fails closed.  MARKER is a random string the
host planted in fake provider keys and GuardFil state and credentials; finding
it anywhere means a secret is reachable.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import os
import signal
import socket
import stat
import sys
import time

MARKER = sys.argv[1] if len(sys.argv) > 1 else "missing-marker"
RELAY_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8899
TIMEOUT = 2.0
results = []


def report(name, escaped, detail=""):
    results.append({"name": name, "escaped": bool(escaped), "detail": str(detail)[:300]})


def attempt(name):
    def wrap(fn):
        try:
            fn(name)
        except Exception as e:   # an unclassified failure fails closed
            report(name, True, f"probe error {type(e).__name__}: {e}")
        return fn
    return wrap


def tcp(host, port, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        return True, "connected"
    except OSError as e:
        return False, f"{errno.errorcode.get(e.errno, e.errno)}"
    finally:
        s.close()


# ---- network -------------------------------------------------------------------------------

@attempt("net.interfaces_only_loopback")
def _(name):
    ifaces = sorted(os.listdir("/sys/class/net"))
    report(name, ifaces != ["lo"], ",".join(ifaces))


@attempt("net.tcp_public")
def _(name):
    hits = [f"{h}:{p}" for h, p in (("1.1.1.1", 443), ("8.8.8.8", 53), ("140.82.112.3", 443))
            if tcp(h, p)[0]]
    report(name, bool(hits), ",".join(hits) or "all refused")


@attempt("net.tcp_ipv6")
def _(name):
    try:
        ok, why = tcp("2606:4700:4700::1111", 443, socket.AF_INET6)
    except OSError as e:
        ok, why = False, str(e)
    report(name, ok, why)


@attempt("net.udp_dns_query")
def _(name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        s.sendto(q, ("8.8.8.8", 53))
        s.recvfrom(512)
        report(name, True, "answer received")
    except OSError as e:
        report(name, False, errno.errorcode.get(e.errno, str(e)) if e.errno else str(e))
    finally:
        s.close()


@attempt("net.dns_resolve")
def _(name):
    try:
        addrs = socket.getaddrinfo("example.com", 443)
        report(name, True, str(addrs[0][4]))
    except socket.gaierror as e:
        report(name, False, str(e))


@attempt("net.cloud_metadata")
def _(name):
    ok, why = tcp("169.254.169.254", 80)
    report(name, ok, why)


@attempt("net.docker_host_gateway")
def _(name):
    hits = [f"172.17.0.1:{p}" for p in (22, 80, 443, 2375, 2376) if tcp("172.17.0.1", p)[0]]
    try:
        socket.getaddrinfo("host.docker.internal", 80)
        hits.append("host.docker.internal resolves")
    except socket.gaierror:
        pass
    report(name, bool(hits), ",".join(hits) or "unreachable")


@attempt("net.raw_icmp_socket")
def _(name):
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
        report(name, True, "raw socket opened")
    except PermissionError as e:
        report(name, False, str(e))


@attempt("net.packet_socket")
def _(name):
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)).close()
        report(name, True, "packet socket opened")
    except PermissionError as e:
        report(name, False, str(e))


@attempt("net.loopback_ports_only_relay")
def _(name):
    open_ports = []
    for port in range(1, 65536):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        # A connect to a port in the ephemeral range can meet itself (TCP
        # self-connect): local and peer address are equal, and nothing listens.
        if s.connect_ex(("127.0.0.1", port)) == 0 and s.getsockname() != s.getpeername():
            open_ports.append(port)
        s.close()
    report(name, open_ports != [RELAY_PORT], f"open: {open_ports}")


@attempt("net.abstract_unix_sockets")
def _(name):
    # Abstract sockets belong to the network namespace the agent shares with the anchor.
    found = []
    with open("/proc/net/unix") as f:
        next(f)
        for line in f:
            parts = line.split()
            if len(parts) >= 8 and parts[7].startswith("@"):
                found.append(parts[7])
    report(name, bool(found), ",".join(found) or "none")


# ---- relay ---------------------------------------------------------------------------------

def http(method, path, body=b"", headers=None):
    s = socket.create_connection(("127.0.0.1", RELAY_PORT), timeout=5)
    try:
        h = {"Host": "127.0.0.1", "Content-Length": str(len(body)), **(headers or {})}
        req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
        s.sendall(req.encode() + body)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0].decode(errors="replace")
        return int(line.split()[1]) if len(line.split()) > 1 else 0
    finally:
        s.close()


@attempt("relay.other_paths_and_methods")
def _(name):
    # The fake broker counts frames; these must all be refused before reaching it.
    tries = [("POST", "/v1/chat/completions"), ("POST", "/v1/responses/../files"), ("GET", "/v1/responses"),
             ("POST", "http://example.com/v1/responses"), ("CONNECT", "example.com:443"),
             ("PUT", "/v1/responses")]
    got = {f"{m} {p}": http(m, p, b"{}") for m, p in tries}
    chunked = http("POST", "/v1/responses", b"0\r\n\r\n", {"Transfer-Encoding": "chunked"})
    got["POST chunked"] = chunked
    report(name, any(200 <= c < 300 for c in got.values()), json.dumps(got))


@attempt("relay.model_path_reaches_only_broker")
def _(name):
    # A valid frame goes to the broker socket and nowhere else; the fake broker answers 418.
    code = http("POST", "/v1/responses", b'{"probe":true}', {"Content-Type": "application/json"})
    report(name, code != 418, f"status {code}")


# ---- host ----------------------------------------------------------------------------------

@attempt("host.docker_socket")
def _(name):
    hits = []
    for p in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock"):
        if os.path.exists(p):
            hits.append(p)
    report(name, bool(hits), ",".join(hits) or "absent")


@attempt("host.write_outside_workspace")
def _(name):
    wrote = []
    for p in ("/etc/gf-probe", "/usr/gf-probe", "/gf-probe", "/srv/gf-probe", "/root/gf-probe"):
        try:
            with open(p, "w") as f:
                f.write("x")
            wrote.append(p)
        except OSError:
            pass
    report(name, bool(wrote), ",".join(wrote) or "all refused")


@attempt("host.no_root")
def _(name):
    report(name, os.geteuid() == 0 or os.getuid() == 0, f"uid={os.getuid()} euid={os.geteuid()}")


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def syscall_fails(fn, *args):
    r = fn(*args)
    return r != 0, errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))


@attempt("host.setuid_root")
def _(name):
    failed, why = syscall_fails(libc.setuid, 0)
    report(name, not failed, why)


@attempt("host.mount")
def _(name):
    failed, why = syscall_fails(libc.mount, b"none", b"/tmp", b"tmpfs", 0, None)
    report(name, not failed, why)


@attempt("host.unshare_user_namespace")
def _(name):
    CLONE_NEWUSER, CLONE_NEWNS = 0x10000000, 0x00020000
    pid = os.fork()
    if pid == 0:   # in a child, so a success cannot change the probe itself
        os._exit(0 if libc.unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0 else 1)
    _, status = os.waitpid(pid, 0)
    report(name, os.waitstatus_to_exitcode(status) == 0, "unshare " + ("worked" if status == 0 else "refused"))


@attempt("host.ptrace")
def _(name):
    PTRACE_ATTACH = 16
    failed, why = syscall_fails(libc.ptrace, PTRACE_ATTACH, 1, None, None)
    report(name, not failed, why)


@attempt("host.mknod_block_device")
def _(name):
    try:
        os.mknod("/tmp/gf-sda", stat.S_IFBLK | 0o600, os.makedev(8, 0))
        report(name, True, "block device created")
    except PermissionError as e:
        report(name, False, str(e))


@attempt("host.devices")
def _(name):
    allowed = {"null", "zero", "full", "random", "urandom", "tty", "console", "pts", "ptmx", "shm",
               "mqueue", "fd", "stdin", "stdout", "stderr", "core"}
    extra = sorted(set(os.listdir("/dev")) - allowed)
    report(name, bool(extra), ",".join(extra) or "standard only")


@attempt("host.proc_1_is_the_container")
def _(name):
    # In the container's own PID namespace, PID 1 is the agent's init, not the host's.
    with open("/proc/1/cmdline", "rb") as f:
        cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
    report(name, "systemd" in cmd or "/sbin/init" in cmd, cmd[:120])


@attempt("host.pids_limited")
def _(name):
    children = []
    try:
        for _ in range(400):
            pid = os.fork()
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            children.append(pid)
    except OSError:
        pass
    finally:
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
    report(name, len(children) >= 400, f"forked {len(children)} before the limit")


# ---- GuardFil secrets ----------------------------------------------------------------------

@attempt("secrets.environment")
def _(name):
    leaked = [k for k, v in os.environ.items() if MARKER in v or "API_KEY" in k.upper()]
    report(name, bool(leaked), ",".join(leaked) or "clean")


@attempt("secrets.marker_anywhere_on_disk")
def _(name):
    found, scanned = [], 0
    needle = MARKER.encode()
    for root, dirs, files in os.walk("/", onerror=lambda e: None):
        if root in ("/proc", "/sys", "/dev"):
            dirs[:] = []
            continue
        for fn in files:
            p = os.path.join(root, fn)
            try:
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode) or st.st_size > (1 << 20):
                    continue
                with open(p, "rb") as f:
                    scanned += 1
                    if needle in f.read():
                        found.append(p)
            except OSError:
                pass
    report(name, bool(found), (",".join(found) or "not found") + f" ({scanned} files read)")


@attempt("secrets.unix_sockets_on_disk")
def _(name):
    socks = []
    for root, dirs, files in os.walk("/", onerror=lambda e: None):
        if root in ("/proc", "/sys", "/dev"):
            dirs[:] = []
            continue
        for fn in files + dirs:
            p = os.path.join(root, fn)
            try:
                if stat.S_ISSOCK(os.lstat(p).st_mode):
                    socks.append(p)
            except OSError:
                pass
    report(name, bool(socks), ",".join(socks) or "none")


for r in results:
    print(json.dumps(r, sort_keys=True), flush=True)
