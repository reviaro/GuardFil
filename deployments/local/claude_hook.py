#!/usr/bin/env python3
"""Claude Code PreToolUse hook: GuardFil decides every tool call (stdlib only).

Installed by run_claude.py as a managed hook with "onFailure": "block", so a
crash, timeout or bad output blocks the call as well.  The hook itself fails
closed too: anything other than a clean ALLOW from GuardFil exits 2 (block).

Mapping to GuardFil requests:
- Bash                          -> {"kind": "shell", "command": ["bash", "-c", CMD], "cwd": CWD}
- Write, Edit, MultiEdit,
  NotebookEdit                  -> {"kind": "file_write", "changes": [{"path": P, "change": add|update}]}
- mcp__SERVER__TOOL             -> {"server": SERVER, "tool": TOOL, "arguments": INPUT}
- any other tool (Read, Grep,
  WebFetch, Task, ...)          -> {"server": "claude", "tool": name, "arguments": PROJECTION}
  The tool ID is lower-cased (GuardFil tool IDs are lower-case: claude.read).
  PROJECTION keeps the inputs a policy judges a call by (the path, pattern,
  URL or query; see PROJECTED); other inputs are dropped.  Each tool must be
  in the tool catalog (deployments/local/executor-catalog.yaml), so a tool
  GuardFil does not know is blocked.
"""
from __future__ import annotations

import json
import argparse
import os
import socket
import sys

# Fixed by the executor's mount, never redirected by workspace settings/env.
SOCK = "/run/guardfil/approval.sock"
TIMEOUT = 630.0   # an "ask me" hold can last up to 600 s
MAX_REPLY = 64 * 1024
PROJECTED = {"read": ("file_path",), "glob": ("pattern", "path"), "grep": ("pattern", "path"), "ls": ("path",),
             "webfetch": ("url",), "websearch": ("query",), "task": ("description", "subagent_type"),
             "agent": ("description", "subagent_type")}
WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}


def request_for(event: dict) -> dict:
    name, args = event["tool_name"], event.get("tool_input") or {}
    if not isinstance(name, str) or not isinstance(args, dict):
        raise ValueError("unreadable tool call")
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else "/workspace"
    if name == "Bash":
        cmd = args.get("command")
        if not isinstance(cmd, str) or not cmd:
            raise ValueError("Bash without a command")
        return {"kind": "shell", "command": ["bash", "-c", cmd], "cwd": cwd}
    if name in WRITE_TOOLS:
        path = args.get(WRITE_TOOLS[name])
        if not isinstance(path, str) or not path:
            raise ValueError(f"{name} without a path")
        path = os.path.normpath(os.path.join(cwd, path))
        return {"kind": "file_write", "changes": [{"path": path, "change": "update" if os.path.exists(path) else "add"}]}
    if name.startswith("mcp__") and name.count("__") >= 2:
        _, server, tool = name.split("__", 2)
        return {"server": server, "tool": tool, "arguments": args, "can_filter": True}
    tool = name.lower()
    projected = {k: args[k] for k in PROJECTED.get(tool, ()) if isinstance(args.get(k), str)}
    # GuardFil decides file-read rules on an absolute path: resolve it against
    # the working directory, as Claude Code does (a missing search path is cwd).
    if tool == "read" and "file_path" in projected:
        projected["file_path"] = os.path.normpath(os.path.join(cwd, projected["file_path"]))
    elif tool in ("glob", "grep", "ls"):
        projected["path"] = os.path.normpath(os.path.join(cwd, projected.get("path", "")))
    return {"server": "claude", "tool": tool, "arguments": projected}


def ask(req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(TIMEOUT)
        s.connect(SOCK)
        s.sendall(json.dumps(req, separators=(",", ":")).encode() + b"\n")
        s.shutdown(socket.SHUT_WR)
        buf = b""
        while len(buf) <= MAX_REPLY:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf)
    finally:
        s.close()


def main(argv=None) -> int:
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--proxy-server", action="append", default=[])
        config = parser.parse_args(argv)
        event = json.load(sys.stdin)
        req = request_for(event)
        # Only owner-configured servers, named in the read-only managed hook,
        # can delegate admission to the proxy. Unknown MCP names still go to
        # policy here and cannot acquire a proxy bypass from environment data.
        if event["tool_name"].startswith("mcp__") and req.get("server") in config.proxy_server:
            verdict = {"effect": "ALLOW", "reasons": ["PROXY_DECIDES_ACTUAL_CALL"]}
        else:
            verdict = ask(req)
        why = " ".join(list(verdict.get("rule_ids") or []) + list(verdict.get("reasons") or []))
        if verdict.get("effect") == "ALLOW":
            json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                              "permissionDecisionReason": f"GuardFil: allowed [{why}]"}}, sys.stdout)
            return 0
        print(f"GuardFil blocked this call [{why}]", file=sys.stderr)
        return 2
    except Exception as e:   # fail closed
        print(f"GuardFil could not decide this call ({type(e).__name__}); blocked", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
