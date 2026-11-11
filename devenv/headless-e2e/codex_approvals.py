#!/usr/bin/env python3
"""Probe native command approval coverage without a provider or credentials.

This checks the app-server protocol used by the executor. It is not a container
isolation test. Commands are fixed, harmless fixture commands in a private
temporary directory; the model is a local HTTP stand-in.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from deployments.local import run_codex as runtime
from redteam.m6.standin import sse_responses


def main(binary):
    commands = ["git status --short", "ls", "cat note", "rg public .", "sed -n 1p note", "/usr/bin/ls",
                "printf GUARDFIL_APPROVAL_CONTROL", "printf GUARDFIL_APPROVAL_CONTROL"]

    class Handler(http.server.BaseHTTPRequestHandler):
        index = 0

        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            i = Handler.index
            Handler.index += 1
            body = (sse_responses(i + 1, tool_name="exec", tool_input="await tools.exec_command({cmd:" +
                                  json.dumps(commands[i]) + "});") if i < len(commands)
                    else sse_responses(i + 1, final_text="fixture complete"))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory(prefix="gf-codex-approvals-") as tmp:
        root = Path(tmp)
        home, workspace = root / "codex", root / "workspace"
        home.mkdir()
        workspace.mkdir()
        (workspace / "note").write_text("public")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        runtime.RELAY_PORT, runtime.WORKSPACE = server.server_port, str(workspace)
        (home / "config.toml").write_text(runtime.config_toml())
        env = {"HOME": str(root), "CODEX_HOME": str(home), "PATH": "/usr/local/bin:/usr/bin:/bin", "SHELL": "/bin/bash"}
        requests, events = [], []

        def decide(socket, request):
            requests.append(request)
            # The repeated command must be checked again after its first allow.
            allow = len(requests) == 7
            return {"effect": "ALLOW" if allow else "BLOCK", "reasons": ["FIXTURE_DECISION"], "rule_ids": []}

        with open(root / "stderr", "wb") as log:
            proc = subprocess.Popen([binary, "app-server", "--stdio"], cwd=workspace, env=env,
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
            try:
                gate = runtime.Gate("/unused", ask=decide, log=lambda _: None)
                app = runtime.AppServer(proc, gate, lambda _: None, on_message=events.append)
                runtime.TURN_IDLE_TIMEOUT_SEC = 30
                runtime.run_turns(app, runtime.interactive_prompts("Run the local fixture.", True), lambda _: None)
                expected = [{"kind": "shell", "command": ["/bin/bash", "-lc", cmd], "cwd": str(workspace)} for cmd in commands]
                if requests != expected:
                    raise AssertionError(f"native approval coverage changed: {requests!r}")
                completed = [e["params"]["item"] for e in events if e.get("method") == "item/completed"
                             and e.get("params", {}).get("item", {}).get("type") == "commandExecution"]
                states = [item["status"] for item in completed]
                if states != ["declined"] * 6 + ["completed", "declined"]:
                    raise AssertionError(f"decisions did not control native execution: {states}")
                if "GUARDFIL_APPROVAL_CONTROL" not in (completed[6].get("aggregatedOutput") or ""):
                    raise AssertionError("allowed command positive control did not execute")
                print("PASS native Codex: 8 commands checked, 7 denied, 1 executed; repeat approval not cached")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", required=True)
    main(str(Path(parser.parse_args().codex).resolve()))
