#!/usr/bin/env python3
"""An example plain-Python agent for run-agent --runtime python (stdlib only).

It keeps notes in its workspace.  The model comes from GuardFil's
model-neutral broker (any provider:model), and every tool call is decided by
GuardFil first (GuardFil.guard): a blocked call never runs.  The tools act
only on /workspace; the executor gives the agent no network at all.

    python3 -I python_agent_example.py --model PROVIDER:MODEL --task TEXT
"""
import argparse
import os
import re
import sys

sys.path[:0] = ["/guardfil-lib/clients", "/guardfil-lib/demo"]
from agent_loop import run  # noqa: E402
from guardfil_client import Blocked, GuardFil  # noqa: E402
from guardfil_model import ask_model  # noqa: E402

WS = "/workspace/notes"
gf = GuardFil(os.environ.get("GUARDFIL_SOCK", "/run/guardfil/approval.sock"))
NAME = re.compile(r"^[a-z0-9_-]{1,64}$")


def _path(name: str) -> str:
    if not NAME.match(name):
        raise ValueError("a note name is lower-case letters, digits, _ or -")
    return os.path.join(WS, name + ".txt")


@gf.guard("notes.list_notes")
def list_notes() -> str:
    return ", ".join(sorted(f[:-4] for f in os.listdir(WS) if f.endswith(".txt"))) or "(none)"


@gf.guard("notes.read_note")
def read_note(name: str) -> str:
    with open(_path(name)) as f:
        return f.read()


@gf.guard("notes.write_note")
def write_note(name: str, text: str) -> str:
    with open(_path(name), "w") as f:
        f.write(text)
    return f"saved {name}"


TOOLS = [
    {"name": "list_notes", "description": "List the saved notes", "parameters": {"type": "object", "properties": {}}},
    {"name": "read_note", "description": "Read a note", "parameters": {
        "type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "write_note", "description": "Save a note (name: lower-case letters, digits, _ or -)", "parameters": {
        "type": "object", "properties": {"name": {"type": "string"}, "text": {"type": "string"}},
        "required": ["name", "text"]}},
]
FUNCS = {"list_notes": list_notes, "read_note": read_note, "write_note": write_note}


def execute(name: str, args: dict) -> str:
    try:
        return str(FUNCS[name](**args))
    except Blocked as e:
        print(f"GuardFil: BLOCK notes.{name} {e}", flush=True)
        return f"refused by GuardFil: {e}"
    except Exception as e:
        return f"error: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--task", required=True)
    a = ap.parse_args()
    os.makedirs(WS, exist_ok=True)
    sock = os.environ.get("BROKER_SOCK", "/run/guardfil-broker/broker.sock")
    run(a.task, a.model, lambda req: ask_model(sock, req), execute, tools=TOOLS,
        system="You keep notes for the user with the tools. If a tool call is refused, say so and stop. Be brief.",
        log=lambda s: print(s, flush=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
