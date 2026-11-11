"""A tiny demo MCP server (stdio, standard library only) for trying GuardFil's
MCP decisions and result filtering with run-codex.

Tools:
  notes.list_notes    list the notes
  notes.read_note     read one note; "deploy" contains credentials on purpose
  notes.add_note      add a note (kept in memory)
"""
import json
import sys

NOTES = {
    "todo": "Buy milk. Review the GuardFil policy.",
    "deploy": ("Deploy checklist:\n1. run migrations\n2. DB_PASSWORD=Tr0ub4dor-prod-2026\n"
               "3. api_key: sk-live-demo-0123456789abcdefghij\n4. restart workers"),
}
TOOLS = [
    {"name": "list_notes", "description": "List note names", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "read_note", "description": "Read a note by name",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "add_note", "description": "Add a note",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "text": {"type": "string"}},
                     "required": ["name", "text"]}},
]


def result(text, error=False):
    return {"content": [{"type": "text", "text": text}], "isError": error}


def call(name, args):
    if name == "list_notes":
        return result(", ".join(sorted(NOTES)))
    if name == "read_note":
        n = args.get("name")
        return result(NOTES[n]) if n in NOTES else result("no such note", True)
    if name == "add_note":
        NOTES[str(args.get("name"))] = str(args.get("text"))
        return result("added")
    return result("unknown tool", True)


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None:
        continue
    if method == "initialize":
        res = {"protocolVersion": params.get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}},
               "serverInfo": {"name": "guardfil-demo-notes", "version": "1"}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        res = call(params.get("name"), params.get("arguments") or {})
    elif method == "ping":
        res = {}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}),
              flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}), flush=True)
