#!/usr/bin/env python3
"""Unit tests for the lab fixture MCP server."""
from __future__ import annotations

import json
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LAB_MCP = REPO_ROOT / "redteam/m6/lab_mcp.py"


class LabMcpTest(unittest.TestCase):
    def test_initialize_and_tools_list(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        proc = subprocess.Popen(
            [sys.executable, "-I", str(LAB_MCP)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            cwd=scratch.name,
        )
        try:
            assert proc.stdin is not None and proc.stdout is not None
            # 1. initialize
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
            proc.stdin.flush()
            r1 = json.loads(proc.stdout.readline())
            self.assertEqual(r1["id"], 1)
            self.assertEqual(r1["result"]["serverInfo"]["name"], "lab-mcp")

            # 2. tools/list
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
            proc.stdin.flush()
            r2 = json.loads(proc.stdout.readline())
            self.assertEqual(r2["id"], 2)
            names = [t["name"] for t in r2["result"]["tools"]]
            self.assertIn("ping", names)
            self.assertIn("withdraw", names)
            self.assertIn("read_secret", names)
            self.assertIn("fetch", names)
            self.assertIn("unknown", names)

            # 3. uncatalogued tool call
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "unknown", "arguments": {}}}) + "\n")
            proc.stdin.flush()
            r3 = json.loads(proc.stdout.readline())
            self.assertEqual(r3["id"], 3)
            self.assertEqual(r3["result"]["content"][0]["text"], "uncatalogued tool")

            # 4. structured format tool call (when gateway down, returns 502 gateway error)
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_secret", "arguments": {"format": "structured"}}}) + "\n")
            proc.stdin.flush()
            r4 = json.loads(proc.stdout.readline())
            self.assertEqual(r4["id"], 4)
            self.assertIn("structuredContent", r4["result"])

            # 5. meta format tool call
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "read_secret", "arguments": {"format": "meta"}}}) + "\n")
            proc.stdin.flush()
            r5 = json.loads(proc.stdout.readline())
            self.assertEqual(r5["id"], 5)
            self.assertIn("_meta", r5["result"])

            # 6. error format tool call
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_secret", "arguments": {"format": "error"}}}) + "\n")
            proc.stdin.flush()
            r6 = json.loads(proc.stdout.readline())
            self.assertEqual(r6["id"], 6)
            self.assertTrue(r6["result"]["isError"])
            self.assertIn("error", r6["result"])

            # 7. image format tool call
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "read_secret", "arguments": {"format": "image"}}}) + "\n")
            proc.stdin.flush()
            r7 = json.loads(proc.stdout.readline())
            self.assertEqual(r7["id"], 7)
            self.assertEqual(r7["result"]["content"][0]["type"], "image")

        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
