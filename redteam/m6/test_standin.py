#!/usr/bin/env python3
"""Unit tests for the scripted stand-in broker."""
from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redteam.m6.standin import (  # noqa: E402
    CLAUDE_SCRIPTS,
    CODEX_SCRIPTS,
    StandinBroker,
    sse_message,
    sse_responses,
)


def parse_sse_events(raw: bytes) -> list[tuple[str, dict]]:
    events = []
    lines = raw.decode("utf-8").split("\n")
    cur_event = None
    cur_data = []
    for line in lines:
        if line.startswith("event: "):
            cur_event = line.split(" ", 1)[1]
        elif line.startswith("data: "):
            cur_data.append(line.split(" ", 1)[1])
        elif line == "":
            if cur_event is not None and cur_data:
                events.append((cur_event, json.loads("".join(cur_data))))
            cur_event = None
            cur_data = []
    return events


class SseFormattingTest(unittest.TestCase):
    def test_parallel_mcp_script_stays_javascript(self):
        broker = StandinBroker(case="mcp")
        broker.turn_idx = 1
        _, body = broker.handle_responses({})
        items = [d["item"] for event, d in parse_sse_events(body) if event == "response.output_item.done"]
        self.assertIn("Promise.allSettled", items[0]["input"])
        self.assertNotIn("exec_command", items[0]["input"])

    def test_sse_message_text(self):
        msg = {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello world"}],
            "stop_reason": "end_turn",
        }
        raw = sse_message(msg)
        events = parse_sse_events(raw)
        event_names = [name for name, _ in events]
        self.assertIn("message_start", event_names)
        self.assertIn("content_block_start", event_names)
        self.assertIn("content_block_delta", event_names)
        self.assertIn("content_block_stop", event_names)
        self.assertIn("message_delta", event_names)
        self.assertIn("message_stop", event_names)

    def test_sse_message_tool_use(self):
        msg = {
            "id": "msg_2",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Running bash"},
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}},
            ],
            "stop_reason": "tool_use",
        }
        raw = sse_message(msg)
        events = parse_sse_events(raw)
        deltas = [d for name, d in events if name == "content_block_delta"]
        self.assertTrue(any("input_json_delta" in str(d) for d in deltas))

    def test_sse_responses_tool_call(self):
        raw = sse_responses(1, tool_name="exec", tool_input='{"command":["ls"]}')
        events = parse_sse_events(raw)
        event_names = [name for name, _ in events]
        self.assertEqual(event_names, [
            "response.created",
            "response.output_item.added",
            "response.output_item.done",
            "response.completed",
        ])
        done_item = events[2][1]["item"]
        self.assertEqual(done_item["name"], "exec")
        self.assertEqual(done_item["input"], '{"command":["ls"]}')


class StandinBrokerSocketTest(unittest.TestCase):
    def test_socket_serving_claude_turns(self):
        with tempfile.TemporaryDirectory() as tmp:
            sockdir = Path(tmp)
            sock_path = sockdir / "broker.sock"
            proc = subprocess.Popen(
                [sys.executable, "-m", "redteam.m6.standin", "--sockdir", str(sockdir),
                 "--case", "claude_bypass", "--max-requests", "10"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                line = proc.stdout.readline()
                self.assertIn("READY ", line)
                line2 = proc.stdout.readline()
                self.assertIn("MESSAGES_BROKER_READY", line2)
                self.assertTrue(sock_path.is_socket())

                import socket
                # Send first request (Messages format)
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(str(sock_path))
                req1 = json.dumps({
                    "model": "claude-sonnet-5-5",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": True,
                }).encode("utf-8")
                s.sendall(struct.pack(">I", len(req1)) + req1)
                hdr = s.recv(8)
                status, rlen = struct.unpack(">II", hdr)
                self.assertEqual(status, 200)
                body = b""
                while len(body) < rlen:
                    chunk = s.recv(min(65536, rlen - len(body)))
                    if not chunk:
                        break
                    body += chunk
                s.close()

                events = parse_sse_events(body)
                starts = [d for name, d in events if name == "content_block_start"]
                tool_starts = [d for d in starts if d.get("content_block", {}).get("type") == "tool_use"]
                self.assertEqual(len(tool_starts), 1)
                self.assertEqual(tool_starts[0]["content_block"]["name"], "Write")

                # Send second request (turn 2)
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(str(sock_path))
                s.sendall(struct.pack(">I", len(req1)) + req1)
                hdr = s.recv(8)
                status, rlen = struct.unpack(">II", hdr)
                self.assertEqual(status, 200)
                body2 = b""
                while len(body2) < rlen:
                    chunk = s.recv(min(65536, rlen - len(body2)))
                    if not chunk:
                        break
                    body2 += chunk
                s.close()
                events2 = parse_sse_events(body2)
                starts2 = [d for name, d in events2 if name == "content_block_start"]
                tool_starts2 = [d for d in starts2 if d.get("content_block", {}).get("type") == "tool_use"]
                self.assertEqual(len(tool_starts2), 1)
                self.assertEqual(tool_starts2[0]["content_block"]["name"], "Write")

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()

    def test_all_cases_defined(self):
        for case in ("money", "secret", "internet", "claude_bypass", "mcp"):
            self.assertIn(case, CLAUDE_SCRIPTS)
            self.assertGreater(len(CLAUDE_SCRIPTS[case]), 1)
            self.assertIsNone(CLAUDE_SCRIPTS[case][-1])

        for case in ("money", "secret", "internet", "mcp"):
            self.assertIn(case, CODEX_SCRIPTS)
            self.assertGreater(len(CODEX_SCRIPTS[case]), 1)
            self.assertIsNone(CODEX_SCRIPTS[case][-1])

    def test_mcp_case_turns_structure(self):
        # Verify Claude MCP script contains mcp tool uses
        claude_mcp = CLAUDE_SCRIPTS["mcp"]
        tool_names = [turn[0] for turn in claude_mcp if turn is not None]
        self.assertIn("mcp__lab__ping", tool_names)
        self.assertIn("mcp__lab__withdraw", tool_names)
        self.assertIn("mcp__lab__read_secret", tool_names)
        self.assertIn("mcp__lab__fetch", tool_names)
        self.assertIn("mcp__lab__unknown", tool_names)

        # Verify Codex MCP script contains direct await tools.mcp__lab calls
        codex_mcp = CODEX_SCRIPTS["mcp"]
        commands = [cmd for cmd in codex_mcp if cmd is not None]
        self.assertTrue(any("tools.mcp__lab__ping" in c for c in commands))
        self.assertTrue(any("tools.mcp__lab__withdraw" in c for c in commands))
        self.assertTrue(any("tools.mcp__lab__read_secret" in c for c in commands))
        self.assertTrue(any("tools.mcp__lab__fetch" in c for c in commands))
        self.assertTrue(any("tools.mcp__lab__unknown" in c for c in commands))


if __name__ == "__main__":
    unittest.main()
