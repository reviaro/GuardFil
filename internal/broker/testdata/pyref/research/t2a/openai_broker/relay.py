#!/usr/bin/env python3
"""Minimal HTTP-to-Unix-socket relay for GuardFil T2a live-relay provider mode.

Runs inside the networkless provider container (python3 stdlib only).
Accepts only POST /v1/responses with Content-Length <= 4 MiB (no chunked encoding),
forwards the raw request body as a single length-prefixed frame over a Unix socket
(/run/guardfil-broker/broker.sock), reads the status+length-prefixed response frame
(bounded to 16 MiB), and writes the HTTP response with Connection: close.
Never reads or forwards any Authorization header, API key, or ledger state.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import signal
import socket
import struct
import sys
import threading
import time
from typing import Any, List, Optional, Tuple

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8899
DEFAULT_SOCKET_PATH = "/run/guardfil-broker/broker.sock"

MAX_REQUEST_BYTES = 4 * 1024 * 1024   # 4 MiB
MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # 16 MiB
REQUEST_READ_TIMEOUT_SEC = 30.0
BROKER_SOCKET_TIMEOUT_SEC = 130.0
ALLOWED_PATH = "/v1/responses"


def _header_values(headers: Any, name: str) -> List[str]:
    """Return all values for header `name` (case-insensitive in HTTPMessage)."""
    if hasattr(headers, "get_all"):
        return list(headers.get_all(name) or [])
    if hasattr(headers, "get"):
        val = headers.get(name)
        return [] if val is None else [val]
    return []


def _read_exact_stream(rfile: Any, length: int, deadline_sec: float, conn: Any = None) -> bytes:
    """Read exactly `length` bytes from an HTTP stream before deadline."""
    end = time.monotonic() + deadline_sec
    chunks: List[bytes] = []
    remaining = length
    read_fn = getattr(rfile, "read1", None) or rfile.read
    while remaining > 0:
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("request body read timeout")
        if conn is not None:
            try:
                conn.settimeout(left)
            except Exception:
                pass
        chunk = read_fn(min(65536, remaining))
        if time.monotonic() > end:
            raise TimeoutError("request body read timeout")
        if not chunk:
            raise ValueError("unexpected EOF reading request body")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_exact_sock(sock: socket.socket, length: int, deadline: float) -> bytes:
    """Read exactly `length` bytes from a socket before monotonic `deadline`."""
    chunks: List[bytes] = []
    remaining = length
    while remaining > 0:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("broker socket read timeout")
        sock.settimeout(left)
        chunk = sock.recv(min(65536, remaining))
        if time.monotonic() > deadline:
            raise TimeoutError("broker socket read timeout")
        if not chunk:
            raise EOFError("unexpected EOF from broker socket")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def forward_frame(
    socket_path: str,
    body: bytes,
    timeout_sec: float = BROKER_SOCKET_TIMEOUT_SEC,
) -> Tuple[int, bytes]:
    """Send one request frame (4B BE length + body) and read reply frame (4B status + 4B length + body)."""
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("request body exceeds 4 MiB limit")

    deadline = time.monotonic() + timeout_sec
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("broker connect timeout")
        sock.settimeout(left)
        sock.connect(socket_path)

        frame_header = struct.pack(">I", len(body))
        sock.sendall(frame_header + body)

        reply_header = _recv_exact_sock(sock, 8, deadline)
        status, reply_len = struct.unpack(">II", reply_header)
        if reply_len > MAX_RESPONSE_BYTES:
            raise ValueError(f"reply frame length {reply_len} exceeds 16 MiB limit")
        if not (100 <= status <= 599):
            raise ValueError(f"invalid reply status {status}")

        reply_body = _recv_exact_sock(sock, reply_len, deadline)
        return status, reply_body


class RelayHTTPServer(HTTPServer):
    """HTTPServer carrying the target Unix socket path."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        socket_path: str,
        socket_timeout_sec: float = BROKER_SOCKET_TIMEOUT_SEC,
        allowed_path: str = ALLOWED_PATH,
    ):
        super().__init__(server_address, RelayRequestHandler)
        self.socket_path = socket_path
        self.socket_timeout_sec = socket_timeout_sec
        self.allowed_path = allowed_path


class RelayRequestHandler(BaseHTTPRequestHandler):
    """Single-request-per-connection HTTP handler forwarding POST /v1/responses to Unix socket."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress access logging to keep container stdout/stderr clean.
        pass

    def _send_fixed(self, status: int, body: bytes) -> None:
        self.close_connection = True
        # A 200 is the model's stream unless the broker sent a JSON body (a non-streaming reply).
        content_type = "text/event-stream" if status == 200 and not body.lstrip().startswith(b"{") else "application/json"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json_error(self, status: int, error_code: str) -> None:
        payload = json.dumps({"error": error_code}, separators=(",", ":")).encode("utf-8")
        self._send_fixed(status, payload)

    def _handle_other_method(self) -> None:
        self._send_json_error(405, "method_not_allowed")

    def do_GET(self) -> None:
        self._handle_other_method()

    def do_PUT(self) -> None:
        self._handle_other_method()

    def do_DELETE(self) -> None:
        self._handle_other_method()

    def do_HEAD(self) -> None:
        self._handle_other_method()

    def do_OPTIONS(self) -> None:
        self._handle_other_method()

    def do_PATCH(self) -> None:
        self._handle_other_method()

    def handle_one_request(self) -> None:
        self.close_connection = True
        super().handle_one_request()
        self.close_connection = True

    def do_POST(self) -> None:
        self.close_connection = True
        server: RelayHTTPServer = self.server  # type: ignore[assignment]

        try:
            self.connection.settimeout(REQUEST_READ_TIMEOUT_SEC)
        except Exception:
            pass

        # Explicitly ignore Authorization header (never read or forward it).
        if self.path not in (server.allowed_path, server.allowed_path + "?beta=true"):
            self._send_json_error(404, "not_found")
            return

        # Refuse chunked or any Transfer-Encoding before reading or forwarding.
        if _header_values(self.headers, "Transfer-Encoding"):
            self._send_json_error(400, "transfer_encoding_not_supported")
            return

        cl_values = _header_values(self.headers, "Content-Length")
        if len(cl_values) != 1:
            self._send_json_error(411 if not cl_values else 400, "content_length_required")
            return

        raw_cl = cl_values[0].strip()
        if not raw_cl.isascii() or not raw_cl.isdigit() or len(raw_cl) > 9:
            self._send_json_error(400, "invalid_content_length")
            return

        content_len = int(raw_cl)
        if content_len > MAX_REQUEST_BYTES:
            self._send_json_error(413, "payload_too_large")
            return

        try:
            body = _read_exact_stream(self.rfile, content_len, REQUEST_READ_TIMEOUT_SEC, self.connection)
        except TimeoutError:
            self._send_json_error(408, "request_timeout")
            return
        except Exception:
            self._send_json_error(400, "bad_request_body")
            return

        try:
            status, reply_body = forward_frame(
                server.socket_path,
                body,
                timeout_sec=server.socket_timeout_sec,
            )
        except Exception:
            self._send_json_error(502, "broker_relay_failed")
            return

        self._send_fixed(status, reply_body)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GuardFil T2a HTTP-to-Unix-socket relay")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port (default 8899)")
    parser.add_argument("--socket-path", default=DEFAULT_SOCKET_PATH, help="Broker Unix socket path")
    parser.add_argument("--path", default=ALLOWED_PATH, choices=(ALLOWED_PATH, "/v1/messages"),
                        help="the one model path relayed (Codex: /v1/responses; Claude Code: /v1/messages)")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    httpd = RelayHTTPServer((args.host, args.port), args.socket_path, allowed_path=args.path)
    stop_event = threading.Event()

    def _on_signal(signum: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    httpd.timeout = 0.2
    try:
        while not stop_event.is_set():
            httpd.handle_request()
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
