#!/usr/bin/env python3
"""GuardFil T2a host-side live OpenAI broker for native Codex MCP feasibility runs.

Owns the OpenAI API key, durable $2.00 budget ledger, and Unix domain socket server
at `<sockdir>/broker.sock`.

Container UID note:
The native Codex probe (`http_mcp_probe.py`) and `preflight.py` enforce `os.getuid() == 1000`
on the host and run all containers (including `provider`) with `--user 1000:1000`.
Because the host broker process and the provider container share UID 1000, `<sockdir>` is
created with mode 0700 and `<sockdir>/broker.sock` with mode 0600 owned by UID 1000,
making the socket directly accessible to the provider container UID without granting
group or world permissions.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import ssl
import stat
import struct
import sys
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

try:
    from research.t2a.openai_budget import (
        BudgetLedger,
        DEFAULT_EXPERIMENT_ID,
        INPUT_TOKEN_RATE_MICROS,
        MAX_INPUT_TOKENS,
        MAX_OUTPUT_TOKENS,
        MIN_RESERVATION_MICROS,
        OUTPUT_TOKEN_RATE_MICROS,
        PINNED_MODEL,
        RESERVATION_AMOUNT_MICROS,
        PINNED_SERVICE_TIER,
        Receipt,
        SettlementCommittedHandleDisabledOutcome,
        SettlementResult,
    )
    from research.t2a.openai_broker.smoke import (
        DEFAULT_EXPERIMENT_ROOT,
        DEFAULT_KEY_FILE,
        _ledger_status_dict,
        _now_utc_str,
        _validate_identifier_local,
        check_key,
        load_key,
        open_or_init_ledger,
        strict_json_loads,
    )
except ImportError:
    from ..openai_budget import (
        BudgetLedger,
        DEFAULT_EXPERIMENT_ID,
        INPUT_TOKEN_RATE_MICROS,
        MAX_INPUT_TOKENS,
        MAX_OUTPUT_TOKENS,
        MIN_RESERVATION_MICROS,
        OUTPUT_TOKEN_RATE_MICROS,
        PINNED_MODEL,
        RESERVATION_AMOUNT_MICROS,
        PINNED_SERVICE_TIER,
        Receipt,
        SettlementCommittedHandleDisabledOutcome,
        SettlementResult,
    )
    from .smoke import (
        DEFAULT_EXPERIMENT_ROOT,
        DEFAULT_KEY_FILE,
        _ledger_status_dict,
        _now_utc_str,
        _validate_identifier_local,
        check_key,
        load_key,
        open_or_init_ledger,
        strict_json_loads,
    )

MAX_REQUEST_FRAME_BYTES = 4 * 1024 * 1024   # 4 MiB
MAX_STREAM_RESPONSE_BYTES = 16 * 1024 * 1024  # 16 MiB
STREAM_DEADLINE_SEC = 120.0
MIN_OUTPUT_TOKENS = 16
DEFAULT_MAX_OUTPUT_TOKENS = 1024
DEFAULT_MAX_REQUESTS = 3
# Per broker process.  Research cases use up to 8; a day-to-day run-codex session up to 64.
# The ledger's cumulative cap and the $2 ceiling still bound everything.
MAX_SESSION_REQUESTS = 64

CASE_LABEL_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

FORBIDDEN_HOSTED_TOOL_EXACT = frozenset({
    "file_search",
    "code_interpreter",
    "image_generation",
    "mcp",
})
FORBIDDEN_HOSTED_TOOL_PREFIXES = (
    "web_search",
    "computer_use",
)

FORBIDDEN_SSE_EVENTS = frozenset({
    "response.failed",
    "response.incomplete",
    "error",
})

ALLOWED_EVIDENCE_KEYS = frozenset({
    "request_id",
    "request_digest",
    "inserted_fields",
    "tool_type_names",
    "http_status",
    "response_id",
    "model",
    "service_tier",
    "usage",
    "response_body_sha256",
    "event_type_counts",
    "outcome_code",
    "ledger_status",
    "timestamps",
})


def _is_forbidden_hosted_tool_type(tool_type: str) -> bool:
    """Return True if `tool_type` names a provider-hosted tool."""
    if tool_type in FORBIDDEN_HOSTED_TOOL_EXACT:
        return True
    for prefix in FORBIDDEN_HOSTED_TOOL_PREFIXES:
        if tool_type.startswith(prefix):
            return True
    return False


def _collect_and_validate_tools(tools_list: Any, seen_types: Set[str]) -> Optional[str]:
    """Validate a tools array recursively, recording tool type names and refusing hosted tools."""
    if not isinstance(tools_list, list):
        return "tools must be a list"
    for tool in tools_list:
        if not isinstance(tool, dict):
            return "each tool must be an object"
        t_type = tool.get("type")
        if type(t_type) is not str or not t_type.strip():
            return "tool missing valid string type"
        seen_types.add(t_type)
        if _is_forbidden_hosted_tool_type(t_type):
            return f"forbidden hosted tool type: {t_type}"
        if t_type not in {"function", "custom", "namespace", "local_shell"}:
            return "only client-side tools are allowed"
        # Namespace tools may carry nested tool definitions
        if "tools" in tool and tool["tools"] is not None:
            err = _collect_and_validate_tools(tool["tools"], seen_types)
            if err is not None:
                return err
    return None


def validate_and_prepare_request(
    raw_body: bytes,
) -> Tuple[Optional[bytes], Optional[str], List[str], List[str], int, Optional[str]]:
    """Validate inbound JSON body, insert defaults if absent, and return outbound bytes + digest.

    Returns:
        (outbound_bytes, digest, inserted_fields, tool_type_names, max_output_tokens, error_reason)
    """
    if len(raw_body) > MAX_REQUEST_FRAME_BYTES:
        return None, None, [], [], 0, "request exceeds 4 MiB limit"

    try:
        obj = strict_json_loads(raw_body)
    except Exception:
        return None, None, [], [], 0, "invalid JSON"

    if not isinstance(obj, dict):
        return None, None, [], [], 0, "top-level JSON must be an object"

    from broker.input_boundary import remote_input_error
    remote_error = remote_input_error(obj)
    if remote_error:
        return None, None, [], [], 0, remote_error

    # Extract tool type names early so they can be logged even on refusal if valid
    seen_tool_types: Set[str] = set()
    tool_err: Optional[str] = None
    if "tools" in obj and obj["tools"] is not None:
        tool_err = _collect_and_validate_tools(obj["tools"], seen_tool_types)

    if tool_err is None and isinstance(obj.get("input"), list):
        for item in obj["input"]:
            if isinstance(item, dict) and item.get("type") == "additional_tools" and "tools" in item:
                tool_err = _collect_and_validate_tools(item["tools"], seen_tool_types)
                if tool_err is not None:
                    break

    if tool_err is None and isinstance(obj.get("tool_choice"), dict):
        tc_type = obj["tool_choice"].get("type")
        if isinstance(tc_type, str) and _is_forbidden_hosted_tool_type(tc_type):
            seen_tool_types.add(tc_type)
            tool_err = f"forbidden hosted tool_choice type: {tc_type}"

    sorted_tool_types = sorted(seen_tool_types)

    if tool_err is not None:
        return None, None, [], sorted_tool_types, 0, tool_err

    # Model check
    model = obj.get("model")
    if type(model) is not str or model != PINNED_MODEL:
        return None, None, [], sorted_tool_types, 0, "model must be gpt-6-luna"

    # Reasoning effort check if reasoning present
    if "reasoning" in obj and obj["reasoning"] is not None:
        reasoning = obj["reasoning"]
        if not isinstance(reasoning, dict) or reasoning.get("effort") != "none":
            return None, None, [], sorted_tool_types, 0, "reasoning.effort must be none"

    # Stream check
    if obj.get("stream") is not True:
        return None, None, [], sorted_tool_types, 0, "stream must be true"

    # Background check
    if "background" in obj and obj["background"] is not False and obj["background"] is not None:
        return None, None, [], sorted_tool_types, 0, "background mode is forbidden"

    inserted_fields: List[str] = []

    # service_tier: absent -> insert "default", else must equal "default"
    if "service_tier" not in obj:
        obj["service_tier"] = PINNED_SERVICE_TIER
        inserted_fields.append("service_tier")
    else:
        st_val = obj["service_tier"]
        if type(st_val) is not str or st_val != PINNED_SERVICE_TIER:
            return None, None, inserted_fields, sorted_tool_types, 0, "service_tier must be default"

    # max_output_tokens: absent -> insert 1024; present must be int 16..1024 (not bool)
    if "max_output_tokens" not in obj:
        obj["max_output_tokens"] = DEFAULT_MAX_OUTPUT_TOKENS
        inserted_fields.append("max_output_tokens")
    else:
        mot = obj["max_output_tokens"]
        if type(mot) is not int or isinstance(mot, bool) or not (MIN_OUTPUT_TOKENS <= mot <= MAX_OUTPUT_TOKENS):
            return (
                None,
                None,
                inserted_fields,
                sorted_tool_types,
                0,
                "max_output_tokens must be int 16..1024",
            )

    inserted_fields.sort()
    outbound_max_output_tokens: int = obj["max_output_tokens"]

    outbound_bytes = json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8")
    digest = hashlib.sha256(outbound_bytes).hexdigest().lower()

    return outbound_bytes, digest, inserted_fields, sorted_tool_types, outbound_max_output_tokens, None


def default_https_streaming_post_transport(
    body_bytes: bytes,
    key: str,
    deadline_sec: float = STREAM_DEADLINE_SEC,
) -> Tuple[int, Mapping[str, str], bytes]:
    """Single-attempt HTTPS POST to https://api.openai.com/v1/responses with 120s monotonic deadline."""
    deadline = time.monotonic() + deadline_sec
    ctx = ssl.create_default_context()
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("stream deadline expired before connect")
    conn = http.client.HTTPSConnection("api.openai.com", 443, timeout=left, context=ctx)
    try:
        conn.request(
            "POST",
            "/v1/responses",
            body=body_bytes,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "Content-Length": str(len(body_bytes)),
                "Connection": "close",
            },
        )
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("stream deadline expired waiting for response headers")
        if conn.sock is not None:
            conn.sock.settimeout(left)
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}

        chunks: List[bytes] = []
        total = 0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("stream deadline expired while reading SSE body")
            if conn.sock is not None:
                conn.sock.settimeout(left)
            chunk = resp.read(min(65536, MAX_STREAM_RESPONSE_BYTES + 1 - total))
            if time.monotonic() > deadline:
                raise TimeoutError("stream deadline expired after SSE read")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_STREAM_RESPONSE_BYTES:
                break

        return resp.status, headers, b"".join(chunks)
    finally:
        conn.close()


PREFLIGHT_PATH = "/v1/responses/input_tokens"
PREFLIGHT_DEADLINE_SEC = 30.0
PREFLIGHT_MAX_BYTES = 64 * 1024
# Body keys the free input-token counting endpoint accepts; everything else is dropped for the preflight only.
PREFLIGHT_KEYS = frozenset({
    "model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls",
    "reasoning", "text", "truncation", "previous_response_id", "conversation",
})
# Feasibility guard: refuse prompts larger than this before reserving (conservative ledger rate is
# 1 microUSD/token, so this bounds a single request's accounted input cost to $0.15).
PREFLIGHT_MAX_INPUT_TOKENS = 150_000


def default_https_input_tokens_transport(body_bytes: bytes, key: str) -> Tuple[int, Mapping[str, str], bytes]:
    """Single-attempt HTTPS POST to the free /v1/responses/input_tokens counting endpoint (no generation)."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection("api.openai.com", 443, timeout=PREFLIGHT_DEADLINE_SEC, context=ctx)
    try:
        conn.request(
            "POST",
            PREFLIGHT_PATH,
            body=body_bytes,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Content-Length": str(len(body_bytes)),
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        raw = resp.read(PREFLIGHT_MAX_BYTES + 1)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, raw
    finally:
        conn.close()


RESERVATION_INPUT_MARGIN_TOKENS = 4096


def reservation_for(counted_input_tokens: Optional[int]) -> int:
    """Worst-case cost of one request in uUSD: the counted input plus 25% and a fixed margin (the count and
    the billed input can differ slightly), plus the output cap.  Unknown count -> the maximum."""
    if type(counted_input_tokens) is not int or isinstance(counted_input_tokens, bool) or counted_input_tokens < 0:
        return RESERVATION_AMOUNT_MICROS
    est_input = -(-counted_input_tokens * 5 // 4) + RESERVATION_INPUT_MARGIN_TOKENS
    amount = est_input * INPUT_TOKEN_RATE_MICROS + MAX_OUTPUT_TOKENS * OUTPUT_TOKEN_RATE_MICROS
    return max(MIN_RESERVATION_MICROS, min(RESERVATION_AMOUNT_MICROS, amount))


def preflight_input_tokens(
    outbound_bytes: bytes,
    key: str,
    transport: Callable[[bytes, str], Tuple[int, Mapping[str, str], bytes]],
) -> Tuple[bool, Optional[int], Optional[int], str]:
    """Validate the request shape with the provider BEFORE any ledger reservation.

    A provider 4xx on the real call would otherwise retain the full reservation and halt the
    cumulative ledger. Returns (ok, http_status, input_tokens, reason_code).
    """
    obj = json.loads(outbound_bytes)
    body = json.dumps({k: v for k, v in obj.items() if k in PREFLIGHT_KEYS},
                      separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")
    try:
        status, _headers, raw = transport(body, key)
    except Exception:
        return False, None, None, "PREFLIGHT_TRANSPORT_FAILURE"
    if status != 200:
        return False, status, None, "PREFLIGHT_PROVIDER_REJECTED"
    if len(raw) > PREFLIGHT_MAX_BYTES:
        return False, status, None, "PREFLIGHT_RESPONSE_TOO_LARGE"
    try:
        resp = strict_json_loads(raw)
    except Exception:
        return False, status, None, "PREFLIGHT_RESPONSE_INVALID"
    n = resp.get("input_tokens")
    if resp.get("object") != "response.input_tokens" or type(n) is not int or n < 0:
        return False, status, None, "PREFLIGHT_RESPONSE_INVALID"
    if n > PREFLIGHT_MAX_INPUT_TOKENS:
        return False, status, n, "PREFLIGHT_INPUT_TOO_LARGE"
    return True, status, n, "PREFLIGHT_OK"


def parse_and_validate_sse(
    http_status: int,
    headers: Mapping[str, str],
    raw_body: bytes,
    outbound_max_output_tokens: int,
) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, int], Optional[str]]:
    """Strictly parse and validate an OpenAI Responses SSE stream.

    Returns:
        (is_valid, extracted_metadata, event_type_counts, error_reason)
    """
    event_type_counts: Dict[str, int] = {}

    if http_status != 200:
        return False, None, event_type_counts, f"expected HTTP 200, got {http_status}"

    if len(raw_body) > MAX_STREAM_RESPONSE_BYTES:
        return False, None, event_type_counts, "SSE body exceeds 16 MiB limit"

    for k, v in headers.items():
        if k.lower() == "content-encoding" and v.strip().lower() not in ("", "identity"):
            return False, None, event_type_counts, f"unsupported content-encoding: {v}"

    try:
        text = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return False, None, event_type_counts, "SSE body is not valid UTF-8"

    # Normalize CRLF -> LF; reject lone CR
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        return False, None, event_type_counts, "lone CR in SSE stream"

    if not normalized.strip():
        return False, None, event_type_counts, "empty SSE stream"

    # Split SSE events separated by blank lines (\n\n)
    raw_blocks = normalized.split("\n\n")

    completed_resp: Optional[Dict[str, Any]] = None
    saw_completed = False
    saw_done_sentinel = False

    for block in raw_blocks:
        if not block.strip():
            continue

        # If we already saw [DONE], nothing non-whitespace may follow
        if saw_done_sentinel:
            return False, None, event_type_counts, "trailing data after [DONE]"

        lines = block.split("\n")
        event_header: Optional[str] = None
        data_lines: List[str] = []

        for line in lines:
            if not line:
                continue
            if line.startswith(":"):
                # SSE comment line
                if saw_completed:
                    return False, None, event_type_counts, "comment after terminal event"
                continue
            if line.startswith("event:"):
                if event_header is not None:
                    return False, None, event_type_counts, "duplicate event: line in SSE block"
                event_header = line[len("event:"):].strip()
                if not event_header:
                    return False, None, event_type_counts, "empty event: header in SSE block"
            elif line.startswith("data:"):
                data_lines.append(line[len("data:"):].strip())
            else:
                return False, None, event_type_counts, "malformed line in SSE block"

        if not data_lines:
            if event_header is not None:
                return False, None, event_type_counts, "event header without data line"
            continue

        if len(data_lines) != 1:
            return False, None, event_type_counts, "multiple data lines in single SSE event"

        data_str = data_lines[0]

        if data_str == "[DONE]":
            if not saw_completed:
                return False, None, event_type_counts, "[DONE] before response.completed"
            if event_header not in (None, "done"):
                return False, None, event_type_counts, "unexpected event header on [DONE]"
            saw_done_sentinel = True
            continue

        try:
            data_obj = strict_json_loads(data_str)
        except Exception:
            return False, None, event_type_counts, "malformed JSON in SSE data"

        ev_type = data_obj.get("type")
        if type(ev_type) is not str or not ev_type:
            return False, None, event_type_counts, "SSE JSON object missing string type"

        if event_header is not None and event_header != ev_type:
            return False, None, event_type_counts, "SSE event header does not match data.type"

        event_type_counts[ev_type] = event_type_counts.get(ev_type, 0) + 1

        if ev_type in FORBIDDEN_SSE_EVENTS:
            return False, None, event_type_counts, f"forbidden SSE event: {ev_type}"

        # Any event after the first response.completed is forbidden
        if saw_completed:
            return False, None, event_type_counts, "trailing event after response.completed"

        if ev_type == "response.completed":
            saw_completed = True
            resp_obj = data_obj.get("response")
            if not isinstance(resp_obj, dict):
                return False, None, event_type_counts, "response.completed missing response object"
            completed_resp = resp_obj

    if not saw_completed or completed_resp is None:
        return False, None, event_type_counts, "missing response.completed event"

    if event_type_counts.get("response.completed", 0) != 1:
        return False, None, event_type_counts, "expected exactly one response.completed event"

    # Validate completed response fields
    resp_id = completed_resp.get("id")
    model_val = completed_resp.get("model")
    tier_val = completed_resp.get("service_tier")
    status_val = completed_resp.get("status")

    partial_meta: Dict[str, Any] = {
        "response_id": resp_id if isinstance(resp_id, str) else None,
        "model": model_val if isinstance(model_val, str) else None,
        "service_tier": tier_val if isinstance(tier_val, str) else None,
        "usage": None,
    }

    if status_val != "completed":
        return False, partial_meta, event_type_counts, f"expected status=='completed', got {status_val!r}"

    if completed_resp.get("error") is not None:
        return False, partial_meta, event_type_counts, "completed response has non-null error"

    if completed_resp.get("incomplete_details") is not None:
        return False, partial_meta, event_type_counts, "completed response has non-null incomplete_details"

    if not _validate_identifier_local(resp_id):
        return False, partial_meta, event_type_counts, "invalid response_id"

    if model_val != PINNED_MODEL:
        return False, partial_meta, event_type_counts, f"model mismatch: {model_val!r}"

    if tier_val != PINNED_SERVICE_TIER:
        return False, partial_meta, event_type_counts, f"service_tier mismatch: {tier_val!r}"

    usage = completed_resp.get("usage")
    if not isinstance(usage, dict):
        return False, partial_meta, event_type_counts, "missing or non-object usage"

    in_tok = usage.get("input_tokens")
    out_tok = usage.get("output_tokens")
    tot_tok = usage.get("total_tokens")

    for field_name, val in (("input_tokens", in_tok), ("output_tokens", out_tok), ("total_tokens", tot_tok)):
        if type(val) is not int or isinstance(val, bool) or val < 0:
            return False, partial_meta, event_type_counts, f"invalid {field_name}"

    if tot_tok != in_tok + out_tok:
        return False, partial_meta, event_type_counts, "total_tokens != input_tokens + output_tokens"

    if out_tok > outbound_max_output_tokens or out_tok > MAX_OUTPUT_TOKENS:
        return False, partial_meta, event_type_counts, "output_tokens exceeds bound"

    if in_tok > MAX_INPUT_TOKENS:
        return False, partial_meta, event_type_counts, "input_tokens exceeds bound"

    partial_meta["usage"] = {
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "total_tokens": tot_tok,
    }
    return True, partial_meta, event_type_counts, None


def append_evidence_jsonl(
    experiment_root: str | Path,
    case_label: str,
    record: Mapping[str, Any],
) -> Path:
    """Append one sanitized evidence line to `<experiment-root>/live-broker-<case-label>.jsonl` (0600)."""
    if set(record.keys()) != ALLOWED_EVIDENCE_KEYS:
        raise ValueError(f"Evidence record keys mismatch: {set(record.keys()) ^ ALLOWED_EVIDENCE_KEYS}")

    root_path = Path(experiment_root).expanduser().resolve()
    if not root_path.exists():
        root_path.mkdir(mode=0o700, parents=True, exist_ok=True)

    filename = f"live-broker-{case_label}.jsonl"
    line_bytes = (
        json.dumps(record, separators=(",", ":"), sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")

    dir_fd = os.open(str(root_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            filename,
            os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            st = os.fstat(file_fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                raise OSError("Invalid evidence file ownership or type")
            if stat.S_IMODE(st.st_mode) != 0o600:
                os.fchmod(file_fd, 0o600)
            written = 0
            while written < len(line_bytes):
                n = os.write(file_fd, line_bytes[written:])
                if n <= 0:
                    raise OSError("Failed to write evidence line")
                written += n
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

    return root_path / filename


class LiveBrokerServer:
    """Host-side serial Unix socket broker for one live MCP case."""

    def __init__(
        self,
        experiment_root: str | Path,
        key_file: str | Path,
        sockdir: str | Path,
        case_label: str,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        initialize_ledger: bool = False,
        get_transport: Optional[Callable] = None,
        post_transport: Optional[Callable[[bytes, str], Tuple[int, Mapping[str, str], bytes]]] = None,
        count_transport: Optional[Callable[[bytes, str], Tuple[int, Mapping[str, str], bytes]]] = None,
    ):
        if not isinstance(case_label, str) or not CASE_LABEL_RE.fullmatch(case_label):
            raise ValueError(f"Invalid case_label: {case_label!r}")
        if type(max_requests) is not int or isinstance(max_requests, bool) or not (1 <= max_requests <= MAX_SESSION_REQUESTS):
            raise ValueError(f"Invalid max_requests: {max_requests!r}")

        self.experiment_root = Path(experiment_root).expanduser().resolve()
        self.key_file = Path(key_file)
        self.sockdir = Path(sockdir).expanduser().resolve()
        self.socket_path = self.sockdir / "broker.sock"
        self.case_label = case_label
        self.max_requests = max_requests
        self.initialize_ledger = initialize_ledger
        self.get_transport = get_transport
        self.post_transport = post_transport or default_https_streaming_post_transport
        self.count_transport = count_transport or default_https_input_tokens_transport

        self._key: Optional[str] = None
        self.ledger: Optional[BudgetLedger] = None
        self._sock: Optional[socket.socket] = None
        self.request_counter: int = 0
        self._stop_requested: bool = False

    def start(self) -> None:
        """Load key, perform free key check BEFORE any reservation, open ledger, and bind Unix socket."""
        # 1. Load key and run free key check once at startup BEFORE any reservation
        key = load_key(self.key_file)
        res = check_key(key, transport=self.get_transport)
        if not res.ok:
            raise RuntimeError(f"Startup key check failed (HTTP {res.status_code}): {res.error_message}")
        self._key = key

        # 2. Open or initialize ledger and verify it can reserve
        ledger = open_or_init_ledger(self.experiment_root, initialize=self.initialize_ledger)
        try:
            status = ledger.get_status()
            if not status.can_reserve:
                raise RuntimeError(
                    f"Ledger cannot reserve at startup (halted={status.halted}, "
                    f"pending={status.has_pending_reservation})"
                )
        except Exception:
            ledger.close()
            raise
        self.ledger = ledger

        # 3. Prepare socket directory (0700) and Unix socket (0600), owned by host/container UID (1000)
        if os.path.islink(str(self.sockdir)):
            self.close()
            raise RuntimeError("Socket directory must not be a symlink")
        self.sockdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(str(self.sockdir), 0o700)
        st_dir = os.lstat(str(self.sockdir))
        if not stat.S_ISDIR(st_dir.st_mode) or st_dir.st_uid != os.getuid() or stat.S_IMODE(st_dir.st_mode) != 0o700:
            self.close()
            raise RuntimeError("Socket directory ownership or permissions invalid")

        if os.path.lexists(str(self.socket_path)):
            st_sock = os.lstat(str(self.socket_path))
            if stat.S_ISSOCK(st_sock.st_mode) and st_sock.st_uid == os.getuid():
                os.unlink(str(self.socket_path))
            else:
                self.close()
                raise RuntimeError("Existing broker.sock path is not an owned Unix socket")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            sock.bind(str(self.socket_path))
        except Exception:
            sock.close()
            self.close()
            raise
        finally:
            os.umask(old_umask)

        os.chmod(str(self.socket_path), 0o600)
        sock.listen(4)
        sock.settimeout(0.2)
        self._sock = sock

    def request_stop(self) -> None:
        self._stop_requested = True

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if os.path.lexists(str(self.socket_path)):
            try:
                st = os.lstat(str(self.socket_path))
                if stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid():
                    os.unlink(str(self.socket_path))
            except OSError:
                pass
        if self.ledger is not None:
            try:
                self.ledger.close()
            except Exception:
                pass
            self.ledger = None
        self._key = None

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int, timeout_sec: float = 10.0) -> bytes:
        deadline = time.monotonic() + timeout_sec
        buf = bytearray()
        while len(buf) < n:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("socket frame read timeout")
            conn.settimeout(left)
            chunk = conn.recv(min(65536, n - len(buf)))
            if not chunk:
                raise EOFError("short frame read")
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _send_reply(conn: socket.socket, status: int, body: bytes) -> None:
        header = struct.pack(">II", status, len(body))
        conn.sendall(header + body)

    def _write_evidence(
        self,
        *,
        request_id: Optional[str],
        request_digest: Optional[str],
        inserted_fields: List[str],
        tool_type_names: List[str],
        http_status: Optional[int],
        response_id: Optional[str],
        model: Optional[str],
        service_tier: Optional[str],
        usage: Optional[Dict[str, int]],
        response_body_sha256: Optional[str],
        event_type_counts: Dict[str, int],
        outcome_code: str,
        start_utc: str,
    ) -> None:
        assert self.ledger is not None
        end_utc = _now_utc_str()
        status_obj = self.ledger.get_status()
        record = {
            "request_id": request_id,
            "request_digest": request_digest,
            "inserted_fields": list(inserted_fields),
            "tool_type_names": list(tool_type_names),
            "http_status": http_status,
            "response_id": response_id,
            "model": model,
            "service_tier": service_tier,
            "usage": usage,
            "response_body_sha256": response_body_sha256,
            "event_type_counts": dict(event_type_counts),
            "outcome_code": outcome_code,
            "ledger_status": _ledger_status_dict(status_obj),
            "timestamps": {
                "started_at_utc": start_utc,
                "completed_at_utc": end_utc,
            },
        }
        append_evidence_jsonl(self.experiment_root, self.case_label, record)

    def handle_frame_bytes(self, raw_body: bytes) -> Tuple[int, bytes]:
        """Process one request body serially and return (status_code, reply_bytes)."""
        assert self.ledger is not None and self._key is not None
        start_utc = _now_utc_str()

        # Check per-broker max-requests cap before any validation or reservation if already at cap
        if self.request_counter >= self.max_requests:
            self._write_evidence(
                request_id=None,
                request_digest=None,
                inserted_fields=[],
                tool_type_names=[],
                http_status=None,
                response_id=None,
                model=None,
                service_tier=None,
                usage=None,
                response_body_sha256=None,
                event_type_counts={},
                outcome_code="MAX_REQUESTS_EXCEEDED",
                start_utc=start_utc,
            )
            return 429, b'{"error":"max_requests_exceeded"}'

        # Step a & b: Validate request body, insert defaults, compute compact JSON + SHA-256 digest
        (
            outbound_bytes,
            digest,
            inserted_fields,
            tool_type_names,
            outbound_max_output_tokens,
            err_reason,
        ) = validate_and_prepare_request(raw_body)

        if err_reason is not None or outbound_bytes is None or digest is None:
            self._write_evidence(
                request_id=None,
                request_digest=None,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=None,
                response_id=None,
                model=None,
                service_tier=None,
                usage=None,
                response_body_sha256=None,
                event_type_counts={},
                outcome_code="REFUSED_PRE_RESERVE",
                start_utc=start_utc,
            )
            return 400, b'{"error":"request_refused_by_broker"}'

        # Free provider-side shape check BEFORE reservation (a 4xx after reserve would halt the ledger).
        pf_ok, pf_status, _pf_tokens, pf_code = preflight_input_tokens(outbound_bytes, self._key, self.count_transport)
        if not pf_ok:
            self._write_evidence(
                request_id=None,
                request_digest=digest,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=pf_status,
                response_id=None,
                model=None,
                service_tier=None,
                usage=None,
                response_body_sha256=None,
                event_type_counts={},
                outcome_code=pf_code,
                start_utc=start_utc,
            )
            return 400, b'{"error":"request_refused_by_preflight"}'

        # Step c: Assign 1-based per-broker request_id
        self.request_counter += 1
        request_id = f"live-{self.case_label}-{self.request_counter}"

        # Step d: Reserve in ledger, sized to this request's worst case (counted input + margin + output cap)
        try:
            permit = self.ledger.reserve(request_id, digest, reservation_for(_pf_tokens))
        except Exception:
            self._stop_requested = True
            self._write_evidence(
                request_id=request_id,
                request_digest=digest,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=None,
                response_id=None,
                model=None,
                service_tier=None,
                usage=None,
                response_body_sha256=None,
                event_type_counts={},
                outcome_code="RESERVE_FAILED",
                start_utc=start_utc,
            )
            return 502, b'{"error":"ledger_reserve_failed"}'

        # Single streaming POST to OpenAI Responses API
        try:
            http_status, headers, resp_bytes = self.post_transport(outbound_bytes, self._key)
        except Exception:
            try:
                self.ledger.record_failure(permit, "REQUEST_TRANSPORT_FAILURE")
            except Exception:
                pass
            self._stop_requested = True
            self._write_evidence(
                request_id=request_id,
                request_digest=digest,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=None,
                response_id=None,
                model=None,
                service_tier=None,
                usage=None,
                response_body_sha256=None,
                event_type_counts={},
                outcome_code="REQUEST_TRANSPORT_FAILURE",
                start_utc=start_utc,
            )
            return 502, b'{"error":"upstream_transport_failure"}'

        resp_sha256 = hashlib.sha256(resp_bytes).hexdigest().lower() if resp_bytes else None

        # Step e: Parse and validate SSE
        is_valid, meta, event_type_counts, _sse_err = parse_and_validate_sse(
            http_status=http_status,
            headers=headers,
            raw_body=resp_bytes,
            outbound_max_output_tokens=outbound_max_output_tokens,
        )

        resp_id = meta.get("response_id") if meta else None
        model_val = meta.get("model") if meta else None
        tier_val = meta.get("service_tier") if meta else None
        usage_val = meta.get("usage") if meta else None

        if not is_valid or usage_val is None:
            try:
                self.ledger.record_failure(permit, "INVALID_RECEIPT_EVIDENCE")
            except Exception:
                pass
            self._stop_requested = True
            self._write_evidence(
                request_id=request_id,
                request_digest=digest,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=http_status,
                response_id=resp_id,
                model=model_val,
                service_tier=tier_val,
                usage=None,
                response_body_sha256=resp_sha256,
                event_type_counts=event_type_counts,
                outcome_code="INVALID_RECEIPT_EVIDENCE",
                start_utc=start_utc,
            )
            return 502, b'{"error":"invalid_upstream_sse"}'

        # Step f: Settle receipt
        receipt = Receipt(
            status="completed",
            response_id=resp_id,
            request_id=request_id,
            request_digest=digest,
            model=model_val,
            service_tier=tier_val,
            input_tokens=usage_val["input_tokens"],
            output_tokens=usage_val["output_tokens"],
            total_tokens=usage_val["total_tokens"],
        )

        try:
            outcome = self.ledger.settle(permit, receipt)
        except Exception:
            try:
                self.ledger.record_failure(permit, "INVALID_RECEIPT_EVIDENCE")
            except Exception:
                pass
            self._stop_requested = True
            self._write_evidence(
                request_id=request_id,
                request_digest=digest,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=http_status,
                response_id=resp_id,
                model=model_val,
                service_tier=tier_val,
                usage=usage_val,
                response_body_sha256=resp_sha256,
                event_type_counts=event_type_counts,
                outcome_code="INVALID_RECEIPT_EVIDENCE",
                start_utc=start_utc,
            )
            return 502, b'{"error":"ledger_settlement_failed"}'

        if isinstance(outcome, SettlementCommittedHandleDisabledOutcome):
            self._stop_requested = True
            self._write_evidence(
                request_id=request_id,
                request_digest=digest,
                inserted_fields=inserted_fields,
                tool_type_names=tool_type_names,
                http_status=http_status,
                response_id=resp_id,
                model=model_val,
                service_tier=tier_val,
                usage=usage_val,
                response_body_sha256=resp_sha256,
                event_type_counts=event_type_counts,
                outcome_code="SETTLEMENT_COMMITTED_HANDLE_DISABLED",
                start_utc=start_utc,
            )
            return 502, b'{"error":"settlement_handle_disabled"}'

        self._write_evidence(
            request_id=request_id,
            request_digest=digest,
            inserted_fields=inserted_fields,
            tool_type_names=tool_type_names,
            http_status=http_status,
            response_id=resp_id,
            model=model_val,
            service_tier=tier_val,
            usage=usage_val,
            response_body_sha256=resp_sha256,
            event_type_counts=event_type_counts,
            outcome_code="SUCCESS",
            start_utc=start_utc,
        )
        return 200, resp_bytes

    def handle_one_connection(self, conn: socket.socket) -> None:
        """Read one request frame from `conn`, process it, and write the reply frame."""
        with conn:
            try:
                hdr = self._recv_exact(conn, 4, timeout_sec=10.0)
                (frame_len,) = struct.unpack(">I", hdr)
                if frame_len > MAX_REQUEST_FRAME_BYTES:
                    self._send_reply(conn, 400, b'{"error":"frame_too_large"}')
                    return
                raw_body = self._recv_exact(conn, frame_len, timeout_sec=15.0)
            except Exception:
                try:
                    self._send_reply(conn, 400, b'{"error":"frame_read_error"}')
                except Exception:
                    pass
                return

            status, reply_body = self.handle_frame_bytes(raw_body)
            try:
                self._send_reply(conn, status, reply_body)
            except Exception:
                pass

    def serve_forever(self) -> int:
        """Run the serial accept loop until stopped via SIGTERM/SIGINT or fatal post-reserve error."""
        if self._sock is None:
            raise RuntimeError("Broker not started")

        print(f"READY {self.socket_path}", flush=True)

        while not self._stop_requested:
            try:
                rlist, _, _ = select.select([self._sock], [], [], 0.1)
            except (OSError, ValueError):
                if self._stop_requested:
                    break
                continue
            if not rlist:
                continue
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_requested:
                    break
                continue
            self.handle_one_connection(conn)

        return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GuardFil T2a host-side live OpenAI broker")
    parser.add_argument(
        "--experiment-root",
        default=str(DEFAULT_EXPERIMENT_ROOT),
        help="Path to experiment root directory",
    )
    parser.add_argument(
        "--initialize-ledger",
        action="store_true",
        help="Initialize ledger if missing",
    )
    parser.add_argument(
        "--key-file",
        default=str(DEFAULT_KEY_FILE),
        help="Path to OpenAI API key file",
    )
    parser.add_argument(
        "--sockdir",
        required=True,
        help="Directory where broker.sock will be created (0700)",
    )
    parser.add_argument(
        "--case-label",
        required=True,
        help="Case label for request_id (live-<case-label>-<n>) and evidence JSONL",
    )
    parser.add_argument(
        "--max-requests",
        type=int,
        default=DEFAULT_MAX_REQUESTS,
        help="Maximum requests allowed in this broker process (default 3)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    broker = LiveBrokerServer(
        experiment_root=args.experiment_root,
        key_file=args.key_file,
        sockdir=args.sockdir,
        case_label=args.case_label,
        max_requests=args.max_requests,
        initialize_ledger=args.initialize_ledger,
    )

    def _sig_handler(_signum: int, _frame: Any) -> None:
        broker.request_stop()

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    try:
        broker.start()
        return broker.serve_forever()
    except Exception as exc:
        print(f"Broker startup/runtime error: {exc}", file=sys.stderr)
        return 1
    finally:
        broker.close()


if __name__ == "__main__":
    sys.exit(main())
