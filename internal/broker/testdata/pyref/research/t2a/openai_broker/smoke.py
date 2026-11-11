"""GuardFil T2a host-only live smoke broker.

Provides a minimal host-only broker slice against the durable T2a ledger
for a single OpenAI request. Enforces strict parameters, cryptographic digest,
single-attempt TLS transport, rigid JSON validation, conservative ledger accounting,
and durable evidence logging.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import sys
from typing import Any, Callable, Mapping, Optional, Tuple

try:
    from research.t2a.openai_budget import (
        BudgetLedger,
        Receipt,
        PINNED_MODEL,
        PINNED_SERVICE_TIER,
        DEFAULT_EXPERIMENT_ID,
        SettlementCommittedHandleDisabledOutcome,
        SettlementResult,
        FailureResult,
        MAX_INPUT_TOKENS,
    )
except ImportError:
    from ..openai_budget import (
        BudgetLedger,
        Receipt,
        PINNED_MODEL,
        PINNED_SERVICE_TIER,
        DEFAULT_EXPERIMENT_ID,
        SettlementCommittedHandleDisabledOutcome,
        SettlementResult,
        FailureResult,
        MAX_INPUT_TOKENS,
    )

DEFAULT_EXPERIMENT_ROOT = Path("~/.local/state/guardfil/t2a-experiment").expanduser()
DEFAULT_KEY_FILE = Path("~/.config/guardfil/credentials.d/openai-api-key").expanduser()
DEFAULT_REQUEST_ID = "host-smoke-1"

MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MiB limit
MAX_CHECK_BYTES = 64 * 1024  # 64 KiB limit for model check
SMOKE_MAX_OUTPUT_TOKENS = 64  # headroom so a short reply is never cut to "incomplete" (which would halt the ledger)


def _now_utc_str() -> str:
    """Return ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def build_request_body() -> tuple[dict, bytes, str]:
    """Build the exact pinned request body, outbound bytes, and SHA-256 digest."""
    obj = {
        "input": "Reply with exactly the word: ok",
        "max_output_tokens": SMOKE_MAX_OUTPUT_TOKENS,
        "model": PINNED_MODEL,
        "reasoning": {"effort": "none"},
        "service_tier": PINNED_SERVICE_TIER,
        "store": False,
        "stream": False,
    }
    raw_bytes = json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8")
    digest = hashlib.sha256(raw_bytes).hexdigest().lower()
    return obj, raw_bytes, digest


def strict_json_loads(data: str | bytes) -> dict:
    """Parse JSON strictly: reject duplicate keys, nonfinites, and require top-level object."""
    if isinstance(data, (bytes, bytearray)):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid UTF-8 encoding in JSON: {e}") from e
    elif not isinstance(data, str):
        raise TypeError(f"JSON input must be str or bytes, got {type(data).__name__}")

    def _pairs_hook(pairs):
        seen = set()
        res = {}
        for k, v in pairs:
            if k in seen:
                raise ValueError(f"Duplicate key detected in JSON: {k!r}")
            seen.add(k)
            res[k] = v
        return res

    def _reject_constant(c):
        raise ValueError(f"Forbidden nonfinite numeric constant in JSON: {c!r}")

    try:
        val = json.loads(
            data,
            object_pairs_hook=_pairs_hook,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as e:
        raise ValueError(f"Corrupt or non-standard JSON: {e}") from e
    except RecursionError:
        raise ValueError("JSON nesting exceeds supported depth") from None

    if not isinstance(val, dict):
        raise ValueError(f"Top-level JSON value must be an object, got {type(val).__name__}")
    return val


def load_key(key_file: str | Path) -> str:
    """Load and validate OpenAI API key from credentials file.

    Opened with O_NOFOLLOW; fstat must be regular file, owner == getuid(),
    mode exactly 0600, size 1..4096. Strip one trailing newline/whitespace;
    reject anything containing whitespace/control chars.
    Never log, print, persist, or include the key in exceptions.
    """
    path_str = os.path.abspath(os.fspath(key_file))
    if os.path.islink(path_str):
        raise ValueError("Key file must not be a symlink")

    try:
        fd = os.open(path_str, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as err:
        if err.errno == errno.ELOOP:
            raise ValueError("Key file must not be a symlink") from None
        raise ValueError("Failed to open key file") from None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Key file must be a regular file")
        if st.st_uid != os.getuid():
            raise ValueError("Key file owner does not match current user")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("Key file mode must be exactly 0600")
        if not (1 <= st.st_size <= 4096):
            raise ValueError("Key file size must be between 1 and 4096 bytes")

        raw_bytes = os.read(fd, 4097)
        if len(raw_bytes) != st.st_size or len(raw_bytes) > 4096:
            raise ValueError("Key file size changed during read or exceeded bounds")

        try:
            key_str = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Key file content must be valid UTF-8") from None

        # Strip one trailing newline/whitespace
        if key_str.endswith("\r\n"):
            key_str = key_str[:-2]
        elif key_str and key_str[-1] in ("\n", "\r", " ", "\t"):
            key_str = key_str[:-1]

        if not key_str:
            raise ValueError("Key file is empty")

        for ch in key_str:
            code = ord(ch)
            if code < 33 or code > 126 or ch.isspace():
                raise ValueError("Key file contains whitespace or control characters")

        return key_str
    finally:
        os.close(fd)


class KeyCheckResult:
    """Result of free key validation against the models endpoint."""

    def __init__(self, ok: bool, status_code: int, error_message: str = ""):
        self.ok = ok
        self.status_code = status_code
        self.error_message = error_message

    def __bool__(self) -> bool:
        return self.ok

    def __int__(self) -> int:
        return self.status_code

    def __iter__(self):
        return iter((self.ok, self.status_code))

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.ok == other
        if isinstance(other, int):
            return self.status_code == other
        return False

    def __repr__(self) -> str:
        return f"KeyCheckResult(ok={self.ok}, status_code={self.status_code})"


def default_https_get_transport(key: str) -> tuple[int, Mapping[str, str], bytes]:
    """Default HTTPS GET transport to OpenAI models endpoint."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection("api.openai.com", 443, timeout=30, context=ctx)
    try:
        conn.request(
            "GET",
            f"/v1/models/{PINNED_MODEL}",
            headers={
                "Authorization": f"Bearer {key}",
                "Accept": "application/json",
            },
        )
        resp = conn.getresponse()
        raw_body = resp.read(MAX_CHECK_BYTES + 1)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, raw_body
    finally:
        conn.close()


def check_key(key: str, transport: Optional[Callable] = None) -> KeyCheckResult:
    """Perform free key check: ONE GET to /v1/models/gpt-6-luna.

    Requires HTTP 200 with JSON id == 'gpt-6-luna'. No ledger interaction.
    """
    if transport is None:
        transport = default_https_get_transport

    try:
        try:
            status, headers, raw_body = transport(key)
        except TypeError:
            status, headers, raw_body = transport(b"", key)
    except Exception as e:
        return KeyCheckResult(ok=False, status_code=0, error_message=f"Transport error: {e}")

    if status != 200:
        return KeyCheckResult(ok=False, status_code=status, error_message=f"HTTP {status}")

    if len(raw_body) > MAX_CHECK_BYTES:
        return KeyCheckResult(ok=False, status_code=status, error_message="Response size exceeds 64 KiB limit")

    for k, v in headers.items():
        if k.lower() == "content-encoding" and v.strip().lower() not in ("", "identity"):
            return KeyCheckResult(ok=False, status_code=status, error_message="Unsupported content-encoding")

    try:
        obj = strict_json_loads(raw_body)
    except Exception as e:
        return KeyCheckResult(ok=False, status_code=status, error_message=f"JSON parse error: {e}")

    if not isinstance(obj, dict) or obj.get("id") != PINNED_MODEL:
        return KeyCheckResult(ok=False, status_code=status, error_message="Model id mismatch")

    return KeyCheckResult(ok=True, status_code=200)


def open_or_init_ledger(
    experiment_root: str | Path,
    initialize: bool = False,
    experiment_id: str = DEFAULT_EXPERIMENT_ID,
) -> BudgetLedger:
    """Open or initialize the budget ledger anchored to experiment_root."""
    root_path = Path(experiment_root).expanduser().resolve()
    if not root_path.exists():
        root_path.mkdir(mode=0o700, parents=True, exist_ok=True)

    ledger_path = root_path / "ledger"
    if initialize and not ledger_path.exists():
        return BudgetLedger.initialize(ledger_path, experiment_id=experiment_id)
    else:
        return BudgetLedger.open(ledger_path)


def default_https_post_transport(body_bytes: bytes, key: str) -> tuple[int, Mapping[str, str], bytes]:
    """Default HTTPS POST transport to OpenAI responses endpoint."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection("api.openai.com", 443, timeout=60, context=ctx)
    try:
        conn.request(
            "POST",
            "/v1/responses",
            body=body_bytes,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Content-Length": str(len(body_bytes)),
            },
        )
        resp = conn.getresponse()
        raw_body = resp.read(MAX_RESPONSE_BYTES + 1)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, raw_body
    finally:
        conn.close()


def extract_output_text_length(resp_obj: Any) -> int:
    """Compute the character length of output text without exposing or returning the text."""
    if not isinstance(resp_obj, dict):
        return 0
    if isinstance(resp_obj.get("output_text"), str):
        return len(resp_obj["output_text"])
    total_len = 0
    output = resp_obj.get("output")
    if isinstance(output, list):
        for item in output:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    total_len += len(item["text"])
                content = item.get("content")
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            total_len += len(part["text"])
                        elif isinstance(part, str):
                            total_len += len(part)
                elif isinstance(content, str):
                    total_len += len(content)
            elif isinstance(item, str):
                total_len += len(item)
    return total_len


def write_evidence(root: str | Path, name: str, data: Mapping[str, Any]) -> Path:
    """Write evidence JSON atomically with mode 0600, O_EXCL, and fsync of file + directory."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        root_path.mkdir(mode=0o700, parents=True, exist_ok=True)

    json_bytes = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    target_path = root_path / name

    dir_fd = os.open(str(root_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            total_written = 0
            while total_written < len(json_bytes):
                n = os.write(file_fd, json_bytes[total_written:])
                if n <= 0:
                    raise OSError("Failed to write evidence bytes")
                total_written += n
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

    return target_path


def _ledger_status_dict(status: Any) -> dict:
    """Extract standard ledger status fields for reporting and evidence."""
    return {
        "experiment_id": status.experiment_id,
        "global_ceiling_micros": status.global_ceiling_micros,
        "committed_spend_micros": status.committed_spend_micros,
        "retained_failed_micros": status.retained_failed_micros,
        "total_spend_micros": status.total_spend_micros,
        "pending_reserved_micros": status.pending_reserved_micros,
        "total_encumbered_micros": status.total_encumbered_micros,
        "remaining_available_micros": status.remaining_available_micros,
        "remaining_budget_micros": status.remaining_budget_micros,
        "total_reservations_count": status.total_reservations_count,
        "settled_requests_count": status.settled_requests_count,
        "has_pending_reservation": status.has_pending_reservation,
        "pending_request_id": status.pending_request_id,
        "halted": status.halted,
        "halt_reason": status.halt_reason,
        "handle_disabled": status.handle_disabled,
        "handle_disabled_reason": status.handle_disabled_reason,
        "can_reserve": status.can_reserve,
    }


def _validate_identifier_local(val: Any) -> bool:
    """Validate identifier string matching ledger rules."""
    if type(val) is not str or not val.strip():
        return False
    s = val.strip()
    if s != val or len(s) > 128:
        return False
    for c in s:
        code = ord(c)
        if code < 33 or code > 126:
            return False
    return True


def run_smoke(
    experiment_root: str | Path = DEFAULT_EXPERIMENT_ROOT,
    key_file: str | Path = DEFAULT_KEY_FILE,
    request_id: str = DEFAULT_REQUEST_ID,
    live: bool = False,
    confirm_spend: Optional[str] = None,
    initialize_ledger: bool = False,
    post_transport: Optional[Callable[[bytes, str], tuple[int, Mapping[str, str], bytes]]] = None,
    get_transport: Optional[Callable] = None,
    check_key_only: bool = False,
) -> tuple[int, dict]:
    """Execute smoke test flow following exact mandatory ordering."""
    if check_key_only:
        try:
            key = load_key(key_file)
            res = check_key(key, transport=get_transport)
            print(res.status_code)
            return (0 if res.ok else 1), {"status_code": res.status_code, "ok": res.ok}
        except Exception as err:
            print("0")
            return 1, {"status_code": 0, "ok": False, "error": str(err)}

    # Validate request_id
    if not _validate_identifier_local(request_id):
        print(f"Error: Invalid request_id: {request_id!r}", file=sys.stderr)
        return 1, {"error": "INVALID_REQUEST_ID"}

    # 1. Build body + digest
    body_obj, body_bytes, request_digest = build_request_body()

    # Open/initialize ledger
    try:
        ledger = open_or_init_ledger(experiment_root, initialize=initialize_ledger)
    except Exception as err:
        print(f"Error opening or initializing ledger: {err}", file=sys.stderr)
        return 1, {"error": "LEDGER_OPEN_FAILED"}

    try:
        status = ledger.get_status()
    except Exception as err:
        print(f"Error checking ledger status: {err}", file=sys.stderr)
        ledger.close()
        return 1, {"error": "LEDGER_STATUS_ERROR"}

    if not status.can_reserve:
        print(
            f"Refusal: Ledger cannot reserve (halted={status.halted}, "
            f"can_reserve={status.can_reserve}, pending={status.has_pending_reservation})",
            file=sys.stderr,
        )
        ledger.close()
        return 1, {"error": "CANNOT_RESERVE", "ledger_status": _ledger_status_dict(status)}

    dry_run_summary = {
        "dry_run": not live,
        "request_id": request_id,
        "request_digest": request_digest,
        "request_body_bytes_len": len(body_bytes),
        "can_reserve": status.can_reserve,
        "remaining_budget_micros": status.remaining_budget_micros,
        "total_reservations_count": status.total_reservations_count,
        "halted": status.halted,
        "model": PINNED_MODEL,
        "service_tier": PINNED_SERVICE_TIER,
    }

    if not live:
        print(json.dumps(dry_run_summary, indent=2, sort_keys=True))
        ledger.close()
        return 0, dry_run_summary

    # --live requires --confirm-spend matching request_id
    if confirm_spend != request_id:
        print("Error: --live requires --confirm-spend matching request_id", file=sys.stderr)
        ledger.close()
        return 1, {"error": "CONFIRM_SPEND_MISMATCH"}

    # 2. Load + validate key file (after status check, before reserve)
    try:
        key = load_key(key_file)
    except Exception as err:
        print(f"Error loading key: {err}", file=sys.stderr)
        ledger.close()
        return 1, {"error": "KEY_LOAD_FAILED"}

    # ADDENDUM: Free key check before reservation
    key_check_res = check_key(key, transport=get_transport)
    if not key_check_res.ok:
        print(
            f"Error: Pre-reserve key check failed (status {key_check_res.status_code}): {key_check_res.error_message}",
            file=sys.stderr,
        )
        ledger.close()
        return 1, {"error": "KEY_CHECK_FAILED", "status_code": key_check_res.status_code}

    # 3. Reserve permit
    try:
        permit = ledger.reserve(request_id, request_digest)
    except Exception as err:
        print(f"Error reserving ledger permit: {err}", file=sys.stderr)
        ledger.close()
        return 1, {"error": "RESERVE_FAILED"}

    # 4. Exactly ONE POST to /v1/responses
    start_utc = _now_utc_str()
    if post_transport is None:
        post_transport = default_https_post_transport

    transport_error = None
    http_status = None
    headers: Mapping[str, str] = {}
    raw_body = b""
    try:
        http_status, headers, raw_body = post_transport(body_bytes, key)
    except Exception as err:
        transport_error = err

    # Handle transport failure
    if transport_error is not None:
        try:
            ledger.record_failure(permit, "REQUEST_TRANSPORT_FAILURE")
        except Exception:
            pass
        status_after = ledger.get_status()
        end_utc = _now_utc_str()
        evidence = {
            "request_id": request_id,
            "request_digest": request_digest,
            "http_status": None,
            "response_id": None,
            "model": None,
            "service_tier": None,
            "usage": None,
            "response_body_sha256": None,
            "output_text_length": 0,
            "ledger_status": _ledger_status_dict(status_after),
            "timestamps": {"started_at_utc": start_utc, "completed_at_utc": end_utc},
            "outcome_code": "REQUEST_TRANSPORT_FAILURE",
        }
        write_evidence(experiment_root, f"host-smoke-{request_id}.json", evidence)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        ledger.close()
        return 1, evidence

    # 5. Read at most 1 MiB (+1 byte overflow detection), check Content-Encoding, parse strict JSON
    is_valid = True
    validation_reason = None
    resp_obj = None

    if len(raw_body) > MAX_RESPONSE_BYTES:
        is_valid = False
        validation_reason = "Response size exceeds 1 MiB limit"

    if is_valid:
        for k, v in headers.items():
            if k.lower() == "content-encoding" and v.strip().lower() not in ("", "identity"):
                is_valid = False
                validation_reason = f"Unsupported content-encoding: {v}"
                break

    if is_valid:
        try:
            resp_obj = strict_json_loads(raw_body)
        except Exception as e:
            is_valid = False
            validation_reason = f"JSON parse error: {e}"

    # 6. Validate response fields
    if is_valid:
        if http_status != 200:
            is_valid = False
            validation_reason = f"Expected HTTP 200, got {http_status}"
        elif not isinstance(resp_obj, dict):
            is_valid = False
            validation_reason = "Top-level JSON must be an object"
        elif resp_obj.get("object") != "response":
            is_valid = False
            validation_reason = f"Expected object=='response', got {resp_obj.get('object')!r}"
        elif resp_obj.get("status") != "completed":
            is_valid = False
            validation_reason = f"Expected status=='completed', got {resp_obj.get('status')!r}"
        elif resp_obj.get("error") is not None:
            is_valid = False
            validation_reason = "error field is present and not null"
        elif resp_obj.get("incomplete_details") is not None:
            is_valid = False
            validation_reason = "incomplete_details field is present and not null"

    resp_id = None
    if is_valid:
        resp_id = resp_obj.get("id")
        if not _validate_identifier_local(resp_id):
            is_valid = False
            validation_reason = f"Invalid response id: {resp_id!r}"

    model_val = None
    tier_val = None
    if is_valid:
        model_val = resp_obj.get("model")
        tier_val = resp_obj.get("service_tier")
        if model_val != PINNED_MODEL:
            is_valid = False
            validation_reason = f"Model mismatch: expected {PINNED_MODEL}, got {model_val!r}"
        elif tier_val != PINNED_SERVICE_TIER:
            is_valid = False
            validation_reason = f"Service tier mismatch: expected {PINNED_SERVICE_TIER}, got {tier_val!r}"

    in_tok = None
    out_tok = None
    tot_tok = None
    if is_valid:
        usage = resp_obj.get("usage")
        if not isinstance(usage, dict):
            is_valid = False
            validation_reason = "Missing or non-object usage"
        else:
            in_tok = usage.get("input_tokens")
            out_tok = usage.get("output_tokens")
            tot_tok = usage.get("total_tokens")

            for name, val in [("input_tokens", in_tok), ("output_tokens", out_tok), ("total_tokens", tot_tok)]:
                if type(val) is not int or isinstance(val, bool):
                    is_valid = False
                    validation_reason = f"{name} must be a strict integer, got {type(val).__name__}"
                    break
                if val < 0:
                    is_valid = False
                    validation_reason = f"{name} must be >= 0, got {val}"
                    break

            if is_valid:
                if out_tok > SMOKE_MAX_OUTPUT_TOKENS:
                    is_valid = False
                    validation_reason = f"output_tokens ({out_tok}) exceeds {SMOKE_MAX_OUTPUT_TOKENS}"
                elif in_tok > MAX_INPUT_TOKENS:
                    is_valid = False
                    validation_reason = f"input_tokens ({in_tok}) exceeds max {MAX_INPUT_TOKENS}"
                elif tot_tok != in_tok + out_tok:
                    is_valid = False
                    validation_reason = (
                        f"total_tokens ({tot_tok}) != input_tokens ({in_tok}) + output_tokens ({out_tok})"
                    )

    # 7. Settlement or failure recording
    resp_sha256 = hashlib.sha256(raw_body).hexdigest().lower() if raw_body else None
    output_len = extract_output_text_length(resp_obj)

    if not is_valid:
        try:
            ledger.record_failure(permit, "INVALID_RECEIPT_EVIDENCE")
        except Exception:
            pass
        status_after = ledger.get_status()
        end_utc = _now_utc_str()
        evidence = {
            "request_id": request_id,
            "request_digest": request_digest,
            "http_status": http_status,
            "response_id": resp_id if isinstance(resp_id, str) else None,
            "model": model_val if isinstance(model_val, str) else None,
            "service_tier": tier_val if isinstance(tier_val, str) else None,
            "usage": None,
            "response_body_sha256": resp_sha256,
            "output_text_length": output_len,
            "ledger_status": _ledger_status_dict(status_after),
            "timestamps": {"started_at_utc": start_utc, "completed_at_utc": end_utc},
            "outcome_code": "INVALID_RECEIPT_EVIDENCE",
        }
        write_evidence(experiment_root, f"host-smoke-{request_id}.json", evidence)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        ledger.close()
        return 1, evidence

    # Valid -> build Receipt and settle
    receipt = Receipt(
        status="completed",
        response_id=resp_id,
        request_id=request_id,
        request_digest=request_digest,
        model=model_val,
        service_tier=tier_val,
        input_tokens=in_tok,
        output_tokens=out_tok,
        total_tokens=tot_tok,
    )

    try:
        outcome = ledger.settle(permit, receipt)
    except Exception:
        status_after = ledger.get_status()
        end_utc = _now_utc_str()
        evidence = {
            "request_id": request_id,
            "request_digest": request_digest,
            "http_status": http_status,
            "response_id": resp_id,
            "model": model_val,
            "service_tier": tier_val,
            "usage": {"input_tokens": in_tok, "output_tokens": out_tok, "total_tokens": tot_tok},
            "response_body_sha256": resp_sha256,
            "output_text_length": output_len,
            "ledger_status": _ledger_status_dict(status_after),
            "timestamps": {"started_at_utc": start_utc, "completed_at_utc": end_utc},
            "outcome_code": "INVALID_RECEIPT_EVIDENCE",
        }
        write_evidence(experiment_root, f"host-smoke-{request_id}.json", evidence)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        ledger.close()
        return 1, evidence

    status_after = ledger.get_status()
    end_utc = _now_utc_str()

    if isinstance(outcome, SettlementCommittedHandleDisabledOutcome):
        outcome_code = "SETTLEMENT_COMMITTED_HANDLE_DISABLED"
        exit_code = 1
    else:
        outcome_code = "SUCCESS"
        exit_code = 0

    evidence = {
        "request_id": request_id,
        "request_digest": request_digest,
        "http_status": http_status,
        "response_id": resp_id,
        "model": model_val,
        "service_tier": tier_val,
        "usage": {"input_tokens": in_tok, "output_tokens": out_tok, "total_tokens": tot_tok},
        "response_body_sha256": resp_sha256,
        "output_text_length": output_len,
        "ledger_status": _ledger_status_dict(status_after),
        "timestamps": {"started_at_utc": start_utc, "completed_at_utc": end_utc},
        "outcome_code": outcome_code,
    }
    write_evidence(experiment_root, f"host-smoke-{request_id}.json", evidence)
    print(json.dumps(evidence, indent=2, sort_keys=True))
    ledger.close()
    return exit_code, evidence


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GuardFil T2a host-only live smoke broker")
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
        help="Path to OpenAI API key credentials file",
    )
    parser.add_argument(
        "--request-id",
        default=DEFAULT_REQUEST_ID,
        help="Request identifier",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live request (requires --confirm-spend matching request-id)",
    )
    parser.add_argument(
        "--confirm-spend",
        default=None,
        help="Confirm spend authorization matching request_id",
    )
    parser.add_argument(
        "--check-key",
        action="store_true",
        help="Run free key check only and exit",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    exit_code, _ = run_smoke(
        experiment_root=args.experiment_root,
        key_file=args.key_file,
        request_id=args.request_id,
        live=args.live,
        confirm_spend=args.confirm_spend,
        initialize_ledger=args.initialize_ledger,
        check_key_only=args.check_key,
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
