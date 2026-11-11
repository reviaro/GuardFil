"""Durable budget ledger for GuardFil T2a Stage B OpenAI research forwarder.

Enforces the numeric cost contract specified in research/t2a/codex-issue.md:
- Global ceiling: 2,000,000 integer microUSD ($2.00 USD).
- Reservation per forwarded request: 1,100,000 integer microUSD ($1.10 USD).
- Maximum 8 total forwarded requests throughout the experiment.
- Strictly at most 1 request in flight at any time.
- Accounting rate: 1 microUSD per input token, 1 microUSD per output token ($1 / 1M).
- Token bounds: input <= 1,050,000; output <= 1,024.
- Model pinned to 'gpt-6-luna'; service tier pinned to 'default'.
- Failed, missing, invalid, or ambiguous settlement retains the full 1,100,000 microUSD
  reservation and permanently halts the ledger. No automatic retry or reset.
- State after restart with an unsettled pending reservation retains the full reserve and halts.
- Durable process synchronization via fcntl file locking, atomic tempfile write,
  fsync of file descriptor, atomic rename/replace, and directory fsync.
- Anchored to verified directory descriptors with descriptor-relative operations (dir_fd),
  O_NOFOLLOW, and strict fstat inode continuity checks through publication return.
- Refuses missing or replaced runtime lock files and detects lease file replacement.
- Closed bounded schemas with duplicate key rejection and deep typed journal replay.
- Normalized receipt contract with replay protection, unique response_ids, and centralized terminal failure revocation.
- Durable settlement intent logging to prevent unresolved publications from ever resuming optimistically.

TRUST DEPENDENCY NOTE:
This ledger provides an offline conservative accounting component enforcing numeric limits,
model strings, tier strings, token bounds, and durable state transitions. It does NOT independently
verify cryptographic TLS certificates or provider authenticity; actual TLS and provider terminal
evidence MUST be verified by a separately reviewed transport broker before settlement.
Settlement values are a conservative token-based accounting bound, NOT an actual
provider billing guarantee. The ledger directory must be kept outside the experimental runtime.
No authenticated=true escape hatch exists.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any, Generator, Mapping, Optional, Tuple
import uuid

from .constants import (
    ALLOWED_INTERNAL_FAILURE_CODES,
    CONFIRMATION_FILE_PREFIX,
    DEFAULT_EXPERIMENT_ID,
    EXPECTED_CONFIRMATION_KEYS,
    EXPECTED_INSPECTION_COMPLETION_KEYS,
    EXPECTED_INSPECTION_GUARD_KEYS,
    EXPECTED_INTENT_KEYS,
    EXPECTED_JOURNAL_FAILED_RETAINED_KEYS,
    EXPECTED_JOURNAL_INITIALIZED_KEYS,
    EXPECTED_JOURNAL_ORPHANED_KEYS,
    EXPECTED_JOURNAL_RESERVED_KEYS,
    EXPECTED_JOURNAL_SETTLED_KEYS,
    EXPECTED_JOURNAL_TERMINAL_UNCERTAINTY_KEYS,
    EXPECTED_PENDING_KEYS,
    EXPECTED_RECEIPT_KEYS,
    EXPECTED_STATE_KEYS,
    GLOBAL_CEILING_MICROS,
    INPUT_TOKEN_RATE_MICROS,
    INSPECTION_COMPLETION_FILENAME,
    INSPECTION_GUARD_FILENAME,
    INTENT_FILENAME,
    INTENT_FILE_PREFIX,
    LEASE_FILENAME,
    LOCK_FILENAME,
    MAX_DIGEST_LENGTH,
    MAX_FORWARDED_REQUESTS,
    MAX_IDENTIFIER_LENGTH,
    MAX_INPUT_TOKENS,
    MAX_INSPECTION_GENERATION,
    MAX_JOURNAL_ENTRIES,
    MAX_OUTPUT_TOKENS,
    MAX_REASON_LENGTH,
    MAX_STATE_FILE_BYTES,
    MAX_TIMESTAMP_LENGTH,
    OUTPUT_TOKEN_RATE_MICROS,
    PINNED_MODEL,
    PINNED_SERVICE_TIER,
    MODEL_RATES,
    model_cost_micros,
    RECORD_TYPE_INSPECTION_COMPLETION,
    RECORD_TYPE_INSPECTION_GUARD,
    RESERVATION_AMOUNT_MICROS,
    MIN_RESERVATION_MICROS,
    SCHEMA_VERSION,
    STATE_FILENAME,
    TERMINAL_STATUS_COMPLETED,
    TERMINAL_UNCERTAINTY_REASONS,
    VALID_JOURNAL_ENTRY_TYPES,
)
from .readonly_io import (
    IoFailure,
    OwnedFds,
    cleanup_after_failure,
    final_entry_checks,
    open_ledger_and_lock,
    unlock as _unlock_readonly,
    validate_dir as _validate_dir_readonly,
)
from .exceptions import (
    BudgetExceededError,
    InFlightReservationError,
    LedgerAlreadyExistsError,
    LedgerBindingError,
    LedgerCorruptError,
    LedgerHaltedError,
    LedgerNotFoundError,
    LedgerSecurityError,
    NoPendingReservationError,
    PermitMismatchError,
    ReservationLimitExceededError,
    SettlementCommittedHandleDisabledError,
    SettlementEvidenceError,
)
from .models import (
    FailureResult,
    LedgerBinding,
    LedgerStatus,
    Receipt,
    ReservationPermit,
    SettlementCommittedHandleDisabledOutcome,
    SettlementResult,
)


class _GuardUnfinishedError(LedgerHaltedError):
    """Internal: the inspection guard has no matching complete witness."""


def _now_utc_str() -> str:
    """Return ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def _safe_json_loads(data: str) -> dict:
    """Parse JSON enforcing uniqueness of object keys and rejecting nonfinites (NaN, Infinity)."""
    def _pairs_hook(pairs):
        seen = set()
        res = {}
        for k, v in pairs:
            if k in seen:
                raise LedgerCorruptError(f"Duplicate key detected in JSON: {k!r}")
            seen.add(k)
            res[k] = v
        return res

    def _reject_constant(c):
        raise LedgerCorruptError(f"Forbidden nonfinite numeric constant in JSON: {c!r}")

    try:
        val = json.loads(
            data,
            object_pairs_hook=_pairs_hook,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as e:
        raise LedgerCorruptError(f"Corrupt or non-standard JSON: {e}") from e
    except RecursionError:
        raise LedgerCorruptError("JSON nesting exceeds the supported depth") from None

    if not isinstance(val, dict):
        raise LedgerCorruptError(f"Top-level JSON value must be an object, got {type(val).__name__}")
    return val


def _validate_identifier(val: Any, field_name: str) -> str:
    """Validate a non-empty printable ASCII identifier within length bounds."""
    if type(val) is not str or not val.strip():
        raise LedgerCorruptError(f"{field_name} must be a non-empty string")
    s = val.strip()
    if len(s) > MAX_IDENTIFIER_LENGTH:
        raise LedgerCorruptError(f"{field_name} length ({len(s)}) exceeds limit of {MAX_IDENTIFIER_LENGTH}")
    for c in s:
        code = ord(c)
        if code < 33 or code > 126:
            raise LedgerCorruptError(f"{field_name} contains invalid character: {c!r}")
    return s


def _validate_digest(val: Any) -> str:
    """Validate request digest within length bounds."""
    if type(val) is not str or not val.strip():
        raise LedgerCorruptError("request_digest must be a non-empty string")
    s = val.strip()
    if len(s) > MAX_DIGEST_LENGTH:
        raise LedgerCorruptError(f"request_digest length ({len(s)}) exceeds limit of {MAX_DIGEST_LENGTH}")
    for c in s:
        code = ord(c)
        if code < 33 or code > 126:
            raise LedgerCorruptError(f"request_digest contains invalid character: {c!r}")
    return s


def _validate_timestamp(val: Any) -> str:
    """Validate timestamp string within length bounds and valid ISO-8601 UTC format."""
    if type(val) is not str or not val.strip():
        raise LedgerCorruptError("timestamp must be a non-empty string")
    s = val
    if s != s.strip():
        raise LedgerCorruptError("timestamp must not carry surrounding whitespace")
    if len(s) > MAX_TIMESTAMP_LENGTH:
        raise LedgerCorruptError(f"timestamp length exceeds limit of {MAX_TIMESTAMP_LENGTH}")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
    except Exception as err:
        raise LedgerCorruptError(f"Invalid ISO-8601 UTC timestamp {val!r}: {err}") from err
    return s


def _validate_int(val: Any, field_name: str, min_val: int = 0, max_val: Optional[int] = None) -> int:
    """Validate integer values strictly rejecting booleans."""
    if type(val) is not int or isinstance(val, bool):
        raise LedgerCorruptError(f"{field_name} must be an integer (not boolean), got {type(val).__name__}")
    if val < min_val:
        raise LedgerCorruptError(f"{field_name} must be >= {min_val}, got {val}")
    if max_val is not None and val > max_val:
        raise LedgerCorruptError(f"{field_name} must be <= {max_val}, got {val}")
    return val


def _sanitize_reason(reason: Any) -> str:
    """Validate failure reason strictly against ALLOWED_INTERNAL_FAILURE_CODES.

    Rejection diagnostics are FIXED bounded text: the rejected caller/provider value
    is never echoed or chained into the raised exception.
    """
    if (
        type(reason) is str
        and reason in ALLOWED_INTERNAL_FAILURE_CODES
        and len(reason) <= MAX_REASON_LENGTH
    ):
        return reason
    raise SettlementEvidenceError(
        "Failure reason rejected: it is not a member of ALLOWED_INTERNAL_FAILURE_CODES"
    ) from None


def _replay_reason(reason: Any) -> str:
    """Replay-side closed failure-code check (corruption, not evidence error)."""
    if type(reason) is not str or reason not in ALLOWED_INTERNAL_FAILURE_CODES:
        raise LedgerCorruptError("Journal reason is not a member of ALLOWED_INTERNAL_FAILURE_CODES")
    return reason


class BudgetLedger:
    """Durable budget ledger enforcing the Stage B numeric cost contract."""

    def __init__(
        self,
        ledger_dir: str | Path,
        experiment_id: str = DEFAULT_EXPERIMENT_ID,
        dir_dev_ino: Optional[Tuple[int, int]] = None,
        lock_dev_ino: Optional[Tuple[int, int]] = None,
        handle_disabled: bool = False,
        handle_disabled_reason: Optional[str] = None,
    ) -> None:
        """Internal constructor. Callers must use initialize() or open()."""
        self._ledger_dir = os.path.abspath(os.fspath(ledger_dir))
        self._experiment_id = experiment_id
        self._dir_dev_ino: Optional[Tuple[int, int]] = dir_dev_ino
        self._lock_dev_ino: Optional[Tuple[int, int]] = lock_dev_ino
        self._held_lease_fd: Optional[int] = None
        self._held_lease_dev_ino: Optional[Tuple[int, int]] = None
        self._poisoned: bool = handle_disabled
        self._poison_reason: Optional[str] = handle_disabled_reason
        self._handle_disabled: bool = handle_disabled
        self._handle_disabled_reason: Optional[str] = handle_disabled_reason
        self._handle_lock = threading.RLock()

    def close(self) -> None:
        """Explicitly release all held locks and close open descriptors.

        Serializes lifetime against concurrent operations on this handle.
        Subsequent operations on a closed handle raise LedgerHaltedError.
        """
        with self._handle_lock:
            self._release_lease()
            self._poison_handle("HANDLE_CLOSED")

    @property
    def is_handle_disabled(self) -> bool:
        """Return whether this specific handle instance has been disabled/poisoned."""
        return self._poisoned or self._handle_disabled

    @property
    def is_experiment_halted(self) -> bool:
        """Return whether the shared experiment on disk is permanently halted."""
        return self.get_status().halted

    def __enter__(self) -> "BudgetLedger":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Lifecycle Management: Initialize and Open
    # -------------------------------------------------------------------------

    @classmethod
    def initialize(
        cls,
        ledger_dir: str | Path,
        experiment_id: str = DEFAULT_EXPERIMENT_ID,
    ) -> "BudgetLedger":
        """Initialize a new budget ledger in a strictly fresh, non-existent directory.

        Fails with LedgerAlreadyExistsError if the directory or any state file exists.
        Anchors directory and lock descriptors to prevent directory swapping.
        """
        ledger_dir_str = os.path.abspath(os.fspath(ledger_dir))

        if os.path.exists(ledger_dir_str) or os.path.islink(ledger_dir_str):
            raise LedgerAlreadyExistsError(
                f"Ledger directory already exists: {ledger_dir_str}; initialize() requires a fresh, non-existent target"
            )

        try:
            os.mkdir(ledger_dir_str, 0o700)
        except FileExistsError:
            raise LedgerAlreadyExistsError(
                f"Ledger directory was concurrently created: {ledger_dir_str}"
            )
        except OSError as err:
            raise LedgerSecurityError(f"Failed to create ledger directory: {err}") from None

        try:
            dir_fd = os.open(ledger_dir_str, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as err:
            raise LedgerSecurityError(f"Failed to open ledger directory descriptor: {err}") from None

        try:
            dir_dev_ino = cls._validate_dir_descriptor_static(dir_fd)

            try:
                lock_fd = os.open(
                    LOCK_FILENAME,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=dir_fd,
                )
            except OSError as err:
                raise LedgerAlreadyExistsError(f"Lock file already exists in {ledger_dir_str}: {err}") from None

            try:
                lock_dev_ino = cls._validate_file_descriptor_static(lock_fd)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    now = _now_utc_str()
                    initial_state = {
                        "schema_version": SCHEMA_VERSION,
                        "experiment_id": experiment_id,
                        "created_at_utc": now,
                        "updated_at_utc": now,
                        "global_ceiling_micros": GLOBAL_CEILING_MICROS,
                        "reservation_amount_micros": RESERVATION_AMOUNT_MICROS,
                        "committed_spend_micros": 0,
                        "retained_failed_micros": 0,
                        "total_reservations_count": 0,
                        "settled_requests_count": 0,
                        "pending_reservation": None,
                        "halted": False,
                        "halt_reason": None,
                        "journal": [
                            {
                                "entry_type": "INITIALIZED",
                                "experiment_id": experiment_id,
                                "global_ceiling_micros": GLOBAL_CEILING_MICROS,
                                "timestamp_utc": now,
                            }
                        ],
                    }
                    cls._atomic_write_state_static(initial_state, dir_fd)

                    # Establish inspection guard and completion witness at generation 1
                    cls._write_guard_static(
                        {
                            "record_type": RECORD_TYPE_INSPECTION_GUARD,
                            "experiment_id": experiment_id,
                            "generation": 1,
                            "armed_at_utc": now,
                        },
                        dir_fd,
                    )
                    cls._write_completion_static(
                        {
                            "record_type": RECORD_TYPE_INSPECTION_COMPLETION,
                            "experiment_id": experiment_id,
                            "generation": 1,
                            "completed_at_utc": now,
                        },
                        dir_fd,
                    )
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        finally:
            os.close(dir_fd)

        return cls(
            ledger_dir_str,
            experiment_id,
            dir_dev_ino=dir_dev_ino,
            lock_dev_ino=lock_dev_ino,
        )

    @classmethod
    def open(cls, ledger_dir: str | Path) -> "BudgetLedger":
        """Open an existing budget ledger for runtime operations.

        Refuses missing directory, missing state file, or security violations.
        Anchors directory and lock descriptors, preserving them on the returned object.
        Resolves any unconfirmed settlement intent evidence or orphaned reservations conservatively.
        """
        ledger_dir_str = os.path.abspath(os.fspath(ledger_dir))

        if os.path.islink(ledger_dir_str):
            raise LedgerSecurityError(f"Ledger directory is a symlink: {ledger_dir_str}")
        if not os.path.exists(ledger_dir_str):
            raise LedgerNotFoundError(f"Ledger directory not found: {ledger_dir_str}")

        try:
            dir_fd = os.open(ledger_dir_str, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as err:
            if err.errno == errno.ELOOP:
                raise LedgerSecurityError(f"Symlink detected on ledger directory {ledger_dir_str}") from err
            raise LedgerNotFoundError(f"Cannot open ledger directory descriptor: {err}") from err

        try:
            dir_dev_ino = cls._validate_dir_descriptor_static(dir_fd)

            try:
                os.stat(STATE_FILENAME, dir_fd=dir_fd)
            except OSError as err:
                if err.errno == errno.ENOENT:
                    raise LedgerNotFoundError(f"State file missing in {ledger_dir_str}") from err
                if err.errno == errno.ELOOP:
                    raise LedgerSecurityError(f"Symlink detected on state path in {ledger_dir_str}") from err
                raise

            try:
                lock_fd = os.open(LOCK_FILENAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=dir_fd)
            except OSError as err:
                if err.errno == errno.ENOENT:
                    raise LedgerSecurityError(f"Runtime lock file missing in {ledger_dir_str}") from err
                if err.errno == errno.ELOOP:
                    raise LedgerSecurityError(f"Symlink detected on lock path in {ledger_dir_str}") from err
                raise

            try:
                lock_dev_ino = cls._validate_file_descriptor_static(lock_fd)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    st_lock_disk = os.stat(LOCK_FILENAME, dir_fd=dir_fd)
                    if (st_lock_disk.st_dev, st_lock_disk.st_ino) != lock_dev_ino:
                        raise LedgerSecurityError("Lock file identity mismatch between descriptor and directory entry")

                    experiment_id, handle_disabled, handle_disabled_reason = cls._open_under_lock(dir_fd)
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        finally:
            os.close(dir_fd)

        return cls(
            ledger_dir_str,
            experiment_id,
            dir_dev_ino=dir_dev_ino,
            lock_dev_ino=lock_dev_ino,
            handle_disabled=handle_disabled,
            handle_disabled_reason=handle_disabled_reason,
        )

    @classmethod
    def _open_under_lock(cls, dir_fd: int) -> Tuple[str, bool, Optional[str]]:
        """Guarded inspection for a fresh handle, under the transaction lock.

        Returns (experiment_id, handle_disabled, handle_disabled_reason). The guard
        (which binds the ledger identity) is read and re-armed BEFORE any
        authoritative ledger/evidence read. A fresh handle is enabled only after a
        complete inspection witness for its own generation was published.
        """
        try:
            guard = cls._read_guard_static(dir_fd, None)
            guard_error: Optional[BaseException] = None
        except (LedgerCorruptError, LedgerSecurityError) as err:
            guard = None
            guard_error = err

        if guard is None:
            # Deliberately disabled reporting path: only already-valid terminal
            # accounting is readable; it never yields authority.
            if guard_error is None:
                guard_error = LedgerCorruptError("Inspection guard missing from ledger directory")
            try:
                state = cls._read_state_static(dir_fd)
            except Exception:
                raise guard_error
            if not state["halted"]:
                raise guard_error
            return state["experiment_id"], True, "INSPECTION_GUARD_CORRUPT"

        experiment_id = guard["experiment_id"]
        try:
            gen = cls._arm_guard_static(dir_fd, experiment_id)
        except _GuardUnfinishedError:
            state = cls._read_state_static(dir_fd, expected_experiment_id=experiment_id)
            reason = state["halt_reason"] if state["halted"] else "UNFINISHED_INSPECTION_GUARD"
            return experiment_id, True, reason
        except (LedgerCorruptError, LedgerSecurityError) as arm_err:
            # Corrupt/unreadable completion (or exhausted generation): report-only for
            # already-valid terminal accounting; never authority.
            try:
                state = cls._read_state_static(dir_fd, expected_experiment_id=experiment_id)
            except Exception:
                raise arm_err
            if not state["halted"]:
                raise
            return experiment_id, True, "INSPECTION_GUARD_CORRUPT"

        state = cls._read_state_static(dir_fd, expected_experiment_id=experiment_id)
        state, uncertain = cls._validate_and_recover_records_under_lock(state, dir_fd)
        if uncertain:
            return experiment_id, True, state["halt_reason"]

        cls._complete_guard_static(dir_fd, experiment_id, gen)

        # Orphaned pending reservation from process death / restart (post-inspection mutation)
        pending = state.get("pending_reservation")
        if pending is not None and not cls._is_lease_held_static(dir_fd):
            amount = pending["reserved_amount_micros"]
            state["retained_failed_micros"] += amount
            state["pending_reservation"] = None
            state["halted"] = True
            state["halt_reason"] = "UNSETTLED_PENDING_RESERVATION_AT_STARTUP"
            state["updated_at_utc"] = _now_utc_str()
            state["journal"].append(
                {
                    "entry_type": "ORPHANED_PENDING_HALTED",
                    "reservation_id": pending["reservation_id"],
                    "request_id": pending["request_id"],
                    "retained_amount_micros": amount,
                    "reason": "UNSETTLED_PENDING_RESERVATION_AT_STARTUP",
                    "timestamp_utc": state["updated_at_utc"],
                }
            )
            cls._atomic_write_state_static(state, dir_fd)
        return experiment_id, False, None

    # -------------------------------------------------------------------------
    # Identity-only binding verification (no state inspection)
    # -------------------------------------------------------------------------

    def verify_binding(self, experiment_root_fd: int, expected_binding: LedgerBinding) -> LedgerBinding:
        """Verify this handle's ledger is the one bound by `expected_binding`; identity only.

        `experiment_root_fd` is BORROWED: never closed or owned here, and the caller
        keeps it open and unchanged. Reads no state/evidence bytes, arms no guard,
        recovers nothing, reserves/settles nothing, and proves neither health nor
        spending eligibility; every later ledger operation still performs its own
        guarded transaction. The result is never cached authorization.

        If another operation owns the handle mutex the call fails immediately with
        BINDING_BUSY (handle state unknown, nothing poisoned or released here).
        Once the mutex is held, ANY failure poisons the handle and releases its
        permit lease before the fixed error escapes. Transaction-lock contention
        is BINDING_BUSY too, but after the mutex was held so the handle is poisoned.
        """
        if (
            type(experiment_root_fd) is not int
            or experiment_root_fd < 0
            or not isinstance(expected_binding, LedgerBinding)
        ):
            raise LedgerBindingError("BINDING_INVALID") from None
        if not self._handle_lock.acquire(blocking=False):
            raise LedgerBindingError("BINDING_BUSY") from None
        try:
            if self._poisoned or self._handle_disabled:
                raise LedgerBindingError("BINDING_DISABLED") from None
            return self._verify_binding_locked(experiment_root_fd, expected_binding)
        finally:
            self._handle_lock.release()

    def _verify_binding_locked(self, root_fd: int, expected: LedgerBinding) -> LedgerBinding:
        codes = {"invalid": "BINDING_INVALID", "io": "BINDING_IO_FAILED", "busy": "BINDING_BUSY"}
        owned = OwnedFds()
        locked_fd: Optional[int] = None
        kind = "io"
        try:
            if self._dir_dev_ino is None or self._lock_dev_ino is None:
                raise IoFailure("invalid")  # unbound handle: never initialize missing identity
            if self._experiment_id != expected.experiment_id:
                raise IoFailure("invalid")
            exp_dir = (expected.directory_device, expected.directory_inode)
            exp_lock = (expected.transaction_lock_device, expected.transaction_lock_inode)
            if self._dir_dev_ino != exp_dir or self._lock_dev_ino != exp_lock:
                raise IoFailure("invalid")

            ledger_fd, dir_id, lock_fd, lock_id = open_ledger_and_lock(root_fd, owned, fcntl.LOCK_EX)
            locked_fd = lock_fd
            if dir_id != self._dir_dev_ino or lock_id != self._lock_dev_ino:
                raise IoFailure("invalid")

            # the directory reached through the handle's configured path must be the same object
            try:
                path_fd = owned.add(os.open(
                    self._ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                ))
            except OSError:
                raise IoFailure("io") from None
            if _validate_dir_readonly(path_fd) != dir_id:
                raise IoFailure("invalid")

            final_entry_checks(root_fd, ledger_fd, lock_fd, dir_id, lock_id)
            try:
                cur = os.stat(self._ledger_dir, follow_symlinks=False)
            except OSError:
                raise IoFailure("io") from None
            if (cur.st_dev, cur.st_ino) != dir_id or not stat.S_ISDIR(cur.st_mode):
                raise IoFailure("invalid")

            _unlock_readonly(lock_fd)
            locked_fd = None
            if owned.close_all():
                raise IoFailure("io")
            return LedgerBinding(
                experiment_id=self._experiment_id,
                directory_device=dir_id[0],
                directory_inode=dir_id[1],
                transaction_lock_device=lock_id[0],
                transaction_lock_inode=lock_id[1],
            )
        except IoFailure as failure:
            kind = failure.kind
            interrupt = None
        except Exception:
            kind = "io"
            interrupt = None
        except BaseException as exc:  # noqa: BLE001 - KeyboardInterrupt/SystemExit after acquisition
            kind = "io"
            interrupt = exc
        else:  # pragma: no cover - the try body always returns or raises
            interrupt = None
        # Failure under the acquired mutex. Authority is revoked FIRST so even a further
        # interruption during cleanup cannot leave an enabled handle; then bounded cleanup
        # visits every owned resource once (no close retry); then the permit lease is released.
        self._poison_handle("SYNC_IDENTITY_CHECK_FAILED")
        pending = cleanup_after_failure(owned, locked_fd)
        try:
            self._release_lease()
        except BaseException as exc:  # noqa: BLE001
            if pending is None:
                pending = exc
        interrupt = interrupt or pending
        if interrupt is not None:
            raise interrupt  # termination exceptions propagate after cleanup; no partial binding
        raise LedgerBindingError(codes[kind]) from None

    # -------------------------------------------------------------------------
    # Core Transactions: Reserve, Settle, Fail, Status
    # -------------------------------------------------------------------------

    def reserve(self, request_id: str, request_digest: str,
                amount_micros: Optional[int] = None) -> ReservationPermit:
        """Atomically reserve funds for a single forwarded request.

        ``amount_micros`` (default: the maximum) must lie in [MIN_RESERVATION_MICROS, RESERVATION_AMOUNT_MICROS].
        Settlement above the reserved amount halts the ledger, so the caller must size it to the worst case."""
        if amount_micros is None:
            amount_micros = RESERVATION_AMOUNT_MICROS
        if (type(amount_micros) is not int or isinstance(amount_micros, bool)
                or not MIN_RESERVATION_MICROS <= amount_micros <= RESERVATION_AMOUNT_MICROS):
            raise ValueError(f"reservation amount must be an int in [{MIN_RESERVATION_MICROS}, "
                             f"{RESERVATION_AMOUNT_MICROS}] uUSD")
        with self._handle_lock:
            if self._poisoned:
                raise LedgerHaltedError(f"Ledger handle is permanently poisoned/halted: {self._poison_reason}")

            try:
                clean_req_id = _validate_identifier(request_id, "request_id")
                clean_digest = _validate_digest(request_digest)
            except LedgerCorruptError as err:
                raise ValueError(str(err)) from err

            with self._lock() as dir_fd:
                # Shared guarded inspection: arm -> authoritative inspection -> complete.
                # Any failure disables this handle before it escapes; no permit/mutation follows.
                state = self._guarded_state(dir_fd)

                if state.get("halted", False):
                    self._poison_handle(state["halt_reason"])
                    self._release_lease()
                    raise LedgerHaltedError(
                        f"Ledger is permanently halted: {state.get('halt_reason')}"
                    )

                # Reusing request ID cannot authorize new calls
                for entry in state.get("journal", []):
                    if entry.get("request_id") == clean_req_id:
                        raise ValueError(f"request_id {clean_req_id!r} was already used in a prior transaction")

                if state.get("pending_reservation") is not None:
                    current_pending = state["pending_reservation"]
                    raise InFlightReservationError(
                        f"A reservation is already in flight: request_id={current_pending.get('request_id')}"
                    )

                total_reservations = state.get("total_reservations_count", 0)
                if total_reservations >= MAX_FORWARDED_REQUESTS:
                    raise ReservationLimitExceededError(
                        f"Maximum forwarded request limit ({MAX_FORWARDED_REQUESTS}) reached"
                    )

                committed = state.get("committed_spend_micros", 0)
                retained = state.get("retained_failed_micros", 0)
                projected = committed + retained + amount_micros
                if projected > GLOBAL_CEILING_MICROS:
                    raise BudgetExceededError(
                        f"Reservation of {amount_micros} uUSD would exceed ceiling: "
                        f"projected={projected} uUSD, ceiling={GLOBAL_CEILING_MICROS} uUSD"
                    )

                # 4. Perform reservation mutation
                self._acquire_lease(dir_fd)

                permit_id = f"permit_{uuid.uuid4().hex}"
                reserved_at = _now_utc_str()

                try:
                    self._verify_held_lease(dir_fd)
                except Exception:
                    self._release_lease()
                    self._poison_handle("LEASE_VERIFICATION_FAILED_AT_RESERVE")
                    raise

                pending = {
                    "reservation_id": permit_id,
                    "request_id": clean_req_id,
                    "request_digest": clean_digest,
                    "reserved_amount_micros": amount_micros,
                    "reserved_at_utc": reserved_at,
                    "pid": os.getpid(),
                }

                state["total_reservations_count"] = total_reservations + 1
                state["pending_reservation"] = pending
                state["updated_at_utc"] = reserved_at
                state["journal"].append(
                    {
                        "entry_type": "RESERVED",
                        "reservation_id": permit_id,
                        "request_id": clean_req_id,
                        "request_digest": clean_digest,
                        "reserved_amount_micros": amount_micros,
                        "reservation_index": total_reservations + 1,
                        "timestamp_utc": reserved_at,
                    }
                )

                try:
                    self._atomic_write_state(state, dir_fd)
                except Exception:
                    self._release_lease()
                    self._poison_handle("RESERVE_DURABLE_WRITE_FAILED")
                    raise

                # Verify synchronization identity continuity through permit return
                self._verify_sync_identities(dir_fd)

                return ReservationPermit(
                    permit_id=permit_id,
                    request_id=clean_req_id,
                    request_digest=clean_digest,
                    reserved_amount_micros=amount_micros,
                    reserved_at_utc=reserved_at,
                )

    def settle(
        self,
        permit: ReservationPermit,
        provider_evidence: Mapping[str, Any] | Receipt,
    ) -> SettlementResult | SettlementCommittedHandleDisabledOutcome:
        """Atomically settle a pending reservation with verified provider usage evidence."""
        with self._handle_lock:
            if self._poisoned:
                raise LedgerHaltedError(f"Ledger handle is permanently poisoned/halted: {self._poison_reason}")

            if not isinstance(permit, ReservationPermit):
                raise PermitMismatchError(f"Expected ReservationPermit, got {type(permit).__name__}")

            with self._lock() as dir_fd:
                # Shared guarded inspection: arm -> authoritative inspection -> complete.
                # Any failure disables this handle before it escapes; no permit/mutation follows.
                state = self._guarded_state(dir_fd)

                if state.get("halted", False):
                    self._poison_handle(state["halt_reason"])
                    self._release_lease()
                    raise LedgerHaltedError(
                        f"Ledger is permanently halted ({state.get('halt_reason')}); settlement is forbidden"
                    )

                pending = state.get("pending_reservation")
                if pending is None:
                    raise NoPendingReservationError(
                        "No active pending reservation exists to settle"
                    )

                if self._held_lease_fd is None:
                    raise InFlightReservationError(
                        "Cannot settle reservation: this handle does not hold an active lease for the in-flight reservation"
                    )

                try:
                    self._verify_held_lease(dir_fd)
                except Exception:
                    self._release_lease()
                    self._poison_handle("LEASE_VERIFICATION_FAILED_AT_SETTLE")
                    raise

                # Match permit to pending reservation
                if (
                    permit.permit_id != pending["reservation_id"]
                    or permit.request_id != pending["request_id"]
                    or permit.request_digest != pending["request_digest"]
                ):
                    mismatch_reason = (
                        f"Permit mismatch: permit({permit.permit_id}, {permit.request_id}) "
                        f"!= pending({pending['reservation_id']}, {pending['request_id']})"
                    )
                    self._fail_and_halt(state, pending, "PERMIT_MISMATCH", dir_fd)
                    raise PermitMismatchError(mismatch_reason)

                # Convert evidence to normalized dictionary if Receipt dataclass
                if isinstance(provider_evidence, Receipt):
                    evidence_dict = {
                        "status": provider_evidence.status,
                        "response_id": provider_evidence.response_id,
                        "request_id": provider_evidence.request_id,
                        "request_digest": provider_evidence.request_digest,
                        "model": provider_evidence.model,
                        "service_tier": provider_evidence.service_tier,
                        "input_tokens": provider_evidence.input_tokens,
                        "output_tokens": provider_evidence.output_tokens,
                        "total_tokens": provider_evidence.total_tokens,
                    }
                elif isinstance(provider_evidence, Mapping):
                    evidence_dict = dict(provider_evidence)
                else:
                    self._fail_and_halt(state, pending, "INVALID_EVIDENCE_TYPE", dir_fd)
                    raise SettlementEvidenceError("Provider evidence must be a Receipt dataclass or Mapping")

                # Validate receipt against closed normalized schema and cost contract
                try:
                    accounted_cost, resp_id = self._validate_and_cost_receipt(evidence_dict, pending, state)
                except SettlementEvidenceError as err:
                    # Centralized terminal failure: revoke authority and release lease BEFORE halt publication
                    failure_code = getattr(err, "failure_code", "INVALID_RECEIPT_EVIDENCE")
                    self._fail_and_halt(state, pending, failure_code, dir_fd)
                    raise

                unencumbered = pending["reserved_amount_micros"] - accounted_cost
                settled_at = _now_utc_str()

                # 4. Establish durable permanent intent evidence before changing reservation state
                intent_record = {
                    "record_type": "SETTLEMENT_INTENT",
                    "experiment_id": state["experiment_id"],
                    "reservation_id": permit.permit_id,
                    "request_id": permit.request_id,
                    "request_digest": permit.request_digest,
                    "response_id": resp_id,
                    "model": evidence_dict["model"],
                    "service_tier": evidence_dict["service_tier"],
                    "input_tokens": evidence_dict["input_tokens"],
                    "output_tokens": evidence_dict["output_tokens"],
                    "total_tokens": evidence_dict["total_tokens"],
                    "settled_amount_micros": accounted_cost,
                    "unencumbered_amount_micros": unencumbered,
                    "timestamp_utc": settled_at,
                }
                try:
                    self._write_intent_static(intent_record, dir_fd)
                except Exception:
                    self._fail_and_halt(state, pending, "SETTLEMENT_INTENT_WRITE_FAILED", dir_fd)
                    raise

                # 2. Update state and commit
                state["committed_spend_micros"] += accounted_cost
                state["settled_requests_count"] += 1
                state["pending_reservation"] = None
                state["updated_at_utc"] = settled_at
                state["journal"].append(
                    {
                        "entry_type": "SETTLED",
                        "reservation_id": permit.permit_id,
                        "request_id": permit.request_id,
                        "request_digest": permit.request_digest,
                        "response_id": resp_id,
                        "model": evidence_dict["model"],
                        "service_tier": evidence_dict["service_tier"],
                        "input_tokens": evidence_dict["input_tokens"],
                        "output_tokens": evidence_dict["output_tokens"],
                        "total_tokens": evidence_dict["total_tokens"],
                        "settled_amount_micros": accounted_cost,
                        "unencumbered_amount_micros": unencumbered,
                        "timestamp_utc": settled_at,
                    }
                )

                try:
                    self._atomic_write_state(state, dir_fd)
                except Exception:
                    # Write failure during state settlement commit point
                    self._poison_handle("SETTLEMENT_WRITE_FAILED")
                    self._release_lease()
                    raise

                # SINGLE SETTLEMENT COMMIT POINT HAS SUCCEEDED.
                # 3. Publish permanent matching confirmation record AFTER commit point
                conf_record = {
                    "record_type": "SETTLEMENT_CONFIRMATION",
                    "experiment_id": state["experiment_id"],
                    "reservation_id": permit.permit_id,
                    "request_id": permit.request_id,
                    "request_digest": permit.request_digest,
                    "response_id": resp_id,
                    "model": evidence_dict["model"],
                    "service_tier": evidence_dict["service_tier"],
                    "input_tokens": evidence_dict["input_tokens"],
                    "output_tokens": evidence_dict["output_tokens"],
                    "total_tokens": evidence_dict["total_tokens"],
                    "settled_amount_micros": accounted_cost,
                    "unencumbered_amount_micros": unencumbered,
                    "timestamp_utc": settled_at,
                }
                try:
                    self._write_confirmation_static(conf_record, dir_fd)
                except Exception:
                    # Post-commit confirmation publication error!
                    # Settlement is committed in durable state; disable current handle
                    self._poison_handle("SETTLEMENT_COMMITTED_CONFIRMATION_FAILED")
                    self._release_lease()
                    return SettlementCommittedHandleDisabledOutcome(
                        request_id=permit.request_id,
                        permit_id=permit.permit_id,
                        response_id=resp_id,
                        accounted_cost_micros=accounted_cost,
                        unencumbered_amount_micros=unencumbered,
                        input_tokens=evidence_dict["input_tokens"],
                        output_tokens=evidence_dict["output_tokens"],
                        total_tokens=evidence_dict["total_tokens"],
                        settled_at_utc=settled_at,
                        error="CONFIRMATION_PUBLICATION_FAILED",
                    )

                # Successful durable settlement: release lease cleanly
                self._release_lease()

                # Verify synchronization identities through return
                self._verify_sync_identities(dir_fd, check_lease=False)

                return SettlementResult(
                    request_id=permit.request_id,
                    permit_id=permit.permit_id,
                    response_id=resp_id,
                    accounted_cost_micros=accounted_cost,
                    unencumbered_amount_micros=unencumbered,
                    input_tokens=evidence_dict["input_tokens"],
                    output_tokens=evidence_dict["output_tokens"],
                    total_tokens=evidence_dict["total_tokens"],
                    settled_at_utc=settled_at,
                )

    def record_failure(self, permit: ReservationPermit, reason: str) -> FailureResult:
        """Atomically record request or transport failure for a pending reservation."""
        with self._handle_lock:
            if self._poisoned:
                raise LedgerHaltedError(f"Ledger handle is permanently poisoned/halted: {self._poison_reason}")

            if not isinstance(permit, ReservationPermit):
                raise PermitMismatchError(f"Expected ReservationPermit, got {type(permit).__name__}")

            with self._lock() as dir_fd:
                # Shared guarded inspection: arm -> authoritative inspection -> complete.
                # Any failure disables this handle before it escapes; no permit/mutation follows.
                state = self._guarded_state(dir_fd)

                if state.get("halted", False):
                    self._poison_handle(state["halt_reason"])
                    self._release_lease()
                    raise LedgerHaltedError(
                        f"Ledger is permanently halted ({state.get('halt_reason')})"
                    )

                pending = state.get("pending_reservation")
                if pending is None:
                    raise NoPendingReservationError(
                        "No active pending reservation exists to fail"
                    )

                if (
                    permit.permit_id != pending["reservation_id"]
                    or permit.request_id != pending["request_id"]
                    or permit.request_digest != pending["request_digest"]
                ):
                    mismatch_reason = (
                        f"Permit mismatch on failure: permit({permit.permit_id}) "
                        f"!= pending({pending['reservation_id']})"
                    )
                    self._fail_and_halt(state, pending, "PERMIT_MISMATCH", dir_fd)
                    raise PermitMismatchError(mismatch_reason)

                # Validate failure reason strictly against ALLOWED_INTERNAL_FAILURE_CODES
                try:
                    clean_reason = _sanitize_reason(reason)
                except SettlementEvidenceError:
                    self._fail_and_halt(state, pending, "INVALID_FAILURE_REASON_REJECTED", dir_fd)
                    raise

                failed_at = _now_utc_str()
                retained_amount = pending["reserved_amount_micros"]

                # Centralized failure revocation: poisons handle and releases lease BEFORE state publication
                self._fail_and_halt(state, pending, clean_reason, dir_fd)

                return FailureResult(
                    request_id=permit.request_id,
                    permit_id=permit.permit_id,
                    retained_amount_micros=retained_amount,
                    reason=clean_reason,
                    failed_at_utc=failed_at,
                )

    def get_status(self) -> LedgerStatus:
        """Inspect current ledger status under lock, through the shared guarded inspection.

        Every status read re-arms and completes the inspection guard like any other
        transaction. If the guard cannot be used, the handle is disabled first and
        only a read-only report is produced: already-terminal accounting keeps its
        original reason/totals; a non-terminal ledger is reported as halted
        (derived, not persisted) because it can never be healthy without a guard.
        """
        with self._handle_lock:
            with self._lock() as dir_fd:
                derived_reason: Optional[str] = None
                try:
                    state = self._guarded_state(dir_fd)
                except LedgerHaltedError:
                    state = self._read_state_static(dir_fd, expected_experiment_id=self._experiment_id)
                    if not state["halted"]:
                        derived_reason = "UNFINISHED_INSPECTION_GUARD"
                except (LedgerCorruptError, LedgerSecurityError):
                    # Guard/inspection failure: the handle is already disabled. Report only.
                    state = self._read_state_static(dir_fd, expected_experiment_id=self._experiment_id)
                    if not state["halted"]:
                        derived_reason = self._poison_reason or "INSPECTION_EVIDENCE_UNCERTAINTY"

                committed = state["committed_spend_micros"]
                retained = state["retained_failed_micros"]
                total_spend = committed + retained
                pending = state.get("pending_reservation")
                pending_reserved = pending["reserved_amount_micros"] if pending is not None else 0
                total_encumbered = total_spend + pending_reserved
                remaining_available = max(0, GLOBAL_CEILING_MICROS - total_encumbered)

                halted = state["halted"] or derived_reason is not None
                halt_reason = state["halt_reason"] if state["halted"] else derived_reason

                return LedgerStatus(
                    experiment_id=state["experiment_id"],
                    global_ceiling_micros=GLOBAL_CEILING_MICROS,
                    committed_spend_micros=committed,
                    retained_failed_micros=retained,
                    total_spend_micros=total_spend,
                    pending_reserved_micros=pending_reserved,
                    total_encumbered_micros=total_encumbered,
                    remaining_available_micros=remaining_available,
                    remaining_budget_micros=remaining_available,
                    total_reservations_count=state["total_reservations_count"],
                    settled_requests_count=state["settled_requests_count"],
                    has_pending_reservation=pending is not None,
                    pending_request_id=pending.get("request_id") if pending else None,
                    halted=halted,
                    halt_reason=halt_reason,
                    handle_disabled=self._poisoned or self._handle_disabled,
                    handle_disabled_reason=self._poison_reason or self._handle_disabled_reason,
                )

    # -------------------------------------------------------------------------
    # Centralized Terminal Failure Revocation
    # -------------------------------------------------------------------------

    def _fail_and_halt(
        self,
        state: dict,
        pending: Optional[dict],
        failure_code: str,
        dir_fd: int,
    ) -> None:
        """Centralized failure handler: revokes handle authority and lease BEFORE halt publication."""
        if failure_code not in ALLOWED_INTERNAL_FAILURE_CODES:
            failure_code = "INVALID_FAILURE_REASON_REJECTED"

        self._poison_handle(failure_code)
        self._release_lease()

        if pending is not None:
            already_failed = any(
                e.get("entry_type") in ("FAILED_RETAINED", "ORPHANED_PENDING_HALTED", "TERMINAL_UNCERTAINTY")
                and e.get("reservation_id") == pending["reservation_id"]
                for e in state.get("journal", [])
            )
            if not already_failed:
                amount = pending["reserved_amount_micros"]
                state["retained_failed_micros"] += amount
                state["pending_reservation"] = None
                state["halted"] = True
                state["halt_reason"] = failure_code
                state["updated_at_utc"] = _now_utc_str()
                state["journal"].append(
                    {
                        "entry_type": "FAILED_RETAINED",
                        "reservation_id": pending["reservation_id"],
                        "request_id": pending["request_id"],
                        "retained_amount_micros": amount,
                        "reason": failure_code,
                        "timestamp_utc": state["updated_at_utc"],
                    }
                )
                self._atomic_write_state(state, dir_fd)

    def _poison_handle(self, reason: str) -> None:
        """Mark this ledger instance as permanently poisoned/halted.

        The reason is always a member of ALLOWED_INTERNAL_FAILURE_CODES (never raw
        exception or provider text); the first recorded cause is preserved.
        """
        if reason not in ALLOWED_INTERNAL_FAILURE_CODES:
            reason = "INVALID_FAILURE_REASON_REJECTED"
        if not self._poisoned:
            self._poison_reason = reason
            self._handle_disabled_reason = reason
        self._poisoned = True
        self._handle_disabled = True

    @staticmethod
    def _validate_and_cost_receipt(
        evidence: dict[str, Any],
        pending: dict[str, Any],
        state: dict[str, Any],
    ) -> Tuple[int, str]:
        """Validate receipt against closed schema, replay checks, and numeric bounds."""
        actual_keys = frozenset(evidence.keys())
        if actual_keys != EXPECTED_RECEIPT_KEYS:
            missing = EXPECTED_RECEIPT_KEYS - actual_keys
            unexpected = actual_keys - EXPECTED_RECEIPT_KEYS
            err = SettlementEvidenceError(
                f"Receipt closed schema violation: missing={len(missing)} field(s), unexpected={len(unexpected)} field(s)"
            )
            err.failure_code = "RECEIPT_SCHEMA_VIOLATION"
            raise err

        status = evidence["status"]
        if status != TERMINAL_STATUS_COMPLETED:
            err = SettlementEvidenceError(
                f"Receipt status must be strictly '{TERMINAL_STATUS_COMPLETED}'"
            )
            err.failure_code = "INVALID_RECEIPT_STATUS"
            raise err

        try:
            resp_id = _validate_identifier(evidence["response_id"], "response_id")
        except LedgerCorruptError as e:
            err = SettlementEvidenceError("Invalid response_id")
            err.failure_code = "INVALID_RESPONSE_ID"
            raise err from None

        # Check for replayed response_id across entire journal
        for entry in state.get("journal", []):
            if entry.get("response_id") == resp_id:
                err = SettlementEvidenceError(
                    "Replay detected: response_id was already settled in a prior transaction"
                )
                err.failure_code = "REPLAYED_RESPONSE_ID"
                raise err

        # Identity binding checks
        if evidence["request_id"] != pending["request_id"]:
            err = SettlementEvidenceError(
                "Receipt request_id mismatch"
            )
            err.failure_code = "REQUEST_ID_MISMATCH"
            raise err
        if evidence["request_digest"] != pending["request_digest"]:
            err = SettlementEvidenceError(
                "Receipt request_digest mismatch"
            )
            err.failure_code = "REQUEST_DIGEST_MISMATCH"
            raise err

        # Priced model and its tier
        if evidence["model"] not in MODEL_RATES:
            err = SettlementEvidenceError(
                "Model mismatch against pinned model"
            )
            err.failure_code = "RECEIPT_MODEL_MISMATCH"
            raise err
        if evidence["service_tier"] != MODEL_RATES[evidence["model"]][2]:
            err = SettlementEvidenceError(
                "Service tier mismatch against pinned tier"
            )
            err.failure_code = "RECEIPT_SERVICE_TIER_MISMATCH"
            raise err

        # Token bounds
        in_tok = evidence["input_tokens"]
        if type(in_tok) is not int or isinstance(in_tok, bool) or in_tok < 0:
            err = SettlementEvidenceError("input_tokens must be a non-negative integer (not bool)")
            err.failure_code = "INVALID_TOKEN_TYPE"
            raise err
        if in_tok > MAX_INPUT_TOKENS:
            err = SettlementEvidenceError(f"input_tokens exceeds supported window ({MAX_INPUT_TOKENS})")
            err.failure_code = "RECEIPT_TOKEN_BOUND_EXCEEDED"
            raise err

        out_tok = evidence["output_tokens"]
        if type(out_tok) is not int or isinstance(out_tok, bool) or out_tok < 0:
            err = SettlementEvidenceError("output_tokens must be a non-negative integer (not bool)")
            err.failure_code = "INVALID_TOKEN_TYPE"
            raise err
        if out_tok > MAX_OUTPUT_TOKENS:
            err = SettlementEvidenceError(f"output_tokens exceeds enforced limit ({MAX_OUTPUT_TOKENS})")
            err.failure_code = "RECEIPT_TOKEN_BOUND_EXCEEDED"
            raise err

        tot_tok = evidence["total_tokens"]
        if type(tot_tok) is not int or isinstance(tot_tok, bool) or tot_tok != (in_tok + out_tok):
            err = SettlementEvidenceError(
                "total_tokens is inconsistent with the sum of input and output tokens"
            )
            err.failure_code = "TOKEN_SUM_INCONSISTENT"
            raise err

        cost = model_cost_micros(evidence["model"], evidence["service_tier"], in_tok, out_tok)
        if cost > pending["reserved_amount_micros"]:
            err = SettlementEvidenceError(
                "Computed cost exceeds reserved amount"
            )
            err.failure_code = "COST_EXCEEDS_RESERVATION"
            raise err

        return cost, resp_id

    # -------------------------------------------------------------------------
    # Lease Management & Synchronization Identity Checks
    # -------------------------------------------------------------------------

    def _acquire_lease(self, dir_fd: int) -> None:
        """Acquire an exclusive non-blocking lease lock on lease.lock to prove active ownership."""
        self._release_lease()
        try:
            lease_fd = os.open(
                LEASE_FILENAME,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise LedgerSecurityError("Symlink detected on lease path") from e
            raise

        try:
            st = self._validate_file_descriptor(lease_fd)
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            st_disk = os.stat(LEASE_FILENAME, dir_fd=dir_fd)
            if (st_disk.st_dev, st_disk.st_ino) != st or st_disk.st_nlink != 1:
                raise LedgerSecurityError("Lease lock file was unlinked or replaced during acquisition")

            self._held_lease_fd = lease_fd
            self._held_lease_dev_ino = st
        except Exception as err:
            try:
                os.close(lease_fd)
            except OSError:
                pass
            if isinstance(err, (BlockingIOError, OSError)) and err.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise InFlightReservationError("Cannot acquire lease: another reservation is actively in flight") from None
            raise

    def _verify_held_lease(self, dir_fd: int) -> None:
        """Verify that the held lease descriptor is still valid and matches the on-disk file."""
        if self._held_lease_fd is None:
            raise InFlightReservationError("No active lease held by this ledger instance")

        try:
            st_f = os.fstat(self._held_lease_fd)
        except OSError as err:
            raise LedgerSecurityError(f"Cannot fstat held lease descriptor: {err}") from None

        if (st_f.st_dev, st_f.st_ino) != self._held_lease_dev_ino or st_f.st_nlink != 1:
            raise LedgerSecurityError("Held lease descriptor inode mismatch or was unlinked")

        try:
            st_disk = os.stat(LEASE_FILENAME, dir_fd=dir_fd)
        except OSError as err:
            raise LedgerSecurityError(f"Lease file missing on disk: {err}") from None

        if (st_disk.st_dev, st_disk.st_ino) != self._held_lease_dev_ino or st_disk.st_nlink != 1:
            raise LedgerSecurityError("Lease file on disk was replaced with a different inode")

    def _verify_sync_identities(self, dir_fd: int, check_lease: bool = True) -> None:
        """Verify that directory and lock identities remain valid right through publication return."""
        try:
            st_dir = os.fstat(dir_fd)
            if (st_dir.st_dev, st_dir.st_ino) != self._dir_dev_ino:
                raise LedgerSecurityError("Directory descriptor identity changed during transaction")

            st_dir_disk = os.stat(".", dir_fd=dir_fd)
            if (st_dir_disk.st_dev, st_dir_disk.st_ino) != self._dir_dev_ino:
                raise LedgerSecurityError("Directory entry identity changed during transaction")

            st_lock_disk = os.stat(LOCK_FILENAME, dir_fd=dir_fd)
            if (st_lock_disk.st_dev, st_lock_disk.st_ino) != self._lock_dev_ino or st_lock_disk.st_nlink != 1:
                raise LedgerSecurityError("Lock file was unlinked or replaced before transaction return")

            if check_lease and self._held_lease_fd is not None:
                self._verify_held_lease(dir_fd)
        except Exception as err:
            self._poison_handle("SYNC_IDENTITY_CHECK_FAILED")
            self._release_lease()
            raise

    def _release_lease(self) -> None:
        """Release the active permit lease exactly once.

        Ownership is transferred out of the handle BEFORE any unlock/close, so a
        termination exception (KeyboardInterrupt/SystemExit) at any point can never
        leave a stale descriptor number that a later close() would apply to an
        unrelated reused descriptor. The close is attempted even if unlock was
        interrupted; no close is ever retried; ordinary OSError is ignored as before;
        the first termination exception is re-raised AFTER both steps were attempted.
        """
        fd = self._held_lease_fd
        if fd is None:
            return
        self._held_lease_fd = None
        self._held_lease_dev_ino = None
        pending: Optional[BaseException] = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        except BaseException as exc:  # noqa: BLE001 - termination exceptions
            pending = exc
        try:
            os.close(fd)
        except OSError:
            pass
        except BaseException as exc:  # noqa: BLE001
            if pending is None:
                pending = exc
        if pending is not None:
            raise pending

    @classmethod
    def _is_lease_held_static(cls, dir_fd: int) -> bool:
        """Check if an active lease lock is currently held by a live process."""
        try:
            test_fd = os.open(LEASE_FILENAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError as err:
            if err.errno == errno.ENOENT:
                return False
            if err.errno == errno.ELOOP:
                raise LedgerSecurityError("Symlink detected on lease path") from err
            return False

        try:
            cls._validate_file_descriptor_static(test_fd)
            fcntl.flock(test_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(test_fd, fcntl.LOCK_UN)
            return False
        except (BlockingIOError, OSError) as err:
            if err.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                return True
            return False
        finally:
            try:
                os.close(test_fd)
            except OSError:
                pass

    @classmethod
    def _validate_dir_descriptor_static(cls, dir_fd: int) -> Tuple[int, int]:
        """Validate directory descriptor ownership, mode, and absence of symlinks."""
        try:
            st = os.fstat(dir_fd)
        except OSError as err:
            raise LedgerSecurityError(f"Cannot fstat directory descriptor: {err}") from None

        if not stat.S_ISDIR(st.st_mode):
            raise LedgerSecurityError("Ledger directory descriptor is not a directory")
        if st.st_uid != os.getuid():
            raise LedgerSecurityError(
                f"Ledger directory owner mismatch: expected UID {os.getuid()}, got {st.st_uid}"
            )
        if (st.st_mode & 0o077) != 0:
            raise LedgerSecurityError(
                f"Ledger directory permissions must not allow group/world access (got {oct(st.st_mode)})"
            )
        return (st.st_dev, st.st_ino)

    @classmethod
    def _validate_file_descriptor_static(cls, fd: int) -> Tuple[int, int]:
        """Validate regular file descriptor ownership, mode, absence of symlinks and hardlinks."""
        try:
            st = os.fstat(fd)
        except OSError as err:
            raise LedgerSecurityError(f"Cannot fstat file descriptor: {err}") from None

        if not stat.S_ISREG(st.st_mode):
            raise LedgerSecurityError("Ledger file descriptor is not a regular file")
        if st.st_uid != os.getuid():
            raise LedgerSecurityError(
                f"Ledger file owner mismatch: expected UID {os.getuid()}, got {st.st_uid}"
            )
        if (st.st_mode & 0o077) != 0:
            raise LedgerSecurityError(
                f"Ledger file permissions must not allow group/world access (got {oct(st.st_mode)})"
            )
        if st.st_nlink != 1:
            raise LedgerSecurityError(
                f"Hard links are strictly forbidden on ledger files (nlink={st.st_nlink})"
            )
        return (st.st_dev, st.st_ino)

    def _validate_dir_descriptor(self, dir_fd: int) -> Tuple[int, int]:
        return self._validate_dir_descriptor_static(dir_fd)

    def _validate_file_descriptor(self, fd: int) -> Tuple[int, int]:
        return self._validate_file_descriptor_static(fd)

    @contextmanager
    def _lock(self) -> Generator[int, None, None]:
        """Acquire exclusive durable file lock anchored to verified directory descriptor."""
        try:
            dir_fd = os.open(self._ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise LedgerSecurityError(f"Symlink detected on ledger directory {self._ledger_dir}") from e
            raise

        try:
            current_dir_id = self._validate_dir_descriptor(dir_fd)
            if self._dir_dev_ino is None:
                self._dir_dev_ino = current_dir_id
            elif self._dir_dev_ino != current_dir_id:
                raise LedgerSecurityError("Ledger directory identity has been replaced")

            try:
                lock_fd = os.open(LOCK_FILENAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=dir_fd)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    raise LedgerSecurityError("Runtime lock file missing") from e
                if e.errno == errno.ELOOP:
                    raise LedgerSecurityError("Symlink detected on lock path") from e
                raise

            try:
                current_lock_id = self._validate_file_descriptor(lock_fd)
                if self._lock_dev_ino is None:
                    self._lock_dev_ino = current_lock_id
                elif self._lock_dev_ino != current_lock_id:
                    raise LedgerSecurityError("Lock file identity has been replaced")

                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    st_lock_disk = os.stat(LOCK_FILENAME, dir_fd=dir_fd)
                    if (st_lock_disk.st_dev, st_lock_disk.st_ino) != self._lock_dev_ino or st_lock_disk.st_nlink != 1:
                        raise LedgerSecurityError("Runtime lock file was unlinked or replaced")

                    st_dir_disk = os.stat(".", dir_fd=dir_fd)
                    if (st_dir_disk.st_dev, st_dir_disk.st_ino) != self._dir_dev_ino:
                        raise LedgerSecurityError("Directory entry identity mismatch")

                    yield dir_fd
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        finally:
            os.close(dir_fd)

    @classmethod
    def _read_state_static(
        cls,
        dir_fd: int,
        expected_experiment_id: Optional[str] = None,
    ) -> dict:
        """Static state reader relative to dir_fd."""
        try:
            fd = os.open(STATE_FILENAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise LedgerSecurityError(f"Symlink detected on state path: {e}") from e
            if e.errno == errno.ENOENT:
                raise LedgerNotFoundError(f"State file missing: {e}") from e
            raise

        try:
            cls._validate_file_descriptor_static(fd)
            st = os.fstat(fd)
            if st.st_size > MAX_STATE_FILE_BYTES:
                raise LedgerCorruptError(
                    f"State file size {st.st_size} exceeds maximum limit of {MAX_STATE_FILE_BYTES} bytes"
                )
            raw_bytes = os.read(fd, MAX_STATE_FILE_BYTES + 1)
            if len(raw_bytes) > MAX_STATE_FILE_BYTES:
                raise LedgerCorruptError("State file exceeded maximum read bounds")
        finally:
            os.close(fd)

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            raise LedgerCorruptError(f"State file is not valid UTF-8: {err}") from err

        state = _safe_json_loads(text)
        cls._validate_and_reconcile_state_static(state, expected_experiment_id)
        return state

    @classmethod
    def _read_bounded_file_static(cls, name: str, dir_fd: int, label: str) -> Optional[bytes]:
        """Bounded descriptor-validated read of a small auxiliary file.

        ONLY ENOENT on open means absence (None). Every other failure over the whole
        descriptor lifetime (open, fstat, read, close) is normalized into
        LedgerSecurityError (uncertainty) or LedgerCorruptError (size). The
        descriptor has exactly one owner: it is closed exactly once, a close error
        is reported (never retried), and cleanup after another failure preserves it.
        """
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        except OSError as err:
            if err.errno == errno.ENOENT:
                return None
            raise LedgerSecurityError(f"Filesystem error opening {label}") from err

        raw_bytes = bytearray()
        try:
            cls._validate_file_descriptor_static(fd)
            st = os.fstat(fd)
            if st.st_size > MAX_STATE_FILE_BYTES:
                raise LedgerCorruptError(f"{label} exceeds maximum size limit of {MAX_STATE_FILE_BYTES} bytes")
            while len(raw_bytes) <= MAX_STATE_FILE_BYTES:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                raw_bytes.extend(chunk)
            if len(raw_bytes) > MAX_STATE_FILE_BYTES:
                raise LedgerCorruptError(f"{label} exceeded maximum read bounds")
        except OSError as err:
            try:
                os.close(fd)
            except OSError:
                pass
            raise LedgerSecurityError(f"Filesystem error reading {label}") from err
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        try:
            os.close(fd)
        except OSError as err:
            # Descriptor state after a failed close is undefined: never close again.
            raise LedgerSecurityError(f"Filesystem error closing {label}") from err
        return bytes(raw_bytes)

    @classmethod
    def _read_record_static(
        cls,
        record_filename: str,
        dir_fd: int,
        expected_type: str,
        expected_experiment_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Read and validate a closed typed intent or confirmation record."""
        raw_bytes = cls._read_bounded_file_static(record_filename, dir_fd, f"record {record_filename}")
        if raw_bytes is None:
            return None

        try:
            content = raw_bytes.decode("utf-8")
            record = _safe_json_loads(content)
        except Exception as err:
            raise LedgerCorruptError(f"Failed to parse record {record_filename}: {err}") from err

        if not isinstance(record, dict):
            raise LedgerCorruptError(f"Record {record_filename} must be a JSON object")

        expected_keys = (
            EXPECTED_INTENT_KEYS
            if expected_type == "SETTLEMENT_INTENT"
            else EXPECTED_CONFIRMATION_KEYS
        )
        if frozenset(record.keys()) != expected_keys:
            raise LedgerCorruptError(
                f"Record {record_filename} schema violation: expected {sorted(expected_keys)}, got {sorted(record.keys())}"
            )

        if record.get("record_type") != expected_type:
            raise LedgerCorruptError(
                f"Record {record_filename} record_type mismatch: expected {expected_type}, got {record.get('record_type')}"
            )

        exp_id = _validate_identifier(record["experiment_id"], "experiment_id")
        if expected_experiment_id is not None and exp_id != expected_experiment_id:
            raise LedgerCorruptError(
                f"Record {record_filename} experiment_id mismatch: expected {expected_experiment_id}, got {exp_id}"
            )

        _validate_identifier(record["reservation_id"], "reservation_id")
        _validate_identifier(record["request_id"], "request_id")
        _validate_digest(record["request_digest"])
        _validate_identifier(record["response_id"], "response_id")
        _validate_timestamp(record["timestamp_utc"])

        if record["model"] not in MODEL_RATES:
            raise LedgerCorruptError(f"Record {record_filename} model mismatch: {record['model']}")
        if record["service_tier"] != MODEL_RATES[record["model"]][2]:
            raise LedgerCorruptError(f"Record {record_filename} service tier mismatch: {record['service_tier']}")

        in_tok = _validate_int(record["input_tokens"], "input_tokens", max_val=MAX_INPUT_TOKENS)
        out_tok = _validate_int(record["output_tokens"], "output_tokens", max_val=MAX_OUTPUT_TOKENS)
        tot_tok = _validate_int(record["total_tokens"], "total_tokens")
        settled_amt = _validate_int(record["settled_amount_micros"], "settled_amount_micros")
        unencumbered = _validate_int(record["unencumbered_amount_micros"], "unencumbered_amount_micros")

        if tot_tok != (in_tok + out_tok):
            raise LedgerCorruptError(f"Record {record_filename} total_tokens derivation error")

        expected_amt = model_cost_micros(record["model"], record["service_tier"], in_tok, out_tok)
        if settled_amt != expected_amt:
            raise LedgerCorruptError(f"Record {record_filename} settled_amount_micros derivation error")

        # The reservation is per request; the exact unencumbered = reserved - settled check is made against
        # the journal's RESERVED entry, and records must equal the journal's SETTLED entry field by field.
        if not MIN_RESERVATION_MICROS <= settled_amt + unencumbered <= RESERVATION_AMOUNT_MICROS:
            raise LedgerCorruptError(f"Record {record_filename} unencumbered_amount_micros derivation error")

        return record

    @classmethod
    def _write_intent_static(cls, intent_record: dict, dir_fd: int) -> None:
        """Write durable permanent intent evidence before changing reservation state."""
        clean_res_id = _validate_identifier(intent_record["reservation_id"], "reservation_id")
        target_name = f"{INTENT_FILE_PREFIX}{clean_res_id}.json"
        cls._atomic_write_record_file_static(intent_record, target_name, dir_fd, ".tmp_intent_")

    @classmethod
    def _write_confirmation_static(cls, conf_record: dict, dir_fd: int) -> None:
        """Write durable permanent confirmation evidence after settlement commit point."""
        clean_res_id = _validate_identifier(conf_record["reservation_id"], "reservation_id")
        target_name = f"{CONFIRMATION_FILE_PREFIX}{clean_res_id}.json"
        cls._atomic_write_record_file_static(conf_record, target_name, dir_fd, ".tmp_confirm_")

    @classmethod
    def _atomic_write_record_file_static(
        cls, record_dict: dict, target_name: str, dir_fd: int, tmp_prefix: str = ".tmp_rec_"
    ) -> None:
        """Atomically and durably write a permanent record file relative to dir_fd."""
        cls._publish_witness_static(record_dict, target_name, tmp_prefix, dir_fd)

    # -------------------------------------------------------------------------
    # Inspection Guard and Completion Witness Management
    # -------------------------------------------------------------------------

    @classmethod
    def _read_witness_static(
        cls, name: str, label: str, dir_fd: int, exp_id: Optional[str],
        keys, record_type: str, ts_field: str,
    ) -> Optional[dict]:
        """Read a guard/completion file; all I/O, decode and parse errors become fixed ledger errors."""
        raw = cls._read_bounded_file_static(name, dir_fd, label)
        if raw is None:
            return None
        try:
            data = _safe_json_loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, LedgerCorruptError):
            raise LedgerCorruptError(f"{label} malformed") from None
        if frozenset(data.keys()) != keys:
            raise LedgerCorruptError(f"{label} schema violation")
        if data.get("record_type") != record_type:
            raise LedgerCorruptError(f"{label} record_type invalid")
        if exp_id is None:
            _validate_identifier(data.get("experiment_id"), "experiment_id")
        elif data.get("experiment_id") != exp_id:
            raise LedgerCorruptError(f"{label} experiment_id mismatch")
        gen = data.get("generation")
        if type(gen) is not int or isinstance(gen, bool) or gen < 1 or gen > MAX_INSPECTION_GENERATION:
            raise LedgerCorruptError(f"{label} generation invalid")
        _validate_timestamp(data.get(ts_field))
        return data

    @classmethod
    def _read_guard_static(cls, dir_fd: int, exp_id: Optional[str]) -> Optional[dict]:
        """Read and validate inspection guard file relative to dir_fd."""
        return cls._read_witness_static(
            INSPECTION_GUARD_FILENAME, "inspection guard", dir_fd, exp_id,
            EXPECTED_INSPECTION_GUARD_KEYS, RECORD_TYPE_INSPECTION_GUARD, "armed_at_utc",
        )

    @classmethod
    def _read_completion_static(cls, dir_fd: int, exp_id: Optional[str]) -> Optional[dict]:
        """Read and validate inspection completion witness relative to dir_fd."""
        return cls._read_witness_static(
            INSPECTION_COMPLETION_FILENAME, "inspection completion", dir_fd, exp_id,
            EXPECTED_INSPECTION_COMPLETION_KEYS, RECORD_TYPE_INSPECTION_COMPLETION, "completed_at_utc",
        )

    @classmethod
    def _publish_witness_static(
        cls, record: dict, final_name: str, tmp_prefix: str, dir_fd: int
    ) -> None:
        encoded = json.dumps(record, indent=2, sort_keys=True).encode("utf-8")
        cls._publish_bytes_static(encoded, final_name, tmp_prefix, dir_fd)

    @classmethod
    def _publish_bytes_static(
        cls, encoded: bytes, final_name: str, tmp_prefix: str, dir_fd: int
    ) -> None:
        """Durably publish a file: write, file-sync, close, replace, directory-sync.

        Single implementation for state, intent, confirmation, guard and completion.

        The temporary descriptor has exactly one owner at any time: it is closed
        once on the failure path, or once on the success path where a close error
        is propagated (the descriptor is never closed a second time). Bounded
        temporary-file cleanup preserves the original failure.
        """
        tmp_name = f"{tmp_prefix}{uuid.uuid4().hex}"
        try:
            tmp_fd = os.open(
                tmp_name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
        except OSError as err:
            if err.errno == errno.ELOOP:
                raise LedgerSecurityError(f"Symlink detected on temporary witness: {err}") from err
            raise

        def _cleanup_tmp() -> None:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass

        try:
            cls._validate_file_descriptor_static(tmp_fd)
            written = 0
            while written < len(encoded):
                n = os.write(tmp_fd, encoded[written:])
                if n == 0:
                    raise OSError(errno.EIO, "Zero bytes written to temporary witness")
                written += n
            os.fsync(tmp_fd)
        except BaseException:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
            _cleanup_tmp()
            raise

        try:
            os.close(tmp_fd)
        except BaseException:
            # Descriptor state after a failed close is undefined: never close again.
            _cleanup_tmp()
            raise

        try:
            os.replace(tmp_name, final_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except BaseException:
            _cleanup_tmp()
            raise

    @classmethod
    def _write_guard_static(cls, guard_dict: dict, dir_fd: int) -> None:
        """Atomically write and synchronize the inspection guard."""
        cls._publish_witness_static(guard_dict, INSPECTION_GUARD_FILENAME, ".tmp_guard_", dir_fd)

    @classmethod
    def _write_completion_static(cls, comp_dict: dict, dir_fd: int) -> None:
        """Atomically write and synchronize the inspection completion witness."""
        cls._publish_witness_static(comp_dict, INSPECTION_COMPLETION_FILENAME, ".tmp_comp_", dir_fd)

    @classmethod
    def _invalidate_completion_static(cls, dir_fd: int) -> None:
        """Unlink the prior completion witness (made durable by the following guard publication)."""
        try:
            os.unlink(INSPECTION_COMPLETION_FILENAME, dir_fd=dir_fd)
        except FileNotFoundError:
            pass

    @classmethod
    def _arm_guard_static(cls, dir_fd: int, exp_id: str) -> int:
        """Verify the surviving completion witness, then durably arm a fresh generation.

        Raises _GuardUnfinishedError for an unfinished/stale inspection, and any
        read/corruption/write error unchanged. The previous completion is
        invalidated (unlinked, then made durable by the guard's directory sync)
        before the next generation can be inspected; generations never repeat
        or wrap.
        """
        guard = cls._read_guard_static(dir_fd, exp_id)
        if guard is None:
            raise LedgerCorruptError("Inspection guard missing from ledger directory")
        completion = cls._read_completion_static(dir_fd, exp_id)
        if completion is None or completion["generation"] != guard["generation"]:
            raise _GuardUnfinishedError("Ledger is permanently halted: UNFINISHED_INSPECTION_GUARD")
        current_gen = guard["generation"]
        if current_gen >= MAX_INSPECTION_GENERATION:
            raise LedgerSecurityError(f"Inspection generation exhausted: {current_gen}")
        next_gen = current_gen + 1
        cls._invalidate_completion_static(dir_fd)
        cls._write_guard_static(
            {
                "record_type": RECORD_TYPE_INSPECTION_GUARD,
                "experiment_id": exp_id,
                "generation": next_gen,
                "armed_at_utc": _now_utc_str(),
            },
            dir_fd,
        )
        return next_gen

    @classmethod
    def _complete_guard_static(cls, dir_fd: int, exp_id: str, generation: int) -> None:
        """Publish the completion witness for `generation` (after all inspection checks)."""
        cls._write_completion_static(
            {
                "record_type": RECORD_TYPE_INSPECTION_COMPLETION,
                "experiment_id": exp_id,
                "generation": generation,
                "completed_at_utc": _now_utc_str(),
            },
            dir_fd,
        )

    def _terminal_reason_if_any(self, dir_fd: int) -> Optional[str]:
        """Best-effort read-only lookup of an already-terminal halt reason (never authority)."""
        try:
            state = self._read_state_static(dir_fd, expected_experiment_id=self._experiment_id)
        except Exception:
            return None
        return state["halt_reason"] if state["halted"] else None

    def _arm_and_verify_inspection_guard(self, dir_fd: int, exp_id: str) -> int:
        """Arm under the transaction lock; any guard/completion failure disables this handle first."""
        try:
            return self._arm_guard_static(dir_fd, exp_id)
        except BaseException as err:
            # Authority is revoked FIRST; only then may a report-only state read happen.
            if isinstance(err, _GuardUnfinishedError):
                self._poison_handle("UNFINISHED_INSPECTION_GUARD")
            else:
                self._poison_handle("INSPECTION_GUARD_CORRUPT")
            self._release_lease()
            if isinstance(err, _GuardUnfinishedError):
                terminal = self._terminal_reason_if_any(dir_fd)
                if terminal is not None:
                    # preserve the already-valid terminal reason for reporting
                    self._poison_reason = terminal
                    self._handle_disabled_reason = terminal
                raise _GuardUnfinishedError(
                    f"Ledger is permanently halted: {terminal or 'UNFINISHED_INSPECTION_GUARD'}"
                ) from None
            raise

    def _complete_inspection_guard(self, dir_fd: int, exp_id: str, generation: int) -> None:
        """Publish matching completion witness; failure disables this handle before escaping."""
        try:
            self._complete_guard_static(dir_fd, exp_id, generation)
        except BaseException:
            self._poison_handle("INSPECTION_COMPLETION_FAILED")
            self._release_lease()
            raise

    def _disable_for_uncertainty(self) -> None:
        """Revoke this handle's authority BEFORE any terminal accounting is published."""
        self._poison_handle("TERMINAL_UNCERTAINTY")
        self._release_lease()

    def _guarded_state(self, dir_fd: int) -> dict:
        """The one shared inspection entry point (reserve/settle/fail/status).

        1. Arm + sync a fresh guard generation BEFORE any authoritative read.
        2. Read and inspect authoritative state and auxiliary evidence.
        3. Only after every check succeeded, publish + sync the completion witness,
           still under the transaction lock and before any mutation.
        Any failure disables this handle BEFORE terminal accounting publication and
        leaves the guard unfinished (never completed).
        """
        gen = self._arm_and_verify_inspection_guard(dir_fd, self._experiment_id)
        try:
            state = self._read_state_static(dir_fd, expected_experiment_id=self._experiment_id)
            state, uncertain = self._validate_and_recover_records_under_lock(
                state, dir_fd, before_halt=self._disable_for_uncertainty
            )
        except BaseException:
            self._poison_handle("INSPECTION_EVIDENCE_UNCERTAINTY")
            self._release_lease()
            raise
        if uncertain:
            # Evidence was found missing/invalid: terminal overlay published; never completed.
            self._poison_handle("TERMINAL_UNCERTAINTY")
            self._release_lease()
            raise LedgerHaltedError(f"Ledger is permanently halted: {state['halt_reason']}")
        self._complete_inspection_guard(dir_fd, state["experiment_id"], gen)
        return state

    @classmethod
    def _validate_and_recover_records_under_lock(
        cls,
        state: dict,
        dir_fd: int,
        before_halt=None,
    ) -> Tuple[dict, bool]:
        """Inspect permanent intent/confirmation evidence under the transaction lock.

        Returns (state, uncertain). An already-terminal state is returned untouched
        (original reason/accounting preserved, no auxiliary files reprocessed).
        If any evidence is missing, contradictory, unreadable or unattributable,
        `before_halt` (handle revocation) runs FIRST, then ONE terminal uncertainty
        overlay event referencing existing reservation IDs is appended; earlier
        history is never rewritten. A scan/read I/O failure re-raises after the
        overlay is published. No state is returned as healthy when uncertain.
        """
        if state["halted"]:
            return state, False

        exp_id = state["experiment_id"]
        journal = state["journal"]
        known_ids = {e["reservation_id"] for e in journal if e.get("entry_type") == "RESERVED"}
        reserved_amounts = {e["reservation_id"]: e["reserved_amount_micros"] for e in journal
                            if e.get("entry_type") == "RESERVED"}
        pending = state.get("pending_reservation")
        pending_res_id = pending["reservation_id"] if pending is not None else None
        settled_ids = {e["reservation_id"]: e for e in journal if e.get("entry_type") == "SETTLED"}

        uncertain_res_ids = set()
        unattributable = False
        uncertainty_error: Optional[BaseException] = None
        has_unresolved_intent = False

        names = []
        try:
            with os.scandir(dir_fd) as it:
                for entry in it:
                    names.append(entry.name)
        except OSError as err:
            unattributable = True
            uncertainty_error = err

        if uncertainty_error is None:
            res_ids_to_check = set(known_ids)
            for name in names:
                for prefix in (INTENT_FILE_PREFIX, CONFIRMATION_FILE_PREFIX):
                    if name.startswith(prefix) and name.endswith(".json"):
                        res_ids_to_check.add(name[len(prefix):-len(".json")])

            for res_id in sorted(res_ids_to_check):
                intent_name = f"{INTENT_FILE_PREFIX}{res_id}.json"
                conf_name = f"{CONFIRMATION_FILE_PREFIX}{res_id}.json"
                intent_rec = conf_rec = None
                intent_err = conf_err = None
                io_failed = False
                try:
                    intent_rec = cls._read_record_static(intent_name, dir_fd, "SETTLEMENT_INTENT", exp_id)
                except LedgerSecurityError as err:
                    io_failed, uncertainty_error = True, err
                except LedgerCorruptError as err:
                    intent_err = err
                try:
                    conf_rec = cls._read_record_static(conf_name, dir_fd, "SETTLEMENT_CONFIRMATION", exp_id)
                except LedgerSecurityError as err:
                    io_failed, uncertainty_error = True, err
                except LedgerCorruptError as err:
                    conf_err = err

                attributable = res_id in known_ids
                if io_failed:
                    uncertain_res_ids.add(res_id)
                    if not attributable:
                        unattributable = True
                    continue

                j_settled = settled_ids.get(res_id)
                if intent_rec is not None and conf_rec is None and conf_err is None:
                    has_unresolved_intent = True

                bad = False
                if j_settled is not None:
                    if conf_rec is None or conf_err is not None or intent_rec is None or intent_err is not None:
                        bad = True
                    else:
                        keys = (
                            "reservation_id", "request_id", "request_digest", "response_id", "model",
                            "service_tier", "input_tokens", "output_tokens", "total_tokens",
                            "settled_amount_micros", "unencumbered_amount_micros", "timestamp_utc",
                        )
                        for k in keys:
                            if not (intent_rec[k] == conf_rec[k] == j_settled[k]) or \
                                    type(intent_rec[k]) is not type(j_settled[k]) or \
                                    type(conf_rec[k]) is not type(j_settled[k]):
                                bad = True
                                break
                elif intent_rec is not None or intent_err is not None:
                    bad = True
                    has_unresolved_intent = True
                elif conf_rec is not None or conf_err is not None:
                    bad = True
                if bad:
                    uncertain_res_ids.add(res_id)
                    if not attributable:
                        unattributable = True

        if not uncertain_res_ids and not unattributable and uncertainty_error is None:
            return state, False

        # --- Uncertainty found: revoke the handle BEFORE publishing terminal accounting ---
        if before_halt is not None:
            before_halt()

        if unattributable:
            affected = set(known_ids)
        else:
            affected = uncertain_res_ids & known_ids
        if pending_res_id is not None:
            affected.add(pending_res_id)
        affected_ids = sorted(affected)

        for uid in affected_ids:
            if uid in settled_ids:
                state["committed_spend_micros"] -= settled_ids[uid]["settled_amount_micros"]
                state["retained_failed_micros"] += reserved_amounts[uid]
            elif uid == pending_res_id:
                state["retained_failed_micros"] += state["pending_reservation"]["reserved_amount_micros"]
                state["pending_reservation"] = None

        now = _now_utc_str()
        terminal_reason = "UNRESOLVED_SETTLEMENT_PUBLICATION" if has_unresolved_intent else "TERMINAL_UNCERTAINTY"
        state["halted"] = True
        state["halt_reason"] = terminal_reason
        state["updated_at_utc"] = now
        journal.append({
            "entry_type": "TERMINAL_UNCERTAINTY",
            "timestamp_utc": now,
            "reason": terminal_reason,
            "uncertain_reservation_ids": affected_ids,
        })
        cls._atomic_write_state_static(state, dir_fd)

        if uncertainty_error is not None:
            raise LedgerSecurityError("Filesystem uncertainty during evidence inspection") from uncertainty_error
        return state, True

    @classmethod
    def _validate_and_reconcile_state_static(
        cls,
        state: dict,
        expected_experiment_id: Optional[str] = None,
    ) -> None:
        """Perform deep typed journal replay, state machine validation, and closed schema checks."""
        # Top-level closed schema
        actual_keys = frozenset(state.keys())
        if actual_keys != EXPECTED_STATE_KEYS:
            missing = EXPECTED_STATE_KEYS - actual_keys
            unexpected = actual_keys - EXPECTED_STATE_KEYS
            raise LedgerCorruptError(
                f"State closed schema violation: missing={sorted(missing)}, unexpected={sorted(unexpected)}"
            )

        schema_v = state.get("schema_version")
        if type(schema_v) is not int or isinstance(schema_v, bool) or schema_v != SCHEMA_VERSION:
            raise LedgerCorruptError(
                f"Unsupported schema version: {schema_v!r} (expected {SCHEMA_VERSION})"
            )

        created_str = _validate_timestamp(state.get("created_at_utc"))
        updated_str = _validate_timestamp(state.get("updated_at_utc"))
        dt_c = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        dt_u = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
        if dt_u < dt_c:
            raise LedgerCorruptError(
                f"updated_at_utc ({updated_str}) precedes created_at_utc ({created_str})"
            )

        exp_id = _validate_identifier(state["experiment_id"], "experiment_id")
        if expected_experiment_id is not None and exp_id != expected_experiment_id:
            raise LedgerCorruptError(
                f"Experiment ID mismatch: {exp_id!r} (expected {expected_experiment_id!r})"
            )

        ceiling = _validate_int(state["global_ceiling_micros"], "global_ceiling_micros")
        if ceiling != GLOBAL_CEILING_MICROS or type(state["global_ceiling_micros"]) is not int:
            raise LedgerCorruptError("Immutable global_ceiling_micros altered")
        res_amt = _validate_int(state["reservation_amount_micros"], "reservation_amount_micros")
        if res_amt != RESERVATION_AMOUNT_MICROS or type(state["reservation_amount_micros"]) is not int:
            raise LedgerCorruptError("Immutable reservation_amount_micros altered")

        committed = _validate_int(state["committed_spend_micros"], "committed_spend_micros")
        retained = _validate_int(state["retained_failed_micros"], "retained_failed_micros")

        # Pending reservation validation
        pending = state.get("pending_reservation")
        pending_amount = 0
        if pending is not None:
            if not isinstance(pending, dict):
                raise LedgerCorruptError("pending_reservation must be a dictionary or None")
            if frozenset(pending.keys()) != EXPECTED_PENDING_KEYS:
                raise LedgerCorruptError(
                    f"pending_reservation schema violation: expected {sorted(EXPECTED_PENDING_KEYS)}, got {sorted(pending.keys())}"
                )
            _validate_identifier(pending["reservation_id"], "pending reservation_id")
            _validate_identifier(pending["request_id"], "pending request_id")
            _validate_digest(pending["request_digest"])
            pending_amount = _validate_int(pending["reserved_amount_micros"], "pending reserved_amount_micros")
            _validate_timestamp(pending["reserved_at_utc"])
            _validate_int(pending["pid"], "pending pid")
            if (not MIN_RESERVATION_MICROS <= pending_amount <= RESERVATION_AMOUNT_MICROS
                    or type(pending["reserved_amount_micros"]) is not int):
                raise LedgerCorruptError("pending_reservation amount mismatch")

        reservations = _validate_int(
            state["total_reservations_count"],
            "total_reservations_count",
            max_val=MAX_FORWARDED_REQUESTS,
        )
        settled = _validate_int(
            state["settled_requests_count"],
            "settled_requests_count",
            max_val=reservations,
        )

        halted = state["halted"]
        if not isinstance(halted, bool):
            raise LedgerCorruptError("halted field must be a boolean")

        halt_reason = state["halt_reason"]
        if halted:
            if not isinstance(halt_reason, str) or not halt_reason.strip():
                raise LedgerCorruptError("halt_reason must be a non-empty string when halted is True")
            if halt_reason not in ALLOWED_INTERNAL_FAILURE_CODES:
                raise LedgerCorruptError(
                    f"halt_reason {halt_reason!r} not in ALLOWED_INTERNAL_FAILURE_CODES"
                )
        if not halted and halt_reason is not None:
            raise LedgerCorruptError("halt_reason must be None when halted is False")

        # Deep Typed Journal Replay & State Machine Transitions
        journal = state["journal"]
        if not isinstance(journal, list) or len(journal) == 0:
            raise LedgerCorruptError("journal must be a non-empty list")
        if len(journal) > MAX_JOURNAL_ENTRIES:
            raise LedgerCorruptError(f"journal exceeds maximum length of {MAX_JOURNAL_ENTRIES}")

        # Exactly one INITIALIZED event at index 0
        init_entry = journal[0]
        if not isinstance(init_entry, dict) or init_entry.get("entry_type") != "INITIALIZED":
            raise LedgerCorruptError("First journal entry must be INITIALIZED")
        if frozenset(init_entry.keys()) != EXPECTED_JOURNAL_INITIALIZED_KEYS:
            raise LedgerCorruptError(
                f"INITIALIZED journal entry schema violation: expected {sorted(EXPECTED_JOURNAL_INITIALIZED_KEYS)}, got {sorted(init_entry.keys())}"
            )
        if init_entry["experiment_id"] != exp_id:
            raise LedgerCorruptError("INITIALIZED entry experiment_id mismatch")
        init_ceiling = _validate_int(init_entry["global_ceiling_micros"], "INITIALIZED entry global_ceiling_micros")
        if init_ceiling != GLOBAL_CEILING_MICROS or type(init_entry["global_ceiling_micros"]) is not int:
            raise LedgerCorruptError("INITIALIZED entry global_ceiling_micros mismatch")
        _validate_timestamp(init_entry["timestamp_utc"])

        seen_permits = set()
        seen_requests = set()
        seen_responses = set()
        historical_settled_map = {}
        historical_reserved_map = {}
        active_res = None
        has_terminal_halt = False
        has_terminal_uncertainty = False
        uncertain_settled_count = 0
        terminal_halt_reason = None
        j_settled_amount = 0
        j_retained_amount = 0
        j_retained_count = 0
        j_settled_count = 0
        j_reserved_count = 0

        for idx, entry in enumerate(journal[1:], start=1):
            if not isinstance(entry, dict):
                raise LedgerCorruptError(f"Journal entry at index {idx} must be a dictionary")

            etype = entry.get("entry_type")
            if etype not in VALID_JOURNAL_ENTRY_TYPES or etype == "INITIALIZED":
                raise LedgerCorruptError(f"Forbidden or malformed journal entry type at index {idx}: {etype!r}")

            if has_terminal_halt:
                raise LedgerCorruptError(f"Event found at index {idx} after terminal halt had already occurred")

            _validate_timestamp(entry.get("timestamp_utc"))

            if etype == "RESERVED":
                if frozenset(entry.keys()) != EXPECTED_JOURNAL_RESERVED_KEYS:
                    raise LedgerCorruptError(
                        f"RESERVED journal entry schema violation at index {idx}: "
                        f"expected {sorted(EXPECTED_JOURNAL_RESERVED_KEYS)}, got {sorted(entry.keys())}"
                    )
                if active_res is not None:
                    raise LedgerCorruptError(
                        f"State machine violation at index {idx}: new RESERVED entry while previous reservation ({active_res['reservation_id']}) is active"
                    )

                pid_val = _validate_identifier(entry["reservation_id"], f"index {idx} reservation_id")
                req_id = _validate_identifier(entry["request_id"], f"index {idx} request_id")
                req_dig = _validate_digest(entry["request_digest"])
                _validate_int(entry["reserved_amount_micros"], f"index {idx} reserved_amount_micros")
                res_idx = _validate_int(entry["reservation_index"], f"index {idx} reservation_index")

                if pid_val in seen_permits:
                    raise LedgerCorruptError(f"Duplicate reservation_id in journal at index {idx}: {pid_val!r}")
                if req_id in seen_requests:
                    raise LedgerCorruptError(f"Duplicate request_id in journal at index {idx}: {req_id!r}")

                seen_permits.add(pid_val)
                seen_requests.add(req_id)

                j_reserved_count += 1
                if res_idx != j_reserved_count:
                    raise LedgerCorruptError(
                        f"reservation_index mismatch at index {idx}: expected {j_reserved_count}, got {res_idx}"
                    )
                res_amt = _validate_int(entry["reserved_amount_micros"], f"index {idx} reserved_amount_micros")
                if (not MIN_RESERVATION_MICROS <= res_amt <= RESERVATION_AMOUNT_MICROS
                        or type(entry["reserved_amount_micros"]) is not int):
                    raise LedgerCorruptError(f"reserved_amount_micros mismatch at index {idx}")

                # Enforce replay ceiling at EVERY RESERVED transition
                if j_settled_amount + j_retained_amount + res_amt > GLOBAL_CEILING_MICROS:
                    raise LedgerCorruptError(
                        f"Replay ceiling violation at index {idx}: committed ({j_settled_amount}) "
                        f"+ retained ({j_retained_amount}) + reserved ({res_amt}) "
                        f"> ceiling ({GLOBAL_CEILING_MICROS})"
                    )

                active_res = entry

            elif etype == "SETTLED":
                if frozenset(entry.keys()) != EXPECTED_JOURNAL_SETTLED_KEYS:
                    raise LedgerCorruptError(
                        f"SETTLED journal entry schema violation at index {idx}: "
                        f"expected {sorted(EXPECTED_JOURNAL_SETTLED_KEYS)}, got {sorted(entry.keys())}"
                    )
                if active_res is None:
                    raise LedgerCorruptError(
                        f"State machine violation at index {idx}: SETTLED entry without active pending reservation"
                    )

                pid_val = _validate_identifier(entry["reservation_id"], f"index {idx} reservation_id")
                req_id = _validate_identifier(entry["request_id"], f"index {idx} request_id")
                req_dig = _validate_digest(entry["request_digest"])
                resp_id = _validate_identifier(entry["response_id"], f"index {idx} response_id")

                if pid_val != active_res["reservation_id"]:
                    raise LedgerCorruptError(f"reservation_id mismatch in SETTLED entry at index {idx}")
                if req_id != active_res["request_id"] or req_dig != active_res["request_digest"]:
                    raise LedgerCorruptError(f"Request identity mismatch in SETTLED entry at index {idx}")

                if entry["model"] not in MODEL_RATES:
                    raise LedgerCorruptError(f"Model mismatch in SETTLED entry at index {idx}: expected {PINNED_MODEL}")
                if entry["service_tier"] != MODEL_RATES[entry["model"]][2]:
                    raise LedgerCorruptError(f"Service tier mismatch in SETTLED entry at index {idx}: expected {PINNED_SERVICE_TIER}")

                if resp_id in seen_responses:
                    raise LedgerCorruptError(f"Duplicate response_id across SETTLED entries: {resp_id!r}")
                seen_responses.add(resp_id)

                in_tok = _validate_int(entry["input_tokens"], f"index {idx} input_tokens", max_val=MAX_INPUT_TOKENS)
                out_tok = _validate_int(entry["output_tokens"], f"index {idx} output_tokens", max_val=MAX_OUTPUT_TOKENS)
                tot_tok = _validate_int(entry["total_tokens"], f"index {idx} total_tokens")
                settled_amt = _validate_int(entry["settled_amount_micros"], f"index {idx} settled_amount_micros")
                unencumbered = _validate_int(entry["unencumbered_amount_micros"], f"index {idx} unencumbered_amount_micros")

                if tot_tok != (in_tok + out_tok):
                    raise LedgerCorruptError(f"total_tokens mismatch in SETTLED entry at index {idx}")

                expected_amt = model_cost_micros(entry["model"], entry["service_tier"], in_tok, out_tok)
                if settled_amt != expected_amt:
                    raise LedgerCorruptError(
                        f"settled_amount_micros derivation error at index {idx}: expected {expected_amt}, got {settled_amt}"
                    )

                if unencumbered != (active_res["reserved_amount_micros"] - settled_amt):
                    raise LedgerCorruptError(f"unencumbered_amount_micros derivation error at index {idx}")

                historical_settled_map[pid_val] = settled_amt
                historical_reserved_map[pid_val] = active_res["reserved_amount_micros"]
                j_settled_amount += settled_amt
                j_settled_count += 1
                active_res = None

            elif etype == "FAILED_RETAINED":
                if frozenset(entry.keys()) != EXPECTED_JOURNAL_FAILED_RETAINED_KEYS:
                    raise LedgerCorruptError(
                        f"FAILED_RETAINED journal entry schema violation at index {idx}: "
                        f"expected {sorted(EXPECTED_JOURNAL_FAILED_RETAINED_KEYS)}, got {sorted(entry.keys())}"
                    )
                if active_res is None:
                    raise LedgerCorruptError(
                        f"State machine violation at index {idx}: FAILED_RETAINED entry without active pending reservation"
                    )

                pid_val = _validate_identifier(entry["reservation_id"], f"index {idx} reservation_id")
                req_id = _validate_identifier(entry["request_id"], f"index {idx} request_id")
                retained_amt = _validate_int(entry["retained_amount_micros"], f"index {idx} retained_amount_micros")
                _replay_reason(entry["reason"])

                if pid_val != active_res["reservation_id"] or req_id != active_res["request_id"]:
                    raise LedgerCorruptError(f"Reservation identity mismatch in FAILED_RETAINED entry at index {idx}")
                if retained_amt != active_res["reserved_amount_micros"]:
                    raise LedgerCorruptError(f"retained_amount_micros mismatch at index {idx}")

                j_retained_amount += retained_amt
                j_retained_count += 1
                active_res = None
                has_terminal_halt = True
                terminal_halt_reason = entry["reason"]

            elif etype == "ORPHANED_PENDING_HALTED":
                if frozenset(entry.keys()) != EXPECTED_JOURNAL_ORPHANED_KEYS:
                    raise LedgerCorruptError(
                        f"ORPHANED_PENDING_HALTED journal entry schema violation at index {idx}: "
                        f"expected {sorted(EXPECTED_JOURNAL_ORPHANED_KEYS)}, got {sorted(entry.keys())}"
                    )
                if active_res is None:
                    raise LedgerCorruptError(
                        f"State machine violation at index {idx}: ORPHANED_PENDING_HALTED entry without active pending reservation"
                    )

                pid_val = _validate_identifier(entry["reservation_id"], f"index {idx} reservation_id")
                req_id = _validate_identifier(entry["request_id"], f"index {idx} request_id")
                retained_amt = _validate_int(entry["retained_amount_micros"], f"index {idx} retained_amount_micros")
                _replay_reason(entry["reason"])

                if pid_val != active_res["reservation_id"] or req_id != active_res["request_id"]:
                    raise LedgerCorruptError(f"Reservation identity mismatch in ORPHANED_PENDING_HALTED entry at index {idx}")
                if retained_amt != active_res["reserved_amount_micros"]:
                    raise LedgerCorruptError(f"retained_amount_micros mismatch at index {idx}")

                j_retained_amount += retained_amt
                j_retained_count += 1
                active_res = None
                has_terminal_halt = True
                terminal_halt_reason = entry["reason"]

            elif etype == "TERMINAL_UNCERTAINTY":
                if idx != len(journal) - 1:
                    raise LedgerCorruptError(
                        f"TERMINAL_UNCERTAINTY entry at index {idx} must be the final journal entry"
                    )
                if frozenset(entry.keys()) != EXPECTED_JOURNAL_TERMINAL_UNCERTAINTY_KEYS:
                    raise LedgerCorruptError(
                        f"TERMINAL_UNCERTAINTY entry schema violation at index {idx}: "
                        f"expected {sorted(EXPECTED_JOURNAL_TERMINAL_UNCERTAINTY_KEYS)}, got {sorted(entry.keys())}"
                    )
                if entry["reason"] not in TERMINAL_UNCERTAINTY_REASONS:
                    raise LedgerCorruptError("TERMINAL_UNCERTAINTY entry carries a non-terminal-uncertainty reason")

                uncertain_ids = entry.get("uncertain_reservation_ids")
                if not isinstance(uncertain_ids, list):
                    raise LedgerCorruptError("uncertain_reservation_ids must be a list of reservation IDs")
                if not uncertain_ids and seen_permits:
                    raise LedgerCorruptError(
                        "uncertain_reservation_ids may be empty only when no reservation was ever recorded"
                    )
                if len(uncertain_ids) > MAX_JOURNAL_ENTRIES:
                    raise LedgerCorruptError(f"uncertain_reservation_ids exceeds maximum of {MAX_JOURNAL_ENTRIES}")
                for uid in uncertain_ids:
                    if type(uid) is not str:
                        raise LedgerCorruptError("uncertain_reservation_ids must contain strings")
                if len(uncertain_ids) != len(set(uncertain_ids)):
                    raise LedgerCorruptError("uncertain_reservation_ids contains duplicate IDs")
                if uncertain_ids != sorted(uncertain_ids):
                    raise LedgerCorruptError("uncertain_reservation_ids must be sorted")

                for uid in uncertain_ids:
                    # Only EXISTING reservations may be referenced; never invent unknown ones
                    if uid in historical_settled_map:
                        # Replace the affected settled bound with its full reservation exactly once
                        j_settled_amount -= historical_settled_map[uid]
                        j_retained_amount += historical_reserved_map[uid]
                        j_retained_count += 1
                        uncertain_settled_count += 1
                    elif active_res is not None and uid == active_res["reservation_id"]:
                        j_retained_amount += active_res["reserved_amount_micros"]
                        j_retained_count += 1
                        active_res = None
                    else:
                        raise LedgerCorruptError("Unknown or non-recoverable reservation_id in uncertain_reservation_ids")

                if active_res is not None:
                    raise LedgerCorruptError("TERMINAL_UNCERTAINTY must cover the current pending reservation")

                has_terminal_halt = True
                has_terminal_uncertainty = True
                terminal_halt_reason = entry["reason"]

        # Terminal halt derived from history
        if halted and not has_terminal_halt:
            raise LedgerCorruptError("Top-level halted flag is True but replayed history has no terminal event")
        if has_terminal_halt:
            if not halted:
                raise LedgerCorruptError("Top-level state halted flag is False but history contains a terminal failure")
            if halt_reason != terminal_halt_reason:
                raise LedgerCorruptError(
                    f"Top-level halt_reason {halt_reason!r} does not match terminal failure reason {terminal_halt_reason!r}"
                )
            if pending is not None:
                raise LedgerCorruptError("pending_reservation must be None when ledger has terminally halted")

        # Verify active reservation matches pending_reservation
        if pending is None:
            if active_res is not None:
                raise LedgerCorruptError(
                    f"Accounting imbalance: active reservation {active_res['reservation_id']} exists in journal but pending_reservation is None"
                )
        else:
            if active_res is None:
                raise LedgerCorruptError(
                    "Accounting imbalance: pending_reservation is present but no active reservation exists in journal"
                )
            if (
                pending["reservation_id"] != active_res["reservation_id"]
                or pending["request_id"] != active_res["request_id"]
                or pending["request_digest"] != active_res["request_digest"]
            ):
                raise LedgerCorruptError(
                    "Identity mismatch between pending_reservation and journal active reservation"
                )

        # Enforce final pending ceiling constraint
        if pending is not None:
            if j_settled_amount + j_retained_amount + pending["reserved_amount_micros"] > GLOBAL_CEILING_MICROS:
                raise LedgerCorruptError(
                    f"Replay ceiling violation with pending reservation: committed ({j_settled_amount}) "
                    f"+ retained ({j_retained_amount}) + pending ({pending['reserved_amount_micros']}) "
                    f"> ceiling ({GLOBAL_CEILING_MICROS})"
                )

        if not has_terminal_uncertainty:
            if j_settled_amount + j_retained_amount + pending_amount > GLOBAL_CEILING_MICROS:
                raise LedgerCorruptError(
                    f"Replay ceiling violation: committed ({j_settled_amount}) "
                    f"+ retained ({j_retained_amount}) > ceiling ({GLOBAL_CEILING_MICROS})"
                )

        # Derive totals and reconcile state values
        if j_reserved_count != reservations:
            raise LedgerCorruptError(
                f"Reconciliation error: journal RESERVED entries ({j_reserved_count}) != total_reservations_count ({reservations})"
            )
        if j_settled_count != settled:
            raise LedgerCorruptError(
                f"Reconciliation error: journal SETTLED entries ({j_settled_count}) != settled_requests_count ({settled})"
            )
        if j_settled_amount != committed:
            raise LedgerCorruptError(
                f"Reconciliation error: journal settled sum ({j_settled_amount}) != committed_spend_micros ({committed})"
            )
        if j_retained_amount != retained:
            raise LedgerCorruptError(
                f"Reconciliation error: journal retained sum ({j_retained_amount}) != retained_failed_micros ({retained})"
            )

        failed_count = j_retained_count
        if has_terminal_uncertainty:
            expected_reservations = (settled - uncertain_settled_count) + failed_count
        else:
            expected_reservations = settled + failed_count + (1 if pending is not None else 0)

        if reservations != expected_reservations:
            raise LedgerCorruptError(
                f"Accounting balance violation: reservations ({reservations}) != "
                f"expected ({expected_reservations})"
            )

    def _atomic_write_state(self, state: dict, dir_fd: int) -> None:
        """Durable atomic write: write to temp file, fsync, rename, and directory fsync relative to dir_fd."""
        self._atomic_write_state_static(state, dir_fd, expected_experiment_id=self._experiment_id)

    @classmethod
    def _atomic_write_state_static(
        cls,
        state: dict,
        dir_fd: int,
        expected_experiment_id: Optional[str] = None,
    ) -> None:
        """Static durable atomic state write relative to dir_fd."""
        cls._validate_and_reconcile_state_static(state, expected_experiment_id)

        encoded = json.dumps(state, indent=2, sort_keys=True).encode("utf-8")

        if len(encoded) > MAX_STATE_FILE_BYTES:
            raise LedgerSecurityError(
                f"Encoded state size ({len(encoded)}) exceeds maximum limit of {MAX_STATE_FILE_BYTES} bytes"
            )

        cls._publish_bytes_static(encoded, STATE_FILENAME, ".tmp_ledger_", dir_fd)
