"""Independent read-only recorded-state report (no active handle, no recovery).

Constructs no BudgetLedger, broker, credential loader or transport; never calls
open()/get_status()/recovery; never writes, creates, synchronizes, replaces or
deletes anything; never opens the guard, intent, confirmation or permit-lease
files. The report is a validated persisted-journal projection ONLY.
"""

import fcntl
import hashlib
import os
from typing import Tuple

from .constants import MAX_STATE_FILE_BYTES
from .exceptions import LedgerCorruptError, LedgerReportUnavailableError
from .ledger import BudgetLedger, _safe_json_loads
from .models import LedgerBinding, RecordedLedgerReport
from .readonly_io import (
    LEDGER_STATE_ENTRY,
    IoFailure,
    OwnedFds,
    check_json_depth,
    cleanup_after_failure,
    entry_identity,
    final_entry_checks,
    open_entry,
    open_ledger_and_lock,
    unlock,
    validate_regular,
)

_CODES = {"invalid": "REPORT_INVALID", "io": "REPORT_IO_FAILED", "busy": "REPORT_BUSY"}


def _read_snapshot(state_fd: int) -> Tuple[bytes, Tuple[int, int], os.stat_result]:
    state_id, st = validate_regular(state_fd)
    if st.st_size > MAX_STATE_FILE_BYTES:
        raise IoFailure("invalid")
    data = bytearray()
    try:
        while len(data) <= MAX_STATE_FILE_BYTES:
            chunk = os.read(state_fd, min(4096, MAX_STATE_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(state_fd)
    except OSError:
        raise IoFailure("io") from None
    if len(data) > MAX_STATE_FILE_BYTES:
        raise IoFailure("invalid")
    # short or changing reads relative to the validated descriptor snapshot
    if (
        len(data) != st.st_size
        or after.st_size != st.st_size
        or after.st_mtime_ns != st.st_mtime_ns
        or (after.st_dev, after.st_ino) != state_id
    ):
        raise IoFailure("invalid")
    return bytes(data), state_id, st


def read_recorded_report(experiment_root_fd: int, expected_binding: LedgerBinding) -> RecordedLedgerReport:
    """Return a RecordedLedgerReport for the ledger bound by `expected_binding`.

    `experiment_root_fd` is borrowed: never closed, duplicated or owned here.
    """
    if (
        type(experiment_root_fd) is not int
        or experiment_root_fd < 0
        or not isinstance(expected_binding, LedgerBinding)
    ):
        raise LedgerReportUnavailableError("REPORT_INVALID") from None

    owned = OwnedFds()
    locked_fd = None
    kind = None
    report = None
    try:
        ledger_fd, dir_id, lock_fd, lock_id = open_ledger_and_lock(experiment_root_fd, owned, fcntl.LOCK_SH)
        locked_fd = lock_fd
        if dir_id != (expected_binding.directory_device, expected_binding.directory_inode):
            raise IoFailure("invalid")
        if lock_id != (expected_binding.transaction_lock_device, expected_binding.transaction_lock_inode):
            raise IoFailure("invalid")

        state_fd = open_entry(LEDGER_STATE_ENTRY, ledger_fd, owned, directory=False)
        raw, state_id, _ = _read_snapshot(state_fd)

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise IoFailure("invalid") from None
        check_json_depth(text)
        try:
            state = _safe_json_loads(text)
            BudgetLedger._validate_and_reconcile_state_static(state, expected_binding.experiment_id)
        except LedgerCorruptError:
            raise IoFailure("invalid") from None

        final_entry_checks(experiment_root_fd, ledger_fd, lock_fd, dir_id, lock_id)
        if entry_identity(LEDGER_STATE_ENTRY, ledger_fd, directory=False) != state_id:
            raise IoFailure("invalid")
        if validate_regular(state_fd)[0] != state_id:
            raise IoFailure("invalid")

        pending = state["pending_reservation"]
        report = RecordedLedgerReport(
            binding=expected_binding,
            state_sha256=hashlib.sha256(raw).hexdigest(),
            recorded_halted=state["halted"],
            recorded_halt_reason=state["halt_reason"],
            recorded_committed_micros=state["committed_spend_micros"],
            recorded_retained_micros=state["retained_failed_micros"],
            recorded_pending_micros=pending["reserved_amount_micros"] if pending is not None else 0,
            recorded_total_reservations=state["total_reservations_count"],
            recorded_settled_requests=state["settled_requests_count"],
        )
        unlock(lock_fd)
        locked_fd = None
        if owned.close_all():
            raise IoFailure("io")
        return report
    except IoFailure as failure:
        kind = failure.kind
        interrupt = None
    except Exception:
        kind = "io"
        interrupt = None
    except BaseException as exc:  # noqa: BLE001 - KeyboardInterrupt/SystemExit after acquisition
        kind = "io"
        interrupt = exc
    # failure cleanup: unconditional, bounded, every owned resource visited once, no retries;
    # termination exceptions propagate AFTER cleanup and never yield a partial report
    cleanup_interrupt = cleanup_after_failure(owned, locked_fd)  # always runs, never short-circuited
    interrupt = interrupt or cleanup_interrupt
    if interrupt is not None:
        raise interrupt
    raise LedgerReportUnavailableError(_CODES[kind]) from None
