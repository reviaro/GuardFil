"""Offline adversarial regression and contract test suite for BudgetLedger.

Exercises all numeric cost constraints, concurrency, crash recovery, security
protections, durability boundaries, and failure handling from research/t2a/codex-issue.md Stage B.
Uses Python stdlib unittest and owned private temporary directories.
Zero network access, zero external dependencies.
"""

import errno
import fcntl
import gc
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

# Ensure repo root is on sys.path for both package and direct module execution
_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from research.t2a.openai_budget.constants import (
    ALLOWED_INTERNAL_FAILURE_CODES,
    CONFIRMATION_FILE_PREFIX,
    DEFAULT_EXPERIMENT_ID,
    GLOBAL_CEILING_MICROS,
    INPUT_TOKEN_RATE_MICROS,
    INSPECTION_COMPLETION_FILENAME,
    INSPECTION_GUARD_FILENAME,
    INTENT_FILENAME,
    INTENT_FILE_PREFIX,
    LEASE_FILENAME,
    LOCK_FILENAME,
    MAX_FORWARDED_REQUESTS,
    MAX_IN_FLIGHT_REQUESTS,
    MAX_INPUT_TOKENS,
    MAX_INSPECTION_GENERATION,
    MAX_OUTPUT_TOKENS,
    MAX_REASON_LENGTH,
    OUTPUT_TOKEN_RATE_MICROS,
    PINNED_MODEL,
    PINNED_SERVICE_TIER,
    RESERVATION_AMOUNT_MICROS,
    STATE_FILENAME,
    TERMINAL_STATUS_COMPLETED,
)
from research.t2a.openai_budget.exceptions import (
    BudgetExceededError,
    InFlightReservationError,
    LedgerAlreadyExistsError,
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
from research.t2a.openai_budget.ledger import BudgetLedger
from research.t2a.openai_budget.models import (
    FailureResult,
    LedgerStatus,
    Receipt,
    ReservationPermit,
    SettlementCommittedHandleDisabledOutcome,
    SettlementResult,
)


def _concurrent_worker_reserve(
    ledger_dir: str,
    req_id: str,
    digest: str,
    barrier: multiprocessing.Barrier,
    result_queue: multiprocessing.Queue,
    settle_event: multiprocessing.Event,
):
    """Worker process attempting to secure a reservation concurrently and deterministically."""
    try:
        ledger = BudgetLedger.open(ledger_dir)
        barrier.wait()
        permit = ledger.reserve(req_id, digest)
        result_queue.put(("SUCCESS", permit.permit_id))

        # Hold the reservation until the competing worker has made its attempt and signaled
        settle_event.wait(timeout=5)

        # Settle cleanly before worker exits
        ledger.settle(
            permit,
            {
                "status": "completed",
                "response_id": f"resp_{req_id}",
                "request_id": req_id,
                "request_digest": digest,
                "model": "gpt-6-luna",
                "service_tier": "default",
                "input_tokens": 100,
                "output_tokens": 50,
                "total_tokens": 150,
            },
        )
    except Exception as exc:
        result_queue.put((type(exc).__name__, str(exc)))
        # Unblock the winning worker to settle
        settle_event.set()


def _crashed_reserving_worker(ledger_dir: str, req_id: str, digest: str):
    """Worker process that reserves funds and exits without settling (simulating crash)."""
    ledger = BudgetLedger.open(ledger_dir)
    ledger.reserve(req_id, digest)


def _concurrent_init_worker(ledger_dir: str, result_queue: multiprocessing.Queue):
    """Worker process attempting to initialize the same ledger directory."""
    try:
        BudgetLedger.initialize(ledger_dir)
        result_queue.put(("SUCCESS", None))
    except Exception as exc:
        result_queue.put((type(exc).__name__, str(exc)))


def _make_receipt(
    permit: ReservationPermit,
    status: str = "completed",
    response_id: str = "resp_001",
    model: str = "gpt-6-luna",
    service_tier: str = "default",
    input_tokens: int = 10_000,
    output_tokens: int = 500,
    total_tokens: int | None = None,
    extra_fields: dict | None = None,
) -> dict:
    if total_tokens is None:
        total_tokens = input_tokens + output_tokens
    receipt = {
        "status": status,
        "response_id": response_id,
        "request_id": permit.request_id,
        "request_digest": permit.request_digest,
        "model": model,
        "service_tier": service_tier,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }
    if extra_fields:
        receipt.update(extra_fields)
    return receipt


class TestBudgetLedger(unittest.TestCase):
    """Comprehensive test suite for BudgetLedger contract and invariants."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-test-")
        self.ledger_dir = os.path.join(self.temp_dir.name, "ledger")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Initialization and Open Semantics
    # -------------------------------------------------------------------------

    def test_initialize_creates_private_directory_and_state(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        self.assertTrue(os.path.isdir(self.ledger_dir))

        st = os.stat(self.ledger_dir)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        self.assertTrue(os.path.isfile(state_path))
        st_file = os.stat(state_path)
        self.assertEqual(stat.S_IMODE(st_file.st_mode), 0o600)

        status = ledger.get_status()
        self.assertEqual(status.committed_spend_micros, 0)
        self.assertEqual(status.retained_failed_micros, 0)
        self.assertEqual(status.total_reservations_count, 0)
        self.assertEqual(status.settled_requests_count, 0)
        self.assertFalse(status.has_pending_reservation)
        self.assertFalse(status.halted)
        self.assertTrue(status.can_reserve)

    def test_initialize_refuses_preexisting_directory(self):
        """Finding 2: initialize() strictly refuses pre-existing target directory."""
        os.mkdir(self.ledger_dir, 0o700)
        with self.assertRaises(LedgerAlreadyExistsError):
            BudgetLedger.initialize(self.ledger_dir)

    def test_initialize_refuses_preexisting_empty_or_tampered_dir(self):
        """Finding 2: initialize() refuses existing directory even if state file is missing."""
        os.mkdir(self.ledger_dir, 0o700)
        lock_path = os.path.join(self.ledger_dir, LOCK_FILENAME)
        Path(lock_path).touch(mode=0o600)

        with self.assertRaises(LedgerAlreadyExistsError):
            BudgetLedger.initialize(self.ledger_dir)

    def test_open_missing_directory_fails_closed(self):
        missing_dir = os.path.join(self.temp_dir.name, "nonexistent")
        with self.assertRaises(LedgerNotFoundError):
            BudgetLedger.open(missing_dir)

    def test_open_missing_state_file_fails_closed(self):
        empty_dir = os.path.join(self.temp_dir.name, "empty_dir")
        os.mkdir(empty_dir, 0o700)
        with self.assertRaises(LedgerNotFoundError):
            BudgetLedger.open(empty_dir)

    # -------------------------------------------------------------------------
    # 2. Filesystem Security, Permissions & Anchored Descriptors
    # -------------------------------------------------------------------------

    def test_security_rejects_symlinked_directory(self):
        real_dir = os.path.join(self.temp_dir.name, "real_dir")
        BudgetLedger.initialize(real_dir)
        symlink_dir = os.path.join(self.temp_dir.name, "symlink_dir")
        os.symlink(real_dir, symlink_dir)

        with self.assertRaises(LedgerSecurityError):
            BudgetLedger.open(symlink_dir)

    def test_security_rejects_symlinked_state_file(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        real_target = os.path.join(self.temp_dir.name, "target_state.json")
        os.rename(state_path, real_target)
        os.symlink(real_target, state_path)

        with self.assertRaises(LedgerSecurityError):
            BudgetLedger.open(self.ledger_dir)

    def test_security_rejects_symlinked_lock_file(self):
        """Finding 4: Lock open with O_NOFOLLOW must reject symlinked lock file."""
        BudgetLedger.initialize(self.ledger_dir)
        lock_path = os.path.join(self.ledger_dir, LOCK_FILENAME)
        real_target = os.path.join(self.temp_dir.name, "target_lock")
        Path(real_target).touch(mode=0o600)
        if os.path.exists(lock_path):
            os.unlink(lock_path)
        os.symlink(real_target, lock_path)

        with self.assertRaises(LedgerSecurityError):
            BudgetLedger.open(self.ledger_dir)

    def test_security_rejects_hard_links_on_lock_or_state(self):
        """Finding 4: Hard links are strictly forbidden on ledger files."""
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        hardlink_path = os.path.join(self.temp_dir.name, "state_hardlink.json")
        os.link(state_path, hardlink_path)

        with self.assertRaises(LedgerSecurityError):
            BudgetLedger.open(self.ledger_dir)

    def test_security_rejects_permissive_directory_permissions(self):
        BudgetLedger.initialize(self.ledger_dir)
        os.chmod(self.ledger_dir, 0o777)
        with self.assertRaises(LedgerSecurityError):
            BudgetLedger.open(self.ledger_dir)

    def test_security_rejects_permissive_state_file_permissions(self):
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        os.chmod(state_path, 0o666)
        with self.assertRaises(LedgerSecurityError):
            BudgetLedger.open(self.ledger_dir)

    # -------------------------------------------------------------------------
    # 3. Reservation and In-Flight Invariants
    # -------------------------------------------------------------------------

    def test_single_reservation_success(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:abc123digest")

        self.assertEqual(permit.request_id, "req_001")
        self.assertEqual(permit.request_digest, "sha256:abc123digest")
        self.assertEqual(permit.reserved_amount_micros, RESERVATION_AMOUNT_MICROS)
        self.assertTrue(permit.permit_id.startswith("permit_"))

        status = ledger.get_status()
        self.assertTrue(status.has_pending_reservation)
        self.assertEqual(status.pending_request_id, "req_001")
        self.assertEqual(status.pending_reserved_micros, 1_100_000)
        self.assertEqual(status.total_encumbered_micros, 1_100_000)
        self.assertEqual(status.remaining_available_micros, 900_000)
        self.assertFalse(status.can_reserve)

    def test_second_reservation_in_flight_strictly_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        ledger.reserve("req_001", "sha256:first")

        with self.assertRaises(InFlightReservationError):
            ledger.reserve("req_002", "sha256:second")

    def test_reused_request_id_in_reserve_rejected(self):
        """Finding 3: Reusing request ID cannot authorize new calls."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:first")
        ledger.settle(permit, _make_receipt(permit, response_id="resp_001"))

        # Attempt to reserve again with same request_id
        with self.assertRaises(ValueError):
            ledger.reserve("req_001", "sha256:another")

    def test_invalid_request_parameters_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        with self.assertRaises(ValueError):
            ledger.reserve("", "sha256:digest")
        with self.assertRaises(ValueError):
            ledger.reserve("req_001", "")
        with self.assertRaises(ValueError):
            ledger.reserve(None, "sha256:digest")

    # -------------------------------------------------------------------------
    # 4. Settlement and Token Accounting Tests
    # -------------------------------------------------------------------------

    def test_successful_settlement_within_ceiling(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        receipt = _make_receipt(
            permit,
            input_tokens=100_000,
            output_tokens=500,
            total_tokens=100_500,
        )
        res = ledger.settle(permit, receipt)

        # 100,000 * 1 + 500 * 1 = 100,500 uUSD ($0.1005 USD)
        self.assertEqual(res.actual_cost_micros, 100_500)
        self.assertEqual(res.refunded_amount_micros, 1_100_000 - 100_500)
        self.assertEqual(res.response_id, "resp_001")

        status = ledger.get_status()
        self.assertEqual(status.committed_spend_micros, 100_500)
        self.assertEqual(status.retained_failed_micros, 0)
        self.assertEqual(status.settled_requests_count, 1)
        self.assertFalse(status.has_pending_reservation)
        self.assertFalse(status.halted)
        self.assertTrue(status.can_reserve)

    def test_settle_then_second_reserve_within_ceiling(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)

        # Request 1: 50,000 tokens ($0.05 USD)
        p1 = ledger.reserve("req_001", "sha256:p1")
        ledger.settle(p1, _make_receipt(p1, response_id="resp_001", input_tokens=49_000, output_tokens=1_000))

        status1 = ledger.get_status()
        self.assertEqual(status1.committed_spend_micros, 50_000)

        # Request 2: Next reserve allowed ($0.05 + $1.10 = $1.15 <= $2.00)
        p2 = ledger.reserve("req_002", "sha256:p2")
        self.assertEqual(p2.request_id, "req_002")

        ledger.settle(p2, _make_receipt(p2, response_id="resp_002", input_tokens=10_000, output_tokens=200))
        status2 = ledger.get_status()
        self.assertEqual(status2.committed_spend_micros, 50_000 + 10_200)
        self.assertEqual(status2.settled_requests_count, 2)

    def test_max_supported_input_and_enforced_output_cost(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        receipt = _make_receipt(
            permit,
            input_tokens=MAX_INPUT_TOKENS,   # 1,050,000
            output_tokens=MAX_OUTPUT_TOKENS,  # 1,024
            total_tokens=MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS,
        )
        res = ledger.settle(permit, receipt)
        expected_cost = 1_050_000 + 1024
        self.assertEqual(res.actual_cost_micros, expected_cost)
        self.assertEqual(res.refunded_amount_micros, 1_100_000 - expected_cost)

    def test_reject_cache_discount_claims(self):
        """Receipt cannot contain cache discount or unapproved pricing overrides."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(
                permit,
                _make_receipt(permit, extra_fields={"cached_tokens": 50_000}),
            )
        status = ledger.get_status()
        self.assertTrue(status.halted)

    # -------------------------------------------------------------------------
    # 5. Closed Normalized Receipt Validation Tests
    # -------------------------------------------------------------------------

    def test_receipt_status_must_be_completed(self):
        """Finding 3: Receipt status other than 'completed' retains full reservation and halts."""
        for invalid_status in ["failed", "incomplete", "cancelled", "running", "unknown"]:
            with self.subTest(status=invalid_status):
                ledger_dir = os.path.join(self.temp_dir.name, f"ledger_{invalid_status}")
                ledger = BudgetLedger.initialize(ledger_dir)
                permit = ledger.reserve("req_001", "sha256:digest")

                with self.assertRaises(SettlementEvidenceError):
                    ledger.settle(permit, _make_receipt(permit, status=invalid_status))

                status = ledger.get_status()
                self.assertTrue(status.halted)
                self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_evidence_wrong_model_rejected_and_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, model="gpt-4o"))

        status = ledger.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_evidence_wrong_service_tier_rejected_and_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, service_tier="auto"))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_evidence_boolean_tokens_rejected_and_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, input_tokens=True))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_evidence_negative_tokens_rejected_and_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, output_tokens=-10))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_evidence_input_tokens_exceeding_window_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, input_tokens=1_050_001))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_evidence_output_tokens_exceeding_limit_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, output_tokens=1_025))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_evidence_inconsistent_total_tokens_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, input_tokens=100, output_tokens=50, total_tokens=200))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_evidence_unexpected_extra_fields_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, extra_fields={"unexpected_field": "val"}))

        status = ledger.get_status()
        self.assertTrue(status.halted)

    def test_receipt_dataclass_accepted(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        receipt = Receipt(
            status="completed",
            response_id="resp_dataclass",
            request_id=permit.request_id,
            request_digest=permit.request_digest,
            model="gpt-6-luna",
            service_tier="default",
            input_tokens=1000,
            output_tokens=50,
            total_tokens=1050,
        )
        res = ledger.settle(permit, receipt)
        self.assertEqual(res.actual_cost_micros, 1050)
        self.assertEqual(res.response_id, "resp_dataclass")

    # -------------------------------------------------------------------------
    # 6. Replay, Duplicate response_id, and Permit Mismatch Tests
    # -------------------------------------------------------------------------

    def test_replayed_response_id_rejected_and_halts(self):
        """Finding 3: Replaying response_id in settlement halts and retains full reserve."""
        ledger = BudgetLedger.initialize(self.ledger_dir)

        p1 = ledger.reserve("req_001", "sha256:p1")
        ledger.settle(p1, _make_receipt(p1, response_id="resp_fixed_001"))

        # Reserve second request
        p2 = ledger.reserve("req_002", "sha256:p2")
        # Attempt to settle with same response_id
        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(p2, _make_receipt(p2, response_id="resp_fixed_001"))

        status = ledger.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_permit_mismatch_rejected_and_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p1 = ledger.reserve("req_001", "sha256:digest")

        bogus_permit = ReservationPermit(
            permit_id="permit_bogus",
            request_id="req_001",
            request_digest="sha256:digest",
            reserved_amount_micros=RESERVATION_AMOUNT_MICROS,
            reserved_at_utc=p1.reserved_at_utc,
        )
        with self.assertRaises(PermitMismatchError):
            ledger.settle(bogus_permit, _make_receipt(p1))

        status = ledger.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_double_settlement_rejected(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")
        receipt = _make_receipt(permit)
        ledger.settle(permit, receipt)

        with self.assertRaises(NoPendingReservationError):
            ledger.settle(permit, receipt)

    def test_settle_when_no_reservation_pending_raises(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        fake_permit = ReservationPermit("p_fake", "req_fake", "sha256:fake", RESERVATION_AMOUNT_MICROS, "now")
        with self.assertRaises(NoPendingReservationError):
            ledger.settle(fake_permit, _make_receipt(fake_permit))

    # -------------------------------------------------------------------------
    # 7. Failure Handling and Permanent Halt Invariants
    # -------------------------------------------------------------------------

    def test_record_failure_retains_full_reservation_and_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        fail_res = ledger.record_failure(permit, "REQUEST_TRANSPORT_FAILURE")
        self.assertEqual(fail_res.retained_amount_micros, 1_100_000)
        self.assertEqual(fail_res.reason, "REQUEST_TRANSPORT_FAILURE")

        status = ledger.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)
        self.assertEqual(status.committed_spend_micros, 0)
        self.assertFalse(status.has_pending_reservation)
        self.assertFalse(status.can_reserve)

        with self.assertRaises(LedgerHaltedError):
            ledger.reserve("req_002", "sha256:digest2")

    def test_halted_state_cannot_be_settled_away(self):
        """Finding 5: A halted state can never later be settled away."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, _make_receipt(permit, model="wrong-model"))

        status = ledger.get_status()
        self.assertTrue(status.halted)

        # Attempt to settle with valid evidence after halt
        with self.assertRaises(LedgerHaltedError):
            ledger.settle(permit, _make_receipt(permit, model="gpt-6-luna"))

    # -------------------------------------------------------------------------
    # 8. Ceiling and Count Limit Invariants
    # -------------------------------------------------------------------------

    def test_budget_ceiling_enforced_against_second_reserve_if_insufficient(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p1 = ledger.reserve("req_001", "sha256:p1")
        # Settle first request with 950,000 uUSD spend ($0.95 USD)
        # Remaining ceiling is $1.05 USD (< $1.10 reservation)
        ledger.settle(p1, _make_receipt(p1, input_tokens=949_000, output_tokens=1_000))

        status = ledger.get_status()
        self.assertEqual(status.committed_spend_micros, 950_000)
        self.assertEqual(status.remaining_available_micros, 2_000_000 - 950_000)
        # Reservations are sized per request since 2026-11-04: a small one still fits ...
        self.assertTrue(status.can_reserve)

        # ... but a full-size ($1.10) reservation would cross the ceiling and is refused.
        with self.assertRaises(BudgetExceededError):
            ledger.reserve("req_002", "sha256:p2")

    def test_max_forwarded_requests_limit_strictly_enforced(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)

        # Issue and settle MAX_FORWARDED_REQUESTS tiny requests (10 uUSD each)
        cap = MAX_FORWARDED_REQUESTS
        for i in range(1, cap + 1):
            req_id = f"req_{i:03d}"
            permit = ledger.reserve(req_id, f"sha256:{req_id}")
            ledger.settle(permit, _make_receipt(permit, response_id=f"resp_{i:03d}", input_tokens=10, output_tokens=0))

        status = ledger.get_status()
        self.assertEqual(status.total_reservations_count, cap)
        self.assertEqual(status.settled_requests_count, cap)
        self.assertFalse(status.can_reserve)

        # The request after the cap must be rejected
        with self.assertRaises(ReservationLimitExceededError):
            ledger.reserve(f"req_{cap + 1:03d}", f"sha256:req_{cap + 1:03d}")

    # -------------------------------------------------------------------------
    # 9. Crash Recovery and Lease Invariants
    # -------------------------------------------------------------------------

    def test_process_death_and_startup_orphaned_reservation_halts_ledger(self):
        """Finding 5: Process death frees lease lock; restart detects orphaned state and halts."""
        BudgetLedger.initialize(self.ledger_dir)
        ctx = multiprocessing.get_context("spawn")
        p = ctx.Process(
            target=_crashed_reserving_worker,
            args=(self.ledger_dir, "req_crash", "sha256:crash_digest"),
        )
        p.start()
        p.join(timeout=10)
        self.assertEqual(p.exitcode, 0)

        # Open ledger afresh after process death
        ledger2 = BudgetLedger.open(self.ledger_dir)
        status2 = ledger2.get_status()

        self.assertTrue(status2.halted)
        self.assertIn("UNSETTLED_PENDING_RESERVATION_AT_STARTUP", status2.halt_reason or "")
        self.assertEqual(status2.retained_failed_micros, 1_100_000)
        self.assertFalse(status2.has_pending_reservation)
        self.assertFalse(status2.can_reserve)

        with self.assertRaises(LedgerHaltedError):
            ledger2.reserve("req_next", "sha256:next")

    # -------------------------------------------------------------------------
    # 10. Concurrency Tests (Cross-Process File Locking & Deterministic Synchronization)
    # -------------------------------------------------------------------------

    def test_cross_process_concurrent_reservations_only_one_granted(self):
        """Finding 6: Concurrency is deterministic by holding the first reservation until competing attempts finish."""
        BudgetLedger.initialize(self.ledger_dir)

        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        barrier = ctx.Barrier(2)
        settle_event = ctx.Event()

        p1 = ctx.Process(
            target=_concurrent_worker_reserve,
            args=(self.ledger_dir, "req_proc1", "sha256:p1", barrier, queue, settle_event),
        )
        p2 = ctx.Process(
            target=_concurrent_worker_reserve,
            args=(self.ledger_dir, "req_proc2", "sha256:p2", barrier, queue, settle_event),
        )

        p1.start()
        p2.start()
        p1.join(timeout=10)
        p2.join(timeout=10)

        results = [queue.get(timeout=2), queue.get(timeout=2)]
        statuses = [r[0] for r in results]

        self.assertIn("SUCCESS", statuses)
        self.assertEqual(statuses.count("SUCCESS"), 1)
        other_status = [s for s in statuses if s != "SUCCESS"][0]
        self.assertEqual(other_status, "InFlightReservationError")

        ledger = BudgetLedger.open(self.ledger_dir)
        status = ledger.get_status()
        self.assertEqual(status.total_reservations_count, 1)
        self.assertEqual(status.settled_requests_count, 1)
        self.assertEqual(status.committed_spend_micros, 150)
        self.assertFalse(status.has_pending_reservation)
        self.assertFalse(status.halted)

    def test_concurrent_initialize_race_only_one_succeeds(self):
        """Finding 2: Concurrent initialize() calls race safely with exclusive creation."""
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()

        p1 = ctx.Process(target=_concurrent_init_worker, args=(self.ledger_dir, queue))
        p2 = ctx.Process(target=_concurrent_init_worker, args=(self.ledger_dir, queue))

        p1.start()
        p2.start()
        p1.join(timeout=10)
        p2.join(timeout=10)

        results = [queue.get(timeout=2), queue.get(timeout=2)]
        statuses = [r[0] for r in results]

        self.assertIn("SUCCESS", statuses)
        self.assertEqual(statuses.count("SUCCESS"), 1)
        other_status = [s for s in statuses if s != "SUCCESS"][0]
        self.assertEqual(other_status, "LedgerAlreadyExistsError")

    # -------------------------------------------------------------------------
    # 11. Atomic Write and Durability Boundaries (Finding 6)
    # -------------------------------------------------------------------------

    def test_atomic_write_failure_cleans_up_temp_and_preserves_state(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)

        with open(os.path.join(self.ledger_dir, STATE_FILENAME), "rb") as f:
            initial_bytes = f.read()

        real_fsync = os.fsync

        def failing_fsync(fd):
            real_fsync(fd)
            raise OSError("Simulated disk I/O failure during fsync")

        with patch("os.fsync", side_effect=failing_fsync):
            with self.assertRaises(OSError):
                ledger.reserve("req_fail", "sha256:fail")

        with open(os.path.join(self.ledger_dir, STATE_FILENAME), "rb") as f:
            current_bytes = f.read()
        self.assertEqual(initial_bytes, current_bytes)

        temp_files = [f for f in os.listdir(self.ledger_dir) if f.startswith(".tmp_")]
        self.assertEqual(len(temp_files), 0)

    def test_durability_boundary_os_write_failure(self):
        """Finding 6: Test write boundary failure cleans up and does not escape permit."""
        ledger = BudgetLedger.initialize(self.ledger_dir)

        with patch("os.write", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            with self.assertRaises(OSError):
                ledger.reserve("req_write_fail", "sha256:wf")

        temp_files = [f for f in os.listdir(self.ledger_dir) if f.startswith(".tmp_")]
        self.assertEqual(len(temp_files), 0)

    def test_durability_boundary_os_replace_failure(self):
        """Finding 6: Test rename boundary failure cleans up and preserves state."""
        ledger = BudgetLedger.initialize(self.ledger_dir)

        with patch("os.replace", side_effect=OSError(errno.EIO, "I/O error on rename")):
            with self.assertRaises(OSError):
                ledger.reserve("req_rename_fail", "sha256:rf")

        temp_files = [f for f in os.listdir(self.ledger_dir) if f.startswith(".tmp_")]
        self.assertEqual(len(temp_files), 0)

    def test_durability_boundary_directory_fsync_failure(self):
        """Finding 6: Directory fsync failure raises, releases lease, and reopen halts conservatively."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        real_fsync = os.fsync
        call_count = 0

        def failing_second_fsync(fd):
            nonlocal call_count
            call_count += 1
            if call_count == 6:  # 1-4: guard/comp fsyncs, 5: state file fsync, 6: state directory fsync
                raise OSError(errno.EIO, "Simulated directory fsync failure")
            real_fsync(fd)

        with patch("os.fsync", side_effect=failing_second_fsync):
            with self.assertRaises(OSError):
                ledger.reserve("req_dir_sync_fail", "sha256:dsf")

        # Handle is poisoned
        with self.assertRaises(LedgerHaltedError):
            ledger.reserve("req_attempt", "sha256:att")

        # Uncertain state cannot resume optimistically: reopen detects unheld lease and halts
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_mutant_no_directory_fsync_fails(self):
        """Finding 6: Mutation regression confirming directory descriptor fsync is executed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        fsync_inodes = []
        real_fsync = os.fsync

        def tracking_fsync(fd):
            try:
                st = os.fstat(fd)
                fsync_inodes.append((st.st_dev, st.st_ino))
            except OSError:
                pass
            real_fsync(fd)

        with patch("os.fsync", side_effect=tracking_fsync):
            ledger.reserve("req_sync_test", "sha256:st")

        # At least two fsyncs must have occurred: one for the state file, one for the directory
        self.assertGreaterEqual(len(fsync_inodes), 2)
        dir_st = os.stat(self.ledger_dir)
        self.assertIn((dir_st.st_dev, dir_st.st_ino), fsync_inodes, "Parent directory descriptor was NOT fsynced!")

    # -------------------------------------------------------------------------
    # 12. Corrupt / Tampered State & Deep Reconciliation Tests (Finding 4)
    # -------------------------------------------------------------------------

    def test_deletion_of_pending_reservation_detected_by_reconciliation(self):
        """Finding 1 reproduction: deleting pending_reservation fails closed on open."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        ledger.reserve("req_001", "sha256:digest")

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        data["pending_reservation"] = None
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_journal_entry_missing_response_id_rejected_on_open(self):
        """Finding 4 QA probe: removing response_id from settled journal entry fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")
        ledger.settle(permit, _make_receipt(permit, response_id="resp_initial"))

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        # Remove response_id from the SETTLED entry
        for entry in data["journal"]:
            if entry.get("entry_type") == "SETTLED":
                del entry["response_id"]

        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_journal_entry_unknown_keys_rejected(self):
        """Finding 4: Extra or unknown keys in journal entries fail closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")
        ledger.settle(permit, _make_receipt(permit))

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        data["journal"][1]["forbidden_extra_key"] = "malicious"
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_journal_duplicate_response_id_rejected(self):
        """Finding 4: Duplicate response_id in journal entries fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p1 = ledger.reserve("req_001", "sha256:p1")
        ledger.settle(p1, _make_receipt(p1, response_id="resp_001"))

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        # Forge a second settled entry with the same response_id
        forged_entry = dict(data["journal"][-1])
        forged_entry["reservation_id"] = "permit_forged"
        forged_entry["request_id"] = "req_002"
        data["journal"].append(forged_entry)

        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_journal_unpaired_settled_entry_rejected(self):
        """Finding 4: State machine violation (SETTLED without prior RESERVED) fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        data["journal"].append({
            "entry_type": "SETTLED",
            "reservation_id": "permit_ghost",
            "request_id": "req_ghost",
            "request_digest": "sha256:ghost",
            "response_id": "resp_ghost",
            "model": "gpt-6-luna",
            "service_tier": "default",
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
            "settled_amount_micros": 150,
            "unencumbered_amount_micros": 1_100_000 - 150,
            "timestamp_utc": "2026-11-02T00:00:00Z",
        })

        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_record_failure_rejects_arbitrary_unbounded_text(self):
        """Finding 4: Arbitrary provider text / multiline payloads in reason are rejected and revoke authority."""
        # Exceeding length limit (256 chars)
        dir1 = os.path.join(self.temp_dir.name, "fail_text_1")
        ledger1 = BudgetLedger.initialize(dir1)
        p1 = ledger1.reserve("req_001", "sha256:d1")
        long_reason = "X" * (MAX_REASON_LENGTH + 1)
        with self.assertRaises(SettlementEvidenceError):
            ledger1.record_failure(p1, long_reason)
        # Verify authority is revoked: cannot later settle the same permit
        with self.assertRaises(LedgerHaltedError):
            ledger1.settle(p1, _make_receipt(p1))

        # Multiline string
        dir2 = os.path.join(self.temp_dir.name, "fail_text_2")
        ledger2 = BudgetLedger.initialize(dir2)
        p2 = ledger2.reserve("req_002", "sha256:d2")
        with self.assertRaises(SettlementEvidenceError):
            ledger2.record_failure(p2, "Error on line 1\nLine 2 details")
        with self.assertRaises(LedgerHaltedError):
            ledger2.settle(p2, _make_receipt(p2))

        # Non-printable characters
        dir3 = os.path.join(self.temp_dir.name, "fail_text_3")
        ledger3 = BudgetLedger.initialize(dir3)
        p3 = ledger3.reserve("req_003", "sha256:d3")
        with self.assertRaises(SettlementEvidenceError):
            ledger3.record_failure(p3, "Error with control \x00 character")
        with self.assertRaises(LedgerHaltedError):
            ledger3.settle(p3, _make_receipt(p3))

    def test_duplicate_keys_in_json_rejected(self):
        """Finding 6: Duplicate keys in state file fail closed."""
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            raw = f.read()

        pos = raw.find('"experiment_id":')
        duplicate_raw = raw[:pos] + '"experiment_id": "dupe",\n  ' + raw[pos:]

        with open(state_path, "w") as f:
            f.write(duplicate_raw)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_nonfinite_numeric_constants_rejected(self):
        """Finding 6: Nonfinite numbers (NaN, Infinity) in state file fail closed."""
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            raw = f.read()

        tampered = raw.replace('"committed_spend_micros": 0', '"committed_spend_micros": NaN')
        with open(state_path, "w") as f:
            f.write(tampered)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_tampered_ceiling_rejected_on_open(self):
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)
        data["global_ceiling_micros"] = 5_000_000
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_tampered_negative_spend_rejected_on_open(self):
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)
        data["committed_spend_micros"] = -100
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_authenticated_escape_hatch_does_not_exist(self):
        """Verify that passing authenticated=True does not bypass model or token checks."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(
                permit,
                _make_receipt(permit, model="unapproved-model", extra_fields={"authenticated": True}),
            )
        status = ledger.get_status()
        self.assertTrue(status.halted)

    # -------------------------------------------------------------------------
    # 13. Directory Anchoring & Inode Continuity Regressions (Findings 1 & 2)
    # -------------------------------------------------------------------------

    def test_directory_identity_preserved_on_open_handle(self):
        """Finding 1 QA probe: open() preserves directory and lock identity on returned handle."""
        BudgetLedger.initialize(self.ledger_dir)
        ledger = BudgetLedger.open(self.ledger_dir)
        self.assertIsNotNone(ledger._dir_dev_ino)
        self.assertIsNotNone(ledger._lock_dev_ino)

        dir_st = os.stat(self.ledger_dir)
        self.assertEqual(ledger._dir_dev_ino, (dir_st.st_dev, dir_st.st_ino))

    def test_swapped_directory_rejected_on_runtime_operation(self):
        """Finding 1 Security probe: swapping directory after open() is detected and rejected."""
        BudgetLedger.initialize(self.ledger_dir)
        handle = BudgetLedger.open(self.ledger_dir)

        # Commit spend on handle
        p1 = handle.reserve("req_001", "sha256:d1")
        handle.settle(p1, _make_receipt(p1, response_id="resp_001"))

        # Swap directory path on disk
        replacement_dir = os.path.join(self.temp_dir.name, "replacement")
        BudgetLedger.initialize(replacement_dir)
        os.rename(self.ledger_dir, self.ledger_dir + ".orig")
        os.rename(replacement_dir, self.ledger_dir)

        # Handle operation must reject the replacement directory
        with self.assertRaises(LedgerSecurityError):
            handle.reserve("req_002", "sha256:d2")

    def test_runtime_lock_file_missing_rejected(self):
        """Finding 2: Deleting runtime lock file is detected and rejected without recreating."""
        BudgetLedger.initialize(self.ledger_dir)
        handle = BudgetLedger.open(self.ledger_dir)

        lock_path = os.path.join(self.ledger_dir, LOCK_FILENAME)
        os.unlink(lock_path)

        with self.assertRaises(LedgerSecurityError):
            handle.reserve("req_001", "sha256:d1")

    def test_runtime_lock_file_replacement_rejected(self):
        """Finding 2: Replacing runtime lock file with different inode is rejected."""
        BudgetLedger.initialize(self.ledger_dir)
        handle = BudgetLedger.open(self.ledger_dir)

        lock_path = os.path.join(self.ledger_dir, LOCK_FILENAME)
        # Rename original lock file to retain its inode in .bak, and create new lock file
        os.rename(lock_path, lock_path + ".bak")
        Path(lock_path).touch(mode=0o600)

        with self.assertRaises(LedgerSecurityError):
            handle.reserve("req_001", "sha256:d1")

    def test_security_repro_paused_reservation_and_renamed_sync_files(self):
        """Finding 2 Security probe: paused reservation with renamed sync files rejects all."""
        BudgetLedger.initialize(self.ledger_dir)
        handle1 = BudgetLedger.open(self.ledger_dir)

        # Hook into handle1 after lease acquisition to rename sync files
        real_verify = handle1._verify_held_lease

        def tamper_and_verify(dir_fd):
            # Security probe: rename lock and lease files
            lock_path = os.path.join(self.ledger_dir, LOCK_FILENAME)
            lease_path = os.path.join(self.ledger_dir, LEASE_FILENAME)
            os.rename(lock_path, lock_path + ".tampered")
            os.rename(lease_path, lease_path + ".tampered")
            real_verify(dir_fd)

        handle1._verify_held_lease = tamper_and_verify

        with self.assertRaises(LedgerSecurityError):
            handle1.reserve("req_001", "sha256:d1")

        # Verify handle1 is poisoned and no permit escaped
        self.assertTrue(handle1._poisoned)

        # A second handle attempting to reserve also fails closed
        handle2 = BudgetLedger(self.ledger_dir, DEFAULT_EXPERIMENT_ID)
        with self.assertRaises((LedgerSecurityError, LedgerNotFoundError)):
            BudgetLedger.open(self.ledger_dir)

    # -------------------------------------------------------------------------
    # 14. Failed Halt Persistence & Irreversibility (Finding 3)
    # -------------------------------------------------------------------------

    def test_record_failure_write_fault_permanently_poisons_handle(self):
        """Finding 3 Security probe: failed halt persistence is irreversible."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        # Inject write failure into record_failure
        with patch.object(ledger, "_atomic_write_state", side_effect=OSError(errno.EIO, "Injected write fault")):
            with self.assertRaises(OSError):
                ledger.record_failure(permit, "REQUEST_TRANSPORT_FAILURE")

        # 1. Handle is permanently poisoned: cannot settle or reserve
        self.assertTrue(ledger._poisoned)
        with self.assertRaises(LedgerHaltedError):
            ledger.settle(permit, _make_receipt(permit))
        with self.assertRaises(LedgerHaltedError):
            ledger.reserve("req_002", "sha256:d2")

        # 2. Disk recovery is conservative: reopen detects dropped lease, retains full $1.10 and halts
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

        # 3. Permitted settlement fails permanently on new handle
        with self.assertRaises(LedgerHaltedError):
            reopened.settle(permit, _make_receipt(permit))

    def test_settle_write_fault_releases_lease_and_halts_conservatively(self):
        """Finding 3: Write failure during settle() releases lease and halts conservatively."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        with patch.object(ledger, "_atomic_write_state", side_effect=OSError(errno.EIO, "Injected settle write fault")):
            with self.assertRaises(OSError):
                ledger.settle(permit, _make_receipt(permit))

        self.assertTrue(ledger._poisoned)

        # Reopen detects unheld lease, retains full $1.10, and halts
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    # -------------------------------------------------------------------------
    # 15. Descriptor Leak & Lifetime Tests (Finding 5)
    # -------------------------------------------------------------------------

    def test_lease_validation_failure_does_not_leak_descriptor(self):
        """Finding 5 Security probe: lease validation error does not leak descriptor."""
        ledger = BudgetLedger.initialize(self.ledger_dir)

        def count_open_fds():
            try:
                return len(os.listdir("/proc/self/fd"))
            except Exception:
                return 0

        initial_fds = count_open_fds()

        orig_validate = ledger._validate_file_descriptor
        call_count = 0

        def fail_on_lease(fd):
            nonlocal call_count
            call_count += 1
            if call_count > 1:  # 1st call validates lock_fd; 2nd call validates lease_fd
                raise LedgerSecurityError("Injected lease descriptor error")
            return orig_validate(fd)

        with patch.object(ledger, "_validate_file_descriptor", side_effect=fail_on_lease):
            with self.assertRaises(LedgerSecurityError):
                with ledger._lock() as dir_fd:
                    ledger._acquire_lease(dir_fd)

        final_fds = count_open_fds()
        self.assertEqual(initial_fds, final_fds)

    def test_abandoned_owner_object_closes_held_lease_on_collection(self):
        """Finding 5 QA probe (lost-owner-object): garbage collection releases held lease."""
        BudgetLedger.initialize(self.ledger_dir)

        def make_and_abandon_reservation():
            h = BudgetLedger.open(self.ledger_dir)
            h.reserve("req_abandoned", "sha256:ab")
            # Handle h falls out of scope here

        make_and_abandon_reservation()
        gc.collect()

        # Reopen must now see lease dropped, retain full $1.10, and halt
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_explicit_close_and_context_manager(self):
        """Finding 5: Explicit close() and context manager cleanly release lease."""
        BudgetLedger.initialize(self.ledger_dir)

        with BudgetLedger.open(self.ledger_dir) as ledger:
            permit = ledger.reserve("req_ctx", "sha256:ctx")
            ledger.settle(permit, _make_receipt(permit, response_id="resp_ctx"))

        status = BudgetLedger.open(self.ledger_dir).get_status()
        self.assertEqual(status.settled_requests_count, 1)
        self.assertFalse(status.halted)

    # -------------------------------------------------------------------------
    # 16. Contract Mutation Robustness Tests
    # -------------------------------------------------------------------------

    def test_mutated_accounting_rate_fails_contract(self):
        """Verify that any permissive rate mutation is detected."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:digest")

        res = ledger.settle(
            permit,
            _make_receipt(permit, response_id="resp_001", input_tokens=10_000, output_tokens=1000),
        )
        self.assertEqual(res.actual_cost_micros, 11_000)
        self.assertNotEqual(res.actual_cost_micros, 5_500)
        self.assertNotEqual(res.actual_cost_micros, 1000)

    def test_mutated_ceiling_fails_contract(self):
        """Contract strictly bounds total ceiling to exactly 2,000,000 microUSD."""
        self.assertEqual(GLOBAL_CEILING_MICROS, 2_000_000)
        self.assertEqual(RESERVATION_AMOUNT_MICROS, 1_100_000)
        self.assertGreater(RESERVATION_AMOUNT_MICROS * 2, GLOBAL_CEILING_MICROS)

    # -------------------------------------------------------------------------
    # 17. Second Correction Review Regressions (Protocol & Security Probes)
    # -------------------------------------------------------------------------

    def test_invalid_receipt_status_write_fault_revokes_authority_and_blocks_later_settlement(self):
        """Review Item 1 Coordinator probe: rejection write fault revokes authority immediately."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:d1")

        # Inject write failure during receipt rejection
        with patch.object(ledger, "_atomic_write_state", side_effect=OSError(errno.EIO, "Injected rejection write fault")):
            with self.assertRaises(OSError):
                ledger.settle(permit, _make_receipt(permit, status="failed"))

        # 1. Authority must be revoked: later settlement on same handle must fail
        self.assertTrue(ledger._poisoned)
        with self.assertRaises(LedgerHaltedError):
            ledger.settle(permit, _make_receipt(permit, status="completed"))

        # 2. Fresh handle also refuses settlement and halts conservatively
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)
        with self.assertRaises(LedgerHaltedError):
            reopened.settle(permit, _make_receipt(permit, status="completed"))

    def test_invalid_failure_reason_revokes_authority_and_blocks_later_settlement(self):
        """Review Item 1 Coordinator probe: invalid failure reason revokes authority immediately."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:d1")

        with self.assertRaises(SettlementEvidenceError):
            ledger.record_failure(permit, "X" * 300)

        # Handle is revoked
        self.assertTrue(ledger._poisoned)
        with self.assertRaises(LedgerHaltedError):
            ledger.settle(permit, _make_receipt(permit, status="completed"))

        # Fresh handle halts conservatively
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.retained_failed_micros, 1_100_000)

    def test_unresolved_settlement_publication_recovered_by_fresh_handle(self):
        """Review Item 2: Unresolved publication failure after rename exposes intent and halts."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:d1")

        call_count = 0
        real_fsync = os.fsync

        def fail_on_dir_sync(fd):
            nonlocal call_count
            call_count += 1
            # 1-4: guard/comp fsyncs, 5: tmp intent fsync, 6: dir fsync intent, 7: tmp state fsync, 8: dir fsync state
            if call_count == 8:
                raise OSError(errno.EIO, "Injected dir fsync fault after state rename")
            real_fsync(fd)

        with patch("os.fsync", side_effect=fail_on_dir_sync):
            with self.assertRaises(OSError):
                ledger.settle(permit, _make_receipt(permit, status="completed", response_id="resp_unres"))

        # Fresh handle opening must detect unresolved intent, reject settlement, retain $1.10 and halt
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.halt_reason, "UNRESOLVED_SETTLEMENT_PUBLICATION")
        self.assertEqual(status.retained_failed_micros, 1_100_000)
        self.assertEqual(status.committed_spend_micros, 0)
        self.assertFalse(status.can_reserve)

    def test_replay_rejects_second_initialized_event(self):
        """Review Item 3 Protocol probe: second INITIALIZED event fails closed."""
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        data["journal"].append(dict(data["journal"][0]))
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_replay_rejects_changed_model_or_service_tier(self):
        """Review Item 3 Protocol probe: changed model or service tier in journal fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p = ledger.reserve("req_001", "sha256:d1")
        ledger.settle(p, _make_receipt(p, response_id="resp_001"))

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        data["journal"][-1]["model"] = "gpt-4o"
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_replay_rejects_duplicate_request_id_across_reservations(self):
        """Review Item 3 Protocol probe: duplicate request_id across reservations fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p1 = ledger.reserve("req_001", "sha256:d1")
        ledger.settle(p1, _make_receipt(p1, response_id="resp_001"))

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        # Forging a second reservation with the same request_id
        data["journal"].append({
            "entry_type": "RESERVED",
            "reservation_id": "permit_other",
            "request_id": "req_001",  # Duplicate!
            "request_digest": "sha256:d2",
            "reserved_amount_micros": 1_100_000,
            "reservation_index": 2,
            "timestamp_utc": "2026-11-02T00:00:00Z",
        })
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_replay_rejects_boolean_numeric_fields(self):
        """Review Item 3 Protocol probe: boolean numeric fields fail closed."""
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        data["committed_spend_micros"] = True
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_replay_rejects_cleared_halt_flag_after_terminal_failure(self):
        """Review Item 3 Protocol probe: clearing top-level halt flag after failed request fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p = ledger.reserve("req_001", "sha256:d1")
        ledger.record_failure(p, "REQUEST_TRANSPORT_FAILURE")

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        # Maliciously reset halted to False
        data["halted"] = False
        data["halt_reason"] = None
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_replay_rejects_event_after_terminal_failure(self):
        """Review Item 3: Any event following a terminal failure fails closed."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p = ledger.reserve("req_001", "sha256:d1")
        ledger.record_failure(p, "REQUEST_TRANSPORT_FAILURE")

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        # Append another event after terminal failure
        data["journal"].append({
            "entry_type": "RESERVED",
            "reservation_id": "permit_after_fail",
            "request_id": "req_002",
            "request_digest": "sha256:d2",
            "reserved_amount_micros": 1_100_000,
            "reservation_index": 2,
            "timestamp_utc": "2026-11-02T00:00:00Z",
        })
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.ledger_dir)

    def test_oversized_request_id_rejected_before_publication(self):
        """Review Item 4 Protocol probe: 300,000-char request ID rejected without writing permit."""
        ledger = BudgetLedger.initialize(self.ledger_dir)
        huge_id = "A" * 300_000

        with self.assertRaises(ValueError):
            ledger.reserve(huge_id, "sha256:digest")

        status = ledger.get_status()
        self.assertEqual(status.total_reservations_count, 0)
        self.assertFalse(status.has_pending_reservation)

    def test_sync_identity_tamper_after_write_blocks_permit_return(self):
        """Review Item 5: Synchronization identity verification through permit return blocks escapes."""
        ledger = BudgetLedger.initialize(self.ledger_dir)

        real_verify = ledger._verify_sync_identities

        def tamper_after_write(dir_fd, check_lease=True):
            # Security probe: replace lock file after state write
            lock_path = os.path.join(ledger._ledger_dir, LOCK_FILENAME)
            os.rename(lock_path, lock_path + ".swapped")
            Path(lock_path).touch(mode=0o600)
            real_verify(dir_fd, check_lease=check_lease)

        ledger._verify_sync_identities = tamper_after_write

        with self.assertRaises(LedgerSecurityError):
            ledger.reserve("req_001", "sha256:d1")

        self.assertTrue(ledger._poisoned)

    # -------------------------------------------------------------------------
    # 18. Third Correction Review Regressions (Settlement Commit & Recovery Contract)
    # -------------------------------------------------------------------------

    def test_already_open_peer_detects_unresolved_intent_under_lock(self):
        """Third review: already-open peer handle validates records and recovers unresolved intent."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        peer = BudgetLedger.open(self.ledger_dir)

        permit = owner.reserve("owner_req", "sha256:d1")

        call_count = 0
        real_fsync = os.fsync

        def fail_state_dir_sync(fd):
            nonlocal call_count
            call_count += 1
            # 1-4: guard/comp fsyncs, 5: tmp intent fsync, 6: dir fsync intent, 7: tmp state fsync, 8: dir fsync state
            if call_count == 8:
                raise OSError(errno.EIO, "Injected state publication directory fsync fault")
            real_fsync(fd)

        with patch("os.fsync", side_effect=fail_state_dir_sync):
            with self.assertRaises(OSError):
                owner.settle(permit, _make_receipt(permit, status="completed", response_id="resp_peer_probe"))

        self.assertTrue(owner._poisoned)

        # Peer was already open BEFORE the fault; peer.reserve() must detect unresolved intent and halt
        with self.assertRaises(LedgerHaltedError):
            peer.reserve("peer_req", "sha256:peer_d")

        s = peer.get_status()
        self.assertTrue(s.halted)
        self.assertEqual(s.halt_reason, "UNRESOLVED_SETTLEMENT_PUBLICATION")
        self.assertEqual(s.retained_failed_micros, 1_100_000)
        self.assertEqual(s.committed_spend_micros, 0)
        self.assertFalse(s.can_reserve)

        owner.close()
        peer.close()

    def test_post_commit_confirmation_failure_returns_disabled_outcome_and_poisons_handle(self):
        """Third review: confirmation publication error returns typed outcome and disables handle."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")

        with patch.object(owner, "_write_confirmation_static", side_effect=OSError(errno.EIO, "Injected confirmation fault")):
            outcome = owner.settle(permit, _make_receipt(permit, response_id="resp_postcommit"))

        self.assertIsInstance(outcome, SettlementCommittedHandleDisabledOutcome)
        self.assertTrue(outcome.handle_disabled)
        self.assertTrue(outcome.is_committed)
        self.assertEqual(outcome.response_id, "resp_postcommit")
        self.assertEqual(outcome.accounted_cost_micros, 10500)

        # Handle is disabled
        self.assertTrue(owner.is_handle_disabled)
        status = owner.get_status()
        self.assertTrue(status.handle_disabled)
        # Because confirmation was lost/omitted, recovery under lock halts conservatively
        self.assertTrue(status.halted)
        self.assertEqual(status.halt_reason, "UNRESOLVED_SETTLEMENT_PUBLICATION")
        self.assertEqual(status.retained_failed_micros, 1_100_000)

        # Fresh handle opening also sees missing confirmation and halts conservatively
        fresh = BudgetLedger.open(self.ledger_dir)
        fresh_status = fresh.get_status()
        self.assertTrue(fresh_status.halted)
        self.assertEqual(fresh_status.retained_failed_micros, 1_100_000)

        owner.close()
        fresh.close()

    def test_post_commit_confirmation_dir_sync_failure_allows_fresh_handle_with_confirmation(self):
        """Third review: surviving complete confirmation proves preceding state sync on fresh handle."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")

        count = 0
        real_fsync = os.fsync

        def fail_conf_dir_sync(fd):
            nonlocal count
            count += 1
            # 1-4: guard/comp fsyncs, 5: tmp intent fsync, 6: dir fsync intent, 7: tmp state fsync, 8: dir fsync state, 9: tmp conf fsync, 10: dir fsync conf
            if count == 10:
                raise OSError(errno.EIO, "Injected confirmation directory fsync fault")
            real_fsync(fd)

        with patch("os.fsync", side_effect=fail_conf_dir_sync):
            outcome = owner.settle(permit, _make_receipt(permit, response_id="resp_conf_sync_fault"))

        self.assertIsInstance(outcome, SettlementCommittedHandleDisabledOutcome)
        self.assertTrue(outcome.handle_disabled)
        self.assertTrue(outcome.is_committed)
        self.assertTrue(owner.is_handle_disabled)

        # But confirmation record was replaced into directory before dir fsync failed!
        conf_file = os.path.join(self.ledger_dir, f"{CONFIRMATION_FILE_PREFIX}{permit.permit_id}.json")
        self.assertTrue(os.path.exists(conf_file))

        # Fresh handle opening sees complete matching confirmation, proving prior state sync!
        fresh = BudgetLedger.open(self.ledger_dir)
        fresh_status = fresh.get_status()
        self.assertFalse(fresh_status.halted)
        self.assertFalse(fresh_status.handle_disabled)
        self.assertEqual(fresh_status.committed_spend_micros, 10500)
        self.assertTrue(fresh_status.can_reserve)

        # Fresh handle can continue and reserve
        permit2 = fresh.reserve("req_002", "sha256:d2")
        self.assertIsNotNone(permit2)

        owner.close()
        fresh.close()

    def test_post_commit_confirmation_success_allows_fresh_handle_to_continue(self):
        """Third review: complete matching confirmation allows fresh handle to continue."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")
        res = owner.settle(permit, _make_receipt(permit, response_id="resp_succ"))
        self.assertIsInstance(res, SettlementResult)

        # Confirm permanent intent and confirmation records exist on disk
        intent_path = os.path.join(self.ledger_dir, f"{INTENT_FILE_PREFIX}{permit.permit_id}.json")
        conf_path = os.path.join(self.ledger_dir, f"{CONFIRMATION_FILE_PREFIX}{permit.permit_id}.json")
        self.assertTrue(os.path.exists(intent_path))
        self.assertTrue(os.path.exists(conf_path))

        # Fresh handle can open and reserve next request within ceiling
        fresh = BudgetLedger.open(self.ledger_dir)
        status = fresh.get_status()
        self.assertFalse(status.halted)
        self.assertFalse(status.handle_disabled)
        self.assertTrue(status.can_reserve)

        permit2 = fresh.reserve("req_002", "sha256:d2")
        self.assertIsNotNone(permit2)

        owner.close()
        fresh.close()

    def test_intent_or_confirmation_stat_error_treated_as_uncertainty_not_absence(self):
        """Third review: non-ENOENT error (EIO) on record stat/open is treated as uncertainty."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")

        call_count = 0
        real_fsync = os.fsync

        def fail_sync(fd):
            nonlocal call_count
            call_count += 1
            if call_count == 8:
                raise OSError(errno.EIO, "State publication dir sync fault")
            real_fsync(fd)

        with patch("os.fsync", side_effect=fail_sync):
            try:
                owner.settle(permit, _make_receipt(permit))
            except OSError:
                pass

        real_open = os.open

        def fail_open(path, flags, *args, **kwargs):
            if isinstance(path, str) and (path.startswith(INTENT_FILE_PREFIX) or path.startswith(CONFIRMATION_FILE_PREFIX)):
                raise OSError(errno.EIO, "Injected disk I/O error on record file")
            return real_open(path, flags, *args, **kwargs)

        with patch("os.open", side_effect=fail_open):
            with self.assertRaises(LedgerSecurityError):
                BudgetLedger.open(self.ledger_dir)

        owner.close()

    def test_replay_rejects_pending_reservation_exceeding_ceiling(self):
        """Third review: replay rejects pending reservation when committed + pending > ceiling."""
        h = BudgetLedger.initialize(self.ledger_dir)
        first = h.reserve("req1", "sha256:d1")
        h.settle(first, _make_receipt(first, input_tokens=999500, output_tokens=500))
        h.close()

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        ts = data["updated_at_utc"]
        data["total_reservations_count"] = 2
        data["journal"].append({
            "entry_type": "RESERVED",
            "reservation_id": "permit_002",
            "request_id": "req2",
            "request_digest": "sha256:d2",
            "reserved_amount_micros": 1_100_000,
            "reservation_index": 2,
            "timestamp_utc": ts,
        })
        data["pending_reservation"] = {
            "reservation_id": "permit_002",
            "request_id": "req2",
            "request_digest": "sha256:d2",
            "reserved_amount_micros": 1_100_000,
            "reserved_at_utc": ts,
            "pid": os.getpid(),
        }

        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger.open(self.ledger_dir)
        self.assertIn("replay ceiling violation", str(ctx.exception).lower())

    def test_replay_rejects_reserved_transition_exceeding_ceiling(self):
        """Third review: replay rejects RESERVED event exceeding ceiling during journal replay."""
        h = BudgetLedger.initialize(self.ledger_dir)
        first = h.reserve("req1", "sha256:d1")
        h.settle(first, _make_receipt(first, input_tokens=999500, output_tokens=500))
        h.close()

        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        ts = data["updated_at_utc"]
        data["total_reservations_count"] = 2
        data["journal"].append({
            "entry_type": "RESERVED",
            "reservation_id": "permit_002",
            "request_id": "req2",
            "request_digest": "sha256:d2",
            "reserved_amount_micros": 1_100_000,
            "reservation_index": 2,
            "timestamp_utc": ts,
        })
        data["pending_reservation"] = {
            "reservation_id": "permit_002",
            "request_id": "req2",
            "request_digest": "sha256:d2",
            "reserved_amount_micros": 1_100_000,
            "reserved_at_utc": ts,
            "pid": os.getpid(),
        }

        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger.open(self.ledger_dir)
        self.assertIn("replay ceiling violation", str(ctx.exception).lower())

    def test_strict_integer_and_monetary_constants_reject_float_and_bool(self):
        """Third review: strict integer schema rejects float and boolean constants."""
        BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            original = json.load(f)

        # 1./2. Float and boolean ceiling: a failed inspection leaves the guard
        # unfinished, so each corruption case uses its own disposable ledger.
        for bad in (2_000_000.0, True):
            case_dir = os.path.join(self.temp_dir.name, f"case_{type(bad).__name__}")
            BudgetLedger.initialize(case_dir)
            case_state = os.path.join(case_dir, STATE_FILENAME)
            data = json.loads(json.dumps(original))
            data["global_ceiling_micros"] = bad
            with open(case_state, "w") as f:
                json.dump(data, f)
            with self.assertRaises(LedgerCorruptError):
                BudgetLedger.open(case_dir)

        # 3. Float tokens in receipt
        ledger = BudgetLedger.open(self.ledger_dir)
        permit = ledger.reserve("req_001", "sha256:d1")
        evidence = {
            "status": "completed",
            "response_id": "resp_float",
            "request_id": permit.request_id,
            "request_digest": permit.request_digest,
            "model": PINNED_MODEL,
            "service_tier": PINNED_SERVICE_TIER,
            "input_tokens": 1000.0,
            "output_tokens": 100,
            "total_tokens": 1100,
        }
        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(permit, evidence)

        ledger.close()

    def test_repeated_recovery_is_idempotent(self):
        """Third review: repeated recovery on unresolved intent retains reserve exactly once."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")

        call_count = 0
        real_fsync = os.fsync

        def fail_sync(fd):
            nonlocal call_count
            call_count += 1
            if call_count == 8:
                raise OSError(errno.EIO, "State publication dir sync fault")
            real_fsync(fd)

        with patch("os.fsync", side_effect=fail_sync):
            try:
                owner.settle(permit, _make_receipt(permit))
            except OSError:
                pass

        # First recovery
        r1 = BudgetLedger.open(self.ledger_dir)
        s1 = r1.get_status()
        self.assertTrue(s1.halted)
        self.assertEqual(s1.retained_failed_micros, 1_100_000)

        # Second recovery
        r2 = BudgetLedger.open(self.ledger_dir)
        s2 = r2.get_status()
        self.assertTrue(s2.halted)
        self.assertEqual(s2.retained_failed_micros, 1_100_000)  # Remains 1.1m, never 2.2m!

        # Third check via another operation
        with self.assertRaises(LedgerHaltedError):
            r2.reserve("req_002", "sha256:d2")

        s3 = r2.get_status()
        self.assertEqual(s3.retained_failed_micros, 1_100_000)

        owner.close()
        r1.close()
        r2.close()

    def test_causal_confirmation_never_published_before_state_sync(self):
        """Third review mutation killer: confirmation publication cannot precede state sync."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")

        events = []
        real_replace = os.replace
        real_fsync = os.fsync

        def tracked_replace(src, dst, **kwargs):
            if "intent_" in dst:
                events.append("intent-replace")
            elif dst == STATE_FILENAME:
                assert "intent-replace" in events
                events.append("state-replace")
            elif "confirmation_" in dst:
                assert "state-replace" in events
                events.append("conf-replace")
            return real_replace(src, dst, **kwargs)

        def tracked_fsync(fd):
            try:
                target = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                target = ""
            real_fsync(fd)
            if target == owner._ledger_dir:
                events.append("dir-fsync")

        with patch("os.replace", side_effect=tracked_replace), patch("os.fsync", side_effect=tracked_fsync):
            owner.settle(permit, _make_receipt(permit))

        # Must strictly have state-replace and dir-fsync before conf-replace
        i_state = events.index("state-replace")
        i_conf = events.index("conf-replace")
        self.assertLess(i_state, i_conf)
        # Verify a directory sync occurred after state-replace and before conf-replace (the commit point)
        dir_syncs_between = [e for e in events[i_state:i_conf] if e == "dir-fsync"]
        self.assertGreaterEqual(len(dir_syncs_between), 1)

        owner.close()

    def test_concurrent_same_handle_close_and_use_serialized(self):
        """Third review: concurrent operations on the same handle are safely serialized."""
        import threading
        owner = BudgetLedger.initialize(self.ledger_dir)
        permit = owner.reserve("req_001", "sha256:d1")

        barrier = threading.Barrier(2)
        errors = []

        def worker_close():
            barrier.wait()
            owner.close()

        def worker_use():
            barrier.wait()
            try:
                owner.settle(permit, _make_receipt(permit))
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker_close)
        t2 = threading.Thread(target=worker_use)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Handle must be closed/disabled
        self.assertTrue(owner.is_handle_disabled)
        owner.close()

    def test_distinguish_handle_disabled_vs_experiment_halted(self):
        """Third review: API and status cleanly distinguish handle-disabled from experiment-halted."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        self.assertFalse(owner.is_handle_disabled)
        self.assertFalse(owner.is_experiment_halted)

        s = owner.get_status()
        self.assertFalse(s.handle_disabled)
        self.assertFalse(s.halted)

        # Explicit close disables handle, but does NOT halt the shared experiment
        owner.close()
        self.assertTrue(owner.is_handle_disabled)

        # Fresh handle confirms experiment on disk is NOT halted
        fresh = BudgetLedger.open(self.ledger_dir)
        self.assertFalse(fresh.is_handle_disabled)
        self.assertFalse(fresh.is_experiment_halted)
        fresh.close()

    # -------------------------------------------------------------------------
    # Section 19: Terminal Evidence Uncertainty and Inspection Guard Tests
    # -------------------------------------------------------------------------

    def test_inspection_guard_armed_before_evidence_reads(self):
        """Inspection guard: arms and increments generation before authoritative reads under lock."""
        owner = BudgetLedger.initialize(self.ledger_dir)

        # Verify initial guard and completion established at generation 1
        with open(os.path.join(self.ledger_dir, INSPECTION_GUARD_FILENAME), "r") as f:
            guard1 = json.load(f)
        with open(os.path.join(self.ledger_dir, INSPECTION_COMPLETION_FILENAME), "r") as f:
            comp1 = json.load(f)
        self.assertEqual(guard1["generation"], 1)
        self.assertEqual(comp1["generation"], 1)

        # Reserving funds arms generation 2
        p1 = owner.reserve("req_001", "sha256:d1")
        with open(os.path.join(self.ledger_dir, INSPECTION_GUARD_FILENAME), "r") as f:
            guard2 = json.load(f)
        with open(os.path.join(self.ledger_dir, INSPECTION_COMPLETION_FILENAME), "r") as f:
            comp2 = json.load(f)
        self.assertEqual(guard2["generation"], 2)
        self.assertEqual(comp2["generation"], 2)

        # Settling arms generation 3
        owner.settle(p1, _make_receipt(p1))
        with open(os.path.join(self.ledger_dir, INSPECTION_GUARD_FILENAME), "r") as f:
            guard3 = json.load(f)
        with open(os.path.join(self.ledger_dir, INSPECTION_COMPLETION_FILENAME), "r") as f:
            comp3 = json.load(f)
        self.assertEqual(guard3["generation"], 3)
        self.assertEqual(comp3["generation"], 3)
        owner.close()

    def test_stale_or_missing_completion_witness_refuses_continuation(self):
        """Inspection guard: unfinished inspection refuses continuation through every handle."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        peer = BudgetLedger.open(self.ledger_dir)

        # Simulate unfinished inspection by removing completion file while guard is armed
        comp_path = os.path.join(self.ledger_dir, INSPECTION_COMPLETION_FILENAME)
        os.unlink(comp_path)

        # Peer handle refuses continuation
        with self.assertRaises(LedgerHaltedError) as ctx:
            peer.reserve("req_blocked", "sha256:b")
        self.assertIn("UNFINISHED_INSPECTION_GUARD", str(ctx.exception))

        # Owner handle also refuses
        with self.assertRaises(LedgerHaltedError) as ctx2:
            owner.reserve("req_blocked2", "sha256:b2")
        self.assertIn("UNFINISHED_INSPECTION_GUARD", str(ctx2.exception))

        # Fresh open also refuses authorization
        fresh = BudgetLedger.open(self.ledger_dir)
        self.assertTrue(fresh.is_handle_disabled)
        with self.assertRaises(LedgerHaltedError):
            fresh.reserve("req_fresh", "sha256:f")
        owner.close()
        peer.close()
        fresh.close()

    def test_inspection_generation_exhaustion_and_wraparound_rejected(self):
        """Inspection guard: generation >= MAX_INSPECTION_GENERATION refuses continuation."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        guard_path = os.path.join(self.ledger_dir, INSPECTION_GUARD_FILENAME)
        comp_path = os.path.join(self.ledger_dir, INSPECTION_COMPLETION_FILENAME)

        with open(guard_path, "r") as f:
            g = json.load(f)
        g["generation"] = MAX_INSPECTION_GENERATION
        with open(guard_path, "w") as f:
            json.dump(g, f)

        with open(comp_path, "r") as f:
            c = json.load(f)
        c["generation"] = MAX_INSPECTION_GENERATION
        with open(comp_path, "w") as f:
            json.dump(c, f)

        with self.assertRaises(LedgerSecurityError) as ctx:
            owner.reserve("req_over", "sha256:over")
        self.assertIn("exhausted", str(ctx.exception).lower())
        owner.close()

    def test_failed_inspection_and_failed_halt_publication_refuses_across_all_handles(self):
        """Inspection guard: failed halt publication cannot restore authorization."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        peer = BudgetLedger.open(self.ledger_dir)
        p = owner.reserve("req1", "sha256:d1")
        owner.settle(p, _make_receipt(p, input_tokens=1000, output_tokens=1000))

        # Remove the confirmation record so that next inspection detects evidence uncertainty
        conf_files = [f for f in os.listdir(self.ledger_dir) if f.startswith(CONFIRMATION_FILE_PREFIX)]
        self.assertEqual(len(conf_files), 1)
        conf_file = os.path.join(self.ledger_dir, conf_files[0])
        os.unlink(conf_file)

        # Inject failure on saving state so that terminal uncertainty publication fails to write
        def fail_write_state(state, dir_fd, *args, **kwargs):
            raise OSError(errno.EIO, "Injected disk fault on halt publication")

        with patch.object(BudgetLedger, "_atomic_write_state_static", side_effect=fail_write_state):
            with self.assertRaises(OSError):
                owner.reserve("req2", "sha256:d2")

        # Because completion was never written for the new generation, all handles are locked out
        with self.assertRaises(LedgerHaltedError) as ctx1:
            owner.reserve("req_owner_after", "sha256:oa")
        self.assertTrue(owner._poisoned)
        self.assertIn("TERMINAL_UNCERTAINTY", str(ctx1.exception))

        with self.assertRaises(LedgerHaltedError) as ctx2:
            peer.reserve("req_peer_after", "sha256:pa")
        self.assertIn("UNFINISHED_INSPECTION_GUARD", str(ctx2.exception))

        # Fresh handle also sees unfinished inspection and disabled handle
        fresh = BudgetLedger.open(self.ledger_dir)
        self.assertTrue(fresh.get_status().halted)
        self.assertTrue(fresh.is_handle_disabled)
        self.assertEqual(fresh.get_status().handle_disabled_reason, "UNFINISHED_INSPECTION_GUARD")
        with self.assertRaises(LedgerHaltedError):
            fresh.reserve("req_fresh_after", "sha256:fa")
        owner.close()
        peer.close()
        fresh.close()

    def test_terminal_uncertainty_preserves_journal_history_after_later_settlement(self):
        """Terminal uncertainty: preserves prior journal events and distinguishes counts."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        p1 = owner.reserve("req1", "sha256:d1")
        owner.settle(p1, _make_receipt(p1, response_id="resp_001", input_tokens=1000, output_tokens=1000))  # cost = 2000 uUSD

        p2 = owner.reserve("req2", "sha256:d2")
        owner.settle(p2, _make_receipt(p2, response_id="resp_002", input_tokens=2000, output_tokens=500))  # cost = 2500 uUSD
        owner.close()

        # Remove confirmation for first settlement (req1)
        conf_p1 = f"{CONFIRMATION_FILE_PREFIX}{p1.permit_id}.json"
        os.unlink(os.path.join(self.ledger_dir, conf_p1))

        # Reopen: should NOT delete settlement events; records TERMINAL_UNCERTAINTY
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.halt_reason, "UNRESOLVED_SETTLEMENT_PUBLICATION")

        # Historical count of settled requests remains 2!
        self.assertEqual(status.total_reservations_count, 2)
        self.assertEqual(status.settled_requests_count, 2)

        # Spend accounting: req1 settled bound (2000) was replaced by 1,100,000 uUSD in retained_failed_micros
        # req2 remains committed at 2500 uUSD
        self.assertEqual(status.committed_spend_micros, 2500)
        self.assertEqual(status.retained_failed_micros, 1_100_000)
        self.assertEqual(status.total_spend_micros, 1_102_500)

        # Journal contains all original RESERVED/SETTLED events plus TERMINAL_UNCERTAINTY
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            st = json.load(f)
        types = [e["entry_type"] for e in st["journal"]]
        self.assertEqual(types, ["INITIALIZED", "RESERVED", "SETTLED", "RESERVED", "SETTLED", "TERMINAL_UNCERTAINTY"])
        unc_entry = st["journal"][-1]
        self.assertEqual(unc_entry["uncertain_reservation_ids"], [p1.permit_id])
        reopened.close()

    def test_terminal_uncertainty_with_multiple_uncertain_ids_exceeding_ceiling(self):
        """Terminal uncertainty: multiple uncertain IDs derived terminal estimate can exceed $2 without granting authority."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        p1 = owner.reserve("req1", "sha256:d1")
        owner.settle(p1, _make_receipt(p1, response_id="resp_001", input_tokens=1000, output_tokens=1000))

        p2 = owner.reserve("req2", "sha256:d2")
        owner.settle(p2, _make_receipt(p2, response_id="resp_002", input_tokens=1000, output_tokens=1000))

        # Third reservation in flight
        p3 = owner.reserve("req3", "sha256:d3")
        owner.close()

        # Remove both confirmations and let p3 lease expire
        conf_p1 = f"{CONFIRMATION_FILE_PREFIX}{p1.permit_id}.json"
        conf_p2 = f"{CONFIRMATION_FILE_PREFIX}{p2.permit_id}.json"
        os.unlink(os.path.join(self.ledger_dir, conf_p1))
        os.unlink(os.path.join(self.ledger_dir, conf_p2))

        # Reopen: both p1 and p2 are uncertain, plus pending p3 retained
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.halt_reason, "UNRESOLVED_SETTLEMENT_PUBLICATION")

        # 1.10 (p1) + 1.10 (p2) + 1.10 (p3) = 3.30 USD retained!
        self.assertEqual(status.retained_failed_micros, 3_300_000)
        self.assertEqual(status.committed_spend_micros, 0)
        self.assertEqual(status.total_spend_micros, 3_300_000)
        self.assertEqual(status.remaining_available_micros, 0)

        # Grants no spending authority and rejects subsequent requests
        with self.assertRaises(LedgerHaltedError):
            reopened.reserve("req_illegal", "sha256:ill")
        reopened.close()

    def test_existing_valid_terminal_state_preserves_reason_without_reverification(self):
        """Terminal uncertainty: existing valid terminal state preserves reason and accounting."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        p = owner.reserve("req1", "sha256:d1")
        owner.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
        owner.close()

        # Reopen: preserves REQUEST_TRANSPORT_FAILURE without changing reason to TERMINAL_UNCERTAINTY
        reopened = BudgetLedger.open(self.ledger_dir)
        status = reopened.get_status()
        self.assertTrue(status.halted)
        self.assertEqual(status.halt_reason, "REQUEST_TRANSPORT_FAILURE")
        self.assertEqual(status.retained_failed_micros, 1_100_000)
        reopened.close()

    def test_inspection_guard_durability_temp_file_cleanup(self):
        """Inspection guard: failure during guard atomic write cleans up all temp files."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        with patch("os.fsync", side_effect=OSError(errno.EIO, "fsync fail on guard")):
            with self.assertRaises(OSError):
                owner.reserve("req_tmp_fail", "sha256:tf")

        temp_files = [f for f in os.listdir(self.ledger_dir) if f.startswith(".tmp_")]
        self.assertEqual(len(temp_files), 0)
        owner.close()

    def test_strict_failure_codes_reject_unlisted_reasons(self):
        """Strict failure codes: reasons outside ALLOWED_INTERNAL_FAILURE_CODES rejected."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        p = owner.reserve("req1", "sha256:d1")
        with self.assertRaises(SettlementEvidenceError) as ctx:
            owner.record_failure(p, "arbitrary unapproved reason string")
        self.assertIn("ALLOWED_INTERNAL_FAILURE_CODES", str(ctx.exception))
        self.assertTrue(owner.get_status().halted)
        self.assertEqual(owner.get_status().halt_reason, "INVALID_FAILURE_REASON_REJECTED")
        owner.close()

    def test_timestamp_strict_iso8601_utc_and_ordering(self):
        """Timestamp verification: strictly validates UTC format and updated_at >= created_at ordering."""
        owner = BudgetLedger.initialize(self.ledger_dir)
        state_path = os.path.join(self.ledger_dir, STATE_FILENAME)
        with open(state_path, "r") as f:
            data = json.load(f)

        # Invert timestamp ordering
        data["updated_at_utc"] = "2020-01-01T00:00:00Z"
        with open(state_path, "w") as f:
            json.dump(data, f)

        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger.open(self.ledger_dir)
        self.assertIn("precedes created_at_utc", str(ctx.exception).lower())
        owner.close()


# =============================================================================
# Inspection-guard / terminal-uncertainty protocol regressions
# =============================================================================

_TMP_PREFIXES = {
    "state": ".tmp_ledger_",
    "guard": ".tmp_guard_",
    "completion": ".tmp_comp_",
    "intent": ".tmp_intent_",
    "confirm": ".tmp_confirm_",
}
_FINAL_NAMES = {
    "state": STATE_FILENAME,
    "guard": INSPECTION_GUARD_FILENAME,
    "completion": INSPECTION_COMPLETION_FILENAME,
}
BOUNDARIES = ("open", "write", "fsync", "close", "replace", "dirsync")


class _Faults:
    """Path-aware publication fault injector over the real os-level calls.

    Records an ordered event log of (op, name). A rule fires for the `nth`
    publication of `kind` at `boundary`; it raises OSError(EIO) after calling the
    optional `hook` (used to inspect handle state AT the fault).
    """

    def __init__(self, test, rules=()):
        self.test = test
        self.rules = [dict(r, seen=0, fired=False) for r in rules]
        self.events = []
        self.fd_names = {}
        self.closes = {}
        self.last_replace = None
        self.released = set()  # descriptors already closed by a close fault
        self.replacements = []  # (failed_fd, replacement_fd) created INSIDE the failing close
        self.double_closes = []
        self.active = True
        self._patches = []

    def _kind_of_tmp(self, name):
        for kind, prefix in _TMP_PREFIXES.items():
            if name.startswith(prefix):
                return kind
        return None

    def _maybe_fire(self, kind, boundary, name):
        for r in self.rules:
            if not self.active or r["fired"]:
                continue
            if r["kind"] == kind and r["boundary"] == boundary:
                r["seen"] += 1
                if r["seen"] == r.get("nth", 1):
                    r["fired"] = True
                    self.events.append(("FAULT", boundary, kind))
                    if r.get("hook"):
                        r["hook"]()
                    raise OSError(errno.EIO, f"injected {boundary} fault on {kind}")

    def __enter__(self):
        real_open, real_write, real_fsync = os.open, os.write, os.fsync
        real_close, real_replace = os.close, os.replace
        faults = self

        def f_open(path, flags, *a, **kw):
            if kw.get("dir_fd") is not None and isinstance(path, str):
                kind = faults._kind_of_tmp(path)
                faults.events.append(("open", path))
                if kind:
                    faults._maybe_fire(kind, "open", path)
                fd = real_open(path, flags, *a, **kw)
                faults.fd_names[fd] = path
                faults.released.discard(fd)
                return fd
            return real_open(path, flags, *a, **kw)

        def f_write(fd, data):
            name = faults.fd_names.get(fd)
            kind = faults._kind_of_tmp(name) if name else None
            if kind:
                faults.events.append(("write", name))
                faults._maybe_fire(kind, "write", name)
            return real_write(fd, data)

        def f_fsync(fd):
            name = faults.fd_names.get(fd)
            if name:
                kind = faults._kind_of_tmp(name)
                faults.events.append(("fsync", name))
                if kind:
                    faults._maybe_fire(kind, "fsync", name)
            elif stat.S_ISDIR(os.fstat(fd).st_mode):
                faults.events.append(("dirsync", faults.last_replace))
                for kind, final in list(_FINAL_NAMES.items()) + [
                    ("intent", None), ("confirm", None)
                ]:
                    lr = faults.last_replace or ""
                    if (final and lr == final) or (
                        kind == "intent" and lr.startswith(INTENT_FILE_PREFIX)
                    ) or (kind == "confirm" and lr.startswith(CONFIRMATION_FILE_PREFIX)):
                        faults._maybe_fire(kind, "dirsync", lr)
            return real_fsync(fd)

        def f_close(fd):
            name = faults.fd_names.get(fd)
            faults.closes[fd] = faults.closes.get(fd, 0) + 1
            if fd in faults.released:
                faults.double_closes.append(fd)
            if name:
                kind = faults._kind_of_tmp(name)
                faults.events.append(("close", name))
                if kind:
                    try:
                        faults._maybe_fire(kind, "close", name)
                    except OSError:
                        faults.fd_names.pop(fd, None)
                        real_close(fd)  # descriptor really is gone; error still reported
                        faults.released.add(fd)
                        # same-number reuse: an unrelated descriptor takes the freed number
                        repl = real_open(os.devnull, os.O_RDONLY)
                        faults.replacements.append((fd, repl))
                        raise
                faults.fd_names.pop(fd, None)
            return real_close(fd)

        def f_replace(src, dst, *a, **kw):
            kind = faults._kind_of_tmp(src)
            faults.events.append(("replace", dst))
            if kind:
                faults._maybe_fire(kind, "replace", dst)
            res = real_replace(src, dst, *a, **kw)
            faults.last_replace = dst
            return res

        for target, fn in (("os.open", f_open), ("os.write", f_write), ("os.fsync", f_fsync),
                           ("os.close", f_close), ("os.replace", f_replace)):
            p = patch(target, side_effect=fn)
            p.start()
            self._patches.append(p)
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        self._patches = []
        return False

    def cleanup(self):
        """Close replacement descriptors AFTER the test verified they survived."""
        for _, repl in self.replacements:
            try:
                os.close(repl)
            except OSError:
                pass
        self.replacements = []

    def restore_io(self):
        self.active = False

    def index(self, op, name_prefix=None, start=0):
        for i in range(start, len(self.events)):
            e = self.events[i]
            if e[0] == op and (name_prefix is None or (e[1] or "").startswith(name_prefix)):
                return i
        return None


class TestInspectionGuardProtocol(unittest.TestCase):
    """Guard-before-read, completion ordering, publication boundaries, terminal overlay."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
        self.d = os.path.join(self.temp_dir.name, "ledger")
        self._handles = []

    def tearDown(self):
        for h in self._handles:
            h.close()
        self.temp_dir.cleanup()

    # ---- helpers -----------------------------------------------------------
    def new(self):
        h = BudgetLedger.initialize(self.d)
        self._handles.append(h)
        return h

    def open_(self, d=None):
        h = BudgetLedger.open(d or self.d)
        self._handles.append(h)
        return h

    @staticmethod
    def wjson(path, obj):
        with open(path, "w") as fh:
            json.dump(obj, fh)

    @staticmethod
    def rjson(path):
        with open(path) as fh:
            return json.load(fh)

    @staticmethod
    def wtext(path, text):
        with open(path, "w") as fh:
            fh.write(text)

    def jread(self, name):
        with open(os.path.join(self.d, name)) as f:
            return json.load(f)

    def state(self):
        return self.jread(STATE_FILENAME)

    def raw(self, name=STATE_FILENAME):
        with open(os.path.join(self.d, name), "rb") as f:
            return f.read()

    def settle_two(self, h):
        p1 = h.reserve("req1", "sha256:d1")
        h.settle(p1, _make_receipt(p1, response_id="resp_1", input_tokens=1000, output_tokens=1000))
        p2 = h.reserve("req2", "sha256:d2")
        h.settle(p2, _make_receipt(p2, response_id="resp_2", input_tokens=2000, output_tokens=500))
        return p1, p2

    def conf(self, permit):
        return os.path.join(self.d, f"{CONFIRMATION_FILE_PREFIX}{permit.permit_id}.json")

    def intent(self, permit):
        return os.path.join(self.d, f"{INTENT_FILE_PREFIX}{permit.permit_id}.json")

    def assertGuardUnfinished(self):
        g = self.jread(INSPECTION_GUARD_FILENAME)["generation"]
        try:
            c = self.jread(INSPECTION_COMPLETION_FILENAME)["generation"]
        except FileNotFoundError:
            c = None
        self.assertNotEqual(g, c, "guard must be durably unfinished")

    def assertNoTmp(self):
        self.assertEqual([f for f in os.listdir(self.d) if f.startswith(".tmp_")], [])

    def assertAllReserveRefused(self, *handles):
        for i, h in enumerate(handles):
            with self.assertRaises((LedgerHaltedError, LedgerCorruptError, LedgerSecurityError)):
                h.reserve(f"after_{i}_{os.urandom(3).hex()}", "sha256:after")

    # ---- 1. guard armed before reads, completion before mutation -----------
    def _ordered(self, faults, first, second):
        a, b = faults.index(*first), faults.index(*second)
        self.assertIsNotNone(a, first)
        self.assertIsNotNone(b, second)
        self.assertLess(a, b, f"{first} must precede {second}: {faults.events}")

    def test_entry_points_publish_and_sync_guard_before_first_state_read(self):
        scenarios = {}

        def mk_reserve():
            h = self.new()
            return lambda: h.reserve("r1", "sha256:r1")

        def mk_status():
            h = self.new()
            return lambda: h.get_status()

        def mk_settle():
            h = self.new()
            p = h.reserve("r1", "sha256:r1")
            return lambda: h.settle(p, _make_receipt(p))

        def mk_fail():
            h = self.new()
            p = h.reserve("r1", "sha256:r1")
            return lambda: h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")

        def mk_open():
            self.new()
            return lambda: self.open_()

        for name, mk in (("reserve", mk_reserve), ("status", mk_status), ("settle", mk_settle),
                         ("record_failure", mk_fail), ("open", mk_open)):
            with self.subTest(entry=name):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                call = mk()
                with _Faults(self) as f:
                    call()
                g_replace = f.index("replace", INSPECTION_GUARD_FILENAME)
                g_sync = f.index("dirsync", INSPECTION_GUARD_FILENAME, g_replace or 0)
                c_replace = f.index("replace", INSPECTION_COMPLETION_FILENAME)
                self.assertIsNotNone(g_replace)
                self.assertIsNotNone(g_sync)
                self.assertIsNotNone(c_replace)
                self.assertLess(g_sync, c_replace)

    def test_state_reads_happen_only_after_guard_publication_and_sync(self):
        """Authoritative reads (state/intent/confirmation opens) never precede the armed guard."""
        reads = []
        real_read = BudgetLedger._read_state_static.__func__
        real_rec = BudgetLedger._read_record_static.__func__
        log = []

        def spy_state(cls, dir_fd, expected_experiment_id=None):
            log.append("state_read")
            return real_read(cls, dir_fd, expected_experiment_id)

        def spy_rec(cls, name, dir_fd, typ, exp=None):
            log.append("record_read")
            return real_rec(cls, name, dir_fd, typ, exp)

        real_publish = BudgetLedger._publish_bytes_static.__func__

        def spy_publish(cls, encoded, final, prefix, dir_fd):
            real_publish(cls, encoded, final, prefix, dir_fd)
            log.append(f"published:{final}")

        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.settle(p, _make_receipt(p))
        with patch.object(BudgetLedger, "_read_state_static", classmethod(spy_state)), \
                patch.object(BudgetLedger, "_read_record_static", classmethod(spy_rec)), \
                patch.object(BudgetLedger, "_publish_bytes_static", classmethod(spy_publish)):
            for label, call in (
                ("reserve", lambda: h.reserve("req2", "sha256:d2")),
                ("status", lambda: h.get_status()),
            ):
                log.clear()
                call()
                with self.subTest(entry=label):
                    first_read = min(i for i, e in enumerate(log) if e.endswith("_read"))
                    self.assertIn(f"published:{INSPECTION_GUARD_FILENAME}", log[:first_read])
                    self.assertLess(
                        log.index(f"published:{INSPECTION_GUARD_FILENAME}"),
                        log.index(f"published:{INSPECTION_COMPLETION_FILENAME}"),
                    )
            log.clear()
            h3 = BudgetLedger.open(self.d)
            self._handles.append(h3)
            first_state = log.index("state_read")
            self.assertIn(f"published:{INSPECTION_GUARD_FILENAME}", log[:first_state])

    def test_completion_published_after_checks_before_every_mutation(self):
        h = self.new()
        with _Faults(self) as f:
            p = h.reserve("req1", "sha256:d1")
        self._ordered(f, ("dirsync", INSPECTION_COMPLETION_FILENAME), ("replace", STATE_FILENAME))
        with _Faults(self) as f:
            h.settle(p, _make_receipt(p))
        c = f.index("dirsync", INSPECTION_COMPLETION_FILENAME)
        intent = f.index("replace", INTENT_FILE_PREFIX)
        state_r = f.index("replace", STATE_FILENAME)
        conf = f.index("replace", CONFIRMATION_FILE_PREFIX)
        self.assertTrue(c < intent < state_r < conf, f.events)
        # generation advances strictly by one per transaction and completion always matches
        before = self.jread(INSPECTION_GUARD_FILENAME)["generation"]
        h.get_status()
        after = self.jread(INSPECTION_GUARD_FILENAME)
        self.assertEqual(after["generation"], before + 1)
        self.assertEqual(self.jread(INSPECTION_COMPLETION_FILENAME)["generation"], before + 1)
        self.assertEqual(after["experiment_id"], DEFAULT_EXPERIMENT_ID)

    # ---- 2. stale / non-reused completion ---------------------------------
    def test_nonmissing_stale_completion_refuses_every_entry_point_without_mutation(self):
        h = self.new()
        h.reserve("req0", "sha256:d0")  # generation 2 after reserve; completion 2
        peer_holder = self.open_()  # gen 3 complete; peer enabled
        stale = self.jread(INSPECTION_COMPLETION_FILENAME)
        guard_gen = self.jread(INSPECTION_GUARD_FILENAME)["generation"]
        stale["generation"] = guard_gen - 1
        with open(os.path.join(self.d, INSPECTION_COMPLETION_FILENAME), "w") as fh:
            json.dump(stale, fh)  # non-missing, valid-schema, STALE
        state_before, guard_before = self.raw(), self.raw(INSPECTION_GUARD_FILENAME)
        for label, call in (
            ("reserve", lambda hh: hh.reserve("blocked", "sha256:b")),
            ("status", lambda hh: hh.get_status()),
        ):
            with self.subTest(entry=label):
                hh = self.open_() if False else peer_holder
                if label == "reserve":
                    with self.assertRaises(LedgerHaltedError) as ctx:
                        call(hh)
                    self.assertIn("UNFINISHED_INSPECTION_GUARD", str(ctx.exception))
                    self.assertTrue(hh.is_handle_disabled)
                else:
                    s = BudgetLedger.open(self.d)
                    self._handles.append(s)
                    self.assertTrue(s.is_handle_disabled)
                    st = s.get_status()
                    self.assertTrue(st.halted)
                    self.assertEqual(st.halt_reason, "UNFINISHED_INSPECTION_GUARD")
                    self.assertFalse(st.can_reserve)
        fresh = self.open_()
        self.assertTrue(fresh.is_handle_disabled)
        self.assertEqual(self.raw(), state_before)
        self.assertEqual(self.raw(INSPECTION_GUARD_FILENAME), guard_before)

    def test_completion_for_other_ledger_or_generation_zero_is_rejected(self):
        h = self.new()
        for mutate in (
            lambda c: c.__setitem__("experiment_id", "other-ledger"),
            lambda c: c.__setitem__("generation", 0),
            lambda c: c.__setitem__("generation", True),
            lambda c: c.__setitem__("generation", 1.0),
            lambda c: c.__setitem__("extra", 1),
        ):
            with self.subTest(m=mutate):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                c = self.jread(INSPECTION_COMPLETION_FILENAME)
                mutate(c)
                with open(os.path.join(self.d, INSPECTION_COMPLETION_FILENAME), "w") as fh:
                    json.dump(c, fh)
                with self.assertRaises((LedgerCorruptError, LedgerSecurityError)):
                    h.reserve("x", "sha256:x")
                self.assertTrue(h.is_handle_disabled)
                self.assertEqual(self.state()["pending_reservation"], None)

    # ---- 3. guard arming faults stop BEFORE inspection ---------------------
    def test_guard_arm_publication_fault_stops_before_inspection_at_every_boundary(self):
        for boundary in BOUNDARIES:
            for entry in ("reserve", "status", "settle", "record_failure"):
                with self.subTest(boundary=boundary, entry=entry):
                    self.temp_dir.cleanup()
                    self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                    self.d = os.path.join(self.temp_dir.name, "ledger")
                    h = self.new()
                    p = None
                    if entry in ("settle", "record_failure"):
                        p = h.reserve("pend", "sha256:pend")
                    calls = {
                        "reserve": lambda: h.reserve("armfault", "sha256:af"),
                        "status": lambda: h.get_status(),
                        "settle": lambda: h.settle(p, _make_receipt(p)),
                        "record_failure": lambda: h.record_failure(p, "REQUEST_TRANSPORT_FAILURE"),
                    }
                    before = self.raw()
                    with _Faults(self, [{"kind": "guard", "boundary": boundary}]) as f:
                        with self.assertRaises(OSError):
                            calls[entry]()
                        fault_at = f.index("FAULT")
                        self.assertIsNotNone(fault_at)
                        # inspection never began: no ledger/evidence read, no mutation after the fault
                        later = f.events[fault_at + 1:]
                        self.assertEqual(
                            [e for e in later if e[1] in (STATE_FILENAME,) or
                             (e[1] or "").startswith((INTENT_FILE_PREFIX, CONFIRMATION_FILE_PREFIX))],
                            [],
                        )
                    self.assertTrue(h.is_handle_disabled)
                    self.assertEqual(h._poison_reason, "INSPECTION_GUARD_CORRUPT")
                    self.assertEqual(self.raw(), before, "no accounting mutation")
                    self.assertNoTmp()
                    # prior completion was invalidated: peers/fresh handles stay closed
                    fresh = self.open_()
                    self.assertTrue(fresh.is_handle_disabled)
                    self.assertAllReserveRefused(fresh)
                    st = fresh.get_status()
                    self.assertTrue(st.halted)
                    self.assertFalse(st.can_reserve)

    # ---- 4. completion publication boundaries -------------------------------
    def test_completion_publication_fault_returns_no_permit_and_starts_no_mutation(self):
        for boundary in BOUNDARIES:
            with self.subTest(boundary=boundary):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                before = self.raw()
                peer = self.open_()
                with _Faults(self, [{"kind": "completion", "boundary": boundary}]) as f:
                    with self.assertRaises(OSError):
                        h.reserve("compfault", "sha256:cf")
                self.assertTrue(h.is_handle_disabled)
                self.assertEqual(h._poison_reason, "INSPECTION_COMPLETION_FAILED")
                self.assertEqual(self.raw(), before)
                self.assertIsNone(self.state()["pending_reservation"])
                self.assertNoTmp()
                self.assertFalse(f.index("replace", STATE_FILENAME))
                if boundary == "dirsync":
                    # witness survived (replace happened): a fresh inspection may proceed
                    fresh = self.open_()
                    self.assertFalse(fresh.is_handle_disabled)
                    self.assertIsNotNone(fresh.reserve("fresh_ok", "sha256:fo"))
                else:
                    # witness lost: durable unfinished guard refuses every handle
                    self.assertAllReserveRefused(peer)
                    fresh = self.open_()
                    self.assertTrue(fresh.is_handle_disabled)
                    self.assertAllReserveRefused(fresh)

    # ---- 5. failed inspection + failed halt publication ---------------------
    def _lost_conf_setup(self):
        h = self.new()
        p1 = h.reserve("req1", "sha256:d1")
        h.settle(p1, _make_receipt(p1, response_id="resp_1", input_tokens=1000, output_tokens=1000))
        peer = self.open_()
        os.unlink(self.conf(p1))
        return h, peer, p1

    def test_failed_inspection_plus_failed_halt_publication_every_entry_old_and_fresh(self):
        for entry in ("reserve", "status", "open", "record_failure", "settle"):
            for cause in ("lost_confirmation", "record_read_eio"):
                with self.subTest(entry=entry, cause=cause):
                    self.temp_dir.cleanup()
                    self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                    self.d = os.path.join(self.temp_dir.name, "ledger")
                    h = self.new()
                    p1 = h.reserve("req1", "sha256:d1")
                    h.settle(p1, _make_receipt(p1, response_id="resp_1", input_tokens=1000, output_tokens=1000))
                    pend = None
                    if entry in ("record_failure", "settle"):
                        pend = h.reserve("req2", "sha256:d2")
                    peer = self.open_()
                    if cause == "lost_confirmation":
                        os.unlink(self.conf(p1))
                    real_open = os.open

                    def eio_open(path, flags, *a, **kw):
                        if isinstance(path, str) and path.startswith(CONFIRMATION_FILE_PREFIX) and cause == "record_read_eio" and eio_on[0]:
                            raise OSError(errno.EIO, "injected record read fault")
                        return real_open(path, flags, *a, **kw)

                    eio_on = [True]
                    caller = {
                        "reserve": lambda: h.reserve("blocked", "sha256:b"),
                        "status": lambda: h.get_status(),
                        "open": lambda: BudgetLedger.open(self.d),
                        "record_failure": lambda: h.record_failure(pend, "REQUEST_TRANSPORT_FAILURE"),
                        "settle": lambda: h.settle(pend, _make_receipt(pend, response_id="resp_2")),
                    }[entry]
                    poisoned_at_publish = []
                    publish_attempts = []
                    real_pub = BudgetLedger._atomic_write_state_static.__func__

                    def failing_pub(cls, state, dir_fd, expected_experiment_id=None):
                        publish_attempts.append(True)
                        poisoned_at_publish.append(h._poisoned)
                        raise OSError(errno.EIO, "injected halt publication failure")

                    with patch("os.open", side_effect=eio_open), \
                            patch.object(BudgetLedger, "_atomic_write_state_static", classmethod(failing_pub)):
                        with self.assertRaises(Exception) as ctx:
                            caller()
                    self.assertIsInstance(ctx.exception, (OSError, LedgerSecurityError, LedgerHaltedError))
                    self.assertTrue(publish_attempts, "terminal publication was attempted")
                    if entry != "open":
                        self.assertTrue(all(poisoned_at_publish), "handle disabled BEFORE terminal publication")
                        self.assertTrue(h.is_handle_disabled)
                    eio_on[0] = False
                    # I/O restored; nothing durable says terminal, but the guard is unfinished
                    self.assertFalse(self.state()["halted"])
                    self.assertGuardUnfinished()
                    victims = [peer] if entry != "open" else [peer, h]
                    if entry != "open":
                        victims.insert(0, h)
                    self.assertAllReserveRefused(*victims)
                    fresh = self.open_()
                    self.assertTrue(fresh.is_handle_disabled)
                    self.assertAllReserveRefused(fresh)
                    st = fresh.get_status()
                    self.assertTrue(st.halted)
                    self.assertFalse(st.can_reserve)

    def test_halt_publication_success_marks_terminal_and_leaves_guard_unfinished(self):
        h, peer, p1 = self._lost_conf_setup()
        with self.assertRaises(LedgerHaltedError):
            h.reserve("req2", "sha256:d2")
        self.assertTrue(h.is_handle_disabled)
        self.assertEqual(h._poison_reason, "TERMINAL_UNCERTAINTY")
        self.assertGuardUnfinished()
        st = self.state()
        self.assertTrue(st["halted"])
        self.assertEqual(st["halt_reason"], "UNRESOLVED_SETTLEMENT_PUBLICATION" if os.path.exists(self.intent(p1)) else "TERMINAL_UNCERTAINTY")
        # peer / fresh handles keep the ORIGINAL terminal reason and accounting
        for hh in (peer, self.open_()):
            s = hh.get_status()
            self.assertEqual(s.halt_reason, st["halt_reason"])
            self.assertEqual(s.retained_failed_micros, 1_100_000)
            self.assertEqual(s.committed_spend_micros, 0)
            self.assertFalse(s.can_reserve)
        self.assertAllReserveRefused(peer)

    # ---- 6. missing / corrupt / unreadable guard ----------------------------
    def test_missing_guard_refuses_before_inspection_and_status_is_never_healthy(self):
        h = self.new()
        peer = self.open_()
        os.unlink(os.path.join(self.d, INSPECTION_GUARD_FILENAME))
        reads = []
        real_state = BudgetLedger._read_state_static.__func__

        def spy(cls, dir_fd, expected_experiment_id=None):
            reads.append(1)
            return real_state(cls, dir_fd, expected_experiment_id)

        with patch.object(BudgetLedger, "_read_state_static", classmethod(spy)):
            with self.assertRaises(LedgerCorruptError):
                h.reserve("x", "sha256:x")
            self.assertEqual(reads, [], "no authoritative read before a valid guard")
        self.assertTrue(h.is_handle_disabled)
        st = peer.get_status()
        self.assertTrue(st.halted)
        self.assertTrue(st.handle_disabled)
        self.assertFalse(st.can_reserve)
        self.assertIn(st.halt_reason, ALLOWED_INTERNAL_FAILURE_CODES)
        with self.assertRaises(LedgerCorruptError):
            BudgetLedger.open(self.d)

    def test_unreadable_or_corrupt_guard_disables_handle_and_stops(self):
        for variant in ("eio", "garbage", "bad_type", "wrong_ledger"):
            with self.subTest(variant=variant):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                gpath = os.path.join(self.d, INSPECTION_GUARD_FILENAME)
                if variant == "garbage":
                    self.wtext(gpath, "{not json")
                elif variant == "bad_type":
                    g = self.jread(INSPECTION_GUARD_FILENAME)
                    g["generation"] = "2"
                    self.wjson(gpath, g)
                elif variant == "wrong_ledger":
                    g = self.jread(INSPECTION_GUARD_FILENAME)
                    g["experiment_id"] = "someone-else"
                    self.wjson(gpath, g)
                real_open = os.open

                def eio(path, flags, *a, **kw):
                    if variant == "eio" and path == INSPECTION_GUARD_FILENAME:
                        raise OSError(errno.EIO, "guard unreadable")
                    return real_open(path, flags, *a, **kw)

                before = self.raw()
                with patch("os.open", side_effect=eio):
                    with self.assertRaises((LedgerCorruptError, LedgerSecurityError)):
                        h.reserve("x", "sha256:x")
                self.assertTrue(h.is_handle_disabled)
                self.assertEqual(h._poison_reason, "INSPECTION_GUARD_CORRUPT")
                self.assertEqual(self.raw(), before)
                with self.assertRaises(LedgerHaltedError):
                    h.reserve("y", "sha256:y")

    def test_missing_guard_on_terminal_state_gives_disabled_report_preserving_accounting(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
        before = self.raw()
        os.unlink(os.path.join(self.d, INSPECTION_GUARD_FILENAME))
        os.unlink(os.path.join(self.d, INSPECTION_COMPLETION_FILENAME))
        rep = BudgetLedger.open(self.d)
        self._handles.append(rep)
        self.assertTrue(rep.is_handle_disabled)
        st = rep.get_status()
        self.assertTrue(st.halted)
        self.assertEqual(st.halt_reason, "REQUEST_TRANSPORT_FAILURE")
        self.assertEqual(st.retained_failed_micros, 1_100_000)
        self.assertFalse(st.can_reserve)
        with self.assertRaises(LedgerHaltedError):
            rep.reserve("again", "sha256:a")
        self.assertEqual(self.raw(), before)
        self.assertFalse(os.path.exists(os.path.join(self.d, INSPECTION_GUARD_FILENAME)))

    # ---- 7. unattributable uncertainty always stops admission ---------------
    def test_scan_eio_on_fresh_ledger_halts_without_inventing_reservations(self):
        h = self.new()
        peer = self.open_()
        with patch("os.scandir", side_effect=OSError(errno.EIO, "scan fault")):
            with self.assertRaises(LedgerSecurityError):
                h.reserve("first", "sha256:f")
        self.assertTrue(h.is_handle_disabled)
        st = self.state()
        self.assertTrue(st["halted"])
        self.assertEqual(st["halt_reason"], "TERMINAL_UNCERTAINTY")
        self.assertEqual(st["journal"][-1]["uncertain_reservation_ids"], [])
        self.assertEqual(st["total_reservations_count"], 0)
        self.assertEqual(st["retained_failed_micros"], 0)
        self.assertEqual(st["committed_spend_micros"], 0)
        self.assertAllReserveRefused(h, peer)
        fresh = self.open_()
        self.assertTrue(fresh.is_handle_disabled)
        self.assertAllReserveRefused(fresh)
        for hh in (peer, fresh):
            self.assertEqual(hh.get_status().halt_reason, "TERMINAL_UNCERTAINTY")

    def test_unmatched_malformed_intent_on_fresh_ledger_halts_admission(self):
        h = self.new()
        peer = self.open_()
        with open(os.path.join(self.d, f"{INTENT_FILE_PREFIX}unknown_res.json"), "w") as fh:
            fh.write("{garbage")
        os.chmod(os.path.join(self.d, f"{INTENT_FILE_PREFIX}unknown_res.json"), 0o600)
        with self.assertRaises(LedgerHaltedError):
            peer.reserve("first", "sha256:f")
        st = self.state()
        self.assertTrue(st["halted"])
        self.assertEqual(st["journal"][-1]["uncertain_reservation_ids"], [])
        self.assertEqual(st["total_reservations_count"], 0)
        self.assertAllReserveRefused(h)
        self.assertEqual(self.open_().get_status().halt_reason, st["halt_reason"])

    def test_unattributable_uncertainty_covers_all_recorded_reservations(self):
        h = self.new()
        p1, p2 = self.settle_two(h)
        p3 = h.reserve("req3", "sha256:d3")
        h.close()
        with open(os.path.join(self.d, f"{INTENT_FILE_PREFIX}stray.json"), "w") as fh:
            fh.write("{garbage")
        os.chmod(os.path.join(self.d, f"{INTENT_FILE_PREFIX}stray.json"), 0o600)
        fresh = self.open_()
        self.assertTrue(fresh.is_handle_disabled)
        st = self.state()
        self.assertEqual(
            st["journal"][-1]["uncertain_reservation_ids"],
            sorted([p1.permit_id, p2.permit_id, p3.permit_id]),
        )
        s = fresh.get_status()
        self.assertEqual(s.retained_failed_micros, 3_300_000)
        self.assertEqual(s.committed_spend_micros, 0)
        self.assertEqual(s.settled_requests_count, 2)
        self.assertEqual(s.total_reservations_count, 3)
        self.assertFalse(s.can_reserve)

    # ---- 8. terminal overlay semantics -------------------------------------
    def test_overlay_preserves_history_totals_counts_and_forbids_later_events(self):
        h = self.new()
        p1, p2 = self.settle_two(h)
        p3 = h.reserve("req3", "sha256:d3")
        h.close()
        journal_before = self.state()["journal"]
        os.unlink(self.conf(p1))
        os.unlink(self.conf(p2))
        fresh = self.open_()
        st = self.state()
        self.assertEqual(st["journal"][:len(journal_before)], journal_before, "history not rewritten")
        self.assertEqual(len(st["journal"]), len(journal_before) + 1)
        ev = st["journal"][-1]
        self.assertEqual(ev["entry_type"], "TERMINAL_UNCERTAINTY")
        self.assertEqual(ev["uncertain_reservation_ids"], sorted([p1.permit_id, p2.permit_id, p3.permit_id]))
        self.assertEqual((st["committed_spend_micros"], st["retained_failed_micros"]), (0, 3_300_000))
        self.assertEqual((st["settled_requests_count"], st["total_reservations_count"]), (2, 3))
        self.assertIsNone(st["pending_reservation"])
        s = fresh.get_status()
        self.assertGreater(s.total_spend_micros, GLOBAL_CEILING_MICROS)
        self.assertEqual(s.remaining_available_micros, 0)
        self.assertFalse(s.can_reserve)
        # idempotent: repeated opens/status do not change bytes
        raw = self.raw()
        for _ in range(3):
            self.open_().get_status()
        self.assertEqual(self.raw(), raw)
        # any later event after the overlay is rejected by replay
        import copy
        for mutate in ("reserved", "settled"):
            bad = copy.deepcopy(st)
            ts = bad["updated_at_utc"]
            bad["journal"].append(
                {"entry_type": "RESERVED", "reservation_id": "permit_x", "request_id": "rx",
                 "request_digest": "sha256:x", "reserved_amount_micros": 1_100_000,
                 "reservation_index": 4, "timestamp_utc": ts}
            )
            bad["total_reservations_count"] = 4
            with self.assertRaises(LedgerCorruptError):
                BudgetLedger._validate_and_reconcile_state_static(bad)
            break

    def test_overlay_cannot_reference_unknown_or_duplicate_ids_or_omit_pending(self):
        import copy
        h = self.new()
        p1, p2 = self.settle_two(h)
        p3 = h.reserve("req3", "sha256:d3")
        h.close()
        os.unlink(self.conf(p1))
        self.open_()
        good = self.state()
        BudgetLedger._validate_and_reconcile_state_static(good)

        def with_ids(ids):
            b = copy.deepcopy(good)
            b["journal"][-1]["uncertain_reservation_ids"] = ids
            return b

        ids = good["journal"][-1]["uncertain_reservation_ids"]
        self.assertEqual(sorted(ids), sorted([p1.permit_id, p3.permit_id]))
        for label, bad_ids in (
            ("unknown", ids + ["permit_invented"]),
            ("duplicate", ids + [ids[0]]),
            ("omits_pending", [p1.permit_id]),
            ("empty_with_history", []),
            ("unsorted", list(reversed(ids))),
            ("non_string", ids + [7]),
        ):
            with self.subTest(label=label):
                with self.assertRaises(LedgerCorruptError):
                    BudgetLedger._validate_and_reconcile_state_static(with_ids(bad_ids))

    def test_overlay_replay_still_applies_unchanged_cap_to_original_admissions(self):
        import copy
        h = self.new()
        p1, p2 = self.settle_two(h)
        os.unlink(self.conf(p1))
        os.unlink(self.conf(p2))
        h.close()
        self.open_()
        st = self.state()
        # original admissions: pretend the first settlement cost almost the whole cap so the
        # second admission would have exceeded $2 -> replay must reject BEFORE applying overlay
        bad = copy.deepcopy(st)
        for e in bad["journal"]:
            if e.get("entry_type") == "SETTLED" and e["reservation_id"] == p1.permit_id:
                e["input_tokens"], e["output_tokens"] = 999_000, 1_000
                e["total_tokens"] = 1_000_000
                e["settled_amount_micros"] = 1_000_000
                e["unencumbered_amount_micros"] = 100_000
        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger._validate_and_reconcile_state_static(bad)
        self.assertIn("Replay ceiling violation", str(ctx.exception))

    def test_loss_of_intent_alone_or_mismatched_fields_or_timestamp_halts(self):
        for label in ("intent_missing", "timestamp_mismatch_conf", "timestamp_mismatch_intent",
                      "amount_mismatch", "conf_extra_key", "intent_garbage"):
            with self.subTest(label=label):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                p1, p2 = self.settle_two(h)
                h.close()
                if label == "intent_missing":
                    os.unlink(self.intent(p1))
                elif label in ("timestamp_mismatch_conf", "timestamp_mismatch_intent"):
                    path = self.conf(p1) if label.endswith("conf") else self.intent(p1)
                    rec = self.rjson(path)
                    rec["timestamp_utc"] = "2020-01-01T00:00:00+00:00"  # valid, but different
                    self.wjson(path, rec)
                elif label == "amount_mismatch":
                    rec = self.rjson(self.conf(p1))
                    rec["input_tokens"] += 1
                    rec["total_tokens"] += 1
                    rec["settled_amount_micros"] += 1
                    rec["unencumbered_amount_micros"] -= 1
                    self.wjson(self.conf(p1), rec)
                elif label == "conf_extra_key":
                    rec = self.rjson(self.conf(p1))
                    rec["extra"] = 1
                    self.wjson(self.conf(p1), rec)
                else:
                    self.wtext(self.intent(p1), "{garbage")
                fresh = self.open_()
                self.assertTrue(fresh.is_handle_disabled)
                st = self.state()
                self.assertEqual(st["journal"][-1]["uncertain_reservation_ids"], [p1.permit_id])
                self.assertEqual(st["committed_spend_micros"], 2500)
                self.assertEqual(st["retained_failed_micros"], 1_100_000)

    # ---- 9. existing terminal state is preserved ----------------------------
    def test_intent_dir_sync_failure_terminal_state_is_idempotent_for_all_readers(self):
        h = self.new()
        peer = self.open_()
        p = h.reserve("req1", "sha256:d1")
        with _Faults(self, [{"kind": "intent", "boundary": "dirsync"}]):
            with self.assertRaises(OSError):
                h.settle(p, _make_receipt(p))
        st = self.state()
        self.assertTrue(st["halted"])
        self.assertEqual(st["halt_reason"], "SETTLEMENT_INTENT_WRITE_FAILED")
        raw = self.raw()
        self.assertTrue(os.path.exists(self.intent(p)))  # auxiliary file exists, must NOT be reprocessed
        for hh in (h, peer, self.open_(), self.open_()):
            s = hh.get_status()
            self.assertEqual(s.halt_reason, "SETTLEMENT_INTENT_WRITE_FAILED")
            self.assertEqual(s.retained_failed_micros, 1_100_000)
            self.assertEqual(s.committed_spend_micros, 0)
            self.assertFalse(s.has_pending_reservation)
        self.assertEqual(self.state()["journal"][-1]["entry_type"], "FAILED_RETAINED")
        self.assertEqual(self.state()["halt_reason"], "SETTLEMENT_INTENT_WRITE_FAILED")
        self.assertEqual(self.raw(), raw)
        self.assertAllReserveRefused(peer)

    def test_terminal_state_stays_readable_with_garbage_auxiliary_files(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
        junk = os.path.join(self.d, f"{INTENT_FILE_PREFIX}{p.permit_id}.json")
        self.wtext(junk, "{garbage")
        os.chmod(junk, 0o600)
        raw = self.raw()
        s = self.open_().get_status()
        self.assertEqual(s.halt_reason, "REQUEST_TRANSPORT_FAILURE")
        self.assertEqual(self.raw(), raw)

    # ---- 10. strict schema / reasons / timestamps ---------------------------
    def test_schema_version_must_be_exact_int_one(self):
        for bad in (True, 1.0, "1", 2, 0, None):
            with self.subTest(bad=bad):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                self.new()
                st = self.state()
                st["schema_version"] = bad
                self.wjson(os.path.join(self.d, STATE_FILENAME), st)
                with self.assertRaises(LedgerCorruptError):
                    BudgetLedger.open(self.d)

    def test_top_level_and_nested_timestamps_validated(self):
        for field, bad in (
            ("created_at_utc", "2020-01-01T00:00:00"),
            ("created_at_utc", " 2020-01-01T00:00:00+00:00"),
            ("created_at_utc", 17),
            ("updated_at_utc", "not-a-time"),
            ("updated_at_utc", None),
        ):
            with self.subTest(field=field, bad=bad):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                self.new()
                st = self.state()
                st[field] = bad
                self.wjson(os.path.join(self.d, STATE_FILENAME), st)
                with self.assertRaises(LedgerCorruptError):
                    BudgetLedger.open(self.d)

    def test_journal_reasons_outside_allowlist_rejected_in_replay(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
        st = self.state()
        for field_path in ("journal", "halt"):
            bad = json.loads(json.dumps(st))
            bad["journal"][-1]["reason"] = "provider said: <secret> failure"
            bad["halt_reason"] = "provider said: <secret> failure"
            with self.assertRaises(LedgerCorruptError):
                BudgetLedger._validate_and_reconcile_state_static(bad)
            break
        bad = json.loads(json.dumps(st))
        bad["journal"][-1]["reason"] = "TERMINAL_UNCERTAINTY"  # allowed code, wrong entry kind is fine; mismatch top-level
        with self.assertRaises(LedgerCorruptError):
            BudgetLedger._validate_and_reconcile_state_static(bad)

    def test_generated_failures_use_closed_codes_and_never_echo_provider_text(self):
        secret = "SECRET-PROVIDER-TEXT-<script>"
        variants = {
            "model": dict(model=secret),
            "tier": dict(service_tier=secret),
            "status": dict(status=secret),
            "response_id": dict(response_id="bad id with spaces " + secret),
            "tokens_neg": dict(input_tokens=-5),
            "tokens_sum": dict(total_tokens=3),
            "tokens_big": dict(input_tokens=MAX_INPUT_TOKENS + 1, total_tokens=MAX_INPUT_TOKENS + 501),
            "extra": dict(extra_fields={secret: 1}),
            "request_id": None,
            "digest": None,
        }
        for label, kw in variants.items():
            with self.subTest(label=label):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                p = h.reserve("req1", "sha256:d1")
                rec = _make_receipt(p, **(kw or {}))
                if label == "request_id":
                    rec["request_id"] = secret
                if label == "digest":
                    rec["request_digest"] = secret
                with self.assertRaises(SettlementEvidenceError) as ctx:
                    h.settle(p, rec)
                self.assertNotIn(secret, str(ctx.exception))
                st = self.state()
                self.assertIn(st["halt_reason"], ALLOWED_INTERNAL_FAILURE_CODES)
                self.assertNotEqual(st["halt_reason"], "INVALID_FAILURE_REASON_REJECTED", label)
                self.assertNotIn(secret, json.dumps(st))
                s = h.get_status()
                self.assertIn(s.handle_disabled_reason, ALLOWED_INTERNAL_FAILURE_CODES)
                self.assertIn(s.halt_reason, ALLOWED_INTERNAL_FAILURE_CODES)
                self.assertNotIn(secret, repr(s))

    def test_handle_poison_reasons_are_closed_codes(self):
        h = self.new()
        h._poison_handle("raw exception text: boom")
        self.assertEqual(h._poison_reason, "INVALID_FAILURE_REASON_REJECTED")
        h2 = self.open_()
        h2._poison_handle("REQUEST_TRANSPORT_FAILURE")
        h2.close()  # first cause preserved after close
        self.assertEqual(h2._poison_reason, "REQUEST_TRANSPORT_FAILURE")

    def test_sync_identity_failure_reason_has_no_raw_exception_text(self):
        h = self.new()
        real = BudgetLedger._verify_held_lease
        calls = []

        def flaky(self_, dir_fd):
            calls.append(1)
            if len(calls) == 2:  # 1st: reserve's own check; 2nd: final sync-identity check
                raise LedgerSecurityError("RAW-EXC-TEXT")
            return real(self_, dir_fd)

        with patch.object(BudgetLedger, "_verify_held_lease", flaky):
            with self.assertRaises(LedgerSecurityError):
                h.reserve("req1", "sha256:d1")
        self.assertEqual(len(calls), 2)
        self.assertEqual(h._poison_reason, "SYNC_IDENTITY_CHECK_FAILED")
        self.assertNotIn("RAW-EXC-TEXT", repr(h.get_status()))

    def test_unlisted_generated_failure_code_is_coerced_not_persisted(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        err = SettlementEvidenceError("x")
        err.failure_code = "raw provider text: do not persist"
        with patch.object(BudgetLedger, "_validate_and_cost_receipt", side_effect=err):
            with self.assertRaises(SettlementEvidenceError):
                h.settle(p, _make_receipt(p))
        st = self.state()
        self.assertEqual(st["halt_reason"], "INVALID_FAILURE_REASON_REJECTED")
        self.assertEqual(st["journal"][-1]["reason"], "INVALID_FAILURE_REASON_REJECTED")
        self.assertEqual(st["retained_failed_micros"], 1_100_000)

    def test_corrupt_state_read_disables_handle_and_unfinished_guard_persists(self):
        h = self.new()
        peer = self.open_()
        good = self.raw()
        with open(os.path.join(self.d, STATE_FILENAME), "w") as fh:
            fh.write("{corrupt")
        with self.assertRaises(LedgerCorruptError):
            h.reserve("x", "sha256:x")
        self.assertTrue(h.is_handle_disabled)
        self.assertEqual(h._poison_reason, "INSPECTION_EVIDENCE_UNCERTAINTY")
        with open(os.path.join(self.d, STATE_FILENAME), "wb") as fh:
            fh.write(good)  # repair is NOT automatic: the guard stays unfinished
        self.assertGuardUnfinished()
        self.assertAllReserveRefused(h, peer, self.open_())

    def test_valid_looking_events_after_terminal_failure_rejected_by_terminal_rule(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
        st = self.state()
        ts = st["updated_at_utc"]
        st["journal"] += [
            {"entry_type": "RESERVED", "reservation_id": "permit_late", "request_id": "req_late",
             "request_digest": "sha256:l", "reserved_amount_micros": 1_100_000,
             "reservation_index": 2, "timestamp_utc": ts},
            {"entry_type": "SETTLED", "reservation_id": "permit_late", "request_id": "req_late",
             "request_digest": "sha256:l", "response_id": "resp_late", "model": PINNED_MODEL,
             "service_tier": PINNED_SERVICE_TIER, "input_tokens": 10, "output_tokens": 10,
             "total_tokens": 20, "settled_amount_micros": 20,
             "unencumbered_amount_micros": 1_099_980, "timestamp_utc": ts},
        ]
        st["total_reservations_count"] = 2
        st["settled_requests_count"] = 1
        st["committed_spend_micros"] = 20
        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger._validate_and_reconcile_state_static(st)
        self.assertIn("after terminal halt", str(ctx.exception))

    # ---- residual correction (2026-11-03 review) ----------------------------
    def _record_io_fault(self, mode, victim_name):
        """Patch real os.read/os.fstat/os.close for ONE auxiliary record file's descriptor."""
        real_open, real_read, real_fstat, real_close = os.open, os.read, os.fstat, os.close
        ctx = {"fds": set(), "closes": [], "replacements": [], "armed": True, "hits": 0}

        def f_open(path, flags, *a, **kw):
            fd = real_open(path, flags, *a, **kw)
            if ctx["armed"] and path == victim_name and kw.get("dir_fd") is not None:
                ctx["fds"].add(fd)
            return fd

        def f_read(fd, n):
            if fd in ctx["fds"] and mode == "read":
                ctx["hits"] += 1
                raise OSError(errno.EIO, "injected record read fault")
            return real_read(fd, n)

        def f_fstat(fd):
            if fd in ctx["fds"] and mode == "fstat":
                ctx["hits"] += 1
                raise OSError(errno.EIO, "injected record fstat fault")
            return real_fstat(fd)

        def f_close(fd):
            if fd in ctx["fds"]:
                ctx["closes"].append(fd)
                ctx["fds"].discard(fd)
                if mode == "close":
                    real_close(fd)
                    ctx["replacements"].append((fd, real_open(os.devnull, os.O_RDONLY)))
                    ctx["hits"] += 1
                    raise OSError(errno.EIO, "injected record close fault")
            return real_close(fd)

        patches = [patch("os.open", side_effect=f_open), patch("os.read", side_effect=f_read),
                   patch("os.fstat", side_effect=f_fstat), patch("os.close", side_effect=f_close)]
        return ctx, patches

    def test_record_read_fstat_close_errors_take_conservative_overlay_path(self):
        for mode in ("read", "fstat", "close", "none"):
            for entry in ("reserve", "status", "open"):
                with self.subTest(mode=mode, entry=entry):
                    self.temp_dir.cleanup()
                    self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                    self.d = os.path.join(self.temp_dir.name, "ledger")
                    h = self.new()
                    p1, p2 = self.settle_two(h)
                    peer = self.open_()
                    victim = f"{CONFIRMATION_FILE_PREFIX}{p1.permit_id}.json"
                    ctx, patches = self._record_io_fault(mode if mode != "none" else "read", victim)
                    ctx["armed"] = mode != "none"
                    for pt in patches:
                        pt.start()
                    try:
                        call = {"reserve": lambda: h.reserve("blocked", "sha256:b"),
                                "status": lambda: h.get_status(),
                                "open": lambda: BudgetLedger.open(self.d)}[entry]
                        if mode == "none":
                            res = call()
                            if entry == "open":
                                self._handles.append(res)
                        elif entry == "status":
                            res = call()  # report path after the overlay
                            self.assertTrue(res.halted)
                        else:
                            with self.assertRaises((LedgerSecurityError, LedgerHaltedError)):
                                call()
                    finally:
                        for pt in patches:
                            pt.stop()
                    st = self.state()
                    if mode == "none":  # healthy control
                        self.assertFalse(st["halted"] if entry != "reserve" else False)
                        self.assertEqual(st["retained_failed_micros"], 0)
                        continue
                    self.assertGreater(ctx["hits"], 0, "fault fired")
                    self.assertTrue(st["halted"])
                    self.assertEqual(st["journal"][-1]["entry_type"], "TERMINAL_UNCERTAINTY")
                    self.assertEqual(st["journal"][-1]["uncertain_reservation_ids"], [p1.permit_id])
                    # conservative retention: full reservation, not the 2000 uUSD bound
                    self.assertEqual(st["retained_failed_micros"], 1_100_000)
                    self.assertEqual(st["committed_spend_micros"], 2500)
                    self.assertEqual(len(ctx["closes"]), len(set(ctx["closes"])) if mode != "close" else len(ctx["closes"]))
                    if mode == "close":
                        self.assertEqual(len(ctx["closes"]), 1, "exactly one close, no retry")
                        for fd, repl in ctx["replacements"]:
                            self.assertEqual(fd, repl)
                            os.fstat(repl)
                            os.close(repl)
                    self.assertAllReserveRefused(h, peer, self.open_())

    def test_record_io_error_plus_failed_halt_publication_refuses_every_handle(self):
        for mode in ("read", "fstat", "close"):
            with self.subTest(mode=mode):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                p1, p2 = self.settle_two(h)
                peer = self.open_()
                ctx, patches = self._record_io_fault(mode, f"{CONFIRMATION_FILE_PREFIX}{p1.permit_id}.json")
                attempts = []

                def failing_pub(cls, state, dir_fd, expected_experiment_id=None):
                    attempts.append(h._poisoned)
                    raise OSError(errno.EIO, "halt publication fault")

                for pt in patches:
                    pt.start()
                try:
                    with patch.object(BudgetLedger, "_atomic_write_state_static", classmethod(failing_pub)):
                        with self.assertRaises(OSError):
                            h.reserve("blocked", "sha256:b")
                finally:
                    for pt in patches:
                        pt.stop()
                for fd, repl in ctx["replacements"]:
                    os.close(repl)
                self.assertEqual(attempts, [True], "disabled before the (failed) publication")
                self.assertFalse(self.state()["halted"])
                self.assertGuardUnfinished()
                self.assertAllReserveRefused(h, peer, self.open_())

    def test_halted_flag_without_terminal_history_is_rejected_and_valid_terminals_kept(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.settle(p, _make_receipt(p, input_tokens=100, output_tokens=50))
        h.close()
        os.unlink(self.conf(p))
        st = self.state()
        st["halted"] = True
        st["halt_reason"] = "TERMINAL_UNCERTAINTY"
        self.wjson(os.path.join(self.d, STATE_FILENAME), st)
        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger.open(self.d)
        self.assertIn("no terminal event", str(ctx.exception))
        # healthy controls: explicit failure, orphan recovery and overlay still load
        for label in ("failure", "overlay", "orphan"):
            self.temp_dir.cleanup()
            self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
            self.d = os.path.join(self.temp_dir.name, "ledger")
            g = self.new()
            q = g.reserve("r1", "sha256:1")
            if label == "failure":
                g.record_failure(q, "REQUEST_TRANSPORT_FAILURE")
            elif label == "overlay":
                g.settle(q, _make_receipt(q))
                os.unlink(self.conf(q))
                g.get_status()
            else:
                g.close()
            s = self.open_().get_status()
            self.assertTrue(s.halted, label)

    def test_unfinished_guard_poisons_before_any_reporting_state_read(self):
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                if terminal:
                    p = h.reserve("req1", "sha256:d1")
                    h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
                    h = self.open_()
                os.unlink(os.path.join(self.d, INSPECTION_COMPLETION_FILENAME))
                seen = []
                real_state = BudgetLedger._read_state_static.__func__

                def spy(cls, dir_fd, expected_experiment_id=None):
                    seen.append(h._poisoned)
                    return real_state(cls, dir_fd, expected_experiment_id)

                with patch.object(BudgetLedger, "_read_state_static", classmethod(spy)):
                    with self.assertRaises(LedgerHaltedError) as ctx:
                        h.reserve("x", "sha256:x")
                self.assertTrue(seen and all(seen), f"state read while handle still enabled: {seen}")
                expected = "REQUEST_TRANSPORT_FAILURE" if terminal else "UNFINISHED_INSPECTION_GUARD"
                self.assertEqual(h._poison_reason, expected)
                self.assertIn(expected, str(ctx.exception))
        # healthy control: a normal inspection reads state while the handle is enabled
        self.temp_dir.cleanup()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
        self.d = os.path.join(self.temp_dir.name, "ledger")
        h = self.new()
        seen = []
        real_state = BudgetLedger._read_state_static.__func__

        def spy2(cls, dir_fd, expected_experiment_id=None):
            seen.append(h._poisoned)
            return real_state(cls, dir_fd, expected_experiment_id)

        with patch.object(BudgetLedger, "_read_state_static", classmethod(spy2)):
            h.reserve("ok", "sha256:ok")
        self.assertEqual(seen, [False])

    def test_invalid_utf8_or_hostile_guard_encoding_is_fixed_error_and_report_only(self):
        payloads = {"bad_utf8": b"\xff\xfe\x00{", "deep": b"[" * 200000, "nonobject": b"[1,2]", "empty": b""}
        for which in (INSPECTION_GUARD_FILENAME, INSPECTION_COMPLETION_FILENAME):
            for label, payload in payloads.items():
                for terminal in (True, False):
                    with self.subTest(file=which, payload=label, terminal=terminal):
                        self.temp_dir.cleanup()
                        self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                        self.d = os.path.join(self.temp_dir.name, "ledger")
                        h = self.new()
                        if terminal:
                            p = h.reserve("req1", "sha256:d1")
                            h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
                        peer_alive = self.open_() if not terminal else None
                        raw_state = self.raw()
                        with open(os.path.join(self.d, which), "wb") as fh:
                            fh.write(payload)
                        # existing/fresh handles: fixed ledger errors, never raw decode errors
                        probe = peer_alive or h
                        with self.assertRaises((LedgerCorruptError, LedgerSecurityError, LedgerHaltedError)):
                            probe.reserve("blocked", "sha256:b")
                        self.assertTrue(probe.is_handle_disabled)
                        if terminal:
                            rep = BudgetLedger.open(self.d)
                            self._handles.append(rep)
                            self.assertTrue(rep.is_handle_disabled)
                            s = rep.get_status()
                            self.assertEqual((s.halt_reason, s.retained_failed_micros), ("REQUEST_TRANSPORT_FAILURE", 1_100_000))
                            self.assertFalse(s.can_reserve)
                            self.assertEqual(self.raw(), raw_state)
                        else:
                            with self.assertRaises((LedgerCorruptError, LedgerSecurityError)):
                                BudgetLedger.open(self.d)
                            s = probe.get_status()
                            self.assertTrue(s.halted)
                            self.assertFalse(s.can_reserve)
                            self.assertEqual(self.raw(), raw_state)
        # healthy control: valid encoding is accepted
        self.temp_dir.cleanup()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
        self.d = os.path.join(self.temp_dir.name, "ledger")
        h = self.new()
        self.assertFalse(self.open_().is_handle_disabled)

    def test_rejected_reason_text_not_echoed_or_chained(self):
        import traceback
        marker = "FAKE_PROVIDER_SECRET_ABC"
        for bad in (marker, marker.encode(), "x" * 5000 + marker, "ok\n" + marker, 7):
            with self.subTest(bad=repr(bad)[:20]):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                p = h.reserve("req1", "sha256:d1")
                with self.assertRaises(SettlementEvidenceError) as ctx:
                    h.record_failure(p, bad)
                e = ctx.exception
                text = "".join(traceback.format_exception(type(e), e, e.__traceback__))
                self.assertNotIn(marker, text)
                self.assertNotIn(marker, str(e))
                self.assertLessEqual(len(str(e)), 200)
                self.assertIn("ALLOWED_INTERNAL_FAILURE_CODES", str(e))
                self.assertIsNone(e.__cause__)
                self.assertTrue(e.__suppress_context__ or e.__context__ is None)
                self.assertNotIn(marker, json.dumps(self.state()))
                self.assertNotIn(marker, repr(h.get_status()))
        # healthy control: an allowed code is accepted verbatim
        self.temp_dir.cleanup()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
        self.d = os.path.join(self.temp_dir.name, "ledger")
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        self.assertEqual(h.record_failure(p, "REQUEST_TRANSPORT_FAILURE").reason, "REQUEST_TRANSPORT_FAILURE")

    def test_invalid_response_id_diagnostic_does_not_chain_provider_text(self):
        import traceback
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        with self.assertRaises(SettlementEvidenceError) as ctx:
            h.settle(p, _make_receipt(p, response_id="bad\u2603SECRETX"))
        e = ctx.exception
        text = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        self.assertNotIn("SECRETX", text)
        self.assertNotIn("\u2603", text)
        self.assertIsNone(e.__cause__)
        self.assertTrue(e.__suppress_context__)

    # ---- 11. descriptor ownership / close errors ---------------------------
    def test_witness_close_error_closes_descriptor_exactly_once_and_blocks_authority(self):
        for kind in ("guard", "completion", "state", "intent", "confirm"):
            with self.subTest(kind=kind):
                self.temp_dir.cleanup()
                self.temp_dir = tempfile.TemporaryDirectory(prefix="guardfil-budget-guard-test-")
                self.d = os.path.join(self.temp_dir.name, "ledger")
                h = self.new()
                p = None
                if kind in ("intent", "confirm"):
                    p = h.reserve("req1", "sha256:d1")
                call = (lambda: h.settle(p, _make_receipt(p))) if p else (lambda: h.reserve("req1", "sha256:d1"))
                with _Faults(self, [{"kind": kind, "boundary": "close"}]) as f:
                    # an unrelated descriptor that reuses the freed number must survive
                    try:
                        out = call()
                    except OSError as err:
                        out = err
                self.assertNoTmp()
                self.assertEqual(f.double_closes, [], "descriptor closed a second time after close fault")
                self.assertTrue(f.replacements, "close fault fired")
                for failed_fd, repl in f.replacements:
                    self.assertEqual(repl, failed_fd, "replacement reuses the SAME descriptor number")
                    os.fstat(repl)  # replacement must still be open: no double close destroyed it
                f.cleanup()
                seq = [e for e in f.events if e[0] == "close" and (e[1] or "").startswith(_TMP_PREFIXES[kind])]
                self.assertEqual(len(seq), 1, seq)
                if kind == "confirm":
                    self.assertIsInstance(out, SettlementCommittedHandleDisabledOutcome)
                    self.assertTrue(h.is_handle_disabled)
                else:
                    self.assertIsInstance(out, OSError)  # no permit / no success escaped
                    self.assertTrue(h.is_handle_disabled)

    def test_failure_cleanup_does_not_close_unrelated_descriptor(self):
        h = self.new()
        sentinel = os.open(os.devnull, os.O_RDONLY)
        try:
            with _Faults(self, [{"kind": "completion", "boundary": "close"}]) as f:
                with self.assertRaises(OSError):
                    h.reserve("req1", "sha256:d1")
            self.assertEqual(f.double_closes, [])
            for failed_fd, repl in f.replacements:
                self.assertEqual(repl, failed_fd)
                os.fstat(repl)
            f.cleanup()
            os.fstat(sentinel)  # still valid
            reused = os.open(os.devnull, os.O_RDONLY)
            os.close(reused)
        finally:
            os.close(sentinel)
        self.assertEqual(h._poison_reason, "INSPECTION_COMPLETION_FAILED")

    # ---- 12. generations -----------------------------------------------------
    def test_generation_strictly_monotonic_and_exhaustion_refused_without_wrap(self):
        h = self.new()
        seen = [self.jread(INSPECTION_GUARD_FILENAME)["generation"]]
        for i in range(4):
            h.get_status()
            seen.append(self.jread(INSPECTION_GUARD_FILENAME)["generation"])
        self.assertEqual(seen, list(range(seen[0], seen[0] + 5)))
        g = self.jread(INSPECTION_GUARD_FILENAME)
        c = self.jread(INSPECTION_COMPLETION_FILENAME)
        g["generation"] = c["generation"] = MAX_INSPECTION_GENERATION
        self.wjson(os.path.join(self.d, INSPECTION_GUARD_FILENAME), g)
        self.wjson(os.path.join(self.d, INSPECTION_COMPLETION_FILENAME), c)
        with self.assertRaises(LedgerSecurityError):
            h.reserve("x", "sha256:x")
        g2 = self.jread(INSPECTION_GUARD_FILENAME)
        self.assertEqual(g2["generation"], MAX_INSPECTION_GENERATION)  # no wrap, no advance
        self.assertTrue(h.is_handle_disabled)

    def test_no_cached_validation_status_rechecks_after_confirmation_removed(self):
        h = self.new()
        p = h.reserve("req1", "sha256:d1")
        h.settle(p, _make_receipt(p))
        self.assertFalse(h.get_status().halted)
        os.unlink(self.conf(p))
        s = h.get_status()
        self.assertTrue(s.halted)
        self.assertEqual(s.retained_failed_micros, 1_100_000)

    # ---- 13. causal cap tests ----------------------------------------------
    def test_cap_rejection_is_caused_by_replay_cap_not_unrelated_journal_error(self):
        h = self.new()
        first = h.reserve("req1", "sha256:d1")
        h.settle(first, _make_receipt(first, input_tokens=999500, output_tokens=500))
        h.close()
        # genuine settlement: both permanent records exist
        self.assertTrue(os.path.exists(self.intent(first)) and os.path.exists(self.conf(first)))
        st = self.state()
        ts = st["updated_at_utc"]
        st["total_reservations_count"] = 2
        st["journal"].append({"entry_type": "RESERVED", "reservation_id": "permit_002", "request_id": "req2",
                              "request_digest": "sha256:d2", "reserved_amount_micros": 1_100_000,
                              "reservation_index": 2, "timestamp_utc": ts})
        st["pending_reservation"] = {"reservation_id": "permit_002", "request_id": "req2",
                                     "request_digest": "sha256:d2", "reserved_amount_micros": 1_100_000,
                                     "reserved_at_utc": ts, "pid": os.getpid()}
        # same state without the cap violation (smaller first settlement) must be ACCEPTED
        ok = json.loads(json.dumps(st))
        for e in ok["journal"]:
            if e.get("entry_type") == "SETTLED":
                e.update(input_tokens=1000, output_tokens=500, total_tokens=1500,
                         settled_amount_micros=1500, unencumbered_amount_micros=1_098_500)
        ok["committed_spend_micros"] = 1500
        BudgetLedger._validate_and_reconcile_state_static(ok)
        with self.assertRaises(LedgerCorruptError) as ctx:
            BudgetLedger._validate_and_reconcile_state_static(st)
        self.assertIn("Replay ceiling violation", str(ctx.exception))
        self.wjson(os.path.join(self.d, STATE_FILENAME), st)
        with self.assertRaises(LedgerCorruptError) as ctx2:
            BudgetLedger.open(self.d)
        self.assertIn("Replay ceiling violation", str(ctx2.exception))


if __name__ == "__main__":
    unittest.main()



class TestSizedReservations(unittest.TestCase):
    """Per-request reservations: any amount in [MIN, MAX]; the old fixed amount is the MAX."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o700)
        self.ledger_dir = os.path.join(self.tmp, "ledger")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_amount_bounds(self):
        from research.t2a.openai_budget import MIN_RESERVATION_MICROS
        ledger = BudgetLedger.initialize(self.ledger_dir)
        for bad in (0, MIN_RESERVATION_MICROS - 1, RESERVATION_AMOUNT_MICROS + 1, True, 5000.0, "5000"):
            with self.assertRaises(ValueError):
                ledger.reserve("req_bad", "sha256:x", bad)
        self.assertFalse(ledger.get_status().has_pending_reservation)
        p = ledger.reserve("req_min", "sha256:x", MIN_RESERVATION_MICROS)
        self.assertEqual(p.reserved_amount_micros, MIN_RESERVATION_MICROS)
        ledger.close()

    def test_mixed_sizes_settle_and_replay_after_reopen(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p1 = ledger.reserve("req_001", "sha256:a")  # legacy full size
        ledger.settle(p1, _make_receipt(p1, response_id="resp_001", input_tokens=10_000, output_tokens=100))
        p2 = ledger.reserve("req_002", "sha256:b", 20_000)
        self.assertEqual(ledger.get_status().total_encumbered_micros, 10_100 + 20_000)
        ledger.settle(p2, _make_receipt(p2, response_id="resp_002", input_tokens=12_000, output_tokens=500))
        ledger.close()
        reopened = BudgetLedger.open(self.ledger_dir)   # full journal replay with mixed amounts
        st = reopened.get_status()
        self.assertEqual((st.settled_requests_count, st.committed_spend_micros, st.halted), (2, 10_100 + 12_500, False))
        p3 = reopened.reserve("req_003", "sha256:c", 15_000)
        self.assertEqual(p3.reserved_amount_micros, 15_000)
        reopened.close()

    def test_cost_above_a_sized_reservation_halts(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p = ledger.reserve("req_001", "sha256:a", 5_000)
        with self.assertRaises(SettlementEvidenceError):
            ledger.settle(p, _make_receipt(p, input_tokens=5_000, output_tokens=100))
        st = ledger.get_status()
        self.assertTrue(st.halted)
        self.assertEqual(st.retained_failed_micros, 5_000)  # the reservation is retained, never undercounted
        ledger.close()
        reopened = BudgetLedger.open(self.ledger_dir)
        self.assertEqual(reopened.get_status().retained_failed_micros, 5_000)
        reopened.close()

    def test_failure_retains_exactly_its_reservation_and_replays(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p1 = ledger.reserve("req_001", "sha256:a", 30_000)
        ledger.settle(p1, _make_receipt(p1, response_id="resp_001", input_tokens=20_000, output_tokens=200))
        p2 = ledger.reserve("req_002", "sha256:b", 7_000)
        ledger.record_failure(p2, "REQUEST_TRANSPORT_FAILURE")
        st = ledger.get_status()
        self.assertEqual((st.committed_spend_micros, st.retained_failed_micros), (20_200, 7_000))
        ledger.close()
        reopened = BudgetLedger.open(self.ledger_dir)
        st = reopened.get_status()
        self.assertEqual((st.committed_spend_micros, st.retained_failed_micros, st.total_reservations_count),
                         (20_200, 7_000, 2))
        reopened.close()

    def test_tampered_sized_amount_is_corruption(self):
        ledger = BudgetLedger.initialize(self.ledger_dir)
        p = ledger.reserve("req_001", "sha256:a", 20_000)
        ledger.settle(p, _make_receipt(p, response_id="resp_001", input_tokens=12_000, output_tokens=500))
        ledger.close()
        state_path = os.path.join(self.ledger_dir, "ledger.json")
        with open(state_path) as f:
            state = json.load(f)
        for e in state["journal"]:
            if e["entry_type"] == "RESERVED":
                e["reserved_amount_micros"] = 25_000      # no longer reserved - settled == unencumbered
        with open(state_path, "w") as f:
            json.dump(state, f)
        with self.assertRaises(Exception):
            BudgetLedger.open(self.ledger_dir)
