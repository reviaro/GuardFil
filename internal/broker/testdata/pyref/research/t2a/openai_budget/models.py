"""Data structures for GuardFil T2a Stage B durable budget ledger."""

from dataclasses import dataclass
from typing import Optional

from .constants import MAX_FORWARDED_REQUESTS, MIN_RESERVATION_MICROS
from .exceptions import LedgerBindingError


@dataclass(frozen=True)
class ReservationPermit:
    """Immutable permit issued upon successful durable reservation.

    Must be presented along with provider evidence to settle or fail the reservation.
    Cannot be replayed or used across multiple requests.
    """
    permit_id: str
    request_id: str
    request_digest: str
    reserved_amount_micros: int
    reserved_at_utc: str


@dataclass(frozen=True)
class Receipt:
    """Normalized terminal provider receipt submitted by the trusted transport authority."""
    status: str
    response_id: str
    request_id: str
    request_digest: str
    model: str
    service_tier: str
    input_tokens: int
    output_tokens: int
    total_tokens: int


@dataclass(frozen=True)
class SettlementResult:
    """Outcome of conservative token-based accounting settlement against the reservation."""
    request_id: str
    permit_id: str
    response_id: str
    accounted_cost_micros: int
    unencumbered_amount_micros: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    settled_at_utc: str

    @property
    def actual_cost_micros(self) -> int:
        """Compatibility property for accounted_cost_micros."""
        return self.accounted_cost_micros

    @property
    def refunded_amount_micros(self) -> int:
        """Compatibility property for unencumbered_amount_micros."""
        return self.unencumbered_amount_micros


@dataclass(frozen=True)
class SettlementCommittedHandleDisabledOutcome:
    """Outcome returned when settlement committed to state but confirmation publication failed.

    The settlement is durably committed to the ledger state.
    The current handle is disabled and cannot authorize further transactions.
    A fresh handle may open and continue only if a complete matching confirmation
    proves preceding state sync; otherwise recovery halts conservatively.
    """
    request_id: str
    permit_id: str
    response_id: str
    accounted_cost_micros: int
    unencumbered_amount_micros: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    settled_at_utc: str
    error: str = "CONFIRMATION_PUBLICATION_FAILED"
    handle_disabled: bool = True
    is_committed: bool = True

    @property
    def actual_cost_micros(self) -> int:
        return self.accounted_cost_micros

    @property
    def refunded_amount_micros(self) -> int:
        return self.unencumbered_amount_micros


@dataclass(frozen=True)
class FailureResult:
    """Outcome when a request fails or evidence is missing/ambiguous.

    The full reserved amount is permanently retained and the ledger halts.
    """
    request_id: str
    permit_id: str
    retained_amount_micros: int
    reason: str
    failed_at_utc: str


@dataclass(frozen=True)
class LedgerStatus:
    """Snapshot of current ledger state."""
    experiment_id: str
    global_ceiling_micros: int
    committed_spend_micros: int
    retained_failed_micros: int
    total_spend_micros: int
    pending_reserved_micros: int
    total_encumbered_micros: int
    remaining_available_micros: int
    remaining_budget_micros: int
    total_reservations_count: int
    settled_requests_count: int
    has_pending_reservation: bool
    pending_request_id: Optional[str]
    halted: bool
    halt_reason: Optional[str]
    handle_disabled: bool = False
    handle_disabled_reason: Optional[str] = None

    @property
    def can_reserve(self) -> bool:
        """Whether a new reservation can currently be accepted."""
        return (
            not self.halted
            and not self.handle_disabled
            and not self.has_pending_reservation
            and self.total_reservations_count < MAX_FORWARDED_REQUESTS
            # Reservations are sized per request (MIN..MAX); report whether the smallest one still fits.
            and (self.total_encumbered_micros + MIN_RESERVATION_MICROS) <= self.global_ceiling_micros
        )


_MAX_U64 = 18_446_744_073_709_551_615


def _strict_u64(value, minimum: int) -> bool:
    return type(value) is int and minimum <= value <= _MAX_U64


@dataclass(frozen=True)
class LedgerBinding:
    """Immutable ledger identity: no permit, descriptor, nonce or authority method.

    Identifiers and filesystem integers use the manifest/claim bounds: exact
    ints (no bool/float), devices 0..2**64-1, inodes 1..2**64-1.
    """

    experiment_id: str
    directory_device: int
    directory_inode: int
    transaction_lock_device: int
    transaction_lock_inode: int

    def __post_init__(self) -> None:
        from .exceptions import LedgerCorruptError
        from .ledger import _validate_identifier

        try:
            _validate_identifier(self.experiment_id, "experiment_id")
        except LedgerCorruptError:
            raise LedgerBindingError("BINDING_INVALID") from None
        if self.experiment_id != self.experiment_id.strip():
            raise LedgerBindingError("BINDING_INVALID") from None
        if not (
            _strict_u64(self.directory_device, 0)
            and _strict_u64(self.directory_inode, 1)
            and _strict_u64(self.transaction_lock_device, 0)
            and _strict_u64(self.transaction_lock_inode, 1)
        ):
            raise LedgerBindingError("BINDING_INVALID") from None


@dataclass(frozen=True)
class RecordedLedgerReport:
    """Validated persisted journal projection; NOT reconciled accounting or an admission capability."""

    binding: LedgerBinding
    state_sha256: str
    recorded_halted: bool
    recorded_halt_reason: Optional[str]
    recorded_committed_micros: int
    recorded_retained_micros: int
    recorded_pending_micros: int
    recorded_total_reservations: int
    recorded_settled_requests: int
    mode: str = "RECORDED_STATE_ONLY"
    reconciliation: str = "NOT_PERFORMED"
