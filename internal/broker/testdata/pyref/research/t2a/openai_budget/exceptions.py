"""Exception hierarchy for GuardFil T2a Stage B durable budget ledger."""


class BudgetError(Exception):
    """Base exception for all budget ledger errors."""


class BudgetExceededError(BudgetError):
    """Raised when remaining budget is insufficient to reserve the required amount."""


class ReservationLimitExceededError(BudgetError):
    """Raised when maximum forwarded requests limit (8) has been reached."""


class InFlightReservationError(BudgetError):
    """Raised when an attempt is made to reserve while another reservation is in flight."""


class LedgerHaltedError(BudgetError):
    """Raised when an operation is attempted on a permanently halted ledger."""


class SettlementEvidenceError(BudgetError):
    """Raised when provider evidence is missing, invalid, errored, or ambiguous."""


class NoPendingReservationError(BudgetError):
    """Raised when settling or failing a request but no reservation is pending."""


class PermitMismatchError(BudgetError):
    """Raised when a provided reservation permit does not match the pending reservation."""


class LedgerNotFoundError(BudgetError):
    """Raised when opening a ledger that has not been initialized."""


class LedgerAlreadyExistsError(BudgetError):
    """Raised when initializing a ledger in a location that already contains state."""


class LedgerCorruptError(BudgetError):
    """Raised when ledger state JSON is malformed, corrupt, or violates schema."""


class LedgerSecurityError(BudgetError):
    """Raised when directory/file permissions, ownership, symlinks, or types fail security checks."""


class SettlementCommittedHandleDisabledError(BudgetError):
    """Raised when settlement committed to state but confirmation publication failed.

    The settlement is committed in durable ledger state; the current handle is disabled.
    """


class LedgerBindingError(BudgetError):
    """Fixed-code failure of the read-only identity binding check.

    The displayed message is exactly the code; no state, caller or exception
    text is carried or chained.
    """

    CODES = ("BINDING_BUSY", "BINDING_DISABLED", "BINDING_INVALID", "BINDING_IO_FAILED")

    def __init__(self, code: str) -> None:
        if code not in self.CODES:
            code = "BINDING_INVALID"
        super().__init__(code)
        self.code = code


class LedgerReportUnavailableError(BudgetError):
    """Fixed-code failure of the independent recorded-state report."""

    CODES = ("REPORT_BUSY", "REPORT_INVALID", "REPORT_IO_FAILED")

    def __init__(self, code: str) -> None:
        if code not in self.CODES:
            code = "REPORT_INVALID"
        super().__init__(code)
        self.code = code
