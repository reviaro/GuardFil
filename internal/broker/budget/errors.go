package budget

import "errors"

var (
	ErrBudgetExceeded           = errors.New("budget ceiling exceeded")
	ErrReservationLimitExceeded = errors.New("maximum forwarded requests limit reached")
	ErrInFlightReservation      = errors.New("another reservation is currently in flight")
	ErrLedgerHalted             = errors.New("ledger is halted")
	ErrSettlementEvidence       = errors.New("invalid or unverified settlement evidence")
	ErrNoPendingReservation     = errors.New("no active pending reservation exists")
	ErrPermitMismatch           = errors.New("permit mismatch")
	ErrLedgerNotFound           = errors.New("ledger not found")
	ErrLedgerAlreadyExists      = errors.New("ledger already exists")
	ErrLedgerCorrupt            = errors.New("ledger state corrupt or invalid")
	ErrLedgerSecurity           = errors.New("ledger security violation")
	ErrGuardUnfinished          = errors.New("unfinished inspection guard")
)
