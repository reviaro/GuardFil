package budget

// ReservationPermit is issued upon a successful durable reservation.
type ReservationPermit struct {
	PermitID             string `json:"permit_id"`
	RequestID            string `json:"request_id"`
	RequestDigest        string `json:"request_digest"`
	ReservedAmountMicros int    `json:"reserved_amount_micros"`
	ReservedAtUTC        string `json:"reserved_at_utc"`
}

// Receipt is normalized terminal provider usage evidence.
type Receipt struct {
	Status        string `json:"status"`
	ResponseID    string `json:"response_id"`
	RequestID     string `json:"request_id"`
	RequestDigest string `json:"request_digest"`
	Model         string `json:"model"`
	ServiceTier   string `json:"service_tier"`
	InputTokens   int    `json:"input_tokens"`
	OutputTokens  int    `json:"output_tokens"`
	TotalTokens   int    `json:"total_tokens"`
}

// SettlementResult is the outcome of settling against a reservation.
type SettlementResult struct {
	RequestID                string `json:"request_id"`
	PermitID                 string `json:"permit_id"`
	ResponseID               string `json:"response_id"`
	AccountedCostMicros      int    `json:"accounted_cost_micros"`
	UnencumberedAmountMicros int    `json:"unencumbered_amount_micros"`
	InputTokens              int    `json:"input_tokens"`
	OutputTokens             int    `json:"output_tokens"`
	TotalTokens              int    `json:"total_tokens"`
	SettledAtUTC             string `json:"settled_at_utc"`
}

// SettlementCommittedHandleDisabledOutcome is returned when settlement was committed to state
// but confirmation publication failed, disabling the handle.
type SettlementCommittedHandleDisabledOutcome struct {
	RequestID                string `json:"request_id"`
	PermitID                 string `json:"permit_id"`
	ResponseID               string `json:"response_id"`
	AccountedCostMicros      int    `json:"accounted_cost_micros"`
	UnencumberedAmountMicros int    `json:"unencumbered_amount_micros"`
	InputTokens              int    `json:"input_tokens"`
	OutputTokens             int    `json:"output_tokens"`
	TotalTokens              int    `json:"total_tokens"`
	SettledAtUTC             string `json:"settled_at_utc"`
	Error                    string `json:"error"`
	HandleDisabled           bool   `json:"handle_disabled"`
	IsCommitted              bool   `json:"is_committed"`
}

// FailureResult is the outcome when a reservation fails and its funds are retained.
type FailureResult struct {
	RequestID            string `json:"request_id"`
	PermitID             string `json:"permit_id"`
	RetainedAmountMicros int    `json:"retained_amount_micros"`
	Reason               string `json:"reason"`
	FailedAtUTC          string `json:"failed_at_utc"`
}

// LedgerStatus is a snapshot of current ledger state.
type LedgerStatus struct {
	ExperimentID             string  `json:"experiment_id"`
	GlobalCeilingMicros      int     `json:"global_ceiling_micros"`
	CommittedSpendMicros     int     `json:"committed_spend_micros"`
	RetainedFailedMicros     int     `json:"retained_failed_micros"`
	TotalSpendMicros         int     `json:"total_spend_micros"`
	PendingReservedMicros    int     `json:"pending_reserved_micros"`
	TotalEncumberedMicros    int     `json:"total_encumbered_micros"`
	RemainingAvailableMicros int     `json:"remaining_available_micros"`
	RemainingBudgetMicros    int     `json:"remaining_budget_micros"`
	TotalReservationsCount   int     `json:"total_reservations_count"`
	SettledRequestsCount     int     `json:"settled_requests_count"`
	HasPendingReservation    bool    `json:"has_pending_reservation"`
	PendingRequestID         *string `json:"pending_request_id"`
	Halted                   bool    `json:"halted"`
	HaltReason               *string `json:"halt_reason"`
	HandleDisabled           bool    `json:"handle_disabled"`
	HandleDisabledReason     *string `json:"handle_disabled_reason"`
}

func (s *LedgerStatus) CanReserve() bool {
	return !s.Halted &&
		!s.HandleDisabled &&
		!s.HasPendingReservation &&
		s.TotalReservationsCount < MaxForwardedRequests &&
		(s.TotalEncumberedMicros+MinReservationMicros) <= s.GlobalCeilingMicros
}
