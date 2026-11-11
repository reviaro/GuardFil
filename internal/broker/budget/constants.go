package budget

import (
	"fmt"
)

const (
	GlobalCeilingMicros     = 2_000_000 // $2.00 USD in integer microdollars
	ReservationAmountMicros = 1_100_000 // $1.10 USD maximum reservation per request
	MaxForwardedRequests    = 256
	MaxInFlightRequests     = 1
	InputTokenRateMicros    = 1
	OutputTokenRateMicros   = 1
	MaxInputTokens          = 1_050_000
	MaxOutputTokens         = 1024
	MinReservationMicros    = MaxOutputTokens * OutputTokenRateMicros // 1024

	PinnedModel       = "gpt-6-luna"
	PinnedServiceTier = "default"

	DefaultExperimentID = "guardfil-t2a-m1-openai-luna"
	SchemaVersion       = 1

	StateFilename                = "ledger.json"
	LockFilename                 = "ledger.lock"
	LeaseFilename                = "lease.lock"
	IntentFilename               = "settlement_intent.json"
	IntentFilePrefix             = "intent_"
	ConfirmationFilePrefix       = "confirmation_"
	InspectionGuardFilename      = "inspection_guard.json"
	InspectionCompletionFilename = "inspection_completion.json"
	RecordTypeInspectionGuard    = "INSPECTION_GUARD"
	RecordTypeInspectionComp     = "INSPECTION_COMPLETION"

	MaxInspectionGeneration = 1_000_000_000
	MaxStateFileBytes       = 524_288 // 512 KiB
	MaxIdentifierLength     = 128
	MaxDigestLength         = 128
	MaxTimestampLength      = 64
	MaxReasonLength         = 256
	MaxJournalEntries       = 514

	TerminalStatusCompleted = "completed"
)

type ModelRate struct {
	InputRateMicros  int
	OutputRateMicros int
	ServiceTier      string
}

// ModelRates defines the cost per token for each supported model.
var ModelRates = map[string]ModelRate{
	PinnedModel:             {InputRateMicros: 1, OutputRateMicros: 1, ServiceTier: "default"},
	"gemini-3.8-flash":      {InputRateMicros: 2, OutputRateMicros: 8, ServiceTier: "default"},
	"gemini-3.6-flash":      {InputRateMicros: 2, OutputRateMicros: 8, ServiceTier: "default"},
	"gemini-3.5-flash-lite": {InputRateMicros: 1, OutputRateMicros: 3, ServiceTier: "default"},
	"claude-sonnet-5-5":     {InputRateMicros: 2, OutputRateMicros: 10, ServiceTier: "standard"},
}

// ModelCostMicros returns the accounted cost of one request in microdollars,
// or -1 and an error if the model or tier is not priced.
func ModelCostMicros(model string, serviceTier string, inputTokens, outputTokens int) (int, error) {
	rate, exists := ModelRates[model]
	if !exists || rate.ServiceTier != serviceTier {
		return -1, fmt.Errorf("unpriced model or tier: %s (tier %s)", model, serviceTier)
	}
	return inputTokens*rate.InputRateMicros + outputTokens*rate.OutputRateMicros, nil
}

// AllowedInternalFailureCodes are the permitted failure codes for terminal halts.
var AllowedInternalFailureCodes = map[string]bool{
	"UNSETTLED_PENDING_RESERVATION_AT_STARTUP": true,
	"UNRESOLVED_SETTLEMENT_PUBLICATION":        true,
	"PERMIT_MISMATCH":                          true,
	"INVALID_FAILURE_REASON_REJECTED":          true,
	"INVALID_RECEIPT_EVIDENCE":                 true,
	"INVALID_EVIDENCE_TYPE":                    true,
	"INVALID_RECEIPT_STATUS":                   true,
	"RECEIPT_TOKEN_BOUND_EXCEEDED":             true,
	"RECEIPT_MODEL_MISMATCH":                   true,
	"RECEIPT_SERVICE_TIER_MISMATCH":            true,
	"REPLAYED_RESPONSE_ID":                     true,
	"SETTLEMENT_INTENT_WRITE_FAILED":           true,
	"SETTLEMENT_CONFIRMATION_WRITE_FAILED":     true,
	"SETTLEMENT_COMMITTED_CONFIRMATION_FAILED": true,
	"SETTLEMENT_WRITE_FAILED":                  true,
	"LEASE_VERIFICATION_FAILED_AT_SETTLE":      true,
	"SYNC_IDENTITY_CHECK_FAILED":               true,
	"HANDLE_CLOSED":                            true,
	"REQUEST_TRANSPORT_FAILURE":                true,
	"UNFINISHED_INSPECTION_GUARD":              true,
	"INSPECTION_COMPLETION_FAILED":             true,
	"INSPECTION_GUARD_CORRUPT":                 true,
	"TERMINAL_UNCERTAINTY":                     true,
	"INSPECTION_EVIDENCE_UNCERTAINTY":          true,
	"RECEIPT_SCHEMA_VIOLATION":                 true,
	"INVALID_RESPONSE_ID":                      true,
	"REQUEST_ID_MISMATCH":                      true,
	"REQUEST_DIGEST_MISMATCH":                  true,
	"INVALID_TOKEN_TYPE":                       true,
	"TOKEN_SUM_INCONSISTENT":                   true,
	"COST_EXCEEDS_RESERVATION":                 true,
	"RESERVE_DURABLE_WRITE_FAILED":             true,
	"LEASE_VERIFICATION_FAILED_AT_RESERVE":     true,
}

var TerminalUncertaintyReasons = map[string]bool{
	"TERMINAL_UNCERTAINTY":              true,
	"UNRESOLVED_SETTLEMENT_PUBLICATION": true,
}

var ValidJournalEntryTypes = map[string]bool{
	"INITIALIZED":             true,
	"RESERVED":                true,
	"SETTLED":                 true,
	"FAILED_RETAINED":         true,
	"ORPHANED_PENDING_HALTED": true,
	"TERMINAL_UNCERTAINTY":    true,
}
