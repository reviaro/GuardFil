package budget

import (
	"encoding/json"
	"fmt"
)

// The Python ledger (research/t2a/openai_budget) requires each journal entry
// and witness record to carry exactly its type's keys, zero values included.
// These sets mirror its EXPECTED_* constants; TestKeySetsMatchPython checks
// them against the Python code.
var journalKeys = map[string][]string{
	"INITIALIZED":             {"entry_type", "experiment_id", "global_ceiling_micros", "timestamp_utc"},
	"RESERVED":                {"entry_type", "request_digest", "request_id", "reservation_id", "reservation_index", "reserved_amount_micros", "timestamp_utc"},
	"SETTLED":                 {"entry_type", "input_tokens", "model", "output_tokens", "request_digest", "request_id", "reservation_id", "response_id", "service_tier", "settled_amount_micros", "timestamp_utc", "total_tokens", "unencumbered_amount_micros"},
	"FAILED_RETAINED":         {"entry_type", "reason", "request_id", "reservation_id", "retained_amount_micros", "timestamp_utc"},
	"ORPHANED_PENDING_HALTED": {"entry_type", "reason", "request_id", "reservation_id", "retained_amount_micros", "timestamp_utc"},
	"TERMINAL_UNCERTAINTY":    {"entry_type", "reason", "timestamp_utc", "uncertain_reservation_ids"},
}

var settlementRecordKeys = []string{"experiment_id", "input_tokens", "model", "output_tokens", "record_type", "request_digest", "request_id", "reservation_id", "response_id", "service_tier", "settled_amount_micros", "timestamp_utc", "total_tokens", "unencumbered_amount_micros"}

var witnessKeys = map[string][]string{
	"SETTLEMENT_INTENT":       settlementRecordKeys,
	"SETTLEMENT_CONFIRMATION": settlementRecordKeys,
	"INSPECTION_GUARD":        {"armed_at_utc", "experiment_id", "generation", "record_type"},
	"INSPECTION_COMPLETION":   {"completed_at_utc", "experiment_id", "generation", "record_type"},
}

// MarshalJSON writes exactly the keys of the entry's type.
func (e JournalEntry) MarshalJSON() ([]byte, error) {
	keys, ok := journalKeys[e.EntryType]
	if !ok {
		return nil, fmt.Errorf("unknown journal entry type %q", e.EntryType)
	}
	all := map[string]any{
		"entry_type": e.EntryType, "experiment_id": e.ExperimentID, "global_ceiling_micros": e.GlobalCeilingMicros,
		"reservation_id": e.ReservationID, "request_id": e.RequestID, "request_digest": e.RequestDigest,
		"reserved_amount_micros": e.ReservedAmountMicros, "reservation_index": e.ReservationIndex,
		"response_id": e.ResponseID, "model": e.Model, "service_tier": e.ServiceTier,
		"input_tokens": e.InputTokens, "output_tokens": e.OutputTokens, "total_tokens": e.TotalTokens,
		"settled_amount_micros": e.SettledAmountMicros, "unencumbered_amount_micros": e.UnencumberedAmountMicros,
		"retained_amount_micros": e.RetainedAmountMicros, "reason": e.Reason, "timestamp_utc": e.TimestampUTC,
		"uncertain_reservation_ids": nonNil(e.UncertainReservationIDs),
	}
	return pick(all, keys)
}

// MarshalJSON writes exactly the keys of the record's type.
func (r WitnessRecord) MarshalJSON() ([]byte, error) {
	keys, ok := witnessKeys[r.RecordType]
	if !ok {
		return nil, fmt.Errorf("unknown witness record type %q", r.RecordType)
	}
	all := map[string]any{
		"record_type": r.RecordType, "experiment_id": r.ExperimentID, "reservation_id": r.ReservationID,
		"request_id": r.RequestID, "request_digest": r.RequestDigest, "response_id": r.ResponseID,
		"model": r.Model, "service_tier": r.ServiceTier, "input_tokens": r.InputTokens,
		"output_tokens": r.OutputTokens, "total_tokens": r.TotalTokens,
		"settled_amount_micros": r.SettledAmountMicros, "unencumbered_amount_micros": r.UnencumberedAmountMicros,
		"generation": r.Generation, "armed_at_utc": r.ArmedAtUTC, "completed_at_utc": r.CompletedAtUTC,
		"timestamp_utc": r.TimestampUTC,
	}
	return pick(all, keys)
}

func pick(all map[string]any, keys []string) ([]byte, error) {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		v, ok := all[k]
		if !ok {
			return nil, fmt.Errorf("no value for key %q", k)
		}
		out[k] = v
	}
	return json.Marshal(out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
