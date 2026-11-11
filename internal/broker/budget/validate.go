package budget

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

var expectedStateKeys = map[string]bool{
	"schema_version":            true,
	"experiment_id":             true,
	"created_at_utc":            true,
	"updated_at_utc":            true,
	"global_ceiling_micros":     true,
	"reservation_amount_micros": true,
	"committed_spend_micros":    true,
	"retained_failed_micros":    true,
	"total_reservations_count":  true,
	"settled_requests_count":    true,
	"pending_reservation":       true,
	"halted":                    true,
	"halt_reason":               true,
	"journal":                   true,
}

var expectedPendingKeys = map[string]bool{
	"reservation_id":         true,
	"request_id":             true,
	"request_digest":         true,
	"reserved_amount_micros": true,
	"reserved_at_utc":        true,
	"pid":                    true,
}

// safeJSONDecode parses JSON enforcing uniqueness of object keys and rejecting nonfinites.
func safeJSONDecode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeJSONValue(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLedgerCorrupt, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: extra data after JSON", ErrLedgerCorrupt)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: extra data after JSON", ErrLedgerCorrupt)
	}
	return v, nil
}

func decodeJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			obj := make(map[string]any)
			seen := make(map[string]struct{})
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("expected string key, got %T", kt)
				}
				if _, exists := seen[key]; exists {
					return nil, fmt.Errorf("Duplicate key detected in JSON: %q", key)
				}
				seen[key] = struct{}{}
				val, err := decodeJSONValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			closing, err := dec.Token()
			if err != nil || closing != json.Delim('}') {
				return nil, fmt.Errorf("expected '}'")
			}
			return obj, nil
		} else if t == '[' {
			var arr []any
			for dec.More() {
				val, err := decodeJSONValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			closing, err := dec.Token()
			if err != nil || closing != json.Delim(']') {
				return nil, fmt.Errorf("expected ']'")
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter: %v", t)
	case bool, string, nil, json.Number:
		return t, nil
	default:
		return nil, fmt.Errorf("unexpected token type: %T", t)
	}
}

func validateIdentifier(val any, fieldName string) (string, error) {
	if _, isBool := val.(bool); isBool {
		return "", fmt.Errorf("%w: %s must be a non-empty string", ErrLedgerCorrupt, fieldName)
	}
	s, ok := val.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%w: %s must be a non-empty string", ErrLedgerCorrupt, fieldName)
	}
	s = strings.TrimSpace(s)
	if len(s) > MaxIdentifierLength {
		return "", fmt.Errorf("%w: %s length (%d) exceeds limit of %d", ErrLedgerCorrupt, fieldName, len(s), MaxIdentifierLength)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 33 || c > 126 {
			return "", fmt.Errorf("%w: %s contains invalid character: %c", ErrLedgerCorrupt, fieldName, c)
		}
	}
	return s, nil
}

func validateDigest(val any) (string, error) {
	if _, isBool := val.(bool); isBool {
		return "", fmt.Errorf("%w: request_digest must be a non-empty string", ErrLedgerCorrupt)
	}
	s, ok := val.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%w: request_digest must be a non-empty string", ErrLedgerCorrupt)
	}
	s = strings.TrimSpace(s)
	if len(s) > MaxDigestLength {
		return "", fmt.Errorf("%w: request_digest length (%d) exceeds limit of %d", ErrLedgerCorrupt, len(s), MaxDigestLength)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 33 || c > 126 {
			return "", fmt.Errorf("%w: request_digest contains invalid character: %c", ErrLedgerCorrupt, c)
		}
	}
	return s, nil
}

func validateTimestamp(val any) (string, time.Time, error) {
	if _, isBool := val.(bool); isBool {
		return "", time.Time{}, fmt.Errorf("%w: timestamp must be a non-empty string", ErrLedgerCorrupt)
	}
	s, ok := val.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", time.Time{}, fmt.Errorf("%w: timestamp must be a non-empty string", ErrLedgerCorrupt)
	}
	if s != strings.TrimSpace(s) {
		return "", time.Time{}, fmt.Errorf("%w: timestamp must not carry surrounding whitespace", ErrLedgerCorrupt)
	}
	if len(s) > MaxTimestampLength {
		return "", time.Time{}, fmt.Errorf("%w: timestamp length exceeds limit of %d", ErrLedgerCorrupt, MaxTimestampLength)
	}

	normalized := s
	if idx := strings.IndexByte(normalized, ' '); idx != -1 {
		normalized = normalized[:idx] + "T" + normalized[idx+1:]
	}

	dt, err := time.Parse(time.RFC3339Nano, normalized)
	if err != nil {
		dt, err = time.Parse(time.RFC3339, normalized)
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: Invalid ISO-8601 UTC timestamp %q: %v", ErrLedgerCorrupt, s, err)
	}
	return s, dt, nil
}

func validateInt(val any, fieldName string, minVal int, maxVal *int) (int, error) {
	if _, isBool := val.(bool); isBool {
		return 0, fmt.Errorf("%w: %s must be an integer (not boolean), got bool", ErrLedgerCorrupt, fieldName)
	}
	switch v := val.(type) {
	case int:
		if v < minVal {
			return 0, fmt.Errorf("%w: %s must be >= %d, got %d", ErrLedgerCorrupt, fieldName, minVal, v)
		}
		if maxVal != nil && v > *maxVal {
			return 0, fmt.Errorf("%w: %s must be <= %d, got %d", ErrLedgerCorrupt, fieldName, *maxVal, v)
		}
		return v, nil
	case int64:
		iv := int(v)
		if iv < minVal {
			return 0, fmt.Errorf("%w: %s must be >= %d, got %d", ErrLedgerCorrupt, fieldName, minVal, iv)
		}
		if maxVal != nil && iv > *maxVal {
			return 0, fmt.Errorf("%w: %s must be <= %d, got %d", ErrLedgerCorrupt, fieldName, *maxVal, iv)
		}
		return iv, nil
	case json.Number:
		str := string(v)
		if strings.ContainsAny(str, ".eE") {
			return 0, fmt.Errorf("%w: %s must be an integer (not float), got %s", ErrLedgerCorrupt, fieldName, str)
		}
		n, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %s must be an integer, got %s", ErrLedgerCorrupt, fieldName, str)
		}
		iv := int(n)
		if iv < minVal {
			return 0, fmt.Errorf("%w: %s must be >= %d, got %d", ErrLedgerCorrupt, fieldName, minVal, iv)
		}
		if maxVal != nil && iv > *maxVal {
			return 0, fmt.Errorf("%w: %s must be <= %d, got %d", ErrLedgerCorrupt, fieldName, *maxVal, iv)
		}
		return iv, nil
	default:
		return 0, fmt.Errorf("%w: %s must be an integer (not boolean), got %T", ErrLedgerCorrupt, fieldName, val)
	}
}

func replayReason(reason any) (string, error) {
	s, ok := reason.(string)
	if !ok || !AllowedInternalFailureCodes[s] {
		return "", fmt.Errorf("%w: Journal reason is not a member of ALLOWED_INTERNAL_FAILURE_CODES", ErrLedgerCorrupt)
	}
	return s, nil
}

func checkClosedSchema(actual map[string]any, expected []string, contextDesc string) error {
	expMap := make(map[string]bool, len(expected))
	for _, k := range expected {
		expMap[k] = true
	}
	var missing, unexpected []string
	for k := range expMap {
		if _, ok := actual[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range actual {
		if !expMap[k] {
			unexpected = append(unexpected, k)
		}
	}
	if len(missing) > 0 || len(unexpected) > 0 {
		sort.Strings(missing)
		sort.Strings(unexpected)
		return fmt.Errorf("%w: %s schema violation: expected %v, got %v", ErrLedgerCorrupt, contextDesc, expected, sortedKeys(actual))
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ValidateAndReconcileStateStatic validates and reconciles state map according to Python budget specifications.
func ValidateAndReconcileStateStatic(state map[string]any, expectedExpID string) (*LedgerState, error) {
	// 1. Top-level closed schema
	var missing, unexpected []string
	for k := range expectedStateKeys {
		if _, ok := state[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range state {
		if !expectedStateKeys[k] {
			unexpected = append(unexpected, k)
		}
	}
	if len(missing) > 0 || len(unexpected) > 0 {
		sort.Strings(missing)
		sort.Strings(unexpected)
		return nil, fmt.Errorf("%w: State closed schema violation: missing=%v, unexpected=%v", ErrLedgerCorrupt, missing, unexpected)
	}

	// 2. Schema version
	schemaV := SchemaVersion
	if _, err := validateInt(state["schema_version"], "schema_version", schemaV, &schemaV); err != nil {
		return nil, fmt.Errorf("%w: Unsupported schema version: %v (expected %d)", ErrLedgerCorrupt, state["schema_version"], SchemaVersion)
	}

	// 3. Timestamps
	createdStr, dtC, err := validateTimestamp(state["created_at_utc"])
	if err != nil {
		return nil, err
	}
	updatedStr, dtU, err := validateTimestamp(state["updated_at_utc"])
	if err != nil {
		return nil, err
	}
	if dtU.Before(dtC) {
		return nil, fmt.Errorf("%w: updated_at_utc (%s) precedes created_at_utc (%s)", ErrLedgerCorrupt, updatedStr, createdStr)
	}

	// 4. Experiment ID
	expID, err := validateIdentifier(state["experiment_id"], "experiment_id")
	if err != nil {
		return nil, err
	}
	if expectedExpID != "" && expID != expectedExpID {
		return nil, fmt.Errorf("%w: Experiment ID mismatch: %q (expected %q)", ErrLedgerCorrupt, expID, expectedExpID)
	}

	// 5. Ceiling & reservation amount
	cVal := GlobalCeilingMicros
	if _, err := validateInt(state["global_ceiling_micros"], "global_ceiling_micros", cVal, &cVal); err != nil {
		return nil, fmt.Errorf("%w: Immutable global_ceiling_micros altered", ErrLedgerCorrupt)
	}
	rVal := ReservationAmountMicros
	if _, err := validateInt(state["reservation_amount_micros"], "reservation_amount_micros", rVal, &rVal); err != nil {
		return nil, fmt.Errorf("%w: Immutable reservation_amount_micros altered", ErrLedgerCorrupt)
	}

	// 6. Spend totals
	committed, err := validateInt(state["committed_spend_micros"], "committed_spend_micros", 0, nil)
	if err != nil {
		return nil, err
	}
	retained, err := validateInt(state["retained_failed_micros"], "retained_failed_micros", 0, nil)
	if err != nil {
		return nil, err
	}

	// 7. Pending reservation
	pendingRaw := state["pending_reservation"]
	var pendingData *PendingReservationData
	var pendingAmount int
	if pendingRaw != nil {
		pMap, ok := pendingRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: pending_reservation must be a dictionary or None", ErrLedgerCorrupt)
		}
		var pMissing, pUnexpected []string
		for k := range expectedPendingKeys {
			if _, ok := pMap[k]; !ok {
				pMissing = append(pMissing, k)
			}
		}
		for k := range pMap {
			if !expectedPendingKeys[k] {
				pUnexpected = append(pUnexpected, k)
			}
		}
		if len(pMissing) > 0 || len(pUnexpected) > 0 {
			sort.Strings(pMissing)
			sort.Strings(pUnexpected)
			return nil, fmt.Errorf("%w: pending_reservation schema violation: expected %v, got %v", ErrLedgerCorrupt, sortedKeysMap(expectedPendingKeys), sortedKeys(pMap))
		}

		pResID, err := validateIdentifier(pMap["reservation_id"], "pending reservation_id")
		if err != nil {
			return nil, err
		}
		pReqID, err := validateIdentifier(pMap["request_id"], "pending request_id")
		if err != nil {
			return nil, err
		}
		pReqDig, err := validateDigest(pMap["request_digest"])
		if err != nil {
			return nil, err
		}
		maxRes := ReservationAmountMicros
		pAmt, err := validateInt(pMap["reserved_amount_micros"], "pending reserved_amount_micros", MinReservationMicros, &maxRes)
		if err != nil {
			return nil, fmt.Errorf("%w: pending_reservation amount mismatch", ErrLedgerCorrupt)
		}
		pTs, _, err := validateTimestamp(pMap["reserved_at_utc"])
		if err != nil {
			return nil, err
		}
		pPID, err := validateInt(pMap["pid"], "pending pid", 0, nil)
		if err != nil {
			return nil, err
		}
		pendingAmount = pAmt
		pendingData = &PendingReservationData{
			ReservationID:        pResID,
			RequestID:            pReqID,
			RequestDigest:        pReqDig,
			ReservedAmountMicros: pAmt,
			ReservedAtUTC:        pTs,
			PID:                  pPID,
		}
	}

	// 8. Counts
	maxReq := MaxForwardedRequests
	reservations, err := validateInt(state["total_reservations_count"], "total_reservations_count", 0, &maxReq)
	if err != nil {
		return nil, err
	}
	settled, err := validateInt(state["settled_requests_count"], "settled_requests_count", 0, &reservations)
	if err != nil {
		return nil, err
	}

	// 9. Halted
	halted, ok := state["halted"].(bool)
	if !ok {
		return nil, fmt.Errorf("%w: halted field must be a boolean", ErrLedgerCorrupt)
	}
	haltReasonRaw := state["halt_reason"]
	var haltReason *string
	if halted {
		hr, ok := haltReasonRaw.(string)
		if !ok || strings.TrimSpace(hr) == "" {
			return nil, fmt.Errorf("%w: halt_reason must be a non-empty string when halted is True", ErrLedgerCorrupt)
		}
		if !AllowedInternalFailureCodes[hr] {
			return nil, fmt.Errorf("%w: halt_reason %q not in ALLOWED_INTERNAL_FAILURE_CODES", ErrLedgerCorrupt, hr)
		}
		haltReason = &hr
	} else {
		if haltReasonRaw != nil {
			return nil, fmt.Errorf("%w: halt_reason must be None when halted is False", ErrLedgerCorrupt)
		}
	}

	// 10. Journal replay
	journalRaw, ok := state["journal"].([]any)
	if !ok || len(journalRaw) == 0 {
		return nil, fmt.Errorf("%w: journal must be a non-empty list", ErrLedgerCorrupt)
	}
	if len(journalRaw) > MaxJournalEntries {
		return nil, fmt.Errorf("%w: journal exceeds maximum length of %d", ErrLedgerCorrupt, MaxJournalEntries)
	}

	// Entry 0: INITIALIZED
	initMap, ok := journalRaw[0].(map[string]any)
	if !ok || initMap["entry_type"] != "INITIALIZED" {
		return nil, fmt.Errorf("%w: First journal entry must be INITIALIZED", ErrLedgerCorrupt)
	}
	if err := checkClosedSchema(initMap, journalKeys["INITIALIZED"], "INITIALIZED journal entry"); err != nil {
		return nil, err
	}
	if initMap["experiment_id"] != expID {
		return nil, fmt.Errorf("%w: INITIALIZED entry experiment_id mismatch", ErrLedgerCorrupt)
	}
	initCeiling, err := validateInt(initMap["global_ceiling_micros"], "INITIALIZED entry global_ceiling_micros", GlobalCeilingMicros, &cVal)
	if err != nil {
		return nil, fmt.Errorf("%w: INITIALIZED entry global_ceiling_micros mismatch", ErrLedgerCorrupt)
	}
	initTs, _, err := validateTimestamp(initMap["timestamp_utc"])
	if err != nil {
		return nil, err
	}

	journalEntries := make([]JournalEntry, len(journalRaw))
	journalEntries[0] = JournalEntry{
		EntryType:           "INITIALIZED",
		ExperimentID:        expID,
		GlobalCeilingMicros: initCeiling,
		TimestampUTC:        initTs,
	}

	seenPermits := make(map[string]bool)
	seenRequests := make(map[string]bool)
	seenResponses := make(map[string]bool)
	historicalSettledMap := make(map[string]int)
	historicalReservedMap := make(map[string]int)
	var activeRes map[string]any
	var hasTerminalHalt bool
	var hasTerminalUncertainty bool
	var uncertainSettledCount int
	var terminalHaltReason string
	var jSettledAmount, jRetainedAmount, jRetainedCount, jSettledCount, jReservedCount int

	for idx := 1; idx < len(journalRaw); idx++ {
		entry, ok := journalRaw[idx].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: Journal entry at index %d must be a dictionary", ErrLedgerCorrupt, idx)
		}
		etype, ok := entry["entry_type"].(string)
		if !ok || !ValidJournalEntryTypes[etype] || etype == "INITIALIZED" {
			return nil, fmt.Errorf("%w: Forbidden or malformed journal entry type at index %d: %v", ErrLedgerCorrupt, idx, entry["entry_type"])
		}
		if hasTerminalHalt {
			return nil, fmt.Errorf("%w: Event found at index %d after terminal halt had already occurred", ErrLedgerCorrupt, idx)
		}
		ts, _, err := validateTimestamp(entry["timestamp_utc"])
		if err != nil {
			return nil, err
		}
		expectedKeys := journalKeys[etype]
		if err := checkClosedSchema(entry, expectedKeys, fmt.Sprintf("%s journal entry at index %d", etype, idx)); err != nil {
			return nil, err
		}

		switch etype {
		case "RESERVED":
			if activeRes != nil {
				return nil, fmt.Errorf("%w: State machine violation at index %d: new RESERVED entry while previous reservation (%s) is active", ErrLedgerCorrupt, idx, activeRes["reservation_id"])
			}
			pidVal, err := validateIdentifier(entry["reservation_id"], fmt.Sprintf("index %d reservation_id", idx))
			if err != nil {
				return nil, err
			}
			reqID, err := validateIdentifier(entry["request_id"], fmt.Sprintf("index %d request_id", idx))
			if err != nil {
				return nil, err
			}
			reqDig, err := validateDigest(entry["request_digest"])
			if err != nil {
				return nil, err
			}
			if seenPermits[pidVal] {
				return nil, fmt.Errorf("%w: Duplicate reservation_id in journal at index %d: %q", ErrLedgerCorrupt, idx, pidVal)
			}
			if seenRequests[reqID] {
				return nil, fmt.Errorf("%w: Duplicate request_id in journal at index %d: %q", ErrLedgerCorrupt, idx, reqID)
			}
			seenPermits[pidVal] = true
			seenRequests[reqID] = true
			jReservedCount++
			resIdx, err := validateInt(entry["reservation_index"], fmt.Sprintf("index %d reservation_index", idx), 0, nil)
			if err != nil {
				return nil, err
			}
			if resIdx != jReservedCount {
				return nil, fmt.Errorf("%w: reservation_index mismatch at index %d: expected %d, got %d", ErrLedgerCorrupt, idx, jReservedCount, resIdx)
			}
			maxR := ReservationAmountMicros
			resAmt, err := validateInt(entry["reserved_amount_micros"], fmt.Sprintf("index %d reserved_amount_micros", idx), MinReservationMicros, &maxR)
			if err != nil {
				return nil, fmt.Errorf("%w: reserved_amount_micros mismatch at index %d", ErrLedgerCorrupt, idx)
			}
			if jSettledAmount+jRetainedAmount+resAmt > GlobalCeilingMicros {
				return nil, fmt.Errorf("%w: Replay ceiling violation at index %d: committed (%d) + retained (%d) + reserved (%d) > ceiling (%d)", ErrLedgerCorrupt, idx, jSettledAmount, jRetainedAmount, resAmt, GlobalCeilingMicros)
			}
			activeRes = map[string]any{
				"reservation_id":         pidVal,
				"request_id":             reqID,
				"request_digest":         reqDig,
				"reserved_amount_micros": resAmt,
			}
			journalEntries[idx] = JournalEntry{
				EntryType:            etype,
				ReservationID:        pidVal,
				RequestID:            reqID,
				RequestDigest:        reqDig,
				ReservedAmountMicros: resAmt,
				ReservationIndex:     resIdx,
				TimestampUTC:         ts,
			}

		case "SETTLED":
			if activeRes == nil {
				return nil, fmt.Errorf("%w: State machine violation at index %d: SETTLED entry without active pending reservation", ErrLedgerCorrupt, idx)
			}
			pidVal, err := validateIdentifier(entry["reservation_id"], fmt.Sprintf("index %d reservation_id", idx))
			if err != nil {
				return nil, err
			}
			reqID, err := validateIdentifier(entry["request_id"], fmt.Sprintf("index %d request_id", idx))
			if err != nil {
				return nil, err
			}
			reqDig, err := validateDigest(entry["request_digest"])
			if err != nil {
				return nil, err
			}
			respID, err := validateIdentifier(entry["response_id"], fmt.Sprintf("index %d response_id", idx))
			if err != nil {
				return nil, err
			}
			if pidVal != activeRes["reservation_id"] {
				return nil, fmt.Errorf("%w: reservation_id mismatch in SETTLED entry at index %d", ErrLedgerCorrupt, idx)
			}
			if reqID != activeRes["request_id"] || reqDig != activeRes["request_digest"] {
				return nil, fmt.Errorf("%w: Request identity mismatch in SETTLED entry at index %d", ErrLedgerCorrupt, idx)
			}
			model, ok := entry["model"].(string)
			tier, ok2 := entry["service_tier"].(string)
			rate, exists := ModelRates[model]
			if !ok || !exists {
				return nil, fmt.Errorf("%w: Model mismatch in SETTLED entry at index %d: expected %s", ErrLedgerCorrupt, idx, PinnedModel)
			}
			if !ok2 || tier != rate.ServiceTier {
				return nil, fmt.Errorf("%w: Service tier mismatch in SETTLED entry at index %d: expected %s", ErrLedgerCorrupt, idx, PinnedServiceTier)
			}
			if seenResponses[respID] {
				return nil, fmt.Errorf("%w: Duplicate response_id across SETTLED entries: %q", ErrLedgerCorrupt, respID)
			}
			seenResponses[respID] = true

			maxIn := MaxInputTokens
			inTok, err := validateInt(entry["input_tokens"], fmt.Sprintf("index %d input_tokens", idx), 0, &maxIn)
			if err != nil {
				return nil, err
			}
			maxOut := MaxOutputTokens
			outTok, err := validateInt(entry["output_tokens"], fmt.Sprintf("index %d output_tokens", idx), 0, &maxOut)
			if err != nil {
				return nil, err
			}
			totTok, err := validateInt(entry["total_tokens"], fmt.Sprintf("index %d total_tokens", idx), 0, nil)
			if err != nil {
				return nil, err
			}
			settledAmt, err := validateInt(entry["settled_amount_micros"], fmt.Sprintf("index %d settled_amount_micros", idx), 0, nil)
			if err != nil {
				return nil, err
			}
			unenc, err := validateInt(entry["unencumbered_amount_micros"], fmt.Sprintf("index %d unencumbered_amount_micros", idx), 0, nil)
			if err != nil {
				return nil, err
			}
			if totTok != (inTok + outTok) {
				return nil, fmt.Errorf("%w: total_tokens mismatch in SETTLED entry at index %d", ErrLedgerCorrupt, idx)
			}
			expectedAmt, err := ModelCostMicros(model, tier, inTok, outTok)
			if err != nil || settledAmt != expectedAmt {
				return nil, fmt.Errorf("%w: settled_amount_micros derivation error at index %d: expected %d, got %d", ErrLedgerCorrupt, idx, expectedAmt, settledAmt)
			}
			activeReserved := activeRes["reserved_amount_micros"].(int)
			if unenc != (activeReserved - settledAmt) {
				return nil, fmt.Errorf("%w: unencumbered_amount_micros derivation error at index %d", ErrLedgerCorrupt, idx)
			}

			historicalSettledMap[pidVal] = settledAmt
			historicalReservedMap[pidVal] = activeReserved
			jSettledAmount += settledAmt
			jSettledCount++
			activeRes = nil
			journalEntries[idx] = JournalEntry{
				EntryType:                etype,
				ReservationID:            pidVal,
				RequestID:                reqID,
				RequestDigest:            reqDig,
				ResponseID:               respID,
				Model:                    model,
				ServiceTier:              tier,
				InputTokens:              inTok,
				OutputTokens:             outTok,
				TotalTokens:              totTok,
				SettledAmountMicros:      settledAmt,
				UnencumberedAmountMicros: unenc,
				TimestampUTC:             ts,
			}

		case "FAILED_RETAINED":
			if activeRes == nil {
				return nil, fmt.Errorf("%w: State machine violation at index %d: FAILED_RETAINED entry without active pending reservation", ErrLedgerCorrupt, idx)
			}
			pidVal, err := validateIdentifier(entry["reservation_id"], fmt.Sprintf("index %d reservation_id", idx))
			if err != nil {
				return nil, err
			}
			reqID, err := validateIdentifier(entry["request_id"], fmt.Sprintf("index %d request_id", idx))
			if err != nil {
				return nil, err
			}
			retainedAmt, err := validateInt(entry["retained_amount_micros"], fmt.Sprintf("index %d retained_amount_micros", idx), 0, nil)
			if err != nil {
				return nil, err
			}
			reason, err := replayReason(entry["reason"])
			if err != nil {
				return nil, err
			}
			if pidVal != activeRes["reservation_id"] || reqID != activeRes["request_id"] {
				return nil, fmt.Errorf("%w: Reservation identity mismatch in FAILED_RETAINED entry at index %d", ErrLedgerCorrupt, idx)
			}
			activeReserved := activeRes["reserved_amount_micros"].(int)
			if retainedAmt != activeReserved {
				return nil, fmt.Errorf("%w: retained_amount_micros mismatch at index %d", ErrLedgerCorrupt, idx)
			}
			jRetainedAmount += retainedAmt
			jRetainedCount++
			activeRes = nil
			hasTerminalHalt = true
			terminalHaltReason = reason
			journalEntries[idx] = JournalEntry{
				EntryType:            etype,
				ReservationID:        pidVal,
				RequestID:            reqID,
				RetainedAmountMicros: retainedAmt,
				Reason:               reason,
				TimestampUTC:         ts,
			}

		case "ORPHANED_PENDING_HALTED":
			if activeRes == nil {
				return nil, fmt.Errorf("%w: State machine violation at index %d: ORPHANED_PENDING_HALTED entry without active pending reservation", ErrLedgerCorrupt, idx)
			}
			pidVal, err := validateIdentifier(entry["reservation_id"], fmt.Sprintf("index %d reservation_id", idx))
			if err != nil {
				return nil, err
			}
			reqID, err := validateIdentifier(entry["request_id"], fmt.Sprintf("index %d request_id", idx))
			if err != nil {
				return nil, err
			}
			retainedAmt, err := validateInt(entry["retained_amount_micros"], fmt.Sprintf("index %d retained_amount_micros", idx), 0, nil)
			if err != nil {
				return nil, err
			}
			reason, err := replayReason(entry["reason"])
			if err != nil {
				return nil, err
			}
			if pidVal != activeRes["reservation_id"] || reqID != activeRes["request_id"] {
				return nil, fmt.Errorf("%w: Reservation identity mismatch in ORPHANED_PENDING_HALTED entry at index %d", ErrLedgerCorrupt, idx)
			}
			activeReserved := activeRes["reserved_amount_micros"].(int)
			if retainedAmt != activeReserved {
				return nil, fmt.Errorf("%w: retained_amount_micros mismatch at index %d", ErrLedgerCorrupt, idx)
			}
			jRetainedAmount += retainedAmt
			jRetainedCount++
			activeRes = nil
			hasTerminalHalt = true
			terminalHaltReason = reason
			journalEntries[idx] = JournalEntry{
				EntryType:            etype,
				ReservationID:        pidVal,
				RequestID:            reqID,
				RetainedAmountMicros: retainedAmt,
				Reason:               reason,
				TimestampUTC:         ts,
			}

		case "TERMINAL_UNCERTAINTY":
			if idx != len(journalRaw)-1 {
				return nil, fmt.Errorf("%w: TERMINAL_UNCERTAINTY entry at index %d must be the final journal entry", ErrLedgerCorrupt, idx)
			}
			reason, ok := entry["reason"].(string)
			if !ok || !TerminalUncertaintyReasons[reason] {
				return nil, fmt.Errorf("%w: TERMINAL_UNCERTAINTY entry carries a non-terminal-uncertainty reason", ErrLedgerCorrupt)
			}
			uidsRaw, ok := entry["uncertain_reservation_ids"].([]any)
			if !ok {
				return nil, fmt.Errorf("%w: uncertain_reservation_ids must be a list of reservation IDs", ErrLedgerCorrupt)
			}
			if len(uidsRaw) == 0 && len(seenPermits) > 0 {
				return nil, fmt.Errorf("%w: uncertain_reservation_ids may be empty only when no reservation was ever recorded", ErrLedgerCorrupt)
			}
			if len(uidsRaw) > MaxJournalEntries {
				return nil, fmt.Errorf("%w: uncertain_reservation_ids exceeds maximum of %d", ErrLedgerCorrupt, MaxJournalEntries)
			}
			uids := make([]string, len(uidsRaw))
			seenUIDs := make(map[string]bool, len(uidsRaw))
			for ui, ur := range uidsRaw {
				uid, ok := ur.(string)
				if !ok {
					return nil, fmt.Errorf("%w: uncertain_reservation_ids must contain strings", ErrLedgerCorrupt)
				}
				if seenUIDs[uid] {
					return nil, fmt.Errorf("%w: uncertain_reservation_ids contains duplicate IDs", ErrLedgerCorrupt)
				}
				seenUIDs[uid] = true
				uids[ui] = uid
			}
			if !sort.StringsAreSorted(uids) {
				return nil, fmt.Errorf("%w: uncertain_reservation_ids must be sorted", ErrLedgerCorrupt)
			}

			for _, uid := range uids {
				if sAmt, ok := historicalSettledMap[uid]; ok {
					jSettledAmount -= sAmt
					jRetainedAmount += historicalReservedMap[uid]
					jRetainedCount++
					uncertainSettledCount++
				} else if activeRes != nil && uid == activeRes["reservation_id"] {
					jRetainedAmount += activeRes["reserved_amount_micros"].(int)
					jRetainedCount++
					activeRes = nil
				} else {
					return nil, fmt.Errorf("%w: Unknown or non-recoverable reservation_id in uncertain_reservation_ids", ErrLedgerCorrupt)
				}
			}

			if activeRes != nil {
				return nil, fmt.Errorf("%w: TERMINAL_UNCERTAINTY must cover the current pending reservation", ErrLedgerCorrupt)
			}
			hasTerminalHalt = true
			hasTerminalUncertainty = true
			terminalHaltReason = reason
			journalEntries[idx] = JournalEntry{
				EntryType:               etype,
				Reason:                  reason,
				UncertainReservationIDs: uids,
				TimestampUTC:            ts,
			}
		}
	}

	// 11. Terminal halt validation
	if halted && !hasTerminalHalt {
		return nil, fmt.Errorf("%w: Top-level halted flag is True but replayed history has no terminal event", ErrLedgerCorrupt)
	}
	if hasTerminalHalt {
		if !halted {
			return nil, fmt.Errorf("%w: Top-level state halted flag is False but history contains a terminal failure", ErrLedgerCorrupt)
		}
		if haltReason == nil || *haltReason != terminalHaltReason {
			return nil, fmt.Errorf("%w: Top-level halt_reason %v does not match terminal failure reason %q", ErrLedgerCorrupt, haltReason, terminalHaltReason)
		}
		if pendingData != nil {
			return nil, fmt.Errorf("%w: pending_reservation must be None when ledger has terminally halted", ErrLedgerCorrupt)
		}
	}

	// 12. Active vs pending reservation
	if pendingData == nil {
		if activeRes != nil {
			return nil, fmt.Errorf("%w: Accounting imbalance: active reservation %s exists in journal but pending_reservation is None", ErrLedgerCorrupt, activeRes["reservation_id"])
		}
	} else {
		if activeRes == nil {
			return nil, fmt.Errorf("%w: Accounting imbalance: pending_reservation is present but no active reservation exists in journal", ErrLedgerCorrupt)
		}
		if pendingData.ReservationID != activeRes["reservation_id"] ||
			pendingData.RequestID != activeRes["request_id"] ||
			pendingData.RequestDigest != activeRes["request_digest"] {
			return nil, fmt.Errorf("%w: Identity mismatch between pending_reservation and journal active reservation", ErrLedgerCorrupt)
		}
	}

	// 13. Replay ceiling checks
	if pendingData != nil {
		if jSettledAmount+jRetainedAmount+pendingData.ReservedAmountMicros > GlobalCeilingMicros {
			return nil, fmt.Errorf("%w: Replay ceiling violation with pending reservation: committed (%d) + retained (%d) + pending (%d) > ceiling (%d)", ErrLedgerCorrupt, jSettledAmount, jRetainedAmount, pendingData.ReservedAmountMicros, GlobalCeilingMicros)
		}
	}
	if !hasTerminalUncertainty {
		if jSettledAmount+jRetainedAmount+pendingAmount > GlobalCeilingMicros {
			return nil, fmt.Errorf("%w: Replay ceiling violation: committed (%d) + retained (%d) > ceiling (%d)", ErrLedgerCorrupt, jSettledAmount, jRetainedAmount, GlobalCeilingMicros)
		}
	}

	// 14. Derived totals and reconciliation
	if jReservedCount != reservations {
		return nil, fmt.Errorf("%w: Reconciliation error: journal RESERVED entries (%d) != total_reservations_count (%d)", ErrLedgerCorrupt, jReservedCount, reservations)
	}
	if jSettledCount != settled {
		return nil, fmt.Errorf("%w: Reconciliation error: journal SETTLED entries (%d) != settled_requests_count (%d)", ErrLedgerCorrupt, jSettledCount, settled)
	}
	if jSettledAmount != committed {
		return nil, fmt.Errorf("%w: Reconciliation error: journal settled sum (%d) != committed_spend_micros (%d)", ErrLedgerCorrupt, jSettledAmount, committed)
	}
	if jRetainedAmount != retained {
		return nil, fmt.Errorf("%w: Reconciliation error: journal retained sum (%d) != retained_failed_micros (%d)", ErrLedgerCorrupt, jRetainedAmount, retained)
	}

	failedCount := jRetainedCount
	var expectedReservations int
	if hasTerminalUncertainty {
		expectedReservations = (settled - uncertainSettledCount) + failedCount
	} else {
		expectedReservations = settled + failedCount
		if pendingData != nil {
			expectedReservations++
		}
	}
	if reservations != expectedReservations {
		return nil, fmt.Errorf("%w: Accounting balance violation: reservations (%d) != expected (%d)", ErrLedgerCorrupt, reservations, expectedReservations)
	}

	return &LedgerState{
		SchemaVersion:           SchemaVersion,
		ExperimentID:            expID,
		CreatedAtUTC:            createdStr,
		UpdatedAtUTC:            updatedStr,
		GlobalCeilingMicros:     GlobalCeilingMicros,
		ReservationAmountMicros: ReservationAmountMicros,
		CommittedSpendMicros:    committed,
		RetainedFailedMicros:    retained,
		TotalReservationsCount:  reservations,
		SettledRequestsCount:    settled,
		PendingReservation:      pendingData,
		Halted:                  halted,
		HaltReason:              haltReason,
		Journal:                 journalEntries,
	}, nil
}

// ValidateWitnessRecord parses and validates an auxiliary witness or inspection record.
func ValidateWitnessRecord(data []byte, expectedType string, expectedExpID string) (*WitnessRecord, error) {
	val, err := safeJSONDecode(data)
	if err != nil {
		return nil, err
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: witness record must be a JSON object", ErrLedgerCorrupt)
	}

	expectedKeys, ok := witnessKeys[expectedType]
	if !ok {
		return nil, fmt.Errorf("%w: unknown witness record type %q", ErrLedgerCorrupt, expectedType)
	}
	if err := checkClosedSchema(m, expectedKeys, fmt.Sprintf("Record %s", expectedType)); err != nil {
		return nil, err
	}

	rtype, ok := m["record_type"].(string)
	if !ok || rtype != expectedType {
		return nil, fmt.Errorf("%w: record_type mismatch: expected %s, got %v", ErrLedgerCorrupt, expectedType, m["record_type"])
	}

	expID, err := validateIdentifier(m["experiment_id"], "experiment_id")
	if err != nil {
		return nil, err
	}
	if expectedExpID != "" && expID != expectedExpID {
		return nil, fmt.Errorf("%w: experiment_id mismatch: expected %s, got %s", ErrLedgerCorrupt, expectedExpID, expID)
	}

	switch expectedType {
	case "INSPECTION_GUARD", "INSPECTION_COMPLETION":
		maxGen := MaxInspectionGeneration
		gen, err := validateInt(m["generation"], "generation", 1, &maxGen)
		if err != nil {
			return nil, fmt.Errorf("%w: generation invalid: %v", ErrLedgerCorrupt, err)
		}
		var tsField string
		var armedAt, completedAt string
		if expectedType == "INSPECTION_GUARD" {
			tsField = "armed_at_utc"
			armedAt, _, err = validateTimestamp(m[tsField])
		} else {
			tsField = "completed_at_utc"
			completedAt, _, err = validateTimestamp(m[tsField])
		}
		if err != nil {
			return nil, err
		}
		return &WitnessRecord{
			RecordType:     expectedType,
			ExperimentID:   expID,
			Generation:     gen,
			ArmedAtUTC:     armedAt,
			CompletedAtUTC: completedAt,
		}, nil

	case "SETTLEMENT_INTENT", "SETTLEMENT_CONFIRMATION":
		resID, err := validateIdentifier(m["reservation_id"], "reservation_id")
		if err != nil {
			return nil, err
		}
		reqID, err := validateIdentifier(m["request_id"], "request_id")
		if err != nil {
			return nil, err
		}
		reqDig, err := validateDigest(m["request_digest"])
		if err != nil {
			return nil, err
		}
		respID, err := validateIdentifier(m["response_id"], "response_id")
		if err != nil {
			return nil, err
		}
		ts, _, err := validateTimestamp(m["timestamp_utc"])
		if err != nil {
			return nil, err
		}
		model, ok := m["model"].(string)
		tier, ok2 := m["service_tier"].(string)
		rate, exists := ModelRates[model]
		if !ok || !exists {
			return nil, fmt.Errorf("%w: model mismatch: %v", ErrLedgerCorrupt, m["model"])
		}
		if !ok2 || tier != rate.ServiceTier {
			return nil, fmt.Errorf("%w: service tier mismatch: %v", ErrLedgerCorrupt, m["service_tier"])
		}

		maxIn := MaxInputTokens
		inTok, err := validateInt(m["input_tokens"], "input_tokens", 0, &maxIn)
		if err != nil {
			return nil, err
		}
		maxOut := MaxOutputTokens
		outTok, err := validateInt(m["output_tokens"], "output_tokens", 0, &maxOut)
		if err != nil {
			return nil, err
		}
		totTok, err := validateInt(m["total_tokens"], "total_tokens", 0, nil)
		if err != nil {
			return nil, err
		}
		if totTok != (inTok + outTok) {
			return nil, fmt.Errorf("%w: total_tokens derivation error", ErrLedgerCorrupt)
		}
		settledAmt, err := validateInt(m["settled_amount_micros"], "settled_amount_micros", 0, nil)
		if err != nil {
			return nil, err
		}
		unenc, err := validateInt(m["unencumbered_amount_micros"], "unencumbered_amount_micros", 0, nil)
		if err != nil {
			return nil, err
		}
		expectedAmt, err := ModelCostMicros(model, tier, inTok, outTok)
		if err != nil || settledAmt != expectedAmt {
			return nil, fmt.Errorf("%w: settled_amount_micros derivation error", ErrLedgerCorrupt)
		}
		if (settledAmt+unenc) < MinReservationMicros || (settledAmt+unenc) > ReservationAmountMicros {
			return nil, fmt.Errorf("%w: unencumbered_amount_micros derivation error", ErrLedgerCorrupt)
		}
		return &WitnessRecord{
			RecordType:               expectedType,
			ExperimentID:             expID,
			ReservationID:            resID,
			RequestID:                reqID,
			RequestDigest:            reqDig,
			ResponseID:               respID,
			Model:                    model,
			ServiceTier:              tier,
			InputTokens:              inTok,
			OutputTokens:             outTok,
			TotalTokens:              totTok,
			SettledAmountMicros:      settledAmt,
			UnencumberedAmountMicros: unenc,
			TimestampUTC:             ts,
		}, nil
	default:
		return nil, fmt.Errorf("%w: unhandled witness record type %s", ErrLedgerCorrupt, expectedType)
	}
}

func sortedKeysMap(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
