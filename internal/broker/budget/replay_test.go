package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDuplicateKeysInJSONRejected(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "dupe_key_ledger")

	l, err := Initialize(ledgerDir, "dupe-keys")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	rawBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	raw := string(rawBytes)
	pos := strings.Index(raw, `"experiment_id":`)
	if pos == -1 {
		t.Fatal("could not find experiment_id")
	}
	duplicateRaw := raw[:pos] + `"experiment_id": "dupe",\n  ` + raw[pos:]
	if err := os.WriteFile(statePath, []byte(duplicateRaw), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for duplicate JSON keys, got %v", err)
	}
}

func TestNonfiniteNumericConstantsRejected(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "nonfinite_ledger")

	l, err := Initialize(ledgerDir, "nonfinite")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	rawBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	tampered := strings.Replace(string(rawBytes), `"committed_spend_micros": 0`, `"committed_spend_micros": NaN`, 1)
	if err := os.WriteFile(statePath, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for NaN constant, got %v", err)
	}
}

func TestReplayRejectDuplicateRequestIDAcrossReservations(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "dupe_req_ledger")

	l, err := Initialize(ledgerDir, "dupe-req")
	if err != nil {
		t.Fatal(err)
	}

	p1, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}
	r1 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-1",
		RequestID:     "req-1",
		RequestDigest: "sha256:1",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   10,
		OutputTokens:  10,
		TotalTokens:   20,
	}
	if _, err := l.Settle(p1, r1); err != nil {
		t.Fatal(err)
	}

	// Attempting to reserve with same request ID in runtime
	_, err = l.Reserve("req-1", "sha256:1", 20000)
	if err == nil {
		t.Fatalf("expected error reusing request_id in reserve")
	}
	l.Close()

	// Tamper state: add second RESERVED with same request_id
	statePath := filepath.Join(ledgerDir, StateFilename)
	rawBytes, _ := os.ReadFile(statePath)
	var state map[string]any
	_ = json.Unmarshal(rawBytes, &state)
	journal := state["journal"].([]any)
	journal = append(journal, map[string]any{
		"entry_type":             "RESERVED",
		"reservation_id":         "permit_new",
		"request_id":             "req-1", // DUPLICATE!
		"request_digest":         "sha256:1",
		"reserved_amount_micros": 20000,
		"reservation_index":      2,
		"timestamp_utc":          nowUTCStr(),
	})
	state["journal"] = journal
	state["total_reservations_count"] = 2
	tampered, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(statePath, tampered, 0600)

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for duplicate request_id in journal, got %v", err)
	}
}

func TestReplayRejectSecondInitializedEvent(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "second_init_ledger")

	l, err := Initialize(ledgerDir, "second-init")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	rawBytes, _ := os.ReadFile(statePath)
	var state map[string]any
	_ = json.Unmarshal(rawBytes, &state)
	journal := state["journal"].([]any)
	journal = append(journal, journal[0]) // append second INITIALIZED
	state["journal"] = journal
	tampered, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(statePath, tampered, 0600)

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for second INITIALIZED event, got %v", err)
	}
}

func TestReplayRejectEventAfterTerminalFailure(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "after_term_ledger")

	l, err := Initialize(ledgerDir, "after-term")
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.RecordFailure(p, "REQUEST_TRANSPORT_FAILURE"); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Tamper state: add another RESERVED entry after terminal failure
	statePath := filepath.Join(ledgerDir, StateFilename)
	rawBytes, _ := os.ReadFile(statePath)
	var state map[string]any
	_ = json.Unmarshal(rawBytes, &state)
	journal := state["journal"].([]any)
	journal = append(journal, map[string]any{
		"entry_type":             "RESERVED",
		"reservation_id":         "permit_after_term",
		"request_id":             "req-after",
		"request_digest":         "sha256:after",
		"reserved_amount_micros": 20000,
		"reservation_index":      2,
		"timestamp_utc":          nowUTCStr(),
	})
	state["journal"] = journal
	state["total_reservations_count"] = 2
	tampered, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(statePath, tampered, 0600)

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for event after terminal failure, got %v", err)
	}
}

func TestReplayRejectClearedHaltFlagAfterTerminalFailure(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "cleared_halt_ledger")

	l, err := Initialize(ledgerDir, "cleared-halt")
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.RecordFailure(p, "REQUEST_TRANSPORT_FAILURE"); err != nil {
		t.Fatal(err)
	}
	l.Close()

	statePath := filepath.Join(ledgerDir, StateFilename)
	rawBytes, _ := os.ReadFile(statePath)
	var state map[string]any
	_ = json.Unmarshal(rawBytes, &state)
	state["halted"] = false // tampered cleared halt flag!
	state["halt_reason"] = nil
	tampered, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(statePath, tampered, 0600)

	if _, err := Open(ledgerDir); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for cleared halt flag, got %v", err)
	}
}

func TestMaxForwardedRequestsLimitStrictlyEnforced(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "max_req_ledger")

	l, err := Initialize(ledgerDir, "max-req")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Issue and settle MaxForwardedRequests tiny requests (10 uUSD each)
	for i := 1; i <= MaxForwardedRequests; i++ {
		reqID := fmt.Sprintf("req-%03d", i)
		p, err := l.Reserve(reqID, fmt.Sprintf("sha256:%s", reqID), MinReservationMicros)
		if err != nil {
			t.Fatalf("failed to reserve %d: %v", i, err)
		}
		r := &Receipt{
			Status:        TerminalStatusCompleted,
			ResponseID:    fmt.Sprintf("resp-%03d", i),
			RequestID:     reqID,
			RequestDigest: fmt.Sprintf("sha256:%s", reqID),
			Model:         PinnedModel,
			ServiceTier:   PinnedServiceTier,
			InputTokens:   1,
			OutputTokens:  0,
			TotalTokens:   1,
		}
		if _, err := l.Settle(p, r); err != nil {
			t.Fatalf("failed to settle %d: %v", i, err)
		}
	}

	st, err := l.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalReservationsCount != MaxForwardedRequests {
		t.Errorf("expected %d reservations, got %d", MaxForwardedRequests, st.TotalReservationsCount)
	}
	if st.SettledRequestsCount != MaxForwardedRequests {
		t.Errorf("expected %d settlements, got %d", MaxForwardedRequests, st.SettledRequestsCount)
	}

	// 257th request must be strictly rejected
	_, err = l.Reserve("req-257", "sha256:257", MinReservationMicros)
	if !errors.Is(err, ErrReservationLimitExceeded) {
		t.Fatalf("expected ErrReservationLimitExceeded, got %v", err)
	}
}

func TestSizedReservationsAndReplayAfterReopen(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "sized_ledger")

	l, err := Initialize(ledgerDir, "sized-exp")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Minimum allowed reservation: MinReservationMicros (1024)
	p1, err := l.Reserve("req-min", "sha256:min", MinReservationMicros)
	if err != nil {
		t.Fatalf("failed to reserve min: %v", err)
	}
	r1 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-min",
		RequestID:     "req-min",
		RequestDigest: "sha256:min",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   10,
		OutputTokens:  10,
		TotalTokens:   20,
	}
	s1, err := l.Settle(p1, r1)
	if err != nil {
		t.Fatal(err)
	}
	if s1.AccountedCostMicros != 20 {
		t.Errorf("expected 20 cost, got %d", s1.AccountedCostMicros)
	}
	if s1.UnencumberedAmountMicros != 1024-20 {
		t.Errorf("expected %d unencumbered, got %d", 1024-20, s1.UnencumberedAmountMicros)
	}

	// 2. Custom sized reservation: 50,000 uUSD
	p2, err := l.Reserve("req-50k", "sha256:50k", 50000)
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-50k",
		RequestID:     "req-50k",
		RequestDigest: "sha256:50k",
		Model:         "claude-sonnet-5-5",
		ServiceTier:   "standard",
		InputTokens:   100,
		OutputTokens:  20,
		TotalTokens:   120,
	}
	s2, err := l.Settle(p2, r2)
	if err != nil {
		t.Fatal(err)
	}
	// 100*2 + 20*10 = 400
	if s2.AccountedCostMicros != 400 {
		t.Errorf("expected 400 cost, got %d", s2.AccountedCostMicros)
	}
	if s2.UnencumberedAmountMicros != 50000-400 {
		t.Errorf("expected %d unencumbered, got %d", 50000-400, s2.UnencumberedAmountMicros)
	}
	l.Close()

	// 3. Reopen and verify replay derived all totals exactly
	l2, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("failed to reopen sized ledger: %v", err)
	}
	defer l2.Close()

	st, err := l2.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedSpendMicros != 420 {
		t.Errorf("expected 420 committed spend, got %d", st.CommittedSpendMicros)
	}
	if st.SettledRequestsCount != 2 || st.TotalReservationsCount != 2 {
		t.Errorf("unexpected counts: %+v", st)
	}
}

func TestSizedReservationBounds(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "bounds_ledger")

	l, err := Initialize(ledgerDir, "bounds-exp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Reservation below MinReservationMicros (1024)
	_, err = l.Reserve("req-low", "sha256:low", MinReservationMicros-1)
	if err == nil {
		t.Fatalf("expected error for reservation below minimum")
	}

	// Reservation above ReservationAmountMicros (1,100,000)
	_, err = l.Reserve("req-high", "sha256:high", ReservationAmountMicros+1)
	if err == nil {
		t.Fatalf("expected error for reservation above maximum")
	}
}
