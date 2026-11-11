package budget

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestReceiptValidation(t *testing.T) {
	cases := []struct {
		name       string
		receiptFn  func(p *ReservationPermit) *Receipt
		expHalt    string
		expErrCode string
	}{
		{
			name: "receipt status not completed",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        "error",
					ResponseID:    "resp-err",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   20,
				}
			},
			expHalt: "INVALID_RECEIPT_STATUS",
		},
		{
			name: "unpriced model",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-model",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         "nonexistent-model",
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   20,
				}
			},
			expHalt: "RECEIPT_MODEL_MISMATCH",
		},
		{
			name: "service tier mismatch",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-tier",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   "premium",
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   20,
				}
			},
			expHalt: "RECEIPT_SERVICE_TIER_MISMATCH",
		},
		{
			name: "input tokens negative",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-neg",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   -5,
					OutputTokens:  10,
					TotalTokens:   5,
				}
			},
			expHalt: "RECEIPT_TOKEN_BOUND_EXCEEDED",
		},
		{
			name: "input tokens exceeding window",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-window",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   MaxInputTokens + 1,
					OutputTokens:  10,
					TotalTokens:   MaxInputTokens + 11,
				}
			},
			expHalt: "RECEIPT_TOKEN_BOUND_EXCEEDED",
		},
		{
			name: "output tokens exceeding limit",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-out",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  MaxOutputTokens + 1,
					TotalTokens:   10 + MaxOutputTokens + 1,
				}
			},
			expHalt: "RECEIPT_TOKEN_BOUND_EXCEEDED",
		},
		{
			name: "inconsistent total tokens",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-incon",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   999,
				}
			},
			expHalt: "TOKEN_SUM_INCONSISTENT",
		},
		{
			name: "request id mismatch",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-req",
					RequestID:     "wrong-request-id",
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   20,
				}
			},
			expHalt: "REQUEST_ID_MISMATCH",
		},
		{
			name: "request digest mismatch",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp-dig",
					RequestID:     p.RequestID,
					RequestDigest: "sha256:wrong",
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   20,
				}
			},
			expHalt: "REQUEST_DIGEST_MISMATCH",
		},
		{
			name: "invalid response id format",
			receiptFn: func(p *ReservationPermit) *Receipt {
				return &Receipt{
					Status:        TerminalStatusCompleted,
					ResponseID:    "resp with space",
					RequestID:     p.RequestID,
					RequestDigest: p.RequestDigest,
					Model:         PinnedModel,
					ServiceTier:   PinnedServiceTier,
					InputTokens:   10,
					OutputTokens:  10,
					TotalTokens:   20,
				}
			},
			expHalt: "INVALID_RESPONSE_ID",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ledgerDir := filepath.Join(tempDir, "ledger")
			l, err := Initialize(ledgerDir, "test-evidence")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()

			permit, err := l.Reserve("req-tc", "sha256:tc", 50000)
			if err != nil {
				t.Fatal(err)
			}

			receipt := tc.receiptFn(permit)
			_, err = l.Settle(permit, receipt)
			if !errors.Is(err, ErrSettlementEvidence) {
				t.Fatalf("expected ErrSettlementEvidence, got %v", err)
			}

			st, err := l.GetStatus()
			if err != nil {
				t.Fatal(err)
			}
			if !st.Halted {
				t.Errorf("expected ledger to halt after evidence violation")
			}
			if st.HaltReason == nil || *st.HaltReason != tc.expHalt {
				t.Errorf("expected halt reason %s, got %v", tc.expHalt, st.HaltReason)
			}
		})
	}
}

func TestReplayedResponseIDRejectedAndHalts(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "replay_resp_ledger")

	l, err := Initialize(ledgerDir, "replay-resp-exp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// First settlement succeeds with response ID "resp-once"
	p1, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}
	r1 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-once",
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

	// Second settlement attempts to reuse response ID "resp-once"
	p2, err := l.Reserve("req-2", "sha256:2", 20000)
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-once", // Replayed!
		RequestID:     "req-2",
		RequestDigest: "sha256:2",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   10,
		OutputTokens:  10,
		TotalTokens:   20,
	}
	_, err = l.Settle(p2, r2)
	if !errors.Is(err, ErrSettlementEvidence) {
		t.Fatalf("expected ErrSettlementEvidence for replayed response_id, got %v", err)
	}

	st, _ := l.GetStatus()
	if !st.Halted || st.HaltReason == nil || *st.HaltReason != "REPLAYED_RESPONSE_ID" {
		t.Fatalf("expected halted with REPLAYED_RESPONSE_ID, got %+v", st)
	}
}

func TestCostExceedsReservationHalts(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "cost_exceeds_ledger")

	l, err := Initialize(ledgerDir, "cost-exceeds")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Sized reservation of 2000 uUSD
	p, err := l.Reserve("req-small", "sha256:small", 2000)
	if err != nil {
		t.Fatal(err)
	}

	// Cost: 2500 in * 1 + 100 out * 1 = 2600 uUSD > 2000 uUSD reserved!
	r := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-exceed",
		RequestID:     "req-small",
		RequestDigest: "sha256:small",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   2500,
		OutputTokens:  100,
		TotalTokens:   2600,
	}
	_, err = l.Settle(p, r)
	if !errors.Is(err, ErrSettlementEvidence) {
		t.Fatalf("expected ErrSettlementEvidence for COST_EXCEEDS_RESERVATION, got %v", err)
	}

	st, _ := l.GetStatus()
	if !st.Halted || st.HaltReason == nil || *st.HaltReason != "COST_EXCEEDS_RESERVATION" {
		t.Fatalf("expected halted with COST_EXCEEDS_RESERVATION, got %+v", st)
	}
	if st.RetainedFailedMicros != 2000 {
		t.Errorf("expected 2000 retained, got %d", st.RetainedFailedMicros)
	}
}

func TestRecordFailureRejectsArbitraryUnboundedText(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "bad_reason_ledger")

	l, err := Initialize(ledgerDir, "bad-reason")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	p, err := l.Reserve("req-1", "sha256:1", 10000)
	if err != nil {
		t.Fatal(err)
	}

	// Arbitrary/unlisted reason
	_, err = l.RecordFailure(p, "server caught fire with custom traceback \n and multi-line message")
	if !errors.Is(err, ErrSettlementEvidence) {
		t.Fatalf("expected ErrSettlementEvidence for unlisted reason, got %v", err)
	}

	st, _ := l.GetStatus()
	if !st.Halted || st.HaltReason == nil || *st.HaltReason != "INVALID_FAILURE_REASON_REJECTED" {
		t.Fatalf("expected halted with INVALID_FAILURE_REASON_REJECTED, got %+v", st)
	}

	// Provider error text must never be persisted in journal or state
	for _, entry := range l.poisonReason {
		_ = entry
	}
	state, _ := readStateFile(ledgerDir, "bad-reason")
	for _, j := range state.Journal {
		if strings.Contains(j.Reason, "traceback") || strings.Contains(j.Reason, "server caught fire") {
			t.Errorf("found echoed provider error in journal: %s", j.Reason)
		}
	}
}

func TestDoubleSettlementAndNoPendingReservation(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "double_settle_ledger")

	l, err := Initialize(ledgerDir, "double-settle")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	p, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}
	r := &Receipt{
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
	if _, err := l.Settle(p, r); err != nil {
		t.Fatal(err)
	}

	// Second settlement with same permit: no pending reservation exists
	_, err = l.Settle(p, r)
	if !errors.Is(err, ErrNoPendingReservation) {
		t.Fatalf("expected ErrNoPendingReservation on double settle, got %v", err)
	}
}

func TestHaltedStateCannotBeSettledAway(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "halted_settle_ledger")

	l, err := Initialize(ledgerDir, "halted-settle")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	p, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}

	// Record failure halts the ledger
	if _, err := l.RecordFailure(p, "REQUEST_TRANSPORT_FAILURE"); err != nil {
		t.Fatal(err)
	}

	// Cannot settle on halted ledger
	r := &Receipt{
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
	_, err = l.Settle(p, r)
	if !errors.Is(err, ErrLedgerHalted) {
		t.Fatalf("expected ErrLedgerHalted, got %v", err)
	}
}

func TestPermitMismatchRejectedAndHalts(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "permit_mismatch_ledger")

	l, err := Initialize(ledgerDir, "permit-mismatch")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	_, err = l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}

	fakePermit := &ReservationPermit{
		PermitID:             "permit_bogus",
		RequestID:            "req-1",
		RequestDigest:        "sha256:1",
		ReservedAmountMicros: 20000,
	}
	r := &Receipt{
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
	_, err = l.Settle(fakePermit, r)
	if !errors.Is(err, ErrPermitMismatch) {
		t.Fatalf("expected ErrPermitMismatch, got %v", err)
	}

	st, _ := l.GetStatus()
	if !st.Halted || st.HaltReason == nil || *st.HaltReason != "PERMIT_MISMATCH" {
		t.Fatalf("expected halted with PERMIT_MISMATCH, got %+v", st)
	}
}
