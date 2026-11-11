package budget

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerLifecycleAndSettlement(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_budget_ledger_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ledgerDir := filepath.Join(tempDir, "ledger")

	// 1. Initialize
	l, err := Initialize(ledgerDir, "test-exp-1")
	if err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer l.Close()

	st, err := l.GetStatus()
	if err != nil {
		t.Fatalf("getStatus failed: %v", err)
	}
	if st.ExperimentID != "test-exp-1" {
		t.Errorf("expID mismatch: %s", st.ExperimentID)
	}
	if st.GlobalCeilingMicros != GlobalCeilingMicros {
		t.Errorf("ceiling mismatch: %d", st.GlobalCeilingMicros)
	}
	if !st.CanReserve() {
		t.Errorf("expected canReserve to be true")
	}

	// 2. Initialize in existing dir fails
	if _, err := Initialize(ledgerDir, "test-exp-1"); !errors.Is(err, ErrLedgerAlreadyExists) {
		t.Fatalf("expected ErrLedgerAlreadyExists, got %v", err)
	}

	// 3. Reserve 1
	permit1, err := l.Reserve("req-1", "sha256:abc", 50000)
	if err != nil {
		t.Fatalf("reserve 1 failed: %v", err)
	}
	if permit1.RequestID != "req-1" || permit1.ReservedAmountMicros != 50000 {
		t.Errorf("permit 1 mismatch: %+v", permit1)
	}

	// In-flight reservation blocks concurrent reserve
	if _, err := l.Reserve("req-2", "sha256:def", 50000); !errors.Is(err, ErrInFlightReservation) {
		t.Fatalf("expected ErrInFlightReservation, got %v", err)
	}

	// 4. Settle 1
	receipt1 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-1",
		RequestID:     "req-1",
		RequestDigest: "sha256:abc",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   100,
		OutputTokens:  50,
		TotalTokens:   150,
	}
	res1, err := l.Settle(permit1, receipt1)
	if err != nil {
		t.Fatalf("settle 1 failed: %v", err)
	}
	// 100*1 + 50*1 = 150
	if res1.AccountedCostMicros != 150 {
		t.Errorf("expected cost 150, got %d", res1.AccountedCostMicros)
	}
	if res1.UnencumberedAmountMicros != 50000-150 {
		t.Errorf("expected unencumbered %d, got %d", 50000-150, res1.UnencumberedAmountMicros)
	}

	st, err = l.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedSpendMicros != 150 {
		t.Errorf("expected committed spend 150, got %d", st.CommittedSpendMicros)
	}
	if st.SettledRequestsCount != 1 {
		t.Errorf("expected settled count 1, got %d", st.SettledRequestsCount)
	}
	if !st.CanReserve() {
		t.Errorf("expected canReserve to be true after settle")
	}

	// 5. Reserve 2 and fail
	permit2, err := l.Reserve("req-2", "sha256:def", 20000)
	if err != nil {
		t.Fatalf("reserve 2 failed: %v", err)
	}

	failRes, err := l.RecordFailure(permit2, "REQUEST_TRANSPORT_FAILURE")
	if err != nil {
		t.Fatalf("recordFailure failed: %v", err)
	}
	if failRes.RetainedAmountMicros != 20000 {
		t.Errorf("expected retained 20000, got %d", failRes.RetainedAmountMicros)
	}

	st, err = l.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Halted {
		t.Errorf("expected ledger to be halted")
	}
	if st.HaltReason == nil || *st.HaltReason != "REQUEST_TRANSPORT_FAILURE" {
		t.Errorf("unexpected halt reason: %v", st.HaltReason)
	}
	if st.RetainedFailedMicros != 20000 {
		t.Errorf("expected retained failed 20000, got %d", st.RetainedFailedMicros)
	}
	if st.CanReserve() {
		t.Errorf("expected canReserve to be false when halted")
	}

	// Cannot reserve on halted ledger
	if _, err := l.Reserve("req-3", "sha256:ghi", 10000); !errors.Is(err, ErrLedgerHalted) {
		t.Fatalf("expected ErrLedgerHalted, got %v", err)
	}
}

func TestModelRatesAndSizedReservations(t *testing.T) {
	// gpt-6-luna: 1 in / 1 out
	cost, err := ModelCostMicros("gpt-6-luna", "default", 100, 20)
	if err != nil || cost != 120 {
		t.Errorf("expected 120, got %d (%v)", cost, err)
	}

	// claude-sonnet-5-5: 2 in / 10 out
	cost, err = ModelCostMicros("claude-sonnet-5-5", "standard", 310, 20)
	if err != nil || cost != 310*2+20*10 {
		t.Errorf("expected %d, got %d (%v)", 310*2+20*10, cost, err)
	}

	// gemini-3.6-flash: 2 in / 8 out
	cost, err = ModelCostMicros("gemini-3.6-flash", "default", 40, 38)
	if err != nil || cost != 40*2+38*8 {
		t.Errorf("expected %d, got %d (%v)", 40*2+38*8, cost, err)
	}

	// unpriced model
	_, err = ModelCostMicros("unknown-model", "default", 10, 10)
	if err == nil {
		t.Errorf("expected error for unknown model")
	}
}

func TestBudgetExceededAndPermitMismatch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_budget_exceeded_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ledgerDir := filepath.Join(tempDir, "ledger")
	l, err := Initialize(ledgerDir, "test-exp-exceeded")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Reservation above GlobalCeilingMicros (2,000,000)
	// Note: ReservationAmountMicros is 1,100,000. So one cannot reserve 2,000,001 (fails reservation bound check).
	// But if we reserve 1,100,000, settle it with 1,100,000 cost, then trying to reserve another 1,100,000
	// would make projected = 2,200,000 > 2,000,000!
	p1, err := l.Reserve("req-1", "sha256:1", 1100000)
	if err != nil {
		t.Fatalf("reserve 1 failed: %v", err)
	}
	// Settle 1,050,000 (1,049,000 in, 1,000 out)
	r1 := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-1",
		RequestID:     "req-1",
		RequestDigest: "sha256:1",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   1049000,
		OutputTokens:  1000,
		TotalTokens:   1050000,
	}
	_, err = l.Settle(p1, r1)
	if err != nil {
		t.Fatalf("settle 1 failed: %v", err)
	}

	st, err := l.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedSpendMicros != 1050000 {
		t.Fatalf("committed spend mismatch: %d", st.CommittedSpendMicros)
	}

	// Now try to reserve 1,000,000: 1,100,000 + 1,000,000 = 2,100,000 > 2,000,000 -> BudgetExceeded
	_, err = l.Reserve("req-2", "sha256:2", 1000000)
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}

	// Reserve 500,000 fits (1,100,000 + 500,000 = 1,600,000 <= 2,000,000)
	p2, err := l.Reserve("req-2", "sha256:2", 500000)
	if err != nil {
		t.Fatalf("reserve 2 failed: %v", err)
	}

	// Permit mismatch
	fakePermit := &ReservationPermit{
		PermitID:             "permit_wrong",
		RequestID:            "req-wrong",
		RequestDigest:        "sha256:wrong",
		ReservedAmountMicros: 500000,
		ReservedAtUTC:        nowUTCStr(),
	}
	_, err = l.Settle(fakePermit, r1)
	if !errors.Is(err, ErrPermitMismatch) {
		t.Fatalf("expected ErrPermitMismatch, got %v", err)
	}

	// After permit mismatch, ledger is halted
	st, _ = l.GetStatus()
	if !st.Halted || st.HaltReason == nil || *st.HaltReason != "PERMIT_MISMATCH" {
		t.Fatalf("expected halted with PERMIT_MISMATCH, got %+v", st)
	}
	_ = p2
}
