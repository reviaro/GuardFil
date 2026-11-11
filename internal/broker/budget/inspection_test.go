package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectionGuardArmedAndGenerationIncremented(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "guard_gen_ledger")

	l, err := Initialize(ledgerDir, "guard-gen")
	if err != nil {
		t.Fatal(err)
	}

	// At init, generation is 1
	guard, err := readWitnessRecord(ledgerDir, InspectionGuardFilename, RecordTypeInspectionGuard, "guard-gen")
	if err != nil || guard.Generation != 1 {
		t.Fatalf("expected generation 1 at init, got %v (%v)", guard, err)
	}

	// First runtime transaction (Reserve) arms guard and increments to 2
	p, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}

	guard2, _ := readWitnessRecord(ledgerDir, InspectionGuardFilename, RecordTypeInspectionGuard, "guard-gen")
	if guard2.Generation != 2 {
		t.Errorf("expected generation 2 after reserve, got %d", guard2.Generation)
	}

	// Settle arms guard and increments to 3
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

	guard3, _ := readWitnessRecord(ledgerDir, InspectionGuardFilename, RecordTypeInspectionGuard, "guard-gen")
	if guard3.Generation != 3 {
		t.Errorf("expected generation 3 after settle, got %d", guard3.Generation)
	}
	l.Close()
}

func TestStaleOrMissingCompletionWitnessRefusesContinuation(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "stale_comp_ledger")

	l, err := Initialize(ledgerDir, "stale-comp")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Remove completion witness to simulate crash between armGuard and completeGuard
	compPath := filepath.Join(ledgerDir, InspectionCompletionFilename)
	if err := os.Remove(compPath); err != nil {
		t.Fatal(err)
	}

	// Reopen must be disabled with UNFINISHED_INSPECTION_GUARD
	l2, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer l2.Close()

	st, err := l2.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !st.HandleDisabled {
		t.Errorf("expected handle to be disabled when completion witness missing")
	}
	if st.HandleDisabledReason == nil || *st.HandleDisabledReason != "UNFINISHED_INSPECTION_GUARD" {
		t.Errorf("expected UNFINISHED_INSPECTION_GUARD, got %v", st.HandleDisabledReason)
	}

	// Cannot reserve on disabled handle
	_, err = l2.Reserve("req-x", "sha256:x", 10000)
	if err == nil {
		t.Errorf("expected reserve to be refused on disabled handle")
	}
}

func TestInspectionGenerationExhaustionRefused(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "exhaust_ledger")

	l, err := Initialize(ledgerDir, "exhaust-gen")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Set generation to MaxInspectionGeneration
	guardPath := filepath.Join(ledgerDir, InspectionGuardFilename)
	compPath := filepath.Join(ledgerDir, InspectionCompletionFilename)

	guardRec := WitnessRecord{
		RecordType:   RecordTypeInspectionGuard,
		ExperimentID: "exhaust-gen",
		Generation:   MaxInspectionGeneration,
		ArmedAtUTC:   nowUTCStr(),
	}
	compRec := WitnessRecord{
		RecordType:     RecordTypeInspectionComp,
		ExperimentID:   "exhaust-gen",
		Generation:     MaxInspectionGeneration,
		CompletedAtUTC: nowUTCStr(),
	}
	ge, _ := json.MarshalIndent(guardRec, "", "  ")
	ce, _ := json.MarshalIndent(compRec, "", "  ")
	_ = os.WriteFile(guardPath, ge, 0600)
	_ = os.WriteFile(compPath, ce, 0600)

	// Attempting to reserve on existing handle must reject exhausted generation
	_, err = l.Reserve("req-over", "sha256:over", 10000)
	if !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity on reserve, got %v", err)
	}

	// Fresh open on unhalted ledger also fails closed with ErrLedgerSecurity
	_, err = Open(ledgerDir)
	if !errors.Is(err, ErrLedgerSecurity) {
		t.Fatalf("expected ErrLedgerSecurity on Open, got %v", err)
	}

	// But if ledger was already halted, Open succeeds in report-only mode
	haltedDir := filepath.Join(tempDir, "exhaust_halted")
	lh, err := Initialize(haltedDir, "exhaust-halted")
	if err != nil {
		t.Fatal(err)
	}
	pHalt, err := lh.Reserve("req-halt", "sha256:halt", 10000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lh.RecordFailure(pHalt, "REQUEST_TRANSPORT_FAILURE"); err != nil {
		t.Fatal(err)
	}
	lh.Close()

	guardPathHalt := filepath.Join(haltedDir, InspectionGuardFilename)
	compPathHalt := filepath.Join(haltedDir, InspectionCompletionFilename)
	guardRecHalt := WitnessRecord{
		RecordType:   RecordTypeInspectionGuard,
		ExperimentID: "exhaust-halted",
		Generation:   MaxInspectionGeneration,
		ArmedAtUTC:   nowUTCStr(),
	}
	compRecHalt := WitnessRecord{
		RecordType:     RecordTypeInspectionComp,
		ExperimentID:   "exhaust-halted",
		Generation:     MaxInspectionGeneration,
		CompletedAtUTC: nowUTCStr(),
	}
	geH, _ := json.MarshalIndent(guardRecHalt, "", "  ")
	ceH, _ := json.MarshalIndent(compRecHalt, "", "  ")
	_ = os.WriteFile(guardPathHalt, geH, 0600)
	_ = os.WriteFile(compPathHalt, ceH, 0600)

	l2, err := Open(haltedDir)
	if err != nil {
		t.Fatalf("expected open to succeed in report mode for halted ledger: %v", err)
	}
	defer l2.Close()

	st, _ := l2.GetStatus()
	if !st.HandleDisabled {
		t.Errorf("expected handle disabled for exhausted generation")
	}
}

func TestUnresolvedSettlementRecoveredByFreshHandle(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "unresolved_intent_ledger")

	l, err := Initialize(ledgerDir, "unresolved-intent")
	if err != nil {
		t.Fatal(err)
	}

	p, err := l.Reserve("req-1", "sha256:1", 20000)
	if err != nil {
		t.Fatal(err)
	}

	// Write intent file manually without settling state (simulates crash after intent write)
	intentRec := WitnessRecord{
		RecordType:               "SETTLEMENT_INTENT",
		ExperimentID:             "unresolved-intent",
		ReservationID:            p.PermitID,
		RequestID:                p.RequestID,
		RequestDigest:            p.RequestDigest,
		ResponseID:               "resp-unresolved",
		Model:                    PinnedModel,
		ServiceTier:              PinnedServiceTier,
		InputTokens:              10,
		OutputTokens:             10,
		TotalTokens:              20,
		SettledAmountMicros:      20,
		UnencumberedAmountMicros: 20000 - 20,
		TimestampUTC:             nowUTCStr(),
	}
	ie, _ := json.MarshalIndent(intentRec, "", "  ")
	intentPath := filepath.Join(ledgerDir, fmt.Sprintf("%s%s.json", IntentFilePrefix, p.PermitID))
	if err := os.WriteFile(intentPath, ie, 0600); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Fresh handle opens: must detect unresolved settlement intent and halt with UNRESOLVED_SETTLEMENT_PUBLICATION
	l2, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer l2.Close()

	st, err := l2.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Halted {
		t.Errorf("expected ledger to be halted by unresolved settlement")
	}
	if st.HaltReason == nil || *st.HaltReason != "UNRESOLVED_SETTLEMENT_PUBLICATION" {
		t.Errorf("expected UNRESOLVED_SETTLEMENT_PUBLICATION, got %v", st.HaltReason)
	}
}

func TestMissingGuardOnTerminalStatePreservesAccounting(t *testing.T) {
	tempDir := t.TempDir()
	ledgerDir := filepath.Join(tempDir, "term_missing_guard_ledger")

	l, err := Initialize(ledgerDir, "term-guard")
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

	// Remove guard file
	guardPath := filepath.Join(ledgerDir, InspectionGuardFilename)
	_ = os.Remove(guardPath)

	// Opening terminal state with missing guard yields disabled reporting handle preserving accounting
	l2, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer l2.Close()

	st, err := l2.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !st.HandleDisabled {
		t.Errorf("expected handle to be disabled")
	}
	if st.RetainedFailedMicros != 20000 {
		t.Errorf("expected 20000 retained spend preserved, got %d", st.RetainedFailedMicros)
	}
}
