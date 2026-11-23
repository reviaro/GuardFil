package budget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func setupLegacyV1Ledger(t *testing.T, stateRoot string, provider string) (string, string, *BudgetLedger) {
	t.Helper()
	spec := ProviderLedgerSpecs[provider]
	legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
	if err := os.MkdirAll(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	ledgerDir := filepath.Join(legacyRoot, "ledger")
	l, err := Initialize(ledgerDir, spec.LegacyID)
	if err != nil {
		t.Fatalf("init legacy %s: %v", provider, err)
	}
	return legacyRoot, ledgerDir, l
}

func settleOne(t *testing.T, l *BudgetLedger, reqID, respID string) {
	t.Helper()
	digest := "sha256:" + reqID + "0000"
	p, err := l.Reserve(reqID, digest, MinReservationMicros)
	if err != nil {
		t.Fatalf("reserve %s: %v", reqID, err)
	}
	r := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    respID,
		RequestID:     reqID,
		RequestDigest: digest,
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   20,
		OutputTokens:  10,
		TotalTokens:   30,
	}
	if _, err := l.Settle(p, r); err != nil {
		t.Fatalf("settle %s: %v", reqID, err)
	}
}

func TestSchemaV2CleanInitAndOpenProviderLedger(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateRoot, 0775); err != nil {
		t.Fatal(err)
	}
	// Real hosts often have 0775 on ~/.local/state/guardfil while provider dirs are 0700.
	if err := os.Chmod(stateRoot, 0775); err != nil {
		t.Fatal(err)
	}

	l, err := OpenProviderLedger(stateRoot, "anthropic", true)
	if err != nil {
		t.Fatalf("OpenProviderLedger fresh: %v", err)
	}
	settleOne(t, l, "req-v2-1", "resp-v2-1")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	targetLedgerDir := filepath.Join(stateRoot, "anthropic", "ledger")
	stOnDisk, err := readStateFile(targetLedgerDir, "guardfil-anthropic-v1")
	if err != nil {
		t.Fatalf("readStateFile v2: %v", err)
	}
	if stOnDisk.SchemaVersion != SchemaVersionV2 || stOnDisk.LegacyExperimentID != "" {
		t.Fatalf("unexpected v2 state metadata: schema=%d legacy=%q", stOnDisk.SchemaVersion, stOnDisk.LegacyExperimentID)
	}

	l2, err := OpenProviderLedger(stateRoot, "anthropic", false)
	if err != nil {
		t.Fatalf("reopen v2: %v", err)
	}
	defer l2.Close()
	st, err := l2.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.ExperimentID != "guardfil-anthropic-v1" || st.CommittedSpendMicros != 30 || st.SettledRequestsCount != 1 {
		t.Fatalf("unexpected v2 status: %+v", st)
	}
}

func TestMigratePopulatedPythonV1AndContinuePostMigrationSpend(t *testing.T) {
	repoRoot := findRepoRoot()
	stateRoot := t.TempDir()
	spec := ProviderLedgerSpecs["openai"]
	legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
	if err := os.MkdirAll(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	legacyLedgerDir := filepath.Join(legacyRoot, "ledger")

	// Create legacy v1 ledger with frozen pyref Python implementation.
	pyScript := `
import sys
from pathlib import Path
from research.t2a.openai_budget.ledger import BudgetLedger
from research.t2a.openai_budget.models import Receipt

l = BudgetLedger.initialize(Path(sys.argv[1]), experiment_id=sys.argv[2])
p = l.reserve("py-legacy-1", "sha256:pylegacy1", 50000)
l.settle(p, Receipt(
    status="completed",
    response_id="resp-py-legacy-1",
    request_id="py-legacy-1",
    request_digest="sha256:pylegacy1",
    model="gpt-6-luna",
    service_tier="default",
    input_tokens=100,
    output_tokens=25,
    total_tokens=125,
))
l.close()
`
	cmd := exec.Command("python3", "-B", "-c", pyScript, legacyLedgerDir, spec.LegacyID)
	cmd.Dir = filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pyref init failed: %v\n%s", err, string(out))
	}

	evPath := filepath.Join(legacyRoot, "live-broker-sample.jsonl")
	if err := os.WriteFile(evPath, []byte(`{"outcome_code":"SUCCESS"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	res, err := MigrateProviderLedger(stateRoot, "openai", false)
	if err != nil {
		t.Fatalf("MigrateProviderLedger failed: %v", err)
	}
	if res.Status != "migrated" || res.CommittedSpendMicros != 125 || res.SettledRequestsCount != 1 {
		t.Fatalf("unexpected migration result: %+v", res)
	}

	// Copied evidence log must exist in target.
	if _, err := os.Stat(filepath.Join(stateRoot, spec.TargetDir, "live-broker-sample.jsonl")); err != nil {
		t.Fatalf("expected copied evidence file: %v", err)
	}

	// CRITICAL P1-1 check: legacyRoot/ledger/ stays in place without ledger.json,
	// so both Open() AND OpenOrInitLedger(..., true, ...) fail closed instead of
	// creating a fresh $2.00 ledger for older binaries.
	if _, err := os.Stat(legacyLedgerDir); err != nil {
		t.Fatalf("legacy ledger dir must remain in place: %v", err)
	}
	if _, err := Open(legacyLedgerDir); !errors.Is(err, ErrLedgerNotFound) {
		t.Fatalf("expected ErrLedgerNotFound on Open(legacyLedgerDir), got %v", err)
	}
	if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
		t.Fatalf("expected ErrLedgerNotFound on OpenOrInitLedger(legacyRoot, true), got %v", err)
	}

	// Open via provider helper under new ID and replay pre-migration response_id.
	l, err := OpenProviderLedger(stateRoot, "openai", true)
	if err != nil {
		t.Fatalf("OpenProviderLedger after migration: %v", err)
	}
	pReplay, err := l.Reserve("post-mig-req-1", "sha256:post1", MinReservationMicros)
	if err != nil {
		t.Fatalf("post-migration reserve: %v", err)
	}
	_, err = l.Settle(pReplay, &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "resp-py-legacy-1",
		RequestID:     "post-mig-req-1",
		RequestDigest: "sha256:post1",
		Model:         PinnedModel,
		ServiceTier:   PinnedServiceTier,
		InputTokens:   5,
		OutputTokens:  5,
		TotalTokens:   10,
	})
	if err == nil {
		t.Fatalf("expected REPLAYED_RESPONSE_ID failure on pre-migration response_id")
	}
	l.Close()

	// Also verify continuous reserve+settle+reopen across pre/post migration boundary (anthropic).
	_, legAntDir, lAnt := setupLegacyV1Ledger(t, stateRoot, "anthropic")
	settleOne(t, lAnt, "ant-pre-1", "ant-resp-pre-1")
	_ = lAnt.Close()

	resAnt, err := MigrateProviderLedger(stateRoot, "anthropic", false)
	if err != nil || resAnt.Status != "migrated" {
		t.Fatalf("migrate anthropic: res=%+v err=%v", resAnt, err)
	}
	_ = legAntDir

	// Re-running migration reports already_migrated.
	again, err := MigrateProviderLedger(stateRoot, "anthropic", false)
	if err != nil || again.Status != "already_migrated" {
		t.Fatalf("expected already_migrated on rerun, got res=%+v err=%v", again, err)
	}

	lAntNew, err := OpenProviderLedger(stateRoot, "anthropic", true)
	if err != nil {
		t.Fatalf("open anthropic migrated: %v", err)
	}
	settleOne(t, lAntNew, "ant-post-2", "ant-resp-post-2")
	_ = lAntNew.Close()

	// Reopen exercises validateAndRecoverRecordsUnderLock across BOTH pre-MIGRATED
	// (legacy ID witnesses) and post-MIGRATED (target ID witnesses) reservations.
	lAntReopen, err := OpenProviderLedger(stateRoot, "anthropic", false)
	if err != nil {
		t.Fatalf("reopen anthropic after post-migration settle: %v", err)
	}
	defer lAntReopen.Close()
	stAnt, err := lAntReopen.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if stAnt.Halted || stAnt.CommittedSpendMicros != 60 || stAnt.SettledRequestsCount != 2 {
		t.Fatalf("unexpected anthropic state after pre+post settlements: %+v", stAnt)
	}
}

func TestMigrateHaltedLedgersPreservesHaltAndDisablesReserve(t *testing.T) {
	t.Run("halted_via_record_failure", func(t *testing.T) {
		stateRoot := t.TempDir()
		legacyRoot, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "req-ok-1", "resp-ok-1")
		p, err := l.Reserve("req-fail-2", "sha256:fail2", MinReservationMicros)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.RecordFailure(p, "INVALID_RECEIPT_EVIDENCE"); err != nil {
			t.Fatal(err)
		}
		_ = l.Close()

		res, err := MigrateProviderLedger(stateRoot, "openai", false)
		if err != nil {
			t.Fatalf("migrate halted openai: %v", err)
		}
		if !res.Halted || res.HaltReason != "INVALID_RECEIPT_EVIDENCE" || res.CommittedSpendMicros != 30 || res.RetainedFailedMicros != MinReservationMicros {
			t.Fatalf("unexpected halted migration result: %+v", res)
		}

		lm, err := OpenProviderLedger(stateRoot, "openai", true)
		if err != nil {
			t.Fatalf("open migrated halted openai: %v", err)
		}
		defer lm.Close()
		st, err := lm.GetStatus()
		if err != nil || !st.Halted || st.HaltReason == nil || *st.HaltReason != "INVALID_RECEIPT_EVIDENCE" || st.CanReserve() {
			t.Fatalf("unexpected migrated halted status: %+v err=%v", st, err)
		}
		if _, err := lm.Reserve("req-after-halt", "sha256:ah", MinReservationMicros); !errors.Is(err, ErrLedgerHalted) {
			t.Fatalf("expected ErrLedgerHalted, got %v", err)
		}
		if _, err := OpenOrInitLedger(legacyRoot, true, ProviderLedgerSpecs["openai"].LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound on legacy open, got %v", err)
		}
	})

	t.Run("halted_via_terminal_uncertainty", func(t *testing.T) {
		stateRoot := t.TempDir()
		legacyRoot, legDir, l := setupLegacyV1Ledger(t, stateRoot, "gemini")
		settleOne(t, l, "gem-1", "gem-resp-1")
		_ = l.Close()

		// Delete both intent & confirmation files so Open() triggers TERMINAL_UNCERTAINTY
		// (which leaves inspection_completion.json absent on disk).
		for _, pat := range []string{IntentFilePrefix + "*.json", ConfirmationFilePrefix + "*.json"} {
			matches, _ := filepath.Glob(filepath.Join(legDir, pat))
			if len(matches) != 1 {
				t.Fatalf("expected 1 match for %s, got %v", pat, matches)
			}
			if err := os.Remove(matches[0]); err != nil {
				t.Fatal(err)
			}
		}
		lh, err := Open(legDir)
		if err != nil {
			t.Fatalf("Open triggering TERMINAL_UNCERTAINTY: %v", err)
		}
		_ = lh.Close()

		res, err := MigrateProviderLedger(stateRoot, "gemini", false)
		if err != nil {
			t.Fatalf("migrate TERMINAL_UNCERTAINTY ledger: %v", err)
		}
		if !res.Halted || res.HaltReason != "TERMINAL_UNCERTAINTY" {
			t.Fatalf("unexpected TERMINAL_UNCERTAINTY migration result: %+v", res)
		}
		lm, err := OpenProviderLedger(stateRoot, "gemini", true)
		if err != nil {
			t.Fatalf("open migrated TERMINAL_UNCERTAINTY ledger: %v", err)
		}
		defer lm.Close()
		st, err := lm.GetStatus()
		if err != nil || !st.Halted || st.HaltReason == nil || *st.HaltReason != "TERMINAL_UNCERTAINTY" || st.CanReserve() {
			t.Fatalf("unexpected migrated TERMINAL_UNCERTAINTY status: %+v err=%v", st, err)
		}
		if _, err := OpenOrInitLedger(legacyRoot, true, ProviderLedgerSpecs["gemini"].LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound on legacy, got %v", err)
		}
	})
}

func TestMigrateMaxCapacity256LedgerAndV1Bound(t *testing.T) {
	stateRoot := t.TempDir()
	_, legDir, l := setupLegacyV1Ledger(t, stateRoot, "anthropic")

	// Fill 255 settled + 1 failed_retained = 1 INITIALIZED + 256*2 + 1? Wait:
	// 255*(RESERVED+SETTLED) + 1*(RESERVED+FAILED_RETAINED) + INITIALIZED = 513;
	// OR 256 settled (513) + TERMINAL_UNCERTAINTY (514) -> MIGRATED makes 515!
	for i := 1; i <= MaxForwardedRequests; i++ {
		reqID := fmt.Sprintf("max-req-%03d", i)
		digest := fmt.Sprintf("sha256:%04d", i)
		p, err := l.Reserve(reqID, digest, MinReservationMicros)
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		if _, err := l.Settle(p, &Receipt{
			Status:        TerminalStatusCompleted,
			ResponseID:    fmt.Sprintf("max-resp-%03d", i),
			RequestID:     reqID,
			RequestDigest: digest,
			Model:         PinnedModel,
			ServiceTier:   PinnedServiceTier,
			InputTokens:   1,
			OutputTokens:  0,
			TotalTokens:   1,
		}); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	_ = l.Close()

	// Remove one confirmation file so Open adds TERMINAL_UNCERTAINTY -> 514 entries in v1.
	confs, _ := filepath.Glob(filepath.Join(legDir, ConfirmationFilePrefix+"*.json"))
	if err := os.Remove(confs[0]); err != nil {
		t.Fatal(err)
	}
	lh, err := Open(legDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = lh.Close()

	stV1, err := readStateFile(legDir, ProviderLedgerSpecs["anthropic"].LegacyID)
	if err != nil {
		t.Fatalf("read v1 514-entry state: %v", err)
	}
	if len(stV1.Journal) != MaxJournalEntries {
		t.Fatalf("expected %d v1 journal entries, got %d", MaxJournalEntries, len(stV1.Journal))
	}

	// Verify v1 still strictly rejects 515 journal entries.
	rawV1Bytes, _ := json.Marshal(stV1)
	var v1Map map[string]any
	_ = json.Unmarshal(rawV1Bytes, &v1Map)
	jArr := v1Map["journal"].([]any)
	v1Map["journal"] = append(jArr, jArr[len(jArr)-1])
	if _, err := ValidateAndReconcileStateStatic(v1Map, ""); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("expected ErrLedgerCorrupt for 515-entry v1 journal, got %v", err)
	}

	// Migrating the 514-entry v1 ledger produces a valid 515-entry v2 ledger!
	res, err := MigrateProviderLedger(stateRoot, "anthropic", false)
	if err != nil || res.Status != "migrated" {
		t.Fatalf("migrate 514-entry v1 ledger: res=%+v err=%v", res, err)
	}
	stV2, err := readStateFile(filepath.Join(stateRoot, "anthropic", "ledger"), ProviderLedgerSpecs["anthropic"].TargetID)
	if err != nil {
		t.Fatalf("validate 515-entry v2 migrated ledger: %v", err)
	}
	if len(stV2.Journal) != MaxMigratedJournalEntries {
		t.Fatalf("expected %d v2 journal entries, got %d", MaxMigratedJournalEntries, len(stV2.Journal))
	}
}

func TestMigrationRefusals(t *testing.T) {
	t.Run("pending_reservation_refused", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		if _, err := l.Reserve("pending-1", "sha256:pend1", MinReservationMicros); err != nil {
			t.Fatal(err)
		}
		_ = l.Close() // releases lease while leaving pending_reservation in ledger.json
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); !errors.Is(err, ErrInFlightReservation) {
			t.Fatalf("expected ErrInFlightReservation for pending reservation, got %v", err)
		}
	})

	t.Run("active_lease_refused", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		defer l.Close()
		if _, err := l.Reserve("inflight-1", "sha256:in1", MinReservationMicros); err != nil {
			t.Fatal(err)
		}
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); !errors.Is(err, ErrInFlightReservation) {
			t.Fatalf("expected ErrInFlightReservation for active lease, got %v", err)
		}
	})

	t.Run("unfinished_inspection_guard_refused", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, legDir, l := setupLegacyV1Ledger(t, stateRoot, "anthropic")
		_ = l.Close()
		if err := os.Remove(filepath.Join(legDir, InspectionCompletionFilename)); err != nil {
			t.Fatal(err)
		}
		if _, err := MigrateProviderLedger(stateRoot, "anthropic", false); !errors.Is(err, ErrGuardUnfinished) {
			t.Fatalf("expected ErrGuardUnfinished, got %v", err)
		}
	})

	t.Run("symlink_legacy_dir_refused", func(t *testing.T) {
		stateRoot := t.TempDir()
		realDir := filepath.Join(t.TempDir(), "real-leg")
		if err := os.MkdirAll(realDir, 0700); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(stateRoot, ProviderLedgerSpecs["gemini"].LegacyDir)
		if err := os.Symlink(realDir, linkPath); err != nil {
			t.Fatal(err)
		}
		if _, err := MigrateProviderLedger(stateRoot, "gemini", false); !errors.Is(err, ErrLedgerSecurity) {
			t.Fatalf("expected ErrLedgerSecurity on symlink legacy dir, got %v", err)
		}
	})

	t.Run("dry_run_makes_no_writes", func(t *testing.T) {
		stateRoot := t.TempDir()
		legRoot, _, l := setupLegacyV1Ledger(t, stateRoot, "gemini")
		settleOne(t, l, "dry-1", "dry-resp-1")
		_ = l.Close()

		res, err := MigrateProviderLedger(stateRoot, "gemini", true)
		if err != nil {
			t.Fatalf("dry-run failed: %v", err)
		}
		if res.Status != "would_migrate" || res.CommittedSpendMicros != 30 {
			t.Fatalf("unexpected dry-run result: %+v", res)
		}
		if _, err := os.Stat(filepath.Join(stateRoot, "gemini")); !os.IsNotExist(err) {
			t.Fatalf("dry-run created target directory")
		}
		if _, err := os.Stat(filepath.Join(legRoot, TombstoneFilename)); !os.IsNotExist(err) {
			t.Fatalf("dry-run wrote tombstone")
		}
	})
}

func TestMigratedLedgerTamperRejection(t *testing.T) {
	t.Run("swapped_witness_experiment_id_fails_closed", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "anthropic")
		settleOne(t, l, "tamper-pre-1", "resp-tp-1")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "anthropic", false); err != nil {
			t.Fatal(err)
		}

		// Open target, settle a post-migration request, then tamper witnesses.
		lm, err := OpenProviderLedger(stateRoot, "anthropic", false)
		if err != nil {
			t.Fatal(err)
		}
		settleOne(t, lm, "tamper-post-2", "resp-tp-2")
		_ = lm.Close()

		targetLedgerDir := filepath.Join(stateRoot, "anthropic", "ledger")
		st, err := readStateFile(targetLedgerDir, "guardfil-anthropic-v1")
		if err != nil {
			t.Fatal(err)
		}
		var preConfName, postConfName string
		for _, e := range st.Journal {
			if e.EntryType == "SETTLED" && e.RequestID == "tamper-pre-1" {
				preConfName = ConfirmationFilePrefix + e.ReservationID + ".json"
			}
			if e.EntryType == "SETTLED" && e.RequestID == "tamper-post-2" {
				postConfName = ConfirmationFilePrefix + e.ReservationID + ".json"
			}
		}

		// Clone stateRoot twice cleanly to test each direction independently.
		rewriteWitnessExp := func(dir, file, newExp string) {
			p := filepath.Join(dir, file)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			m["experiment_id"] = newExp
			enc, _ := json.MarshalIndent(m, "", "  ")
			if err := os.WriteFile(p, enc, 0600); err != nil {
				t.Fatal(err)
			}
		}

		// 1. Pre-migration witness swapped to target ID -> Open halts with TERMINAL_UNCERTAINTY.
		dirA := filepath.Join(t.TempDir(), "ledgerA")
		copyTestDir(t, targetLedgerDir, dirA)
		rewriteWitnessExp(dirA, preConfName, "guardfil-anthropic-v1")
		la, err := Open(dirA)
		if err != nil {
			t.Fatalf("unexpected Open err: %v", err)
		}
		sta, _ := la.GetStatus()
		_ = la.Close()
		if !sta.Halted || sta.HaltReason == nil || *sta.HaltReason != "TERMINAL_UNCERTAINTY" {
			t.Fatalf("expected TERMINAL_UNCERTAINTY when pre-migration witness carries target ID, got %+v", sta)
		}

		// 2. Post-migration witness forged with legacy ID -> Open halts with TERMINAL_UNCERTAINTY.
		dirB := filepath.Join(t.TempDir(), "ledgerB")
		copyTestDir(t, targetLedgerDir, dirB)
		rewriteWitnessExp(dirB, postConfName, "guardfil-m4-anthropic")
		lb, err := Open(dirB)
		if err != nil {
			t.Fatalf("unexpected Open err: %v", err)
		}
		stb, _ := lb.GetStatus()
		_ = lb.Close()
		if !stb.Halted || stb.HaltReason == nil || *stb.HaltReason != "TERMINAL_UNCERTAINTY" {
			t.Fatalf("expected TERMINAL_UNCERTAINTY when post-migration witness carries legacy ID, got %+v", stb)
		}
	})

	t.Run("inspection_generation_reset_rejected", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
			t.Fatal(err)
		}
		targetLedgerDir := filepath.Join(stateRoot, "openai", "ledger")
		for _, fn := range []string{InspectionGuardFilename, InspectionCompletionFilename} {
			p := filepath.Join(targetLedgerDir, fn)
			raw, _ := os.ReadFile(p)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			m["generation"] = 1 // lower than MIGRATED inspection_generation (2)
			enc, _ := json.MarshalIndent(m, "", "  ")
			if err := os.WriteFile(p, enc, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := Open(targetLedgerDir); !errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrLedgerCorrupt when inspection generation is reset, got %v", err)
		}
	})

	t.Run("invalid_schema_combinations_rejected", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
			t.Fatal(err)
		}
		targetStateBytes, _ := os.ReadFile(filepath.Join(stateRoot, "openai", "ledger", StateFilename))

		var base map[string]any
		_ = json.Unmarshal(targetStateBytes, &base)

		// 1. legacy_experiment_id rejected under schema_version 1.
		bad1Bytes, _ := json.Marshal(base)
		var m1 map[string]any
		_ = json.Unmarshal(bad1Bytes, &m1)
		m1["schema_version"] = 1
		if _, err := ValidateAndReconcileStateStatic(m1, ""); !errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrLedgerCorrupt for v1 + legacy_experiment_id, got %v", err)
		}

		// 2. Duplicate MIGRATED entry rejected.
		bad2Bytes, _ := json.Marshal(base)
		var m2 map[string]any
		_ = json.Unmarshal(bad2Bytes, &m2)
		j2 := m2["journal"].([]any)
		m2["journal"] = append(j2, j2[len(j2)-1])
		if _, err := ValidateAndReconcileStateStatic(m2, ""); !errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrLedgerCorrupt for duplicate MIGRATED entry, got %v", err)
		}

		// 3. legacy_experiment_id without MIGRATED rejected.
		bad3Bytes, _ := json.Marshal(base)
		var m3 map[string]any
		_ = json.Unmarshal(bad3Bytes, &m3)
		j3 := m3["journal"].([]any)
		m3["journal"] = j3[:len(j3)-1]
		if _, err := ValidateAndReconcileStateStatic(m3, ""); !errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrLedgerCorrupt for legacy_experiment_id without MIGRATED, got %v", err)
		}
	})
}

func TestDualDirectoryAndCrashRecovery(t *testing.T) {
	t.Run("unmigrated_legacy_refuses_open_and_never_inits_target", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		_ = l.Close()

		if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(stateRoot, "openai")); !os.IsNotExist(err) {
			t.Fatalf("OpenProviderLedger created target dir despite unmigrated legacy!")
		}
	})

	t.Run("tombstoned_legacy_missing_target_refuses_init", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(stateRoot, "openai")); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrLedgerCorrupt when target missing under tombstone, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(stateRoot, "openai")); !os.IsNotExist(err) {
			t.Fatalf("OpenProviderLedger re-initialized missing target under tombstone!")
		}
	})

	t.Run("crash_after_target_rename_recovers_safely", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, legDir, l := setupLegacyV1Ledger(t, stateRoot, "anthropic")
		settleOne(t, l, "crash-a-1", "resp-ca-1")
		_ = l.Close()

		if _, err := migrateProviderLedgerWithHook(stateRoot, "anthropic", false, faultAfterTargetRename); err == nil {
			t.Fatalf("expected injected fault after target rename")
		}
		// Brokers must fail closed on dual state.
		if _, err := OpenProviderLedger(stateRoot, "anthropic", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired in interrupted state, got %v", err)
		}
		// Dry-run sees interrupted recovery.
		dryRes, err := MigrateProviderLedger(stateRoot, "anthropic", true)
		if err != nil || dryRes.Status != "would_finalize_interrupted_migration" {
			t.Fatalf("expected would_finalize_interrupted_migration, got res=%+v err=%v", dryRes, err)
		}
		// Live rerun recovers cleanly.
		recRes, err := MigrateProviderLedger(stateRoot, "anthropic", false)
		if err != nil || recRes.Status != "migrated_recovered" {
			t.Fatalf("expected migrated_recovered, got res=%+v err=%v", recRes, err)
		}
		lm, err := OpenProviderLedger(stateRoot, "anthropic", true)
		if err != nil {
			t.Fatalf("OpenProviderLedger after recovery: %v", err)
		}
		_ = lm.Close()
		if _, err := OpenOrInitLedger(filepath.Dir(legDir), true, ProviderLedgerSpecs["anthropic"].LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound on legacy after recovery, got %v", err)
		}
	})

	t.Run("crash_after_tombstone_write_recovers_safely", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "gemini")
		settleOne(t, l, "crash-b-1", "resp-cb-1")
		_ = l.Close()

		if _, err := migrateProviderLedgerWithHook(stateRoot, "gemini", false, faultAfterTombstoneWrite); err == nil {
			t.Fatalf("expected injected fault after tombstone write")
		}
		// While legacy/ledger/ledger.json still exists, brokers MUST still fail closed.
		if _, err := OpenProviderLedger(stateRoot, "gemini", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired while legacy ledger.json still exists, got %v", err)
		}
		recRes, err := MigrateProviderLedger(stateRoot, "gemini", false)
		if err != nil || recRes.Status != "migrated_recovered" {
			t.Fatalf("expected migrated_recovered, got res=%+v err=%v", recRes, err)
		}
		lm, err := OpenProviderLedger(stateRoot, "gemini", true)
		if err != nil {
			t.Fatal(err)
		}
		_ = lm.Close()
	})

	t.Run("diverged_legacy_after_crash_fails_closed", func(t *testing.T) {
		stateRoot := t.TempDir()
		legRoot, legDir, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "div-1", "resp-div-1")
		_ = l.Close()

		if _, err := migrateProviderLedgerWithHook(stateRoot, "openai", false, faultAfterTargetRename); err == nil {
			t.Fatalf("expected injected fault")
		}
		// Simulate an old binary spending from legacy in the interrupted window.
		lo, err := Open(legDir)
		if err != nil {
			t.Fatal(err)
		}
		settleOne(t, lo, "div-old-binary-2", "resp-div-2")
		_ = lo.Close()

		if _, err := MigrateProviderLedger(stateRoot, "openai", false); !errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrLedgerCorrupt when legacy diverged after Step A, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(legRoot, TombstoneFilename)); !os.IsNotExist(err) {
			t.Fatalf("tombstone must not be written when legacy diverged")
		}
	})
}

func snapshotTreeBytes(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			out["dir:"+rel] = nil
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out["file:"+rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProvenanceAndLegacyScaffoldHardening(t *testing.T) {
	t.Run("tombstone_rejects_unrelated_clean_target", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "prov-1", "resp-prov-1")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
			t.Fatal(err)
		}

		targetDir := filepath.Join(stateRoot, "openai", "ledger")
		if err := os.Rename(targetDir, filepath.Join(stateRoot, "preserved-migrated-ledger")); err != nil {
			t.Fatal(err)
		}
		fresh, err := InitializeV2(targetDir, ProviderLedgerSpecs["openai"].TargetID)
		if err != nil {
			t.Fatal(err)
		}
		_ = fresh.Close()

		if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState opening unrelated target beside tombstone, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from MigrateProviderLedger on unrelated target, got %v", err)
		}
	})

	t.Run("tombstone_missing_or_damaged_legacy_scaffold_fails_closed", func(t *testing.T) {
		for _, tc := range []string{"missing_ledger_dir", "missing_lock", "missing_backup", "corrupt_backup"} {
			t.Run(tc, func(t *testing.T) {
				stateRoot := t.TempDir()
				legacyRoot, legacyDir, l := setupLegacyV1Ledger(t, stateRoot, "openai")
				settleOne(t, l, "scaf-1", "resp-scaf-1")
				_ = l.Close()
				if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
					t.Fatal(err)
				}

				switch tc {
				case "missing_ledger_dir":
					if err := os.RemoveAll(legacyDir); err != nil {
						t.Fatal(err)
					}
				case "missing_lock":
					if err := os.Remove(filepath.Join(legacyDir, LockFilename)); err != nil {
						t.Fatal(err)
					}
				case "missing_backup":
					if err := os.Remove(filepath.Join(legacyDir, PreMigrationBackupFilename)); err != nil {
						t.Fatal(err)
					}
				case "corrupt_backup":
					if err := os.WriteFile(filepath.Join(legacyDir, PreMigrationBackupFilename), []byte("{corrupt"), 0600); err != nil {
						t.Fatal(err)
					}
				}

				if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrMigrationState) {
					t.Fatalf("expected ErrMigrationState on %s, got %v", tc, err)
				}
				if _, err := MigrateProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrMigrationState) {
					t.Fatalf("expected ErrMigrationState from migrate-ledger on %s, got %v", tc, err)
				}
				// Verify no new legacy ledger was initialized alongside target.
				if _, err := os.Stat(filepath.Join(legacyRoot, "ledger", StateFilename)); !os.IsNotExist(err) {
					t.Fatalf("legacy ledger.json unexpectedly present")
				}
			})
		}
	})

	t.Run("fresh_v2_install_creates_legacy_sentinel_blocking_old_binary", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["anthropic"]
		l, err := OpenProviderLedger(stateRoot, "anthropic", true)
		if err != nil {
			t.Fatal(err)
		}
		settleOne(t, l, "fresh-1", "resp-fresh-1")
		_ = l.Close()

		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		// Old binary calling OpenOrInitLedger on legacyRoot MUST fail closed, never open a second $2 ledger.
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound from old binary on fresh_v2 legacy sentinel, got %v", err)
		}

		res, err := MigrateProviderLedger(stateRoot, "anthropic", true)
		if err != nil || res.Status != "initialized_v2" || res.SettledRequestsCount != 1 {
			t.Fatalf("expected initialized_v2 status on fresh v2 install, got res=%+v err=%v", res, err)
		}

		// Removing legacy sentinel must fail closed on OpenProviderLedger.
		if err := os.RemoveAll(legacyRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProviderLedger(stateRoot, "anthropic", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when legacy sentinel removed beside v2 target, got %v", err)
		}
	})

	t.Run("multiple_post_migration_settlements_pass_provenance", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "gemini")
		settleOne(t, l, "multi-pre-1", "resp-mp-1")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "gemini", false); err != nil {
			t.Fatal(err)
		}

		lm, err := OpenProviderLedger(stateRoot, "gemini", false)
		if err != nil {
			t.Fatal(err)
		}
		settleOne(t, lm, "multi-post-2", "resp-mp-2")
		settleOne(t, lm, "multi-post-3", "resp-mp-3")
		_ = lm.Close()

		reopened, err := OpenProviderLedger(stateRoot, "gemini", false)
		if err != nil {
			t.Fatalf("reopen after multiple post-migration settlements: %v", err)
		}
		st, _ := reopened.GetStatus()
		_ = reopened.Close()
		if st.SettledRequestsCount != 3 || st.CommittedSpendMicros != 90 {
			t.Fatalf("unexpected status after 3 settlements: %+v", st)
		}

		migRes, err := MigrateProviderLedger(stateRoot, "gemini", true)
		if err != nil || migRes.Status != "already_migrated" || migRes.SettledRequestsCount != 3 {
			t.Fatalf("expected already_migrated with 3 settlements, got res=%+v err=%v", migRes, err)
		}
	})
}

func TestDryRunZeroMutationsAcrossAllStates(t *testing.T) {
	t.Run("fresh_legacy_creates_no_lease_or_bytes", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, legDir, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		_ = l.Close()
		if _, err := os.Stat(filepath.Join(legDir, LeaseFilename)); !os.IsNotExist(err) {
			t.Fatalf("expected no lease.lock initially")
		}
		before := snapshotTreeBytes(t, stateRoot)
		res, err := MigrateProviderLedger(stateRoot, "openai", true)
		if err != nil || res.Status != "would_migrate" {
			t.Fatalf("expected would_migrate, got res=%+v err=%v", res, err)
		}
		after := snapshotTreeBytes(t, stateRoot)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("dry-run mutated fresh legacy tree")
		}
	})

	t.Run("completed_migration_guard_and_files_unchanged", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "dry-comp-1", "resp-dc-1")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
			t.Fatal(err)
		}
		before := snapshotTreeBytes(t, stateRoot)
		res, err := MigrateProviderLedger(stateRoot, "openai", true)
		if err != nil || res.Status != "already_migrated" {
			t.Fatalf("expected already_migrated, got res=%+v err=%v", res, err)
		}
		after := snapshotTreeBytes(t, stateRoot)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("dry-run mutated migrated ledger tree")
		}
	})

	t.Run("interrupted_migration_dry_run_unchanged", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "anthropic")
		settleOne(t, l, "dry-int-1", "resp-di-1")
		_ = l.Close()
		if _, err := migrateProviderLedgerWithHook(stateRoot, "anthropic", false, faultAfterTargetRename); err == nil {
			t.Fatal("expected injected fault")
		}
		before := snapshotTreeBytes(t, stateRoot)
		res, err := MigrateProviderLedger(stateRoot, "anthropic", true)
		if err != nil || res.Status != "would_finalize_interrupted_migration" {
			t.Fatalf("expected would_finalize_interrupted_migration, got res=%+v err=%v", res, err)
		}
		after := snapshotTreeBytes(t, stateRoot)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("dry-run mutated interrupted migration tree")
		}
	})

	t.Run("damaged_target_confirmation_fails_read_only_without_halting", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "dmg-1", "resp-dmg-1")
		_ = l.Close()
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); err != nil {
			t.Fatal(err)
		}
		targetLedgerDir := filepath.Join(stateRoot, "openai", "ledger")
		confs, _ := filepath.Glob(filepath.Join(targetLedgerDir, ConfirmationFilePrefix+"*.json"))
		if len(confs) != 1 {
			t.Fatalf("expected 1 confirmation, got %v", confs)
		}
		if err := os.Remove(confs[0]); err != nil {
			t.Fatal(err)
		}

		before := snapshotTreeBytes(t, stateRoot)
		if _, err := MigrateProviderLedger(stateRoot, "openai", true); err == nil {
			t.Fatalf("expected error on missing confirmation in target during dry-run")
		}
		after := snapshotTreeBytes(t, stateRoot)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("dry-run mutated damaged target ledger (e.g. halted or bumped guard)")
		}
	})
}

func TestEmptyAndEvidenceOnlyLegacyAndLargeEvidenceCopy(t *testing.T) {
	t.Run("empty_legacy_dir_retires_cleanly", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["openai"]
		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		if err := os.MkdirAll(legacyRoot, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legacyRoot, 0700)

		if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired on empty legacy dir, got %v", err)
		}
		dryRes, err := MigrateProviderLedger(stateRoot, "openai", true)
		if err != nil || dryRes.Status != "would_retire_empty_legacy" {
			t.Fatalf("expected would_retire_empty_legacy, got res=%+v err=%v", dryRes, err)
		}
		res, err := MigrateProviderLedger(stateRoot, "openai", false)
		if err != nil || res.Status != "retired_empty_legacy" {
			t.Fatalf("expected retired_empty_legacy, got res=%+v err=%v", res, err)
		}
		// Old binary cannot re-initialize retired legacy dir.
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound on retired empty legacy dir, got %v", err)
		}
		// New binary opens cleanly.
		l, err := OpenProviderLedger(stateRoot, "openai", true)
		if err != nil {
			t.Fatalf("OpenProviderLedger after empty legacy retire: %v", err)
		}
		_ = l.Close()
		again, err := MigrateProviderLedger(stateRoot, "openai", true)
		if err != nil || again.Status != "initialized_v2" {
			t.Fatalf("expected initialized_v2 on rerun, got res=%+v err=%v", again, err)
		}
	})

	t.Run("evidence_only_legacy_dir_migrates_and_copies_evidence", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["openai"]
		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		if err := os.MkdirAll(filepath.Join(legacyRoot, "ledger"), 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legacyRoot, 0700)
		_ = os.Chmod(filepath.Join(legacyRoot, "ledger"), 0700)
		evData := []byte(`{"outcome_code":"NO_STATE"}` + "\n")
		if err := os.WriteFile(filepath.Join(legacyRoot, "live-broker-old.jsonl"), evData, 0600); err != nil {
			t.Fatal(err)
		}

		res, err := MigrateProviderLedger(stateRoot, "openai", false)
		if err != nil || res.Status != "retired_empty_legacy" {
			t.Fatalf("expected retired_empty_legacy, got res=%+v err=%v", res, err)
		}
		copied, err := os.ReadFile(filepath.Join(stateRoot, spec.TargetDir, "live-broker-old.jsonl"))
		if err != nil || !bytes.Equal(copied, evData) {
			t.Fatalf("expected copied evidence, got err=%v", err)
		}
	})

	t.Run("partial_legacy_dir_with_files_inside_ledger_fails_closed", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["openai"]
		legLedger := filepath.Join(stateRoot, spec.LegacyDir, "ledger")
		if err := os.MkdirAll(legLedger, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Dir(legLedger), 0700)
		_ = os.Chmod(legLedger, 0700)
		if err := os.WriteFile(filepath.Join(legLedger, "stray.txt"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState on partial legacy dir, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRoot, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from migrate on partial legacy dir, got %v", err)
		}
	})

	t.Run("large_evidence_over_512KiB_and_bad_evidence_caught_in_dry_run", func(t *testing.T) {
		stateRoot := t.TempDir()
		legRoot, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		_ = l.Close()

		bigEvidence := bytes.Repeat([]byte("a"), 600*1024)
		if err := os.WriteFile(filepath.Join(legRoot, "live-broker-large.jsonl"), bigEvidence, 0600); err != nil {
			t.Fatal(err)
		}
		dryRes, err := MigrateProviderLedger(stateRoot, "openai", true)
		if err != nil || dryRes.Status != "would_migrate" {
			t.Fatalf("dry-run should accept 600 KiB evidence, got res=%+v err=%v", dryRes, err)
		}
		res, err := MigrateProviderLedger(stateRoot, "openai", false)
		if err != nil || res.Status != "migrated" {
			t.Fatalf("migration with 600 KiB evidence failed: res=%+v err=%v", res, err)
		}
		got, err := os.ReadFile(filepath.Join(stateRoot, "openai", "live-broker-large.jsonl"))
		if err != nil || !bytes.Equal(got, bigEvidence) {
			t.Fatalf("copied large evidence mismatch: err=%v len=%d", err, len(got))
		}

		// Bad permissions on evidence must be caught in dry-run with ErrEvidenceCopy (and NOT ErrLedgerCorrupt).
		stateRoot2 := t.TempDir()
		legRoot2, _, l2 := setupLegacyV1Ledger(t, stateRoot2, "anthropic")
		_ = l2.Close()
		badEv := filepath.Join(legRoot2, "live-broker-worldread.jsonl")
		if err := os.WriteFile(badEv, []byte("{}\n"), 0644); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(badEv, 0644)
		_, err = MigrateProviderLedger(stateRoot2, "anthropic", true)
		if !errors.Is(err, ErrEvidenceCopy) || errors.Is(err, ErrLedgerCorrupt) {
			t.Fatalf("expected ErrEvidenceCopy (and not ErrLedgerCorrupt) in dry-run, got %v", err)
		}
	})

	t.Run("blocking_fifo_evidence_file_rejected_without_blocking", func(t *testing.T) {
		// 1. Populated v1 legacy ledger with a FIFO evidence file.
		stateRoot := t.TempDir()
		legRoot, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "fifo-1", "resp-fifo-1")
		_ = l.Close()

		fifoPath := filepath.Join(legRoot, "live-broker-fifo.jsonl")
		if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
			t.Fatalf("mkfifo: %v", err)
		}
		if err := os.Chmod(fifoPath, 0600); err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 3)
		go func() {
			_, err := MigrateProviderLedger(stateRoot, "openai", true)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrEvidenceCopy) || !errors.Is(err, ErrLedgerSecurity) || errors.Is(err, ErrLedgerCorrupt) {
				t.Fatalf("expected ErrEvidenceCopy+ErrLedgerSecurity on FIFO in dry-run, got %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("MigrateProviderLedger dry-run blocked on FIFO evidence file")
		}

		go func() {
			_, err := MigrateProviderLedger(stateRoot, "openai", false)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrEvidenceCopy) || !errors.Is(err, ErrLedgerSecurity) || errors.Is(err, ErrLedgerCorrupt) {
				t.Fatalf("expected ErrEvidenceCopy+ErrLedgerSecurity on FIFO in live migration, got %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("MigrateProviderLedger live blocked on FIFO evidence file")
		}

		// 2. Evidence-only legacy directory with a FIFO evidence file.
		stateRoot2 := t.TempDir()
		spec2 := ProviderLedgerSpecs["gemini"]
		legRoot2 := filepath.Join(stateRoot2, spec2.LegacyDir)
		if err := os.MkdirAll(legRoot2, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legRoot2, 0700)
		fifoPath2 := filepath.Join(legRoot2, "neutral-broker-fifo.jsonl")
		if err := syscall.Mkfifo(fifoPath2, 0600); err != nil {
			t.Fatalf("mkfifo2: %v", err)
		}
		_ = os.Chmod(fifoPath2, 0600)

		for _, op := range []struct {
			name string
			fn   func() error
		}{
			{"dry_run", func() error { _, err := MigrateProviderLedger(stateRoot2, "gemini", true); return err }},
			{"live", func() error { _, err := MigrateProviderLedger(stateRoot2, "gemini", false); return err }},
			{"open_provider", func() error { _, err := OpenProviderLedger(stateRoot2, "gemini", true); return err }},
		} {
			ch := make(chan error, 1)
			go func(f func() error) {
				ch <- f()
			}(op.fn)
			select {
			case err := <-ch:
				if !errors.Is(err, ErrEvidenceCopy) || !errors.Is(err, ErrLedgerSecurity) {
					t.Fatalf("%s: expected ErrEvidenceCopy+ErrLedgerSecurity on FIFO, got %v", op.name, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s blocked on FIFO evidence file", op.name)
			}
		}
	})
}

func TestHealthyLegacySettledWitnessValidationAndHaltedEvidencePreservation(t *testing.T) {
	t.Run("healthy_legacy_journal_witness_mismatch_rejected_before_dry_run_or_publish", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(t *testing.T, legDir string, st *LedgerState)
		}{
			{
				name: "confirmation_response_id_mismatch",
				mutate: func(t *testing.T, legDir string, st *LedgerState) {
					for _, e := range st.Journal {
						if e.EntryType == "SETTLED" {
							p := filepath.Join(legDir, ConfirmationFilePrefix+e.ReservationID+".json")
							raw, err := os.ReadFile(p)
							if err != nil {
								t.Fatal(err)
							}
							var m map[string]any
							_ = json.Unmarshal(raw, &m)
							m["response_id"] = "resp-forged-valid-schema"
							enc, _ := json.MarshalIndent(m, "", "  ")
							if err := os.WriteFile(p, enc, 0600); err != nil {
								t.Fatal(err)
							}
							return
						}
					}
				},
			},
			{
				name: "intent_settled_amount_and_tokens_mismatch",
				mutate: func(t *testing.T, legDir string, st *LedgerState) {
					for _, e := range st.Journal {
						if e.EntryType == "SETTLED" {
							p := filepath.Join(legDir, IntentFilePrefix+e.ReservationID+".json")
							raw, err := os.ReadFile(p)
							if err != nil {
								t.Fatal(err)
							}
							var m map[string]any
							_ = json.Unmarshal(raw, &m)
							// Self-consistent witness record (passes ValidateWitnessRecord alone)
							// that disagrees with the SETTLED journal entry.
							m["input_tokens"] = 10
							m["output_tokens"] = 5
							m["total_tokens"] = 15
							m["settled_amount_micros"] = 15
							m["unencumbered_amount_micros"] = MinReservationMicros - 15
							enc, _ := json.MarshalIndent(m, "", "  ")
							if err := os.WriteFile(p, enc, 0600); err != nil {
								t.Fatal(err)
							}
							return
						}
					}
				},
			},
			{
				name: "swapped_reservation_id_inside_witness",
				mutate: func(t *testing.T, legDir string, st *LedgerState) {
					var resIDs []string
					for _, e := range st.Journal {
						if e.EntryType == "SETTLED" {
							resIDs = append(resIDs, e.ReservationID)
						}
					}
					if len(resIDs) < 2 {
						t.Fatalf("expected >= 2 settled entries")
					}
					p0 := filepath.Join(legDir, ConfirmationFilePrefix+resIDs[0]+".json")
					p1 := filepath.Join(legDir, ConfirmationFilePrefix+resIDs[1]+".json")
					b0, _ := os.ReadFile(p0)
					b1, _ := os.ReadFile(p1)
					if err := os.WriteFile(p0, b1, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p1, b0, 0600); err != nil {
						t.Fatal(err)
					}
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				stateRoot := t.TempDir()
				legRoot, legDir, l := setupLegacyV1Ledger(t, stateRoot, "openai")
				settleOne(t, l, "healthy-1", "resp-h-1")
				settleOne(t, l, "healthy-2", "resp-h-2")
				_ = l.Close()

				st, err := readStateFile(legDir, ProviderLedgerSpecs["openai"].LegacyID)
				if err != nil {
					t.Fatal(err)
				}
				tc.mutate(t, legDir, st)

				before := snapshotTreeBytes(t, stateRoot)
				if _, err := MigrateProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrLedgerCorrupt) || !errors.Is(err, ErrSettlementEvidence) {
					t.Fatalf("dry-run: expected ErrLedgerCorrupt+ErrSettlementEvidence, got %v", err)
				}
				afterDry := snapshotTreeBytes(t, stateRoot)
				if !reflect.DeepEqual(before, afterDry) {
					t.Fatalf("dry-run mutated stateRoot on witness mismatch")
				}

				if _, err := MigrateProviderLedger(stateRoot, "openai", false); !errors.Is(err, ErrLedgerCorrupt) || !errors.Is(err, ErrSettlementEvidence) {
					t.Fatalf("live: expected ErrLedgerCorrupt+ErrSettlementEvidence, got %v", err)
				}
				if _, err := os.Stat(filepath.Join(stateRoot, "openai")); !os.IsNotExist(err) {
					t.Fatalf("target directory must not be published on healthy legacy witness mismatch")
				}
				if _, err := os.Stat(filepath.Join(legRoot, TombstoneFilename)); !os.IsNotExist(err) {
					t.Fatalf("tombstone must not be written on healthy legacy witness mismatch")
				}
			})
		}
	})

	t.Run("halted_legacy_with_mismatched_corrupt_or_dangling_witness_evidence_migrates_cleanly", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			expectedHalt string
			breakWitness func(t *testing.T, legDir string, st *LedgerState)
		}{
			{
				name:         "mismatched_confirmation_field",
				expectedHalt: "TERMINAL_UNCERTAINTY",
				breakWitness: func(t *testing.T, legDir string, st *LedgerState) {
					for _, e := range st.Journal {
						if e.EntryType == "SETTLED" {
							p := filepath.Join(legDir, ConfirmationFilePrefix+e.ReservationID+".json")
							raw, _ := os.ReadFile(p)
							var m map[string]any
							_ = json.Unmarshal(raw, &m)
							m["response_id"] = "resp-mismatch-causing-halt"
							enc, _ := json.MarshalIndent(m, "", "  ")
							if err := os.WriteFile(p, enc, 0600); err != nil {
								t.Fatal(err)
							}
							return
						}
					}
				},
			},
			{
				name:         "corrupt_confirmation_json_left_on_disk",
				expectedHalt: "TERMINAL_UNCERTAINTY",
				breakWitness: func(t *testing.T, legDir string, st *LedgerState) {
					for _, e := range st.Journal {
						if e.EntryType == "SETTLED" {
							p := filepath.Join(legDir, ConfirmationFilePrefix+e.ReservationID+".json")
							if err := os.WriteFile(p, []byte("{corrupt-halted-evidence"), 0600); err != nil {
								t.Fatal(err)
							}
							return
						}
					}
				},
			},
			{
				name:         "dangling_intent_without_confirmation",
				expectedHalt: "UNRESOLVED_SETTLEMENT_PUBLICATION",
				breakWitness: func(t *testing.T, legDir string, st *LedgerState) {
					for _, e := range st.Journal {
						if e.EntryType == "SETTLED" {
							p := filepath.Join(legDir, ConfirmationFilePrefix+e.ReservationID+".json")
							if err := os.Remove(p); err != nil {
								t.Fatal(err)
							}
							return
						}
					}
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				stateRoot := t.TempDir()
				_, legDir, l := setupLegacyV1Ledger(t, stateRoot, "gemini")
				settleOne(t, l, "halt-ev-1", "resp-hev-1")
				_ = l.Close()

				st, err := readStateFile(legDir, ProviderLedgerSpecs["gemini"].LegacyID)
				if err != nil {
					t.Fatal(err)
				}
				tc.breakWitness(t, legDir, st)

				// Opening v1 ledger records TERMINAL_UNCERTAINTY / UNRESOLVED_SETTLEMENT_PUBLICATION
				// while leaving the broken witness evidence files in place on disk.
				lh, err := Open(legDir)
				if err != nil {
					t.Fatalf("Open triggering halt: %v", err)
				}
				_ = lh.Close()

				dryRes, err := MigrateProviderLedger(stateRoot, "gemini", true)
				if err != nil || dryRes.Status != "would_migrate" || !dryRes.Halted || dryRes.HaltReason != tc.expectedHalt {
					t.Fatalf("dry-run halted legacy failed: res=%+v err=%v", dryRes, err)
				}
				res, err := MigrateProviderLedger(stateRoot, "gemini", false)
				if err != nil || res.Status != "migrated" || !res.Halted || res.HaltReason != tc.expectedHalt {
					t.Fatalf("live migrate halted legacy failed: res=%+v err=%v", res, err)
				}

				lm, err := OpenProviderLedger(stateRoot, "gemini", true)
				if err != nil {
					t.Fatalf("OpenProviderLedger after halted migration: %v", err)
				}
				defer lm.Close()
				stAfter, err := lm.GetStatus()
				if err != nil || !stAfter.Halted || stAfter.HaltReason == nil || *stAfter.HaltReason != tc.expectedHalt || stAfter.CanReserve() {
					t.Fatalf("unexpected post-migration halted status: %+v err=%v", stAfter, err)
				}
			})
		}
	})
}

func TestResumableFreshInitAndEmptyLegacyRetirementAcrossFaults(t *testing.T) {
	t.Run("fresh_init_chained_faults_and_second_retries", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["anthropic"]
		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		legacyLedgerDir := filepath.Join(legacyRoot, "ledger")
		targetRoot := filepath.Join(stateRoot, spec.TargetDir)

		// Attempt 1: fault right after durable intent + sentinel published (before targetRoot rename).
		if _, err := openProviderLedgerWithHook(stateRoot, "anthropic", true, faultAfterIntentWrite); err == nil {
			t.Fatal("expected faultAfterIntentWrite")
		}
		// Old binary must already be excluded!
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound from old binary after faultAfterIntentWrite, got %v", err)
		}
		// Read-only open (initialize=false) must fail closed without mutating disk.
		beforeRO1 := snapshotTreeBytes(t, stateRoot)
		if _, err := OpenProviderLedger(stateRoot, "anthropic", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState on initialize=false during unfinished fresh_init, got %v", err)
		}
		if !reflect.DeepEqual(beforeRO1, snapshotTreeBytes(t, stateRoot)) {
			t.Fatal("initialize=false mutated stateRoot after faultAfterIntentWrite")
		}
		intentOnDisk, err := validateMigrationIntent(legacyLedgerDir, spec)
		if err != nil {
			t.Fatalf("validateMigrationIntent after fault 1: %v", err)
		}

		// Retry 1: advances from staged target -> targetRoot rename, then hits faultAfterTargetRename.
		if _, err := openProviderLedgerWithHook(stateRoot, "anthropic", true, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename on retry 1")
		}
		if _, err := os.Stat(targetRoot); err != nil {
			t.Fatalf("expected targetRoot to exist after retry 1: %v", err)
		}
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound from old binary after faultAfterTargetRename, got %v", err)
		}

		// Retry 2 (second retry!): advances to writing tombstone, then hits faultAfterTombstoneWrite.
		if _, err := openProviderLedgerWithHook(stateRoot, "anthropic", true, faultAfterTombstoneWrite); err == nil {
			t.Fatal("expected faultAfterTombstoneWrite on retry 2")
		}
		if _, err := os.Stat(filepath.Join(legacyRoot, TombstoneFilename)); err != nil {
			t.Fatalf("expected tombstone to exist after retry 2: %v", err)
		}
		if _, err := os.Stat(filepath.Join(legacyLedgerDir, MigrationIntentFilename)); err != nil {
			t.Fatalf("expected migration_intent.json still present before finalization: %v", err)
		}

		// Retry 3: finalizes intent removal and opens the ledger cleanly.
		l, err := OpenProviderLedger(stateRoot, "anthropic", true)
		if err != nil {
			t.Fatalf("OpenProviderLedger final retry failed: %v", err)
		}
		settleOne(t, l, "resumed-fresh-1", "resp-rf-1")
		_ = l.Close()

		if _, err := os.Stat(filepath.Join(legacyLedgerDir, MigrationIntentFilename)); !os.IsNotExist(err) {
			t.Fatalf("expected migration_intent.json removed after completion")
		}
		stFinal, err := readStateFile(filepath.Join(targetRoot, "ledger"), spec.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		if stFinal.CreatedAtUTC != intentOnDisk.TargetCreatedAtUTC {
			t.Fatalf("target was reinitialized instead of resumed: created_at_utc=%q != intent=%q", stFinal.CreatedAtUTC, intentOnDisk.TargetCreatedAtUTC)
		}
	})

	t.Run("fresh_init_missing_or_unrelated_target_never_accepted_or_reinitialized", func(t *testing.T) {
		spec := ProviderLedgerSpecs["openai"]

		// Case 1: Staged target deleted after faultAfterIntentWrite -> must fail closed, never reinitialize.
		stateRoot1 := t.TempDir()
		if _, err := openProviderLedgerWithHook(stateRoot1, "openai", true, faultAfterIntentWrite); err == nil {
			t.Fatal("expected faultAfterIntentWrite")
		}
		intent1, err := validateMigrationIntent(filepath.Join(stateRoot1, spec.LegacyDir, "ledger"), spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(stateRoot1, intent1.StageDirName)); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProviderLedger(stateRoot1, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when staged target deleted, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(stateRoot1, spec.TargetDir)); !os.IsNotExist(err) {
			t.Fatal("missing staged target was reinitialized!")
		}

		// Case 2: Published target deleted after faultAfterTargetRename -> must fail closed, never reinitialize.
		stateRoot2 := t.TempDir()
		if _, err := openProviderLedgerWithHook(stateRoot2, "openai", true, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename")
		}
		if err := os.RemoveAll(filepath.Join(stateRoot2, spec.TargetDir)); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProviderLedger(stateRoot2, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when target deleted after faultAfterTargetRename, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRoot2, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from MigrateProviderLedger when target deleted, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(stateRoot2, spec.TargetDir)); !os.IsNotExist(err) {
			t.Fatal("missing published target was reinitialized!")
		}

		// Case 3: Published target replaced with unrelated clean v2 target during interrupted init.
		stateRoot3 := t.TempDir()
		if _, err := openProviderLedgerWithHook(stateRoot3, "openai", true, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename")
		}
		targetLedger3 := filepath.Join(stateRoot3, spec.TargetDir, "ledger")
		if err := os.RemoveAll(filepath.Join(stateRoot3, spec.TargetDir)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		unrelated, err := InitializeV2(targetLedger3, spec.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		_ = unrelated.Close()

		if _, err := OpenProviderLedger(stateRoot3, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when target swapped with unrelated v2 ledger during init, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRoot3, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from MigrateProviderLedger on unrelated target during init, got %v", err)
		}

		// Case 4: Completed fresh_v2 install rejects swapped unrelated clean v2 target.
		stateRoot4 := t.TempDir()
		l4, err := OpenProviderLedger(stateRoot4, "openai", true)
		if err != nil {
			t.Fatal(err)
		}
		settleOne(t, l4, "v2-orig-1", "resp-v2-orig-1")
		_ = l4.Close()

		targetLedger4 := filepath.Join(stateRoot4, spec.TargetDir, "ledger")
		if err := os.RemoveAll(targetLedger4); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		unrelated4, err := InitializeV2(targetLedger4, spec.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		_ = unrelated4.Close()

		if _, err := OpenProviderLedger(stateRoot4, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when completed fresh_v2 target replaced with unrelated target, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRoot4, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from MigrateProviderLedger on replaced fresh_v2 target, got %v", err)
		}
	})

	t.Run("retire_empty_and_evidence_only_legacy_chained_faults_and_second_retries", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["gemini"]
		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		legacyLedgerDir := filepath.Join(legacyRoot, "ledger")
		targetRoot := filepath.Join(stateRoot, spec.TargetDir)
		if err := os.MkdirAll(legacyLedgerDir, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legacyRoot, 0700)
		_ = os.Chmod(legacyLedgerDir, 0700)
		evContent := []byte(`{"outcome_code":"RESUMABLE_RETIRE"}` + "\n")
		if err := os.WriteFile(filepath.Join(legacyRoot, "neutral-broker-retire.jsonl"), evContent, 0600); err != nil {
			t.Fatal(err)
		}

		// Attempt 1: faultAfterIntentWrite.
		if _, err := migrateProviderLedgerWithHook(stateRoot, "gemini", false, faultAfterIntentWrite); err == nil {
			t.Fatal("expected faultAfterIntentWrite")
		}
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound from old binary after faultAfterIntentWrite, got %v", err)
		}
		if _, err := OpenProviderLedger(stateRoot, "gemini", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired while retirement interrupted at fault 1, got %v", err)
		}
		beforeDry1 := snapshotTreeBytes(t, stateRoot)
		dry1, err := MigrateProviderLedger(stateRoot, "gemini", true)
		if err != nil || dry1.Status != "would_retire_empty_legacy" {
			t.Fatalf("dry-run at fault 1: res=%+v err=%v", dry1, err)
		}
		if !reflect.DeepEqual(beforeDry1, snapshotTreeBytes(t, stateRoot)) {
			t.Fatal("dry-run mutated stateRoot at fault 1")
		}
		intentOnDisk, err := validateMigrationIntent(legacyLedgerDir, spec)
		if err != nil {
			t.Fatal(err)
		}

		// Retry 1: promotes stageDir -> targetRoot, then hits faultAfterTargetRename.
		if _, err := migrateProviderLedgerWithHook(stateRoot, "gemini", false, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename on retry 1")
		}
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound from old binary after faultAfterTargetRename, got %v", err)
		}
		if _, err := OpenProviderLedger(stateRoot, "gemini", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired while retirement interrupted at fault 2, got %v", err)
		}
		beforeDry2 := snapshotTreeBytes(t, stateRoot)
		dry2, err := MigrateProviderLedger(stateRoot, "gemini", true)
		if err != nil || dry2.Status != "would_retire_empty_legacy" {
			t.Fatalf("dry-run at fault 2: res=%+v err=%v", dry2, err)
		}
		if !reflect.DeepEqual(beforeDry2, snapshotTreeBytes(t, stateRoot)) {
			t.Fatal("dry-run mutated stateRoot at fault 2")
		}

		// Retry 2 (second retry!): writes tombstone, then hits faultAfterTombstoneWrite.
		if _, err := migrateProviderLedgerWithHook(stateRoot, "gemini", false, faultAfterTombstoneWrite); err == nil {
			t.Fatal("expected faultAfterTombstoneWrite on retry 2")
		}
		if _, err := OpenProviderLedger(stateRoot, "gemini", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired while retirement interrupted at fault 3, got %v", err)
		}
		beforeDry3 := snapshotTreeBytes(t, stateRoot)
		dry3, err := MigrateProviderLedger(stateRoot, "gemini", true)
		if err != nil || dry3.Status != "would_retire_empty_legacy" {
			t.Fatalf("dry-run at fault 3: res=%+v err=%v", dry3, err)
		}
		if !reflect.DeepEqual(beforeDry3, snapshotTreeBytes(t, stateRoot)) {
			t.Fatal("dry-run mutated stateRoot at fault 3")
		}

		// Retry 3: removes migration_intent.json and completes retirement.
		res, err := MigrateProviderLedger(stateRoot, "gemini", false)
		if err != nil || res.Status != "retired_empty_legacy" {
			t.Fatalf("expected retired_empty_legacy on final retry, got res=%+v err=%v", res, err)
		}
		copiedEv, err := os.ReadFile(filepath.Join(targetRoot, "neutral-broker-retire.jsonl"))
		if err != nil || !bytes.Equal(copiedEv, evContent) {
			t.Fatalf("copied evidence mismatch after resumed retirement: err=%v", err)
		}
		stFinal, err := readStateFile(filepath.Join(targetRoot, "ledger"), spec.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		if stFinal.CreatedAtUTC != intentOnDisk.TargetCreatedAtUTC {
			t.Fatalf("retired target was reinitialized instead of resumed: %q != %q", stFinal.CreatedAtUTC, intentOnDisk.TargetCreatedAtUTC)
		}

		l, err := OpenProviderLedger(stateRoot, "gemini", true)
		if err != nil {
			t.Fatalf("OpenProviderLedger after resumed retirement: %v", err)
		}
		_ = l.Close()
	})

	t.Run("retire_empty_legacy_rejects_unrelated_or_missing_target", func(t *testing.T) {
		spec := ProviderLedgerSpecs["openai"]

		// 1. Pre-existing unrelated target beside unretired empty legacy dir.
		stateRoot1 := t.TempDir()
		legRoot1 := filepath.Join(stateRoot1, spec.LegacyDir)
		tgtLedger1 := filepath.Join(stateRoot1, spec.TargetDir, "ledger")
		if err := os.MkdirAll(legRoot1, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legRoot1, 0700)
		if err := os.MkdirAll(filepath.Dir(tgtLedger1), 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Dir(tgtLedger1), 0700)
		lUnrel1, err := InitializeV2(tgtLedger1, spec.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		_ = lUnrel1.Close()

		if _, err := OpenProviderLedger(stateRoot1, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState on unretired empty legacy + unrelated target, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRoot1, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from MigrateProviderLedger on unretired empty legacy + unrelated target, got %v", err)
		}

		// 2. Target deleted after faultAfterTargetRename during empty legacy retirement.
		stateRoot2 := t.TempDir()
		legRoot2 := filepath.Join(stateRoot2, spec.LegacyDir)
		if err := os.MkdirAll(legRoot2, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legRoot2, 0700)
		if _, err := migrateProviderLedgerWithHook(stateRoot2, "openai", false, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename")
		}
		if err := os.RemoveAll(filepath.Join(stateRoot2, spec.TargetDir)); err != nil {
			t.Fatal(err)
		}
		if _, err := MigrateProviderLedger(stateRoot2, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when target deleted during empty legacy retirement, got %v", err)
		}
		if _, err := OpenProviderLedger(stateRoot2, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from OpenProviderLedger when target deleted during retirement, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(stateRoot2, spec.TargetDir)); !os.IsNotExist(err) {
			t.Fatal("missing target was reinitialized during empty legacy retirement!")
		}
	})

	t.Run("populated_migration_chained_faults_and_second_retry", func(t *testing.T) {
		stateRoot := t.TempDir()
		_, _, l := setupLegacyV1Ledger(t, stateRoot, "openai")
		settleOne(t, l, "chain-pop-1", "resp-cp-1")
		_ = l.Close()

		// Attempt 1: faultAfterTargetRename.
		if _, err := migrateProviderLedgerWithHook(stateRoot, "openai", false, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename")
		}
		// Retry 1: writes tombstone and hits faultAfterTombstoneWrite.
		if _, err := migrateProviderLedgerWithHook(stateRoot, "openai", false, faultAfterTombstoneWrite); err == nil {
			t.Fatal("expected faultAfterTombstoneWrite on retry 1")
		}
		if _, err := OpenProviderLedger(stateRoot, "openai", true); !errors.Is(err, ErrLedgerMigrationRequired) {
			t.Fatalf("expected ErrLedgerMigrationRequired before Step B.2 rename, got %v", err)
		}
		// Retry 2 (second retry!): completes Step B.2 rename and returns migrated_recovered.
		res, err := MigrateProviderLedger(stateRoot, "openai", false)
		if err != nil || res.Status != "migrated_recovered" || res.CommittedSpendMicros != 30 {
			t.Fatalf("expected migrated_recovered on second retry, got res=%+v err=%v", res, err)
		}
		lm, err := OpenProviderLedger(stateRoot, "openai", false)
		if err != nil {
			t.Fatalf("open after second retry: %v", err)
		}
		_ = lm.Close()
	})

	t.Run("existing_v2_install_without_target_created_at_utc_remains_compatible", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["anthropic"]
		l, err := OpenProviderLedger(stateRoot, "anthropic", true)
		if err != nil {
			t.Fatal(err)
		}
		settleOne(t, l, "compat-v2-1", "resp-cv2-1")
		_ = l.Close()

		// Rewrite migrated_to.json into the 7-key pre-provenance format (omitting target_created_at_utc).
		tombPath := filepath.Join(stateRoot, spec.LegacyDir, TombstoneFilename)
		raw, err := os.ReadFile(tombPath)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "target_created_at_utc")
		enc, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(tombPath, enc, 0600); err != nil {
			t.Fatal(err)
		}

		// Existing v2 install must open and inspect cleanly.
		l2, err := OpenProviderLedger(stateRoot, "anthropic", false)
		if err != nil {
			t.Fatalf("OpenProviderLedger on 7-key existing v2 install failed: %v", err)
		}
		st, err := l2.GetStatus()
		_ = l2.Close()
		if err != nil || st.CommittedSpendMicros != 30 {
			t.Fatalf("unexpected status on 7-key v2 install: %+v err=%v", st, err)
		}
		migRes, err := MigrateProviderLedger(stateRoot, "anthropic", true)
		if err != nil || migRes.Status != "initialized_v2" {
			t.Fatalf("MigrateProviderLedger on 7-key v2 install failed: res=%+v err=%v", migRes, err)
		}

		// Even with 7-key tombstone, replacing target with a newly initialized v2 ledger (created after migrated_at_utc) is rejected!
		time.Sleep(2 * time.Millisecond)
		targetLedgerDir := filepath.Join(stateRoot, spec.TargetDir, "ledger")
		if err := os.RemoveAll(targetLedgerDir); err != nil {
			t.Fatal(err)
		}
		laterTarget, err := InitializeV2(targetLedgerDir, spec.TargetID)
		if err != nil {
			t.Fatal(err)
		}
		_ = laterTarget.Close()
		if _, err := OpenProviderLedger(stateRoot, "anthropic", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState when 7-key v2 target replaced by later InitializeV2, got %v", err)
		}
	})

	t.Run("concurrent_initializers_converge_safely_on_single_v2_ledger", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["openai"]
		const workers = 8

		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, workers)
		ledgers := make([]*BudgetLedger, workers)

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				l, err := OpenProviderLedger(stateRoot, "openai", true)
				ledgers[idx] = l
				errs[idx] = err
			}(i)
		}
		// A read-only migration inspection can race the first open as well.
		// Before publication it sees a new provider. After publication it must
		// validate the same v2 ledger that the initializers return.
		var inspection *MigrationResult
		var inspectErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			inspection, inspectErr = MigrateProviderLedger(stateRoot, "openai", true)
		}()
		close(start)
		wg.Wait()

		if inspectErr != nil {
			t.Fatalf("concurrent dry run: %v", inspectErr)
		}
		if inspection.Status != "not_initialized" && inspection.Status != "initialized_v2" {
			t.Fatalf("unexpected concurrent dry-run result: %s", inspection.Status)
		}
		for i := 0; i < workers; i++ {
			if errs[i] != nil {
				t.Fatalf("concurrent initializer %d failed: %v", i, errs[i])
			}
			if ledgers[i] == nil {
				t.Fatalf("concurrent initializer %d returned nil ledger", i)
			}
		}
		settleOne(t, ledgers[0], "conc-req-1", "conc-resp-1")
		for i := 0; i < workers; i++ {
			_ = ledgers[i].Close()
		}

		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		if _, err := OpenOrInitLedger(legacyRoot, true, spec.LegacyID); !errors.Is(err, ErrLedgerNotFound) {
			t.Fatalf("expected ErrLedgerNotFound from old binary after concurrent init, got %v", err)
		}
		lCheck, err := OpenProviderLedger(stateRoot, "openai", false)
		if err != nil {
			t.Fatalf("reopen after concurrent init: %v", err)
		}
		defer lCheck.Close()
		st, err := lCheck.GetStatus()
		if err != nil || st.CommittedSpendMicros != 30 || st.SettledRequestsCount != 1 {
			t.Fatalf("unexpected state after concurrent init: %+v err=%v", st, err)
		}
	})

	t.Run("early_fault_before_intent_publish_and_lock_only_refusal", func(t *testing.T) {
		spec := ProviderLedgerSpecs["openai"]

		for _, withEmptyLedgerDir := range []bool{false, true} {
			stateRoot := t.TempDir()
			legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
			if err := os.MkdirAll(legacyRoot, 0700); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(legacyRoot, 0700)
			if withEmptyLedgerDir {
				legLedger := filepath.Join(legacyRoot, "ledger")
				if err := os.MkdirAll(legLedger, 0700); err != nil {
					t.Fatal(err)
				}
				_ = os.Chmod(legLedger, 0700)
			}
			if err := os.WriteFile(filepath.Join(legacyRoot, "live-broker-early.jsonl"), []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}

			if _, err := migrateProviderLedgerWithHook(stateRoot, "openai", false, faultBeforeIntentPublish); err == nil {
				t.Fatal("expected faultBeforeIntentPublish")
			}
			// Must NOT leave a lock-only legacy directory behind!
			if _, err := os.Stat(filepath.Join(legacyRoot, "ledger", LockFilename)); !os.IsNotExist(err) {
				t.Fatalf("faultBeforeIntentPublish left lock file in legacyRoot/ledger (withEmptyLedgerDir=%v)", withEmptyLedgerDir)
			}
			res, err := MigrateProviderLedger(stateRoot, "openai", false)
			if err != nil || res.Status != "retired_empty_legacy" {
				t.Fatalf("retry after faultBeforeIntentPublish (withEmptyLedgerDir=%v) failed: res=%+v err=%v", withEmptyLedgerDir, res, err)
			}
		}

		// Also verify fresh init recovers after faultBeforeIntentPublish.
		stateRootFresh := t.TempDir()
		if _, err := openProviderLedgerWithHook(stateRootFresh, "openai", true, faultBeforeIntentPublish); err == nil {
			t.Fatal("expected faultBeforeIntentPublish on fresh init")
		}
		lf, err := OpenProviderLedger(stateRootFresh, "openai", true)
		if err != nil {
			t.Fatalf("fresh init retry after faultBeforeIntentPublish failed: %v", err)
		}
		_ = lf.Close()

		// Existing lock-only ambiguous legacy directory (lock present without state, tombstone, or intent) MUST still refuse.
		stateRootAmbig := t.TempDir()
		ambigLedger := filepath.Join(stateRootAmbig, spec.LegacyDir, "ledger")
		if err := os.MkdirAll(ambigLedger, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Dir(ambigLedger), 0700)
		_ = os.Chmod(ambigLedger, 0700)
		if err := os.WriteFile(filepath.Join(ambigLedger, LockFilename), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProviderLedger(stateRootAmbig, "openai", true); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState on lock-only ambiguous legacy dir, got %v", err)
		}
		if _, err := MigrateProviderLedger(stateRootAmbig, "openai", false); !errors.Is(err, ErrMigrationState) {
			t.Fatalf("expected ErrMigrationState from MigrateProviderLedger on lock-only ambiguous legacy dir, got %v", err)
		}
	})

	t.Run("stale_temporary_tombstone_files_handled_safely", func(t *testing.T) {
		spec := ProviderLedgerSpecs["gemini"]

		// 1. Mid-write .tmp_tomb_* left during empty/evidence-only retirement after target publish.
		stateRoot := t.TempDir()
		legRoot := filepath.Join(stateRoot, spec.LegacyDir)
		if err := os.MkdirAll(legRoot, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legRoot, 0700)
		if _, err := migrateProviderLedgerWithHook(stateRoot, "gemini", false, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename")
		}
		tmpTomb := filepath.Join(legRoot, ".tmp_tomb_"+strings.Repeat("1", 32))
		if err := os.WriteFile(tmpTomb, []byte(`{"partial":`), 0600); err != nil {
			t.Fatal(err)
		}

		// Dry-run must accept regular .tmp_tomb_* without deleting or mutating it.
		beforeDry := snapshotTreeBytes(t, stateRoot)
		dryRes, err := MigrateProviderLedger(stateRoot, "gemini", true)
		if err != nil || dryRes.Status != "would_retire_empty_legacy" {
			t.Fatalf("dry-run with .tmp_tomb_* failed: res=%+v err=%v", dryRes, err)
		}
		if !reflect.DeepEqual(beforeDry, snapshotTreeBytes(t, stateRoot)) {
			t.Fatal("dry-run mutated .tmp_tomb_*")
		}

		// Nonregular / bad-permission .tmp_tomb_* must be rejected with ErrLedgerSecurity.
		evilTomb := filepath.Join(legRoot, ".tmp_tomb_"+strings.Repeat("a", 32))
		if err := os.WriteFile(evilTomb, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(evilTomb, 0644)
		if _, err := MigrateProviderLedger(stateRoot, "gemini", true); !errors.Is(err, ErrLedgerSecurity) {
			t.Fatalf("expected ErrLedgerSecurity on world-readable .tmp_tomb_evil, got %v", err)
		}
		_ = os.Remove(evilTomb)

		// Live recovery cleans up .tmp_tomb_* and finalizes retirement.
		res, err := MigrateProviderLedger(stateRoot, "gemini", false)
		if err != nil || res.Status != "retired_empty_legacy" {
			t.Fatalf("live recovery with .tmp_tomb_* failed: res=%+v err=%v", res, err)
		}
		if _, err := os.Stat(tmpTomb); !os.IsNotExist(err) {
			t.Fatal("expected stale .tmp_tomb_* to be removed during live recovery")
		}

		// 2. Mid-write .tmp_tomb_* left during populated migration after target publish.
		stateRoot2 := t.TempDir()
		legRoot2, _, l2 := setupLegacyV1Ledger(t, stateRoot2, "gemini")
		settleOne(t, l2, "tomb-tmp-1", "resp-tt-1")
		_ = l2.Close()
		if _, err := migrateProviderLedgerWithHook(stateRoot2, "gemini", false, faultAfterTargetRename); err == nil {
			t.Fatal("expected faultAfterTargetRename")
		}
		tmpTomb2 := filepath.Join(legRoot2, ".tmp_tomb_"+strings.Repeat("2", 32))
		if err := os.WriteFile(tmpTomb2, []byte(`{"partial":`), 0600); err != nil {
			t.Fatal(err)
		}
		localFile := filepath.Join(legRoot2, ".tmp_tomb_personal-notes")
		if err := os.WriteFile(localFile, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		res2, err := MigrateProviderLedger(stateRoot2, "gemini", false)
		if err != nil || res2.Status != "migrated_recovered" {
			t.Fatalf("populated recovery with .tmp_tomb_* failed: res=%+v err=%v", res2, err)
		}
		if _, err := os.Stat(tmpTomb2); !os.IsNotExist(err) {
			t.Fatal("expected stale .tmp_tomb_* removed during populated recovery")
		}
		if data, err := os.ReadFile(localFile); err != nil || string(data) != "fixture" {
			t.Fatal("recovery changed an unrelated local file")
		}
	})

	t.Run("many_evidence_filenames_keep_migration_intent_compact_and_resumable", func(t *testing.T) {
		stateRoot := t.TempDir()
		spec := ProviderLedgerSpecs["openai"]
		legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
		if err := os.MkdirAll(legacyRoot, 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(legacyRoot, 0700)

		// 1,200 long evidence filenames (~96 KiB of names if serialized as a list).
		const numFiles = 1200
		for i := 0; i < numFiles; i++ {
			name := fmt.Sprintf("live-broker-run-%04d-0123456789abcdef0123456789abcdef0123456789abcdef.jsonl", i)
			if err := os.WriteFile(filepath.Join(legacyRoot, name), []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}

		if _, err := migrateProviderLedgerWithHook(stateRoot, "openai", false, faultAfterIntentWrite); err == nil {
			t.Fatal("expected faultAfterIntentWrite")
		}
		intentPath := filepath.Join(legacyRoot, "ledger", MigrationIntentFilename)
		fi, err := os.Stat(intentPath)
		if err != nil {
			t.Fatalf("stat migration_intent.json: %v", err)
		}
		if fi.Size() > 1024 {
			t.Fatalf("expected compact migration_intent.json (< 1 KiB), got %d bytes", fi.Size())
		}
		intent, err := validateMigrationIntent(filepath.Join(legacyRoot, "ledger"), spec)
		if err != nil {
			t.Fatalf("validateMigrationIntent with %d evidence files failed: %v", numFiles, err)
		}
		if intent.EvidenceCount != numFiles {
			t.Fatalf("expected EvidenceCount=%d, got %d", numFiles, intent.EvidenceCount)
		}

		res, err := MigrateProviderLedger(stateRoot, "openai", false)
		if err != nil || res.Status != "retired_empty_legacy" {
			t.Fatalf("resume retirement with %d evidence files failed: res=%+v err=%v", numFiles, res, err)
		}
	})
}

func copyTestDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range entries {
		data, err := os.ReadFile(filepath.Join(src, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, de.Name()), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
