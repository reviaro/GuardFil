package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/broker/budget"
)

func TestMainCommandParsing(t *testing.T) {
	// Empty args
	if err := run([]string{}); err == nil {
		t.Errorf("expected error for empty args")
	}

	// Unknown subcommand
	if err := run([]string{"unknown_cmd"}); err == nil {
		t.Errorf("expected error for unknown subcommand")
	}

	// Help flags
	if err := run([]string{"--help"}); err != nil {
		t.Errorf("expected nil error for --help, got %v", err)
	}
	if err := run([]string{"help"}); err != nil {
		t.Errorf("expected nil error for help, got %v", err)
	}

	// Responses missing required flags
	if err := run([]string{"responses"}); err == nil || !strings.Contains(err.Error(), "--sockdir") {
		t.Errorf("expected error for missing --sockdir in responses, got %v", err)
	}
	if err := run([]string{"responses", "--sockdir", "/tmp"}); err == nil || !strings.Contains(err.Error(), "--case-label") {
		t.Errorf("expected error for missing --case-label in responses, got %v", err)
	}

	// Messages missing required flags
	if err := run([]string{"messages"}); err == nil || !strings.Contains(err.Error(), "--sockdir") {
		t.Errorf("expected error for missing --sockdir in messages, got %v", err)
	}
	if err := run([]string{"messages", "--sockdir", "/tmp"}); err == nil || !strings.Contains(err.Error(), "--label") {
		t.Errorf("expected error for missing --label in messages, got %v", err)
	}

	// Neutral missing required flags (when not --check)
	if err := run([]string{"neutral"}); err == nil || !strings.Contains(err.Error(), "--sockdir") {
		t.Errorf("expected error for missing --sockdir in neutral, got %v", err)
	}

	// Relay missing required flags
	if err := run([]string{"relay"}); err == nil || !strings.Contains(err.Error(), "--path") {
		t.Errorf("expected error for missing --path in relay, got %v", err)
	}

	// Migrate-ledger invalid provider
	if err := run([]string{"migrate-ledger", "--provider", "bogus"}); err == nil || !strings.Contains(err.Error(), "invalid --provider") {
		t.Errorf("expected invalid --provider error, got %v", err)
	}
}

func TestRunMigrateLedgerDryRunAndApply(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateRoot := filepath.Join(home, ".local/state/guardfil")

	spec := budget.ProviderLedgerSpecs["anthropic"]
	legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
	if err := os.MkdirAll(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	l, err := budget.Initialize(filepath.Join(legacyRoot, "ledger"), spec.LegacyID)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	if err := run([]string{"migrate-ledger", "--provider", "all", "--state-root", stateRoot, "--dry-run"}); err != nil {
		t.Fatalf("dry-run migrate-ledger failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, spec.TargetDir)); !os.IsNotExist(err) {
		t.Fatalf("dry-run unexpectedly created target directory")
	}
	if _, err := os.Stat(filepath.Join(legacyRoot, "ledger", budget.LeaseFilename)); !os.IsNotExist(err) {
		t.Fatalf("dry-run unexpectedly created lease.lock")
	}

	if err := run([]string{"migrate-ledger", "--provider", "all", "--state-root", stateRoot}); err != nil {
		t.Fatalf("migrate-ledger failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, spec.TargetDir, "ledger", budget.StateFilename)); err != nil {
		t.Fatalf("expected migrated state file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacyRoot, budget.TombstoneFilename)); err != nil {
		t.Fatalf("expected legacy tombstone: %v", err)
	}
}

func TestRunMigrateLedgerAllContinuesAcrossFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateRoot := filepath.Join(home, ".local/state/guardfil")

	// Break openai (partial/unfinished guard), keep gemini healthy legacy.
	oaSpec := budget.ProviderLedgerSpecs["openai"]
	oaLegacy := filepath.Join(stateRoot, oaSpec.LegacyDir)
	if err := os.MkdirAll(oaLegacy, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(oaLegacy, 0700)
	lo, err := budget.Initialize(filepath.Join(oaLegacy, "ledger"), oaSpec.LegacyID)
	if err != nil {
		t.Fatal(err)
	}
	_ = lo.Close()
	if err := os.Remove(filepath.Join(oaLegacy, "ledger", budget.InspectionCompletionFilename)); err != nil {
		t.Fatal(err)
	}

	gemSpec := budget.ProviderLedgerSpecs["gemini"]
	gemLegacy := filepath.Join(stateRoot, gemSpec.LegacyDir)
	if err := os.MkdirAll(gemLegacy, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(gemLegacy, 0700)
	lg, err := budget.Initialize(filepath.Join(gemLegacy, "ledger"), gemSpec.LegacyID)
	if err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()

	err = run([]string{"migrate-ledger", "--provider", "all", "--state-root", stateRoot})
	if err == nil {
		t.Fatalf("expected error from --provider all when openai fails")
	}
	// Gemini MUST still have migrated even though openai (first in SupportedProviders) failed.
	if _, statErr := os.Stat(filepath.Join(stateRoot, gemSpec.TargetDir, "ledger", budget.StateFilename)); statErr != nil {
		t.Fatalf("expected gemini migration to complete despite earlier openai failure: %v", statErr)
	}
}
