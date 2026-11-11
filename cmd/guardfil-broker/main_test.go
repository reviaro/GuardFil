package main

import (
	"strings"
	"testing"
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
}
