package main

import (
	"testing"

	"github.com/reviaro/guardfil/internal/playground"
)

func TestParseToolsFlag(t *testing.T) {
	tests := []struct {
		input   string
		want    playground.ToolSet
		wantErr bool
	}{
		{"demo", playground.ToolSetDemo, false},
		{"claude-code", playground.ToolSetClaudeCode, false},
		{"bogus", "", true},
		{"", "", true},
		{"DEMO", "", true},
		{"Claude-Code", "", true},
		{"claude_code", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := playground.ParseToolSet(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("ParseToolSet(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ParseToolSet(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseToolSet(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
