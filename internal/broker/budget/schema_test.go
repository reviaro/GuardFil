package budget

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

// The key sets the Go ledger writes must be the Python ledger's EXPECTED_* sets.
func TestKeySetsMatchPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	repo := findRepoRoot()
	cmd := exec.Command(py, "-B", "-c", `
import json
from research.t2a.openai_budget import constants as c
print(json.dumps({n: sorted(getattr(c, n)) for n in dir(c) if n.startswith("EXPECTED_")}))`)
	cmd.Dir = filepath.Join(repo, "internal", "broker", "testdata", "pyref")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "internal", "broker", "testdata", "pyref"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python: %v", err)
	}
	var want map[string][]string
	if err := json.Unmarshal(out, &want); err != nil {
		t.Fatal(err)
	}
	check := func(goName string, keys []string, pyName string) {
		got := append([]string(nil), keys...)
		sort.Strings(got)
		w := want[pyName]
		if len(w) == 0 || len(w) != len(got) {
			t.Errorf("%s: go %v, python %s %v", goName, got, pyName, w)
			return
		}
		for i := range got {
			if got[i] != w[i] {
				t.Errorf("%s: go %v, python %s %v", goName, got, pyName, w)
				return
			}
		}
	}
	for typ, py := range map[string]string{"INITIALIZED": "EXPECTED_JOURNAL_INITIALIZED_KEYS", "RESERVED": "EXPECTED_JOURNAL_RESERVED_KEYS",
		"SETTLED": "EXPECTED_JOURNAL_SETTLED_KEYS", "FAILED_RETAINED": "EXPECTED_JOURNAL_FAILED_RETAINED_KEYS",
		"ORPHANED_PENDING_HALTED": "EXPECTED_JOURNAL_ORPHANED_KEYS", "TERMINAL_UNCERTAINTY": "EXPECTED_JOURNAL_TERMINAL_UNCERTAINTY_KEYS"} {
		check(typ, journalKeys[typ], py)
	}
	for typ, py := range map[string]string{"SETTLEMENT_INTENT": "EXPECTED_INTENT_KEYS", "SETTLEMENT_CONFIRMATION": "EXPECTED_CONFIRMATION_KEYS",
		"INSPECTION_GUARD": "EXPECTED_INSPECTION_GUARD_KEYS", "INSPECTION_COMPLETION": "EXPECTED_INSPECTION_COMPLETION_KEYS"} {
		check(typ, witnessKeys[typ], py)
	}
}

// Zero values are written, never dropped: an unbilled settlement has zero
// cost and a refused reply zero output tokens.
func TestZeroValuedFieldsAreKept(t *testing.T) {
	b, err := json.Marshal(JournalEntry{EntryType: "SETTLED", ReservationID: "r", RequestID: "q", RequestDigest: "d",
		ResponseID: "p", Model: "m", ServiceTier: "standard", TimestampUTC: "t"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"input_tokens", "output_tokens", "total_tokens", "settled_amount_micros", "unencumbered_amount_micros"} {
		if v, ok := m[k]; !ok || v != float64(0) {
			t.Errorf("%s: %v (present %v)", k, v, ok)
		}
	}
	if _, err := json.Marshal(JournalEntry{EntryType: "NOPE"}); err == nil {
		t.Error("unknown entry type was written")
	}
}
