package budget

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func TestPythonGoLedgerCrossCompatibility(t *testing.T) {
	repoRoot := findRepoRoot()
	tempDir, err := os.MkdirTemp("", "test_compat_ledger_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	ledgerDir := filepath.Join(tempDir, "ledger")

	// 1. Python initializes the ledger and performs 1 reservation and settlement
	pyInitScript := `
import sys
from pathlib import Path
from research.t2a.openai_budget.ledger import BudgetLedger
from research.t2a.openai_budget.models import Receipt

ledger_dir = Path(sys.argv[1])
ledger = BudgetLedger.initialize(ledger_dir, experiment_id="compat-exp-1")
permit = ledger.reserve("py-req-1", "sha256:1111", 50000)
receipt = Receipt(
    status="completed",
    response_id="py-resp-1",
    request_id="py-req-1",
    request_digest="sha256:1111",
    model="gpt-6-luna",
    service_tier="default",
    input_tokens=100,
    output_tokens=50,
    total_tokens=150,
)
settled = ledger.settle(permit, receipt)
st = ledger.get_status()
print(f"PY_INIT_DONE committed={st.committed_spend_micros} reservations={st.total_reservations_count}")
ledger.close()
`
	cmd := exec.Command("python3", "-B", "-c", pyInitScript, ledgerDir)
	cmd.Dir = filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python init failed: %v, output: %s", err, string(out))
	}
	if !strings.Contains(string(out), "PY_INIT_DONE committed=150 reservations=1") {
		t.Fatalf("unexpected python output: %s", string(out))
	}

	// 2. Go opens the Python-created ledger, validates status, reserves and settles
	goLedger, err := Open(ledgerDir)
	if err != nil {
		t.Fatalf("Go failed to open python-created ledger: %v", err)
	}

	st, err := goLedger.GetStatus()
	if err != nil {
		t.Fatalf("Go GetStatus failed: %v", err)
	}
	if st.ExperimentID != "compat-exp-1" {
		t.Errorf("expID mismatch: %s", st.ExperimentID)
	}
	if st.CommittedSpendMicros != 150 || st.TotalReservationsCount != 1 || st.SettledRequestsCount != 1 {
		t.Errorf("Go status mismatch: %+v", st)
	}

	goPermit, err := goLedger.Reserve("go-req-2", "sha256:2222", 60000)
	if err != nil {
		t.Fatalf("Go reserve failed: %v", err)
	}

	goReceipt := &Receipt{
		Status:        TerminalStatusCompleted,
		ResponseID:    "go-resp-2",
		RequestID:     "go-req-2",
		RequestDigest: "sha256:2222",
		Model:         "claude-sonnet-5-5",
		ServiceTier:   "standard",
		InputTokens:   200,
		OutputTokens:  40,
		TotalTokens:   240,
	}
	// claude: 200*2 + 40*10 = 400 + 400 = 800
	goSettled, err := goLedger.Settle(goPermit, goReceipt)
	if err != nil {
		t.Fatalf("Go settle failed: %v", err)
	}
	if goSettled.AccountedCostMicros != 800 {
		t.Errorf("expected cost 800, got %d", goSettled.AccountedCostMicros)
	}
	if err := goLedger.Close(); err != nil {
		t.Fatalf("Go close failed: %v", err)
	}

	// 3. Python re-opens the ledger written by Go and verifies the Go settlement
	pyVerifyScript := `
import sys
from pathlib import Path
from research.t2a.openai_budget.ledger import BudgetLedger

ledger_dir = Path(sys.argv[1])
ledger = BudgetLedger.open(ledger_dir)
st = ledger.get_status()
print(f"PY_VERIFY_DONE committed={st.committed_spend_micros} reservations={st.total_reservations_count} settled={st.settled_requests_count}")
assert st.committed_spend_micros == 150 + 800
assert st.total_reservations_count == 2
assert st.settled_requests_count == 2
ledger.close()
`
	cmd2 := exec.Command("python3", "-B", "-c", pyVerifyScript, ledgerDir)
	cmd2.Dir = filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref")
	cmd2.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref"))
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("python verify failed: %v, output: %s", err, string(out2))
	}
	if !strings.Contains(string(out2), "PY_VERIFY_DONE committed=950 reservations=2 settled=2") {
		t.Fatalf("unexpected python verify output: %s", string(out2))
	}
}
