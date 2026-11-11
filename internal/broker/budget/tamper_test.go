package budget

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The ledger is a cost control: a ledger file whose totals or journal were
// changed must not be trusted.  Python builds a valid ledger, makes tampered
// copies and confirms its own ledger refuses each; the Go ledger must refuse
// every one too, and still open the untouched original.
const tamperScript = `
import copy, json, shutil, sys
from pathlib import Path
from research.t2a.openai_budget.ledger import BudgetLedger
from research.t2a.openai_budget.models import Receipt

base = Path(sys.argv[1])
orig = base / "orig" / "ledger"
orig.parent.mkdir(parents=True)
l = BudgetLedger.initialize(orig, experiment_id="tamper-1")
for i, (model, tier, inp, out) in enumerate([("gpt-6-luna", "default", 100, 50), ("claude-sonnet-5-5", "standard", 200, 0)]):
    p = l.reserve(f"req-{i}", f"sha256:{i:04d}", 30000)
    l.settle(p, Receipt(status="completed", response_id=f"resp-{i}", request_id=f"req-{i}", request_digest=f"sha256:{i:04d}",
                        model=model, service_tier=tier, input_tokens=inp, output_tokens=out, total_tokens=inp + out))
p = l.reserve("req-f", "sha256:ffff", 30000)
l.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
l.close()
state = json.loads((orig / "ledger.json").read_text())

def settled(s):
    return [e for e in s["journal"] if e["entry_type"] == "SETTLED"]

mutations = {
  "committed spend lowered": lambda s: s.__setitem__("committed_spend_micros", 1),
  "committed spend raised": lambda s: s.__setitem__("committed_spend_micros", s["committed_spend_micros"] + 1),
  "retained failed changed": lambda s: s.__setitem__("retained_failed_micros", 0),
  "reservation count changed": lambda s: s.__setitem__("total_reservations_count", 1),
  "settled count changed": lambda s: s.__setitem__("settled_requests_count", 5),
  "ceiling raised": lambda s: s.__setitem__("global_ceiling_micros", 10**9),
  "schema version": lambda s: s.__setitem__("schema_version", 99),
  "extra top-level key": lambda s: s.__setitem__("note", "x"),
  "halted without reason": lambda s: s.__setitem__("halted", True),
  "bogus pending reservation": lambda s: s.__setitem__("pending_reservation", {"reservation_id": "x"}),
  "settled amount edited": lambda s: settled(s)[0].__setitem__("settled_amount_micros", 1),
  "settled tokens edited": lambda s: settled(s)[0].__setitem__("input_tokens", 1),
  "unknown model": lambda s: settled(s)[0].__setitem__("model", "gpt-free"),
  "settled entry removed": lambda s: s["journal"].remove(settled(s)[-1]),
  "entry type unknown": lambda s: s["journal"][-1].__setitem__("entry_type", "REFUNDED"),
  "duplicate reservation id": lambda s: s["journal"].append(copy.deepcopy(s["journal"][1])),
  "reservation index out of order": lambda s: [e for e in s["journal"] if e["entry_type"] == "RESERVED"][1].__setitem__("reservation_index", 7),
  "initialized experiment differs": lambda s: s["journal"][0].__setitem__("experiment_id", "other"),
  "journal entry missing a key": lambda s: settled(s)[0].pop("output_tokens"),
  "negative spend": lambda s: s.__setitem__("committed_spend_micros", -5),
}
refused = []
for name, mutate in mutations.items():
    d = base / name.replace(" ", "_") / "ledger"
    d.parent.mkdir(parents=True)
    shutil.copytree(orig, d)
    s = copy.deepcopy(state)
    mutate(s)
    (d / "ledger.json").write_text(json.dumps(s))
    try:
        BudgetLedger.open(d).close()
    except Exception:
        refused.append({"name": name, "dir": str(d)})
print(json.dumps({"orig": str(orig), "refused": refused, "total": len(mutations)}))
`

func TestTamperedLedgersAreRefused(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	repo := findRepoRoot()
	base := t.TempDir()
	cmd := exec.Command(py, "-B", "-c", tamperScript, base)
	cmd.Dir = filepath.Join(repo, "internal", "broker", "testdata", "pyref")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "internal", "broker", "testdata", "pyref"))
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("python: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var res struct {
		Orig    string `json:"orig"`
		Total   int    `json:"total"`
		Refused []struct {
			Name string `json:"name"`
			Dir  string `json:"dir"`
		} `json:"refused"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Refused) < res.Total-2 {
		t.Fatalf("python refused only %d of %d tampered ledgers; the fixture is wrong", len(res.Refused), res.Total)
	}
	l, err := Open(res.Orig)
	if err != nil {
		t.Fatalf("untouched ledger: %v", err)
	}
	l.Close()
	for _, c := range res.Refused {
		if l, err := Open(c.Dir); err == nil {
			l.Close()
			t.Errorf("%s: Python refuses this ledger, Go opened it", c.Name)
		}
	}
}
