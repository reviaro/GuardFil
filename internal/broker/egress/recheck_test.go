package egress_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/broker/adapters"
	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/egress"
	"github.com/reviaro/guardfil/internal/broker/messages"
	"github.com/reviaro/guardfil/internal/broker/neutral"
	"github.com/reviaro/guardfil/internal/broker/responses"
)

func TestCloudGuardRechecksAfterTokenCountingAndBeforeRetries(t *testing.T) {
	for _, variant := range []string{"responses-count", "messages-count", "messages-retry", "neutral-count", "neutral-retry"} {
		t.Run(variant, func(t *testing.T) {
			ledger, err := budget.Initialize(filepath.Join(t.TempDir(), "ledger"), "privacy-recheck")
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			blocked, calls := false, 0
			guard := egress.Guard(func() error {
				if blocked {
					return errors.New("local-only access stopped cloud requests")
				}
				return nil
			})
			switch {
			case strings.HasPrefix(variant, "responses"):
				srv, err := responses.NewResponsesBrokerServer(ledger, "synthetic", "privacy", 4, t.TempDir(), t.TempDir(), nil,
					func([]byte, string) (int, map[string]string, []byte, error) {
						blocked = true
						return 200, nil, []byte(`{"object":"response.input_tokens","input_tokens":10}`), nil
					},
					func([]byte, string) (int, map[string]string, []byte, error) { calls++; return 400, nil, nil, nil })
				if err != nil {
					t.Fatal(err)
				}
				srv.CloudGuard = guard
				status, body := srv.HandleFrameBytes([]byte(`{"model":"gpt-6-luna","stream":true,"input":"text"}`))
				if status != 403 {
					t.Fatalf("response after privacy change: %d %s", status, body)
				}
			case strings.HasPrefix(variant, "messages"):
				srv, err := messages.NewMessagesBrokerServer(ledger, "synthetic", "privacy", 4,
					func(path string, _ map[string]string, _ []byte) (int, []byte, error) {
						if strings.HasSuffix(path, "count_tokens") {
							blocked = strings.HasSuffix(variant, "count")
							return 200, []byte(`{"input_tokens":10}`), nil
						}
						calls++
						blocked = true
						return 503, []byte(`{"error":{"message":"retry"}}`), nil
					}, 0, "")
				if err != nil {
					t.Fatal(err)
				}
				srv.CloudGuard = guard
				status, body := srv.HandleFrame([]byte(`{"model":"claude-sonnet-5-5","max_tokens":16,"messages":[{"role":"user","content":"text"}]}`))
				if status != 403 {
					t.Fatalf("message after privacy change: %d %s", status, body)
				}
			default:
				srv, err := neutral.NewNeutralBrokerServer(map[string]*budget.BudgetLedger{"gemini": ledger}, "privacy", 4, map[string]string{"gemini": "synthetic"},
					func(req *adapters.HTTPRequest, _ map[string]string) (int, []byte, error) {
						if strings.HasSuffix(req.Path, ":countTokens") {
							blocked = strings.HasSuffix(variant, "count")
							return 200, []byte(`{"totalTokens":10}`), nil
						}
						calls++
						blocked = true
						return 503, []byte(`{"error":{"message":"retry"}}`), nil
					}, "", map[string]bool{"gemini": true}, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				srv.CloudGuard = guard
				out := srv.Handle([]byte(`{"model":"gemini:gemini-3.6-flash","max_output_tokens":16,"messages":[{"role":"user","content":"text"}]}`))
				if out["ok"] != false {
					t.Fatal(out)
				}
			}
			expected := 0
			if strings.HasSuffix(variant, "retry") {
				expected = 1
			}
			if calls != expected {
				t.Fatalf("generation/retry crossed privacy boundary: got %d upstream calls, want %d", calls, expected)
			}
			status, err := ledger.GetStatus()
			if err != nil || status.TotalEncumberedMicros != 0 {
				t.Fatalf("locally blocked request left a charge or reservation: %+v %v", status, err)
			}
		})
	}
}
