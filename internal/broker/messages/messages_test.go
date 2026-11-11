package messages

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/broker/budget"
)

func sampleCCReq() map[string]any {
	return map[string]any{
		"model":      Model,
		"max_tokens": 32000,
		"stream":     true,
		"thinking":   map[string]any{"type": "enabled", "budget_tokens": 8000},
		"system": []any{
			map[string]any{
				"type":          "text",
				"text":          "sys",
				"cache_control": map[string]any{"type": "ephemeral"},
			},
		},
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "text", "text": "hi"},
				},
			},
		},
		"tools": []any{
			map[string]any{
				"name":         "Bash",
				"description":  "run",
				"input_schema": map[string]any{"type": "object"},
			},
		},
		"metadata": map[string]any{"user_id": "u"},
	}
}

var sampleReply = []byte(`{
  "id": "msg_1",
  "type": "message",
  "role": "assistant",
  "model": "claude-sonnet-5-5",
  "stop_reason": "tool_use",
  "stop_sequence": null,
  "content": [
    {"type": "text", "text": "ok"},
    {"type": "tool_use", "id": "tu1", "name": "Bash", "input": {"command": "ls"}}
  ],
  "usage": {
    "input_tokens": 10,
    "cache_creation_input_tokens": 100,
    "cache_read_input_tokens": 1000,
    "output_tokens": 20,
    "service_tier": "standard"
  }
}`)

type fakeTransport struct {
	replies    [][]byte
	statuses   []int
	sent       []string
	sentBodies [][]byte
}

func (f *fakeTransport) call(path string, headers map[string]string, body []byte) (int, []byte, error) {
	f.sent = append(f.sent, path)
	f.sentBodies = append(f.sentBodies, body)
	if strings.HasSuffix(path, "count_tokens") {
		return 200, []byte(`{"input_tokens": 1110}`), nil
	}
	if len(f.replies) > 0 {
		r := f.replies[0]
		f.replies = f.replies[1:]
		st := f.statuses[0]
		f.statuses = f.statuses[1:]
		return st, r, nil
	}
	return 200, sampleReply, nil
}

func setupTestBroker(t *testing.T, statuses []int, replies [][]byte, priorMicros int) (*MessagesBrokerServer, *budget.BudgetLedger, *fakeTransport, func()) {
	tempDir, err := os.MkdirTemp("", "test_messages_broker_")
	if err != nil {
		t.Fatal(err)
	}

	ledgerDir := filepath.Join(tempDir, "ledger")
	ledger, err := budget.Initialize(ledgerDir, "test-messages-exp")
	if err != nil {
		t.Fatal(err)
	}

	ft := &fakeTransport{
		statuses: statuses,
		replies:  replies,
	}

	srv, err := NewMessagesBrokerServer(ledger, "test-key", "t", 8, ft.call, priorMicros, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.sleepFn = func(d time.Duration) {} // no real delay in tests

	cleanup := func() {
		_ = ledger.Close()
		_ = os.RemoveAll(tempDir)
	}
	return srv, ledger, ft, cleanup
}

func TestSettlesWithCacheCountedAndStreamsBack(t *testing.T) {
	srv, ledger, ft, cleanup := setupTestBroker(t, []int{200}, [][]byte{sampleReply}, 0)
	defer cleanup()

	rawReq, _ := json.Marshal(sampleCCReq())
	status, body := srv.HandleFrame(rawReq)
	if status != 200 {
		t.Fatalf("expected 200, got %d, body: %s", status, string(body))
	}

	// Verify sent request fields
	lastBody := ft.sentBodies[len(ft.sentBodies)-1]
	var sentObj map[string]any
	_ = json.Unmarshal(lastBody, &sentObj)
	if toInt(sentObj["max_tokens"]) != budget.MaxOutputTokens {
		t.Errorf("max_tokens mismatch: %v", sentObj["max_tokens"])
	}
	if sentObj["thinking"] != nil {
		t.Errorf("thinking should be stripped")
	}
	if sentObj["stream"] != nil {
		t.Errorf("stream should be stripped")
	}

	// Check event stream format
	text := string(body)
	if !strings.HasPrefix(text, "event: message_start") {
		t.Errorf("expected SSE to start with message_start, got: %s", text[:100])
	}
	if !strings.Contains(text, `\"command\":\"ls\"`) && !strings.Contains(text, `"command":"ls"`) {
		t.Errorf("expected command ls in SSE stream, got: %s", text)
	}
	if !strings.HasSuffix(strings.TrimSpace(text), `{"type":"message_stop"}`) {
		t.Errorf("expected SSE to end with message_stop, got: %s", text[len(text)-100:])
	}

	// Verify ledger accounting:
	// 10 + 2*100 + ceil(1000/10) = 310 input tokens * 2 = 620
	// 20 output tokens * 10 = 200
	// total = 820
	st, err := ledger.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedSpendMicros != 820 {
		t.Errorf("expected 820 committed spend, got %d", st.CommittedSpendMicros)
	}
}

func TestCacheWriteSplitCountedByTTL(t *testing.T) {
	// 1 input + 4*1.25 (5) + 5*2 (10) = 16
	splitUsage := map[string]any{
		"input_tokens":                1,
		"cache_creation_input_tokens": 9,
		"cache_creation": map[string]any{
			"ephemeral_5m_input_tokens": 4,
			"ephemeral_1h_input_tokens": 5,
		},
	}
	tok, err := BillableInput(splitUsage)
	if err != nil || tok != 16 {
		t.Errorf("expected 16, got %d (%v)", tok, err)
	}

	// a split that does not add up falls back to 2x (18)
	invalidSplitUsage := map[string]any{
		"input_tokens":                0,
		"cache_creation_input_tokens": 9,
		"cache_creation": map[string]any{
			"ephemeral_5m_input_tokens": 1,
		},
	}
	tok, err = BillableInput(invalidSplitUsage)
	if err != nil || tok != 18 {
		t.Errorf("expected 18, got %d (%v)", tok, err)
	}
}

func TestJSONReplyWhenNotStreaming(t *testing.T) {
	srv, _, _, cleanup := setupTestBroker(t, []int{200}, [][]byte{sampleReply}, 0)
	defer cleanup()

	c := sampleCCReq()
	c["stream"] = false
	rawReq, _ := json.Marshal(c)
	status, body := srv.HandleFrame(rawReq)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	var res map[string]any
	if err := json.Unmarshal(body, &res); err != nil || res["id"] != "msg_1" {
		t.Errorf("expected json response with id msg_1, got: %s", string(body))
	}
}

func TestProviderSideToolsAndFieldsRefusedBeforeSpend(t *testing.T) {
	badRequests := []map[string]any{
		func() map[string]any {
			c := sampleCCReq()
			c["tools"] = []any{map[string]any{"type": "web_search_20250305", "name": "web_search"}}
			return c
		}(),
		func() map[string]any {
			c := sampleCCReq()
			c["tools"] = []any{map[string]any{"type": "code_execution_20250825", "name": "code_execution"}}
			return c
		}(),
		func() map[string]any {
			c := sampleCCReq()
			c["mcp_servers"] = []any{map[string]any{"type": "url", "url": "https://evil.example/mcp"}}
			return c
		}(),
		func() map[string]any {
			c := sampleCCReq()
			c["container"] = "c1"
			return c
		}(),
		func() map[string]any {
			c := sampleCCReq()
			c["model"] = "claude-opus-5-5"
			return c
		}(),
		func() map[string]any {
			c := sampleCCReq()
			c["messages"] = []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "server_tool_use", "id": "x"}}}}
			return c
		}(),
		func() map[string]any {
			c := sampleCCReq()
			c["tool_choice"] = map[string]any{"type": "web_search"}
			return c
		}(),
	}

	for idx, bad := range badRequests {
		srv, ledger, ft, cleanup := setupTestBroker(t, nil, nil, 0)
		rawReq, _ := json.Marshal(bad)
		status, _ := srv.HandleFrame(rawReq)
		if status != 400 {
			t.Errorf("case %d: expected 400, got %d", idx, status)
		}
		if len(ft.sent) != 0 {
			t.Errorf("case %d: transport called when it should be refused before spend", idx)
		}
		st, _ := ledger.GetStatus()
		if st.TotalSpendMicros != 0 {
			t.Errorf("case %d: spend recorded on refusal: %d", idx, st.TotalSpendMicros)
		}
		cleanup()
	}
}

func TestOverloadRetriedThenClosedAtZero(t *testing.T) {
	overloadBody := []byte(`{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`)
	statuses := []int{529, 529, 529, 529, 529}
	replies := [][]byte{overloadBody, overloadBody, overloadBody, overloadBody, overloadBody}

	srv, ledger, _, cleanup := setupTestBroker(t, statuses, replies, 0)
	defer cleanup()

	rawReq, _ := json.Marshal(sampleCCReq())
	status, _ := srv.HandleFrame(rawReq)
	if status != 529 {
		t.Fatalf("expected 529, got %d", status)
	}

	st, _ := ledger.GetStatus()
	if st.TotalSpendMicros != 0 {
		t.Errorf("expected 0 total spend, got %d", st.TotalSpendMicros)
	}
	if !st.CanReserve() {
		t.Errorf("expected canReserve to remain true")
	}
	if srv.stopped {
		t.Errorf("expected broker not to be stopped")
	}
}

func TestBadReplyHalts(t *testing.T) {
	badReply := []byte(`{"type":"message","id":"m","usage":{}}`)
	srv, ledger, _, cleanup := setupTestBroker(t, []int{200}, [][]byte{badReply}, 0)
	defer cleanup()

	rawReq, _ := json.Marshal(sampleCCReq())
	status, _ := srv.HandleFrame(rawReq)
	if status != 502 {
		t.Fatalf("expected 502, got %d", status)
	}
	if !srv.stopped {
		t.Errorf("expected broker to be stopped after bad reply")
	}
	st, _ := ledger.GetStatus()
	if !st.Halted {
		t.Errorf("expected ledger to be halted")
	}
}

func TestProviderCeiling(t *testing.T) {
	srv, _, ft, cleanup := setupTestBroker(t, nil, nil, 1_999_000)
	defer cleanup()

	rawReq, _ := json.Marshal(sampleCCReq())
	status, _ := srv.HandleFrame(rawReq)
	if status != 429 {
		t.Fatalf("expected 429 for provider ceiling, got %d", status)
	}
	if len(ft.sent) != 1 || ft.sent[0] != "/v1/messages/count_tokens" {
		t.Errorf("expected only count_tokens called, got %v", ft.sent)
	}
}

func TestInvalidIDsHaltLedger(t *testing.T) {
	badIDReplies := [][]byte{
		[]byte(`{"type":"message","id":"","model":"claude-sonnet-5-5","usage":{"input_tokens":10,"output_tokens":10}}`),
		[]byte(`{"type":"message","id":"   ","model":"claude-sonnet-5-5","usage":{"input_tokens":10,"output_tokens":10}}`),
		[]byte(`{"type":"message","id":12345,"model":"claude-sonnet-5-5","usage":{"input_tokens":10,"output_tokens":10}}`),
	}

	for idx, badReply := range badIDReplies {
		srv, ledger, _, cleanup := setupTestBroker(t, []int{200}, [][]byte{badReply}, 0)
		rawReq, _ := json.Marshal(sampleCCReq())
		status, _ := srv.HandleFrame(rawReq)
		if status != 502 {
			t.Errorf("case %d: expected 502, got %d", idx, status)
		}
		if !srv.stopped {
			t.Errorf("case %d: expected broker stopped", idx)
		}
		st, err := ledger.GetStatus()
		if err != nil || !st.Halted {
			t.Errorf("case %d: expected ledger halted", idx)
		}
		if st.HaltReason == nil || *st.HaltReason != "INVALID_RESPONSE_ID" {
			t.Errorf("case %d: expected INVALID_RESPONSE_ID, got %v", idx, st.HaltReason)
		}
		cleanup()
	}
}

func TestReplyModelMismatchHaltsLedger(t *testing.T) {
	wrongModelReply := []byte(`{
		"id": "msg_wrong_1",
		"type": "message",
		"role": "assistant",
		"model": "claude-3-haiku",
		"content": [{"type": "text", "text": "wrong model"}],
		"usage": {"input_tokens": 10, "output_tokens": 10}
	}`)

	srv, ledger, _, cleanup := setupTestBroker(t, []int{200}, [][]byte{wrongModelReply}, 0)
	defer cleanup()

	rawReq, _ := json.Marshal(sampleCCReq())
	status, _ := srv.HandleFrame(rawReq)
	if status != 502 {
		t.Fatalf("expected 502, got %d", status)
	}
	if !srv.stopped {
		t.Errorf("expected broker stopped after model mismatch")
	}
	st, err := ledger.GetStatus()
	if err != nil || !st.Halted {
		t.Fatalf("expected ledger halted")
	}
	if st.HaltReason == nil || *st.HaltReason != "RECEIPT_MODEL_MISMATCH" {
		t.Errorf("expected RECEIPT_MODEL_MISMATCH, got %v", st.HaltReason)
	}
}

func TestAllowedFailureCodesOnBadStatusAndMalformed(t *testing.T) {
	// Status 418 (non-200 and not unbilled) records INVALID_RECEIPT_EVIDENCE
	srv, ledger, _, cleanup := setupTestBroker(t, []int{418}, [][]byte{[]byte("teapot")}, 0)
	rawReq, _ := json.Marshal(sampleCCReq())
	status, _ := srv.HandleFrame(rawReq)
	if status != 502 {
		t.Errorf("expected 502, got %d", status)
	}
	st, _ := ledger.GetStatus()
	if !st.Halted || st.HaltReason == nil || *st.HaltReason != "INVALID_RECEIPT_EVIDENCE" {
		t.Errorf("expected INVALID_RECEIPT_EVIDENCE, got %v", st.HaltReason)
	}
	cleanup()

	// Malformed JSON reply records RECEIPT_SCHEMA_VIOLATION
	srv2, ledger2, _, cleanup2 := setupTestBroker(t, []int{200}, [][]byte{[]byte("not-json")}, 0)
	status2, _ := srv2.HandleFrame(rawReq)
	if status2 != 502 {
		t.Errorf("expected 502, got %d", status2)
	}
	st2, _ := ledger2.GetStatus()
	if !st2.Halted || st2.HaltReason == nil || *st2.HaltReason != "RECEIPT_SCHEMA_VIOLATION" {
		t.Errorf("expected RECEIPT_SCHEMA_VIOLATION, got %v", st2.HaltReason)
	}
	cleanup2()
}
