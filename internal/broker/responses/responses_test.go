package responses_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/relay"
	"github.com/reviaro/guardfil/internal/broker/responses"
)

var allowedEvidenceKeys = map[string]bool{
	"request_id":           true,
	"request_digest":       true,
	"inserted_fields":      true,
	"tool_type_names":      true,
	"http_status":          true,
	"response_id":          true,
	"model":                true,
	"service_tier":         true,
	"usage":                true,
	"response_body_sha256": true,
	"event_type_counts":    true,
	"outcome_code":         true,
	"ledger_status":        true,
	"timestamps":           true,
}

func makeSSEStream(
	responseID string,
	model string,
	serviceTier string,
	status string,
	inputTokens int,
	outputTokens int,
	totalTokens int,
	outputText string,
	includeDone bool,
	extraEvents []string,
	trailingRaw []byte,
) []byte {
	if model == "" {
		model = responses.PinnedModel
	}
	if serviceTier == "" {
		serviceTier = responses.PinnedServiceTier
	}
	if status == "" {
		status = "completed"
	}

	var sb strings.Builder
	// 1. response.created
	evCreated := fmt.Sprintf(`{"type":"response.created","response":{"id":%q,"status":"in_progress","model":%q,"service_tier":%q}}`,
		responseID, model, serviceTier)
	sb.WriteString("event: response.created\ndata: " + evCreated + "\n\n")

	// 2. response.output_text.delta
	evDelta := fmt.Sprintf(`{"type":"response.output_text.delta","delta":%q}`, outputText)
	sb.WriteString("event: response.output_text.delta\ndata: " + evDelta + "\n\n")

	// extra events
	for _, extra := range extraEvents {
		sb.WriteString(extra)
	}

	// 3. response.completed
	evCompleted := fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"object":"response","status":%q,"model":%q,"service_tier":%q,"error":null,"incomplete_details":null,"usage":{"input_tokens":%d,"output_tokens":%d,"total_tokens":%d},"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":%q}]}]}}`,
		responseID, status, model, serviceTier, inputTokens, outputTokens, totalTokens, outputText)
	sb.WriteString("event: response.completed\ndata: " + evCompleted + "\n\n")

	if includeDone {
		sb.WriteString("data: [DONE]\n\n")
	}

	out := []byte(sb.String())
	if len(trailingRaw) > 0 {
		out = append(out, trailingRaw...)
	}
	return out
}

func fakeGetOK(key string) (int, map[string]string, []byte, error) {
	return 200, map[string]string{"content-type": "application/json"}, []byte(`{"id":"gpt-6-luna"}`), nil
}

func fakeCountOK(body []byte, key string) (int, map[string]string, []byte, error) {
	return 200, map[string]string{"content-type": "application/json"}, []byte(`{"object":"response.input_tokens","input_tokens":1200}`), nil
}

func TestHappySSEPathSettlesAndDeliversExactBytes(t *testing.T) {
	tmpDir := t.TempDir()
	expRoot := filepath.Join(tmpDir, "exp")
	sockDir := filepath.Join(tmpDir, "sock")
	fakeKeySecret := "sk-live-broker-test-secret-abcdef123456"

	ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}
	defer ledger.Close()

	expectedSSE1 := makeSSEStream("resp_accept_1", "", "", "completed", 30, 15, 45, "secret-assistant-response-1", false, nil, nil)
	expectedSSE2 := makeSSEStream("resp_accept_2", "", "", "completed", 40, 12, 52, "secret-assistant-response-2", true, nil, nil)
	replies := [][]byte{expectedSSE1, expectedSSE2}

	var outboundSeen []map[string]any

	fakePost := func(body []byte, key string) (int, map[string]string, []byte, error) {
		if key != fakeKeySecret {
			t.Errorf("expected key %s, got %s", fakeKeySecret, key)
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		outboundSeen = append(outboundSeen, m)
		r := replies[0]
		replies = replies[1:]
		return 200, map[string]string{"content-type": "text/event-stream"}, r, nil
	}

	srv, err := responses.NewResponsesBrokerServer(ledger, fakeKeySecret, "accept", 3, sockDir, expRoot, fakeGetOK, fakeCountOK, fakePost)
	if err != nil {
		t.Fatalf("NewResponsesBrokerServer error: %v", err)
	}
	defer srv.Close()

	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start error: %v", err)
	}

	stDir, err := os.Stat(sockDir)
	if err != nil || stDir.Mode().Perm() != 0700 {
		t.Fatalf("expected sockDir perm 0700, got %v", stDir.Mode())
	}
	stSock, err := os.Stat(srv.SocketPath())
	if err != nil || stSock.Mode().Perm() != 0600 {
		t.Fatalf("expected broker.sock perm 0600, got %v", stSock.Mode())
	}

	go func() {
		_ = srv.Serve()
	}()

	time.Sleep(50 * time.Millisecond)

	// Request 1: omits service_tier and max_output_tokens
	req1 := map[string]any{
		"model":     responses.PinnedModel,
		"reasoning": map[string]any{"effort": "none"},
		"stream":    true,
		"input": []any{
			map[string]any{"type": "message", "role": "user", "content": "secret-user-prompt-text"},
			map[string]any{
				"type": "additional_tools",
				"role": "developer",
				"tools": []any{
					map[string]any{
						"type":  "namespace",
						"name":  "mcp__testmcp",
						"tools": []any{map[string]any{"type": "function", "name": "write_canary", "parameters": map[string]any{"secret_arg": "x"}}},
					},
				},
			},
		},
		"tools": []any{map[string]any{"type": "custom", "name": "exec"}},
	}
	req1Bytes, _ := json.Marshal(req1)

	status1, body1, err := relay.ForwardFrame(srv.SocketPath(), req1Bytes, 5*time.Second)
	if err != nil {
		t.Fatalf("forward_frame req1 failed: %v", err)
	}
	if status1 != 200 {
		t.Fatalf("expected status 200, got %d, body: %s", status1, string(body1))
	}
	if string(body1) != string(expectedSSE1) {
		t.Fatalf("body1 mismatch")
	}

	// Request 2: provides service_tier and max_output_tokens
	req2 := map[string]any{
		"model":             responses.PinnedModel,
		"stream":            true,
		"service_tier":      "default",
		"max_output_tokens": 256,
		"input":             "follow-up prompt",
	}
	req2Bytes, _ := json.Marshal(req2)

	status2, body2, err := relay.ForwardFrame(srv.SocketPath(), req2Bytes, 5*time.Second)
	if err != nil {
		t.Fatalf("forward_frame req2 failed: %v", err)
	}
	if status2 != 200 {
		t.Fatalf("expected status 200, got %d, body: %s", status2, string(body2))
	}
	if string(body2) != string(expectedSSE2) {
		t.Fatalf("body2 mismatch")
	}

	// Check outbound requests
	if len(outboundSeen) != 2 {
		t.Fatalf("expected 2 outbound requests, got %d", len(outboundSeen))
	}
	if outboundSeen[0]["service_tier"] != "default" || outboundSeen[0]["max_output_tokens"] != float64(1024) {
		t.Errorf("outbound1 defaults not inserted: %v", outboundSeen[0])
	}
	if outboundSeen[1]["service_tier"] != "default" || outboundSeen[1]["max_output_tokens"] != float64(256) {
		t.Errorf("outbound2 not preserved: %v", outboundSeen[1])
	}

	// Check ledger status
	st, err := ledger.GetStatus()
	if err != nil {
		t.Fatalf("failed to get ledger status: %v", err)
	}
	if st.TotalReservationsCount != 2 || st.SettledRequestsCount != 2 {
		t.Errorf("expected 2 reservations and settlements, got %d and %d", st.TotalReservationsCount, st.SettledRequestsCount)
	}
	if st.Halted {
		t.Errorf("ledger unexpectedly halted")
	}
	if st.CommittedSpendMicros != 45+52 {
		t.Errorf("expected committed spend 97, got %d", st.CommittedSpendMicros)
	}

	// Check evidence
	evPath := filepath.Join(expRoot, "live-broker-accept.jsonl")
	evData, err := os.ReadFile(evPath)
	if err != nil {
		t.Fatalf("failed to read evidence: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(evData)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 evidence lines, got %d", len(lines))
	}

	for idx, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d invalid JSON: %v", idx, err)
		}
		for k := range allowedEvidenceKeys {
			if _, ok := rec[k]; !ok {
				t.Errorf("line %d missing allowed key: %s", idx, k)
			}
		}
		for k := range rec {
			if !allowedEvidenceKeys[k] {
				t.Errorf("line %d contains unexpected key: %s", idx, k)
			}
		}
	}

	// Check that secrets do not leak
	for _, forbidden := range []string{fakeKeySecret, "secret-user-prompt-text", "secret_arg", "secret-assistant-response-1"} {
		if strings.Contains(string(evData), forbidden) {
			t.Errorf("evidence leaked secret: %s", forbidden)
		}
	}
}

func TestPreReserveRefusals(t *testing.T) {
	tmpDir := t.TempDir()
	expRoot := filepath.Join(tmpDir, "exp")
	sockDir := filepath.Join(tmpDir, "sock")
	fakeKeySecret := "sk-live-broker-test-secret-123"

	ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}
	defer ledger.Close()

	postCalls := 0
	fakePost := func(body []byte, key string) (int, map[string]string, []byte, error) {
		postCalls++
		return 200, nil, makeSSEStream("r", "", "", "", 1, 1, 2, "ok", false, nil, nil), nil
	}

	srv, err := responses.NewResponsesBrokerServer(ledger, fakeKeySecret, "refuse", 3, sockDir, expRoot, fakeGetOK, fakeCountOK, fakePost)
	if err != nil {
		t.Fatalf("NewResponsesBrokerServer error: %v", err)
	}
	defer srv.Close()

	invalidPayloads := []struct {
		name string
		body []byte
	}{
		{"wrong_model", []byte(`{"model":"gpt-5.6-terra","stream":true}`)},
		{"snapshot_model", []byte(`{"model":"gpt-6-luna-2026-01-01","stream":true}`)},
		{"effort_low", []byte(`{"model":"gpt-6-luna","reasoning":{"effort":"low"},"stream":true}`)},
		{"stream_false", []byte(`{"model":"gpt-6-luna","stream":false}`)},
		{"stream_missing", []byte(`{"model":"gpt-6-luna"}`)},
		{"background_true", []byte(`{"model":"gpt-6-luna","stream":true,"background":true}`)},
		{"tier_priority", []byte(`{"model":"gpt-6-luna","stream":true,"service_tier":"priority"}`)},
		{"mot_15", []byte(`{"model":"gpt-6-luna","stream":true,"max_output_tokens":15}`)},
		{"mot_1025", []byte(`{"model":"gpt-6-luna","stream":true,"max_output_tokens":1025}`)},
		{"mot_bool_true", []byte(`{"model":"gpt-6-luna","stream":true,"max_output_tokens":true}`)},
		{"hosted_web_search", []byte(`{"model":"gpt-6-luna","stream":true,"tools":[{"type":"web_search_preview"}]}`)},
		{"hosted_file_search", []byte(`{"model":"gpt-6-luna","stream":true,"tools":[{"type":"file_search"}]}`)},
		{"hosted_code_interpreter", []byte(`{"model":"gpt-6-luna","stream":true,"tools":[{"type":"code_interpreter"}]}`)},
		{"hosted_image_gen", []byte(`{"model":"gpt-6-luna","stream":true,"tools":[{"type":"image_generation"}]}`)},
		{"hosted_computer_use", []byte(`{"model":"gpt-6-luna","stream":true,"tools":[{"type":"computer_use_preview"}]}`)},
		{"hosted_remote_mcp", []byte(`{"model":"gpt-6-luna","stream":true,"tools":[{"type":"mcp"}]}`)},
		{"duplicate_json_key", []byte(`{"model":"gpt-6-luna","model":"gpt-6-luna","stream":true}`)},
	}

	for _, tc := range invalidPayloads {
		t.Run(tc.name, func(t *testing.T) {
			status, reply := srv.HandleFrameBytes(tc.body)
			if status != 400 {
				t.Errorf("[%s] expected status 400, got %d (reply: %s)", tc.name, status, string(reply))
			}
			if !strings.Contains(string(reply), "error") {
				t.Errorf("[%s] expected error in reply", tc.name)
			}
		})
	}

	if postCalls != 0 {
		t.Errorf("expected 0 post calls, got %d", postCalls)
	}
	if srv.RequestCounter() != 0 {
		t.Errorf("expected request counter 0, got %d", srv.RequestCounter())
	}

	st, _ := ledger.GetStatus()
	if st.TotalReservationsCount != 0 {
		t.Errorf("expected 0 reservations, got %d", st.TotalReservationsCount)
	}
	if st.Halted {
		t.Errorf("ledger unexpectedly halted")
	}
}

func TestPreflightRejections(t *testing.T) {
	rejected := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 400, nil, []byte(`{"error":{"message":"bad input"}}`), nil
	}
	tooLarge := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, nil, []byte(`{"object":"response.input_tokens","input_tokens":150001}`), nil
	}
	malformed := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, nil, []byte(`{"object":"response.input_tokens","input_tokens":true}`), nil
	}
	boom := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 0, nil, nil, errors.New("connection failed")
	}

	cases := []struct {
		name string
		fn   responses.CountTransportFunc
	}{
		{"rejected", rejected},
		{"too_large", tooLarge},
		{"malformed", malformed},
		{"boom", boom},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			expRoot := filepath.Join(tmpDir, "exp")
			sockDir := filepath.Join(tmpDir, "sock")
			ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
			if err != nil {
				t.Fatalf("failed to init ledger: %v", err)
			}
			defer ledger.Close()

			postCalls := 0
			fakePost := func(b []byte, k string) (int, map[string]string, []byte, error) {
				postCalls++
				return 200, nil, nil, nil
			}

			srv, err := responses.NewResponsesBrokerServer(ledger, "sk-test", "pf", 3, sockDir, expRoot, fakeGetOK, tc.fn, fakePost)
			if err != nil {
				t.Fatalf("failed to create server: %v", err)
			}
			defer srv.Close()

			req := []byte(`{"model":"gpt-6-luna","stream":true}`)
			status, reply := srv.HandleFrameBytes(req)
			if status != 400 {
				t.Errorf("expected status 400, got %d", status)
			}
			if !strings.Contains(string(reply), "preflight") {
				t.Errorf("expected 'preflight' in reply, got %s", string(reply))
			}
			if postCalls != 0 {
				t.Errorf("expected 0 post calls, got %d", postCalls)
			}
			if srv.RequestCounter() != 0 {
				t.Errorf("expected request counter 0, got %d", srv.RequestCounter())
			}
			st, _ := ledger.GetStatus()
			if st.TotalReservationsCount != 0 {
				t.Errorf("expected 0 reservations")
			}
			if st.Halted {
				t.Errorf("ledger unexpectedly halted")
			}
		})
	}
}

func TestPreflightBodyDropsGenerationOnlyFields(t *testing.T) {
	tmpDir := t.TempDir()
	expRoot := filepath.Join(tmpDir, "exp")
	sockDir := filepath.Join(tmpDir, "sock")
	ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}
	defer ledger.Close()

	var seenPreflight map[string]any
	captureCount := func(b []byte, k string) (int, map[string]string, []byte, error) {
		_ = json.Unmarshal(b, &seenPreflight)
		return 200, nil, []byte(`{"object":"response.input_tokens","input_tokens":42}`), nil
	}

	fakePost := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, makeSSEStream("r", "", "", "", 42, 10, 52, "ok", false, nil, nil), nil
	}

	srv, err := responses.NewResponsesBrokerServer(ledger, "sk-test", "pfbody", 3, sockDir, expRoot, fakeGetOK, captureCount, fakePost)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	req := []byte(`{"model":"gpt-6-luna","stream":true,"store":false,"input":[],"tools":[],"include":["reasoning.encrypted_content"],"prompt_cache_key":"x"}`)
	status, _ := srv.HandleFrameBytes(req)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	var keys []string
	for k := range seenPreflight {
		keys = append(keys, k)
	}
	expected := "input,model,tools"
	joined := strings.Join(keys, ",")
	if !strings.Contains(joined, "input") || !strings.Contains(joined, "model") || !strings.Contains(joined, "tools") || strings.Contains(joined, "store") || strings.Contains(joined, "include") {
		t.Errorf("unexpected preflight keys: %v (expected %s)", keys, expected)
	}
}

func TestMaxRequestsCap(t *testing.T) {
	tmpDir := t.TempDir()
	expRoot := filepath.Join(tmpDir, "exp")
	sockDir := filepath.Join(tmpDir, "sock")
	ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}
	defer ledger.Close()

	postCalls := 0
	fakePost := func(b []byte, k string) (int, map[string]string, []byte, error) {
		postCalls++
		return 200, map[string]string{"content-type": "text/event-stream"}, makeSSEStream(fmt.Sprintf("r_%d", postCalls), "", "", "", 10, 5, 15, "ok", false, nil, nil), nil
	}

	srv, err := responses.NewResponsesBrokerServer(ledger, "sk-test", "cap", 2, sockDir, expRoot, fakeGetOK, fakeCountOK, fakePost)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	req := []byte(`{"model":"gpt-6-luna","stream":true}`)
	s1, _ := srv.HandleFrameBytes(req)
	s2, _ := srv.HandleFrameBytes(req)
	s3, r3 := srv.HandleFrameBytes(req)

	if s1 != 200 || s2 != 200 {
		t.Errorf("expected first two to be 200, got %d and %d", s1, s2)
	}
	if s3 != 429 {
		t.Errorf("expected third to be 429, got %d", s3)
	}
	if !strings.Contains(string(r3), "max_requests_exceeded") {
		t.Errorf("expected max_requests_exceeded in reply: %s", string(r3))
	}
	if postCalls != 2 {
		t.Errorf("expected 2 post calls, got %d", postCalls)
	}

	st, _ := ledger.GetStatus()
	if st.TotalReservationsCount != 2 || st.SettledRequestsCount != 2 {
		t.Errorf("expected 2 reservations and settlements, got %d and %d", st.TotalReservationsCount, st.SettledRequestsCount)
	}
	if st.Halted {
		t.Errorf("ledger unexpectedly halted")
	}
}

func assertPostReserveFailure(t *testing.T, postFn responses.PostTransportFunc, expectedOutcome string, outboundMOT int) {
	tmpDir := t.TempDir()
	expRoot := filepath.Join(tmpDir, "exp")
	sockDir := filepath.Join(tmpDir, "sock")
	fakeKeySecret := "sk-live-broker-test-secret-123"

	ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
	if err != nil {
		t.Fatalf("failed to init ledger: %v", err)
	}
	defer ledger.Close()

	srv, err := responses.NewResponsesBrokerServer(ledger, fakeKeySecret, "fail", 3, sockDir, expRoot, fakeGetOK, fakeCountOK, postFn)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	req := map[string]any{"model": responses.PinnedModel, "stream": true}
	if outboundMOT > 0 {
		req["max_output_tokens"] = outboundMOT
	}
	reqBytes, _ := json.Marshal(req)

	status, reply := srv.HandleFrameBytes(reqBytes)
	if status != 502 {
		t.Errorf("expected status 502, got %d", status)
	}
	if strings.Contains(string(reply), "event: response.completed") {
		t.Errorf("SSE bytes unexpectedly delivered in error reply: %s", string(reply))
	}
	if !strings.Contains(string(reply), "error") {
		t.Errorf("expected error in reply: %s", string(reply))
	}
	if !srv.StopRequested() {
		t.Errorf("expected stopRequested to be true")
	}

	st, _ := ledger.GetStatus()
	if expectedOutcome != "SETTLEMENT_COMMITTED_HANDLE_DISABLED" {
		if !st.Halted {
			t.Errorf("expected ledger to be halted")
		}
		expectedRetained := responses.ReservationFor(1200)
		if st.RetainedFailedMicros != expectedRetained {
			t.Errorf("expected retained failed %d, got %d", expectedRetained, st.RetainedFailedMicros)
		}
		if st.HasPendingReservation {
			t.Errorf("expected no pending reservation")
		}
	}

	evPath := filepath.Join(expRoot, "live-broker-fail.jsonl")
	evData, err := os.ReadFile(evPath)
	if err != nil {
		t.Fatalf("failed to read evidence: %v", err)
	}
	var rec map[string]any
	_ = json.Unmarshal([]byte(strings.Split(string(evData), "\n")[0]), &rec)
	if rec["outcome_code"] != expectedOutcome {
		t.Errorf("expected outcome %s, got %v", expectedOutcome, rec["outcome_code"])
	}
	if strings.Contains(string(evData), fakeKeySecret) {
		t.Errorf("evidence contains secret key")
	}
}

func TestMalformedSSEHaltsLedger(t *testing.T) {
	postFn := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, []byte("event: response.created\ndata: {not-valid-json}\n\n"), nil
	}
	assertPostReserveFailure(t, postFn, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestTwoCompletedEventsHaltsLedger(t *testing.T) {
	compExtra := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_dup\",\"status\":\"completed\",\"model\":\"gpt-6-luna\",\"service_tier\":\"default\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"total_tokens\":15}}}\n\n"
	sse := makeSSEStream("resp_dup", "", "", "", 10, 5, 15, "ok", false, []string{compExtra}, nil)
	postFn := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sse, nil
	}
	assertPostReserveFailure(t, postFn, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestResponseFailedEventHaltsLedger(t *testing.T) {
	failExtra := "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"r1\",\"status\":\"failed\"}}\n\n"
	sse := makeSSEStream("r1", "", "", "", 10, 5, 15, "ok", false, []string{failExtra}, nil)
	postFn := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sse, nil
	}
	assertPostReserveFailure(t, postFn, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestResponseIncompleteEventHaltsLedger(t *testing.T) {
	incExtra := "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r1\",\"status\":\"incomplete\"}}\n\n"
	sse := makeSSEStream("r1", "", "", "", 10, 5, 15, "ok", false, []string{incExtra}, nil)
	postFn := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sse, nil
	}
	assertPostReserveFailure(t, postFn, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestErrorEventHaltsLedger(t *testing.T) {
	errExtra := "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"server error\"}}\n\n"
	sse := makeSSEStream("r1", "", "", "", 10, 5, 15, "ok", false, []string{errExtra}, nil)
	postFn := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sse, nil
	}
	assertPostReserveFailure(t, postFn, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestTrailingJunkAfterCompletedHaltsLedger(t *testing.T) {
	sse1 := makeSSEStream("r1", "", "", "", 10, 5, 15, "ok", false, nil, []byte("event: extra\ndata: {\"type\":\"extra\"}\n\n"))
	assertPostReserveFailure(t, func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sse1, nil
	}, "INVALID_RECEIPT_EVIDENCE", 0)

	sse2 := makeSSEStream("r1", "", "", "", 10, 5, 15, "ok", true, nil, []byte("JUNK_AFTER_DONE\n\n"))
	assertPostReserveFailure(t, func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sse2, nil
	}, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestUsageMismatchAndOutputBoundHaltsLedger(t *testing.T) {
	// total != in + out (10 + 5 != 16)
	sseSum := makeSSEStream("r1", "", "", "", 10, 5, 16, "ok", false, nil, nil)
	assertPostReserveFailure(t, func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sseSum, nil
	}, "INVALID_RECEIPT_EVIDENCE", 0)

	// output_tokens (33) > outbound max_output_tokens (32)
	sseOver := makeSSEStream("r1", "", "", "", 10, 33, 43, "ok", false, nil, nil)
	assertPostReserveFailure(t, func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sseOver, nil
	}, "INVALID_RECEIPT_EVIDENCE", 32)
}

func TestModelSnapshotOrWrongTierHaltsLedger(t *testing.T) {
	sseSnap := makeSSEStream("r1", "gpt-6-luna-2026-01-01", "", "", 10, 5, 15, "ok", false, nil, nil)
	assertPostReserveFailure(t, func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sseSnap, nil
	}, "INVALID_RECEIPT_EVIDENCE", 0)

	sseTier := makeSSEStream("r1", "", "priority", "", 10, 5, 15, "ok", false, nil, nil)
	assertPostReserveFailure(t, func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 200, map[string]string{"content-type": "text/event-stream"}, sseTier, nil
	}, "INVALID_RECEIPT_EVIDENCE", 0)
}

func TestTransportExceptionRecordsFailureAndHaltsLedger(t *testing.T) {
	postFn := func(b []byte, k string) (int, map[string]string, []byte, error) {
		return 0, nil, nil, errors.New("upstream read timeout")
	}
	assertPostReserveFailure(t, postFn, "REQUEST_TRANSPORT_FAILURE", 0)
}

func TestEvidenceRecordSHA256(t *testing.T) {
	data := []byte("hello world")
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Fatalf("sha256 mismatch")
	}
}

func TestReservationForModelRegression(t *testing.T) {
	// Zero tokens: minimum reservation with margin
	amt, ok := responses.ReservationForModel(responses.PinnedModel, 0)
	expectedZero := responses.ReservationInputMarginTokens*1 + responses.MaxOutputTokens*1
	if !ok || amt != expectedZero {
		t.Fatalf("expected %d for 0 tokens, got %d, %v", expectedZero, amt, ok)
	}

	// Unknown size sentinel (-1) fits built-in model
	amt, ok = responses.ReservationForModel(responses.PinnedModel, -1)
	if !ok || amt != budget.ReservationAmountMicros {
		t.Fatalf("expected ReservationAmountMicros for -1 on PinnedModel, got %d, %v", amt, ok)
	}

	// Unknown size sentinel (-1) on expensive model exceeds ReservationAmountMicros
	amt, ok = responses.ReservationForModel("claude-sonnet-5-5", -1)
	if ok || amt != 0 {
		t.Fatalf("expected rejection for -1 on claude-sonnet-5-5, got %d, %v", amt, ok)
	}

	// Negative bounds: tokens < -1 must be rejected
	for _, badTokens := range []int{-2, -5, -100, -1_000_000} {
		if amt, ok := responses.ReservationForModel(responses.PinnedModel, badTokens); ok || amt != 0 {
			t.Fatalf("expected rejection for negative input %d, got %d, %v", badTokens, amt, ok)
		}
	}

	// Upper bound: countedInput > MaxInputTokens must be rejected
	if amt, ok := responses.ReservationForModel(responses.PinnedModel, budget.MaxInputTokens+1); ok || amt != 0 {
		t.Fatalf("expected rejection for input exceeding MaxInputTokens, got %d, %v", amt, ok)
	}

	// Capping of estimated input at MaxInputTokens:
	// countedInput = 1_000_000 produces estInput > budget.MaxInputTokens without cap.
	// With cap to budget.MaxInputTokens, cost is budget.MaxInputTokens*1 + responses.MaxOutputTokens*1 <= budget.ReservationAmountMicros.
	amt, ok = responses.ReservationForModel(responses.PinnedModel, 1_000_000)
	expectedCapped := budget.MaxInputTokens*1 + responses.MaxOutputTokens*1
	if !ok || amt != expectedCapped {
		t.Fatalf("expected %d with capped estInput, got %d, %v", expectedCapped, amt, ok)
	}

	// Reject margin-inclusive cost above ReservationAmountMicros instead of clamping:
	// A model with 10 USD/MTok in and 10 USD/MTok out.
	// countedInput = 100_000 (within preflight limits): raw cost fits, but margin cost exceeds budget.ReservationAmountMicros.
	// Must be rejected (not clamped to ReservationAmountMicros)!
	testModel := "test-model-margin-reject"
	budget.ModelRates[testModel] = budget.ModelRate{InputRateMicros: 10, OutputRateMicros: 10, ServiceTier: "default"}
	t.Cleanup(func() { delete(budget.ModelRates, testModel) })

	amt, ok = responses.ReservationForModel(testModel, 100_000)
	if ok || amt != 0 {
		t.Fatalf("expected rejection for margin-inclusive cost exceeding ceiling, got %d, %v", amt, ok)
	}

	// Unpriced model
	if amt, ok := responses.ReservationForModel("unpriced-model-xyz", 100); ok || amt != 0 {
		t.Fatalf("expected rejection for unpriced model, got %d, %v", amt, ok)
	}

	// Invalid rate (<= 0)
	zeroRateModel := "test-zero-rate-model"
	budget.ModelRates[zeroRateModel] = budget.ModelRate{InputRateMicros: 0, OutputRateMicros: 1, ServiceTier: "default"}
	t.Cleanup(func() { delete(budget.ModelRates, zeroRateModel) })
	if amt, ok := responses.ReservationForModel(zeroRateModel, 100); ok || amt != 0 {
		t.Fatalf("expected rejection for zero input rate, got %d, %v", amt, ok)
	}
}
