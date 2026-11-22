package neutral

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/broker/adapters"
	"github.com/reviaro/guardfil/internal/broker/budget"
)

var openAIReply = []byte(`{
  "id": "resp_1",
  "status": "completed",
  "model": "gpt-6-luna",
  "service_tier": "default",
  "output": [
    {"type": "message", "content": [{"type": "output_text", "text": "Done."}]},
    {"type": "function_call", "call_id": "call_9", "name": "place_order", "arguments": "{\"symbol\":\"ACME\",\"quantity\":5,\"limit_price\":9.95}"}
  ],
  "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150}
}`)

var geminiReplyWithSig = []byte(`{
  "responseId": "r1",
  "modelVersion": "gemini-3.6-flash-001",
  "candidates": [{
    "content": {
      "role": "model",
      "parts": [
        {"functionCall": {"name": "place_order", "args": {"symbol": "ACME"}}, "thoughtSignature": "c2lnbmF0dXJl"}
      ]
    },
    "finishReason": "STOP"
  }],
  "usageMetadata": {"promptTokenCount": 40, "candidatesTokenCount": 8, "thoughtsTokenCount": 30}
}`)

func sampleNeutralReq(model string) map[string]any {
	if model == "" {
		model = "openai:gpt-6-luna"
	}
	return map[string]any{
		"model": model,
		"messages": []any{
			map[string]any{"role": "user", "content": "Buy 5 ACME at 9.95"},
		},
		"tools": []any{
			map[string]any{"name": "place_order", "parameters": map[string]any{"type": "object"}},
		},
		"max_output_tokens": 64,
	}
}

type fakeTransport struct {
	sent       []*adapters.HTTPRequest
	auths      []map[string]string
	statuses   []int
	replies    [][]byte
	preflights int
	reqCount   int
}

func (f *fakeTransport) call(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
	if strings.HasSuffix(req.Path, ":countTokens") || strings.HasSuffix(req.Path, "/count_tokens") {
		f.preflights++
		return 200, []byte(`{"totalTokens": 10, "input_tokens": 10}`), nil
	}
	f.reqCount++
	f.sent = append(f.sent, req)
	f.auths = append(f.auths, auth)
	if len(f.replies) > 0 {
		r := f.replies[0]
		f.replies = f.replies[1:]
		st := f.statuses[0]
		f.statuses = f.statuses[1:]
		return st, r, nil
	}
	reply := bytes.Replace(openAIReply, []byte(`"resp_1"`), []byte(fmt.Sprintf(`"resp_%d"`, f.reqCount)), 1)
	return 200, reply, nil
}

func setupTestServer(t *testing.T, liveProviders map[string]bool, priorSpend map[string]int) (*NeutralBrokerServer, map[string]*budget.BudgetLedger, *fakeTransport, func()) {
	tempDir, err := os.MkdirTemp("", "test_neutral_broker_")
	if err != nil {
		t.Fatal(err)
	}

	ledgers := make(map[string]*budget.BudgetLedger)
	for _, p := range []string{"openai", "gemini", "anthropic"} {
		pDir := filepath.Join(tempDir, p)
		l, err := budget.Initialize(pDir, "exp-"+p)
		if err != nil {
			t.Fatal(err)
		}
		ledgers[p] = l
	}

	ft := &fakeTransport{}
	keys := map[string]string{
		"openai":    "sk-test-KEY",
		"gemini":    "gk",
		"anthropic": "ak",
	}

	srv, err := NewNeutralBrokerServer(
		ledgers,
		"t",
		4,
		keys,
		ft.call,
		"",
		liveProviders,
		DefaultProviderModels,
		priorSpend,
	)
	if err != nil {
		t.Fatal(err)
	}
	srv.sleepFn = func(d time.Duration) {}

	cleanup := func() {
		for _, l := range ledgers {
			_ = l.Close()
		}
		_ = os.RemoveAll(tempDir)
	}
	return srv, ledgers, ft, cleanup
}

func TestOpenAIRoundTripChargesLedger(t *testing.T) {
	srv, ledgers, ft, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	raw, _ := json.Marshal(sampleNeutralReq("openai:gpt-6-luna"))
	res := srv.Handle(raw)
	if res["ok"] != true {
		t.Fatalf("expected ok true, got: %v", res)
	}

	reply := res["reply"].(*adapters.NeutralReply)
	if len(reply.ToolCalls) != 1 || reply.ToolCalls[0].Name != "place_order" {
		t.Fatalf("unexpected reply: %+v", reply)
	}
	lp := fmt.Sprint(reply.ToolCalls[0].Arguments["limit_price"])
	if lp != "9.95" {
		t.Errorf("expected limit_price 9.95, got %v", lp)
	}

	// Verify ledger state
	st, err := ledgers["openai"].GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.SettledRequestsCount != 1 {
		t.Errorf("expected 1 settled request, got %d", st.SettledRequestsCount)
	}
	if st.CommittedSpendMicros != 150 { // 120 in + 30 out
		t.Errorf("expected 150 spend, got %d", st.CommittedSpendMicros)
	}

	// Verify key sent
	if ft.auths[0]["Authorization"] != "Bearer sk-test-KEY" {
		t.Errorf("auth header mismatch: %v", ft.auths[0])
	}
}

func TestOtherProvidersNotLive(t *testing.T) {
	live := map[string]bool{"openai": true}
	srv, ledgers, _, cleanup := setupTestServer(t, live, nil)
	defer cleanup()

	for _, m := range []string{"anthropic:claude-sonnet-5-5", "gemini:gemini-3.6-flash"} {
		raw, _ := json.Marshal(sampleNeutralReq(m))
		res := srv.Handle(raw)
		if res["ok"] != false {
			t.Errorf("%s: expected ok false, got: %v", m, res)
		}
		errMsg, _ := res["error"].(string)
		if !strings.Contains(errMsg, "not enabled for live calls") {
			t.Errorf("%s: unexpected error: %s", m, errMsg)
		}
	}

	st, _ := ledgers["openai"].GetStatus()
	if st.TotalReservationsCount != 0 {
		t.Errorf("reservations made on refusal: %d", st.TotalReservationsCount)
	}
}

func TestGeminiLiveModelAndSignatures(t *testing.T) {
	srv, ledgers, ft, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	ft.statuses = []int{200, 200}
	geminiReply2 := bytes.Replace(geminiReplyWithSig, []byte(`"r1"`), []byte(`"r2"`), 1)
	ft.replies = [][]byte{geminiReplyWithSig, geminiReply2}

	raw, _ := json.Marshal(sampleNeutralReq("gemini:gemini-3.6-flash"))
	res := srv.Handle(raw)
	if res["ok"] != true {
		t.Fatalf("gemini request 1 failed: %v", res)
	}

	st, _ := ledgers["gemini"].GetStatus()
	if st.SettledRequestsCount != 1 {
		t.Errorf("gemini settled count mismatch: %d", st.SettledRequestsCount)
	}
	// 40 in * 2 + 38 out * 8 = 80 + 304 = 384
	if st.CommittedSpendMicros != 384 {
		t.Errorf("gemini cost mismatch: %d", st.CommittedSpendMicros)
	}

	// Second request carrying tool response follows up with thoughtSignature
	reply := res["reply"].(*adapters.NeutralReply)
	call := reply.ToolCalls[0]
	follow := sampleNeutralReq("gemini:gemini-3.6-flash")
	follow["messages"] = []any{
		map[string]any{"role": "user", "content": "Buy"},
		map[string]any{"role": "assistant", "content": "", "tool_calls": []any{
			map[string]any{"id": call.ID, "name": call.Name, "arguments": call.Arguments},
		}},
		map[string]any{"role": "tool", "tool_call_id": call.ID, "name": call.Name, "content": "ok"},
	}
	rawFollow, _ := json.Marshal(follow)
	res2 := srv.Handle(rawFollow)
	if res2["ok"] != true {
		t.Fatalf("gemini follow-up request failed: %v", res2)
	}

	// Verify thoughtSignature was echoed in outbound request
	lastSent := ft.sent[len(ft.sent)-1]
	if !strings.Contains(string(lastSent.Body), `"thoughtSignature":"c2lnbmF0dXJl"`) {
		t.Errorf("thoughtSignature missing in sent body: %s", string(lastSent.Body))
	}
}

func TestGeminiPreflightRefusalSpendsNothing(t *testing.T) {
	srv, ledgers, _, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	srv.transport = func(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
		if strings.HasSuffix(req.Path, ":countTokens") {
			return 400, []byte(`{"error": {"code": 400, "message": "Invalid JSON payload"}}`), nil
		}
		t.Fatal("paid call after a refused preflight!")
		return 500, nil, nil
	}

	raw, _ := json.Marshal(sampleNeutralReq("gemini:gemini-3.6-flash"))
	res := srv.Handle(raw)
	if res["ok"] != false {
		t.Fatalf("expected ok false, got %v", res)
	}
	errMsg, _ := res["error"].(string)
	if !strings.Contains(errMsg, "before any spend") || !strings.Contains(errMsg, "Invalid JSON payload") {
		t.Errorf("unexpected error message: %s", errMsg)
	}

	st, _ := ledgers["gemini"].GetStatus()
	if st.TotalReservationsCount != 0 {
		t.Errorf("expected 0 reservations, got %d", st.TotalReservationsCount)
	}
	if srv.stopped {
		t.Errorf("expected broker not to be stopped on preflight refusal")
	}
}

func TestTransientErrorsRetriedInOneReservation(t *testing.T) {
	srv, ledgers, _, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	responses := []struct {
		status int
		body   []byte
	}{
		{status: 503, body: []byte(`{"error":{"message":"overloaded"}}`)},
		{status: 429, body: []byte(`{}`)},
		{status: 200, body: openAIReply},
	}
	idx := 0
	srv.transport = func(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
		r := responses[idx]
		idx++
		return r.status, r.body, nil
	}

	raw, _ := json.Marshal(sampleNeutralReq("openai:gpt-6-luna"))
	res := srv.Handle(raw)
	if res["ok"] != true {
		t.Fatalf("expected retry success, got %v", res)
	}

	st, _ := ledgers["openai"].GetStatus()
	if st.TotalReservationsCount != 1 || st.SettledRequestsCount != 1 {
		t.Errorf("expected 1 reservation and 1 settlement, got res=%d set=%d", st.TotalReservationsCount, st.SettledRequestsCount)
	}

	// Always 503 -> settles at 0 tokens
	srvAlways, ledgersAlways, _, cleanupAlways := setupTestServer(t, nil, nil)
	defer cleanupAlways()
	srvAlways.transport = func(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
		return 503, []byte(`{}`), nil
	}
	resAlways := srvAlways.Handle(raw)
	if resAlways["ok"] != false {
		t.Fatalf("expected ok false, got %v", resAlways)
	}
	errAlways, _ := resAlways["error"].(string)
	if !strings.Contains(errAlways, "nothing was billed") {
		t.Errorf("expected 'nothing was billed' message, got %s", errAlways)
	}
	stAlways, _ := ledgersAlways["openai"].GetStatus()
	if stAlways.TotalSpendMicros != 0 {
		t.Errorf("expected 0 spend, got %d", stAlways.TotalSpendMicros)
	}
	if stAlways.SettledRequestsCount != 1 {
		t.Errorf("expected 1 zero-settlement, got %d", stAlways.SettledRequestsCount)
	}
	if srvAlways.stopped {
		t.Errorf("expected srvAlways not stopped")
	}
}

func TestRetiredLedgersCountTowardProviderCeiling(t *testing.T) {
	// Provider ceiling is 2,000,000. Prior spend 1,999,000.
	// Reservation for gemini with max_output_tokens 64 is ~2000 uUSD.
	// 1,999,000 + 2000 > 2,000,000 -> provider ceiling exceeded!
	prior := map[string]int{"gemini": 1_999_000}
	srv, ledgers, _, cleanup := setupTestServer(t, nil, prior)
	defer cleanup()

	raw, _ := json.Marshal(sampleNeutralReq("gemini:gemini-3.6-flash"))
	res := srv.Handle(raw)
	if res["ok"] != false {
		t.Fatalf("expected ceiling refusal, got %v", res)
	}
	errMsg, _ := res["error"].(string)
	if !strings.Contains(errMsg, "across all its ledgers") {
		t.Errorf("unexpected error: %s", errMsg)
	}
	st, _ := ledgers["gemini"].GetStatus()
	if st.TotalReservationsCount != 0 {
		t.Errorf("expected 0 reservations, got %d", st.TotalReservationsCount)
	}
}

func TestRequestLimit(t *testing.T) {
	srv, _, _, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	raw, _ := json.Marshal(sampleNeutralReq("openai:gpt-6-luna"))
	// maxRequests is 4
	for i := 0; i < 4; i++ {
		res := srv.Handle(raw)
		if res["ok"] != true {
			t.Fatalf("req %d failed: %v", i, res)
		}
	}
	// 5th request should fail with limit error
	res5 := srv.Handle(raw)
	if res5["ok"] != false {
		t.Fatalf("expected 5th request to fail, got %v", res5)
	}
	errMsg, _ := res5["error"].(string)
	if !strings.Contains(errMsg, "limit") {
		t.Errorf("expected limit error, got %s", errMsg)
	}
}

func TestSocketAndClient(t *testing.T) {
	srv, _, _, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	tempDir, err := os.MkdirTemp("", "test_sock_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "b.sock")
	go func() {
		_ = srv.Serve(sockPath)
	}()

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial unix socket: %v", err)
	}
	defer conn.Close()

	reqBytes, _ := json.Marshal(sampleNeutralReq("openai:gpt-6-luna"))
	_, _ = conn.Write(append(reqBytes, '\n'))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("failed to read reply from socket: %v", err)
	}

	var res map[string]any
	if err := json.Unmarshal(line, &res); err != nil || res["ok"] != true {
		t.Fatalf("expected ok true reply from socket, got %s", string(line))
	}
}

// Audit finding 5: a 4xx the provider does not bill (here from a tool schema
// OpenAI rejects; OpenAI has no free preflight) halted the shared ledger.
func TestProviderRefusalSettlesAtZeroAndKeepsLedger(t *testing.T) {
	srv, ledgers, ft, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()
	ft.statuses = []int{400}
	ft.replies = [][]byte{[]byte(`{"error":{"message":"Invalid schema for function 't'"}}`)}
	raw, _ := json.Marshal(sampleNeutralReq("openai:gpt-6-luna"))
	res := srv.Handle(raw)
	if res["ok"] != false || !strings.Contains(fmt.Sprint(res["error"]), "nothing was billed") {
		t.Fatalf("refusal reply: %v", res)
	}
	st, _ := ledgers["openai"].GetStatus()
	if st.Halted || st.CommittedSpendMicros != 0 || st.SettledRequestsCount != 1 {
		t.Fatalf("ledger after a 400: %+v", st)
	}
	// The next request still goes through.
	res = srv.Handle(raw)
	if res["ok"] != true {
		t.Fatalf("a later request failed: %v", res)
	}
}

func TestModelBindingAndPrefixRejection(t *testing.T) {
	// 1. Explicit known Gemini alias preserves reply.Model as provider-reported metadata,
	// while settlement receipt is bound to requested model.
	srv, ledgers, ft, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()
	ft.statuses = []int{200}
	ft.replies = [][]byte{geminiReplyWithSig} // modelVersion is gemini-3.6-flash-001

	raw, _ := json.Marshal(sampleNeutralReq("gemini:gemini-3.6-flash"))
	res := srv.Handle(raw)
	if res["ok"] != true {
		t.Fatalf("expected ok, got %v", res)
	}
	rep, ok := res["reply"].(*adapters.NeutralReply)
	if !ok || rep.Model != "gemini-3.6-flash-001" {
		t.Fatalf("expected provider-reported model preserved as gemini-3.6-flash-001, got %v", res["reply"])
	}
	st, _ := ledgers["gemini"].GetStatus()
	if st.SettledRequestsCount != 1 {
		t.Fatalf("expected 1 settled, got %d", st.SettledRequestsCount)
	}
	if st.CommittedSpendMicros != 384 {
		t.Fatalf("expected 384 spend from gemini-3.6-flash rate, got %d", st.CommittedSpendMicros)
	}

	// 2. Generic prefix matching rejected (e.g. gemini-3.6-flash-preview is not in KnownGeminiAliases)
	srv2, ledgers2, ft2, cleanup2 := setupTestServer(t, nil, nil)
	defer cleanup2()
	ft2.statuses = []int{200}
	previewReply := bytes.Replace(geminiReplyWithSig, []byte(`"gemini-3.6-flash-001"`), []byte(`"gemini-3.6-flash-preview"`), 1)
	ft2.replies = [][]byte{previewReply}

	res2 := srv2.Handle(raw)
	if res2["ok"] != false {
		t.Fatalf("expected failure for unaliased prefix model, got %v", res2)
	}
	st2, _ := ledgers2["gemini"].GetStatus()
	if !st2.Halted || st2.HaltReason == nil || *st2.HaltReason != "RECEIPT_MODEL_MISMATCH" {
		t.Fatalf("expected halted with RECEIPT_MODEL_MISMATCH, got %+v", st2)
	}

	// 3. A different priced model must still be bound to the request.
	srv3, ledgers3, ft3, cleanup3 := setupTestServer(t, nil, nil)
	defer cleanup3()
	ft3.statuses = []int{200}
	wrongOpenAIReply := bytes.Replace(openAIReply, []byte(`"gpt-6-luna"`), []byte(`"gemini-3.6-flash"`), 1)
	ft3.replies = [][]byte{wrongOpenAIReply}

	rawOpenAI, _ := json.Marshal(sampleNeutralReq("openai:gpt-6-luna"))
	res3 := srv3.Handle(rawOpenAI)
	if res3["ok"] != false {
		t.Fatalf("expected failure for mismatched reply model, got %v", res3)
	}
	st3, _ := ledgers3["openai"].GetStatus()
	if !st3.Halted || st3.HaltReason == nil || *st3.HaltReason != "RECEIPT_MODEL_MISMATCH" {
		t.Fatalf("expected halted with RECEIPT_MODEL_MISMATCH, got %+v", st3)
	}
}

func TestServeStopsPromptlyOnRequestStop(t *testing.T) {
	srv, _, _, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	sockDir, err := os.MkdirTemp("", "gf-neu-stop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "b.sock")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(sockPath)
	}()

	deadline := time.Now().Add(2 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		srv.stopMu.Lock()
		ready = srv.listener != nil
		srv.stopMu.Unlock()
		if ready {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ready {
		srv.RequestStop()
		t.Fatal("Serve did not start listening within 2s")
	}
	// Let the Serve goroutine block inside Accept().
	time.Sleep(20 * time.Millisecond)

	srv.RequestStop()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned unexpected error on stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit promptly after RequestStop")
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket path %s to be removed on exit, stat err=%v", sockPath, err)
	}
}

func TestRequestStopBeforeServe(t *testing.T) {
	srv, _, _, cleanup := setupTestServer(t, nil, nil)
	defer cleanup()

	sockDir, err := os.MkdirTemp("", "gf-neu-prestop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "b.sock")

	srv.RequestStop()
	if err := srv.Serve(sockPath); err != nil {
		t.Fatalf("expected nil from Serve after RequestStop, got %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected no socket file %s after pre-stop, stat err=%v", sockPath, err)
	}
}

func TestRunNeutralBrokerRefusesWhenAnyProviderLegacyUnmigrated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDFIL_OWNER_SOCKET", "")
	t.Setenv("GUARDFIL_SESSION_ID", "")

	credDir := filepath.Join(home, ".config/guardfil/credentials.d")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "openai-api-key"), []byte("sk-fake\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "gemini-api-key"), []byte("gk-fake\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Clean v2 gemini ledger + unmigrated legacy openai ledger -> must fail closed!
	stateRoot := filepath.Join(home, ".local/state/guardfil")
	lg, err := budget.OpenProviderLedger(stateRoot, "gemini", true)
	if err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()

	spec := budget.ProviderLedgerSpecs["openai"]
	legacyRoot := filepath.Join(stateRoot, spec.LegacyDir)
	if err := os.MkdirAll(legacyRoot, 0700); err != nil {
		t.Fatal(err)
	}
	lo, err := budget.Initialize(filepath.Join(legacyRoot, "ledger"), spec.LegacyID)
	if err != nil {
		t.Fatal(err)
	}
	_ = lo.Close()

	err = RunNeutralBroker(filepath.Join(t.TempDir(), "sock"), "legacyrefuse", 2, false)
	if !errors.Is(err, budget.ErrLedgerMigrationRequired) {
		t.Fatalf("expected ErrLedgerMigrationRequired, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, spec.TargetDir)); !os.IsNotExist(statErr) {
		t.Fatalf("openai target dir created despite unmigrated legacy")
	}
}
