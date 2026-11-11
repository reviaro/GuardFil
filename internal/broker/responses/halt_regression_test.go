package responses_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/responses"
)

// Audit finding 5: a provider 400 (e.g. an agent's unknown field) or a reply
// cut off at max_output_tokens halted the shared ledger for good.
func TestUnbilledStatusAndCutOffDoNotHaltLedger(t *testing.T) {
	tmp := t.TempDir()
	expRoot := filepath.Join(tmp, "exp")
	ledger, err := budget.Initialize(filepath.Join(expRoot, "ledger"), budget.DefaultExperimentID)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	cutOff := strings.NewReplacer(
		"event: response.completed", "event: response.incomplete",
		`"type":"response.completed"`, `"type":"response.incomplete"`,
		`"incomplete_details":null`, `"incomplete_details":{"reason":"max_output_tokens"}`,
	).Replace(string(makeSSEStream("resp_cut", "", "", "incomplete", 20, 16, 36, "partial", true, nil, nil)))
	replies := []struct {
		status int
		body   []byte
	}{
		{400, []byte(`{"error":{"code":"unknown_parameter","param":"zz_dummy"}}`)},
		{200, []byte(cutOff)},
		{200, makeSSEStream("resp_ok", "", "", "completed", 10, 5, 15, "ok", true, nil, nil)},
	}
	post := func(b []byte, k string) (int, map[string]string, []byte, error) {
		r := replies[0]
		replies = replies[1:]
		return r.status, map[string]string{"content-type": "text/event-stream"}, r.body, nil
	}
	srv, err := responses.NewResponsesBrokerServer(ledger, "sk-test-secret-0123456789", "halt", 5, filepath.Join(tmp, "sock"), expRoot, fakeGetOK, fakeCountOK, post)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	send := func(req map[string]any) int {
		b, _ := json.Marshal(req)
		st, _ := srv.HandleFrameBytes(b)
		return st
	}

	if st := send(map[string]any{"model": responses.PinnedModel, "stream": true, "zz_dummy": 1}); st != 400 {
		t.Fatalf("400 reply: broker returned %d", st)
	}
	if st := send(map[string]any{"model": responses.PinnedModel, "stream": true, "max_output_tokens": 16}); st != 200 {
		t.Fatalf("cut-off reply: broker returned %d", st)
	}
	if st := send(map[string]any{"model": responses.PinnedModel, "stream": true}); st != 200 {
		t.Fatalf("a later request was refused (%d): the ledger halted", st)
	}
	s, err := ledger.GetStatus()
	if err != nil || s.Halted {
		t.Fatalf("ledger halted: %+v %v", s, err)
	}
	if s.SettledRequestsCount != 3 {
		t.Fatalf("want 3 settlements (zero, cut-off usage, normal), got %+v", s)
	}
}

// Stored provider state is refused before any spend.
func TestStoredProviderStateRefused(t *testing.T) {
	for _, extra := range []map[string]any{
		{"prompt": map[string]any{"id": "pmpt_dummy"}},
		{"previous_response_id": "resp_dummy"},
		{"conversation": "conv_dummy"},
		{"store": true},
	} {
		req := map[string]any{"model": responses.PinnedModel, "stream": true}
		for k, v := range extra {
			req[k] = v
		}
		b, _ := json.Marshal(req)
		if r := responses.ValidateAndPrepareRequest(b); r.ErrorReason == "" {
			t.Errorf("%v: accepted", extra)
		}
	}
	b, _ := json.Marshal(map[string]any{"model": responses.PinnedModel, "stream": true, "store": false})
	if r := responses.ValidateAndPrepareRequest(b); r.ErrorReason != "" {
		t.Errorf("store:false refused: %s", r.ErrorReason)
	}
}
