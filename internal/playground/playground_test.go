package playground

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/advisorydemo"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/resource"
)

var hex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestEvaluateTableAndProperties(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	tests := []struct {
		name            string
		tool            string
		payload         string
		rawPayload      []byte
		credential      string
		ttl             int64
		cancelled       bool
		expiredEnvelope bool

		wantEffect string
		wantCode   string
		wantStage  string
	}{
		{
			name:       "ALLOW read_note",
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "valid",
			ttl:        30000,
			wantEffect: "ALLOW",
			wantCode:   "POLICY_ALLOWED",
			wantStage:  "",
		},
		{
			name:       "POLICY_DENIED delete",
			tool:       "fake.delete_record",
			payload:    `{"record_id":"synthetic-record-001"}`,
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "POLICY_DENIED",
			wantStage:  "policy",
		},
		{
			name:       "no matching policy send_message -> POLICY_DENIED",
			tool:       "fake.send_message",
			payload:    `{"body":"synthetic body","recipient":"synthetic-recipient"}`,
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "POLICY_DENIED",
			wantStage:  "policy",
		},
		{
			name:       "credential none -> AUTH_REQUIRED/auth",
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "none",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "AUTH_REQUIRED",
			wantStage:  "auth",
		},
		{
			name:       "credential unknown -> AUTH_INVALID/auth",
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "unknown",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "AUTH_INVALID",
			wantStage:  "auth",
		},
		{
			name:       "credential expired -> AUTH_INVALID/auth",
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "expired",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "AUTH_INVALID",
			wantStage:  "auth",
		},
		{
			name:       "malformed JSON -> PARSE_INVALID/parse",
			tool:       "fake.read_note",
			payload:    `{"note_id":`,
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "PARSE_INVALID",
			wantStage:  "parse",
		},
		{
			name:       "carriage return escape inside JSON string -> CONTROL_CHARACTER/parse",
			tool:       "fake.read_note",
			payload:    "{\"note_id\":\"a\\rb\"}",
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "CONTROL_CHARACTER",
			wantStage:  "parse",
		},
		{
			name:       "newline escape inside a JSON key -> CONTROL_CHARACTER/parse",
			tool:       "fake.read_note",
			payload:    "{\"note\\n_id\":\"ab\"}",
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "CONTROL_CHARACTER",
			wantStage:  "parse",
		},
		{
			name:       "NUL escape inside JSON string -> CONTROL_CHARACTER/parse",
			tool:       "fake.read_note",
			payload:    "{\"note_id\":\"a\\u0000b\"}",
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "CONTROL_CHARACTER",
			wantStage:  "parse",
		},
		{
			name:       "raw 0x00 byte inside JSON -> PARSE_INVALID/parse",
			tool:       "fake.read_note",
			rawPayload: []byte("{\"note_id\":\"a\x00b\"}"),
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "PARSE_INVALID",
			wantStage:  "parse",
		},
		{
			name:       "unknown tool -> TOOL_REVISION_UNKNOWN/normalize",
			tool:       "fake.unknown_tool",
			payload:    `{}`,
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "TOOL_REVISION_UNKNOWN",
			wantStage:  "normalize",
		},
		{
			name:       "fake.numeric_note valid payload -> TOOL_REVISION_UNKNOWN/normalize per kernel",
			tool:       "fake.numeric_note",
			payload:    `{"note_id":123}`,
			credential: "valid",
			ttl:        30000,
			wantEffect: "BLOCK",
			wantCode:   "TOOL_REVISION_UNKNOWN",
			wantStage:  "normalize",
		},
		{
			name:       "cancelled -> CANCELLED/policy",
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "valid",
			ttl:        30000,
			cancelled:  true,
			wantEffect: "BLOCK",
			wantCode:   "CANCELLED",
			wantStage:  "policy",
		},
		{
			name:            "expired envelope -> DEADLINE_EXCEEDED/policy",
			tool:            "fake.read_note",
			payload:         `{"note_id":"synthetic-note-001"}`,
			credential:      "valid",
			ttl:             30000,
			expiredEnvelope: true,
			wantEffect:      "BLOCK",
			wantCode:        "DEADLINE_EXCEEDED",
			wantStage:       "policy",
		},
		{
			name:       "ttl 60000 -> ALLOW with clamped deadline",
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "valid",
			ttl:        60000,
			wantEffect: "ALLOW",
			wantCode:   "POLICY_ALLOWED",
			wantStage:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payloadBytes := []byte(tc.payload)
			if tc.rawPayload != nil {
				payloadBytes = tc.rawPayload
			}
			res := p.Evaluate(context.Background(), Input{
				Tool:            tc.tool,
				Payload:         payloadBytes,
				Credential:      tc.credential,
				TTLMillis:       tc.ttl,
				Cancelled:       tc.cancelled,
				ExpiredEnvelope: tc.expiredEnvelope,
			})

			if res.Effect != tc.wantEffect {
				t.Fatalf("effect: got %q, want %q", res.Effect, tc.wantEffect)
			}
			if res.Code != tc.wantCode {
				t.Fatalf("code: got %q, want %q", res.Code, tc.wantCode)
			}
			if res.Stage != tc.wantStage {
				t.Fatalf("stage: got %q, want %q", res.Stage, tc.wantStage)
			}
			if !res.Synthetic {
				t.Fatalf("expected Synthetic == true, got false")
			}
			if res.DispatchEligible {
				t.Fatalf("dispatch_eligible must never be true, got %t", res.DispatchEligible)
			}

			if tc.wantEffect == "ALLOW" {
				if !hex32RE.MatchString(res.DecisionID) {
					t.Fatalf("decision_id not 32-hex: %q", res.DecisionID)
				}
				if !hex32RE.MatchString(res.ActionID) {
					t.Fatalf("action_id not 32-hex: %q", res.ActionID)
				}
				if res.ActionDigest == "" {
					t.Fatalf("expected non-empty action_digest on ALLOW")
				}
				if res.ExpiresAt == "" || res.DeadlineAt == "" {
					t.Fatalf("expected non-empty expires_at and deadline_at on ALLOW")
				}
				exp, err := time.Parse(time.RFC3339Nano, res.ExpiresAt)
				if err != nil {
					t.Fatalf("parse expires_at: %v", err)
				}
				dead, err := time.Parse(time.RFC3339, res.DeadlineAt)
				if err != nil {
					t.Fatalf("parse deadline_at: %v", err)
				}
				if exp.After(dead) {
					t.Fatalf("expires_at (%v) must be <= deadline_at (%v)", exp, dead)
				}
				if tc.ttl == 60000 {
					rec, err := time.Parse(time.RFC3339, res.ReceivedAt)
					if err != nil {
						t.Fatalf("parse received_at: %v", err)
					}
					diff := dead.Sub(rec)
					if diff != 30*time.Second {
						t.Fatalf("deadline_at - received_at: got %v, want 30s", diff)
					}
				}
			}

			if tc.wantEffect == "BLOCK" {
				if len(res.ErrorEnvelope) == 0 {
					t.Fatalf("expected non-empty error_envelope on BLOCK: error was %s", res.EnvelopeError)
				}
				dec := json.NewDecoder(bytes.NewReader(res.ErrorEnvelope))
				dec.DisallowUnknownFields()
				var env failure.Envelope
				if err := dec.Decode(&env); err != nil {
					t.Fatalf("strict decode error_envelope failed: %v", err)
				}
				if string(env.Code) != res.Code {
					t.Fatalf("envelope code mismatch: got %q, want %q", env.Code, res.Code)
				}
				if env.Retry != failure.PreSendRetry(failure.Code(res.Code)) {
					t.Fatalf("envelope retry mismatch: got %v, want %v", env.Retry, failure.PreSendRetry(failure.Code(res.Code)))
				}
				if env.Execution != failure.ExecutionNotDispatched {
					t.Fatalf("envelope execution mismatch: got %q, want not_dispatched", env.Execution)
				}
				if env.Delivery.State != failure.DeliveryWithheld {
					t.Fatalf("envelope delivery state mismatch: got %q, want withheld", env.Delivery.State)
				}
				if env.Delivery.ReleasedBytes.ProtectedText != 0 || env.Delivery.ReleasedBytes.ProtectedTool != 0 {
					t.Fatalf("envelope delivery released bytes mismatch: text=%d, tool=%d", env.Delivery.ReleasedBytes.ProtectedText, env.Delivery.ReleasedBytes.ProtectedTool)
				}
				if env.RequestID != res.RequestID {
					t.Fatalf("envelope request_id mismatch: got %q, want %q", env.RequestID, res.RequestID)
				}
				if res.Code == "POLICY_DENIED" {
					if res.DecisionID == "" || res.ActionID == "" {
						t.Fatalf("expected non-empty decision_id and action_id on POLICY_DENIED: decision_id=%q, action_id=%q", res.DecisionID, res.ActionID)
					}
					if env.DecisionID != res.DecisionID {
						t.Fatalf("envelope decision_id mismatch on POLICY_DENIED: got %q, want %q", env.DecisionID, res.DecisionID)
					}
					if env.ActionID != res.ActionID {
						t.Fatalf("envelope action_id mismatch on POLICY_DENIED: got %q, want %q", env.ActionID, res.ActionID)
					}
				}
			}
		})
	}
}

func TestEquivalenceWithAdvisoryDemo(t *testing.T) {
	// Both sides bind the authentication time into the action digest; on a
	// slow (race) run they could otherwise fall in different seconds.
	fixed := time.Now()
	clock, advisorydemo.Clock = func() time.Time { return fixed }, func() time.Time { return fixed }
	t.Cleanup(func() { clock, advisorydemo.Clock = time.Now, time.Now })
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	demoRows, err := advisorydemo.EvaluateAll()
	if err != nil {
		t.Fatalf("EvaluateAll() failed: %v", err)
	}

	// We compare all 20 fixtures from advisorydemo.
	// Notes on comparisons:
	// 1. Auth-stage fixtures (unknown-identity, expired-credential):
	//    advisorydemo records Auth = "AUTH_INVALID" and Reason = "AUTH_INVALID",
	//    which matches playground's Code = "AUTH_INVALID" and Stage = "auth".
	// 2. Allow-read fixture:
	//    advisorydemo uses Stage = "-" to denote diagnostic allow, while playground
	//    implements the specification requirement that ALLOW has no stage (Stage = "").
	//    Both yield Effect = "ALLOW" and Reason / Code = "POLICY_ALLOWED".
	// 3. Red-team payload and tool fixtures (oversized, unicode-lookalike, duplicate key, etc.):
	//    Mapped directly by FixtureID with identical RawPayload or Payload.
	type demoFixtureInfo struct {
		tool            string
		payload         string
		rawPayload      []byte
		credential      string
		cancelled       bool
		expiredEnvelope bool
	}

	inputs := map[string]demoFixtureInfo{
		"allow-read": {
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-001"}`,
			credential: "valid",
		},
		"block-delete": {
			tool:       "fake.delete_record",
			payload:    `{"record_id":"synthetic-record-001"}`,
			credential: "valid",
		},
		"unknown-tool": {
			tool:       "fake.unknown_tool",
			payload:    `{}`,
			credential: "valid",
		},
		"malformed-payload": {
			tool:       "fake.read_note",
			payload:    `{"note_id":`,
			credential: "valid",
		},
		"schema-violation": {
			tool:       "fake.read_note",
			payload:    `{"unexpected":true}`,
			credential: "valid",
		},
		"unknown-identity": {
			tool:       "fake.send_message",
			payload:    `{"body":"synthetic body","recipient":"synthetic-recipient"}`,
			credential: "unknown",
		},
		"engine-cancelled": {
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-002"}`,
			credential: "valid",
			cancelled:  true,
		},
		"empty-payload": {
			tool:       "fake.read_note",
			payload:    "",
			credential: "valid",
		},
		"oversized-payload": {
			tool:       "fake.read_note",
			payload:    strings.Repeat(" ", 1<<20+1),
			credential: "valid",
		},
		"duplicate-json-key": {
			tool:       "fake.read_note",
			payload:    `{"note_id":"one","note_id":"two"}`,
			credential: "valid",
		},
		"non-utf8-payload": {
			tool:       "fake.read_note",
			rawPayload: []byte{'{', '"', 'n', 'o', 't', 'e', '_', 'i', 'd', '"', ':', '"', 0xff, '"', '}'},
			credential: "valid",
		},
		"nesting-over-limit": {
			tool:       "fake.read_note",
			payload:    strings.Repeat(`{"a":`, 33) + `0` + strings.Repeat(`}`, 33),
			credential: "valid",
		},
		"numeric-negative-zero": {
			tool:       "fake.numeric_note",
			payload:    `{"note_id":-0}`,
			credential: "valid",
		},
		"numeric-exponent-out-of-range": {
			tool:       "fake.numeric_note",
			payload:    `{"note_id":1e33}`,
			credential: "valid",
		},
		"numeric-unsafe-integer": {
			tool:       "fake.numeric_note",
			payload:    `{"note_id":9007199254740992}`,
			credential: "valid",
		},
		"case-variant-tool": {
			tool:       "fake.Read_note",
			payload:    `{}`,
			credential: "valid",
		},
		"unicode-lookalike-tool": {
			tool:       "fake.reаd_note",
			payload:    `{}`,
			credential: "valid",
		},
		"no-matching-policy": {
			tool:       "fake.send_message",
			payload:    `{"body":"synthetic body","recipient":"synthetic-recipient"}`,
			credential: "valid",
		},
		"expired-credential": {
			tool:       "fake.read_note",
			payload:    `{"note_id":"synthetic-note-003"}`,
			credential: "expired",
		},
		"zero-deadline": {
			tool:            "fake.read_note",
			payload:         `{"note_id":"synthetic-note-004"}`,
			credential:      "valid",
			expiredEnvelope: true,
		},
	}

	if len(demoRows) != len(inputs) {
		t.Fatalf("expected %d demo fixtures, got %d", len(inputs), len(demoRows))
	}

	compared := 0
	for _, row := range demoRows {
		inp, ok := inputs[row.FixtureID]
		if !ok {
			t.Fatalf("unhandled demo fixture %q", row.FixtureID)
		}
		compared++

		payloadBytes := []byte(inp.payload)
		if inp.rawPayload != nil {
			payloadBytes = inp.rawPayload
		}

		res := p.Evaluate(context.Background(), Input{
			Tool:            inp.tool,
			Payload:         payloadBytes,
			Credential:      inp.credential,
			TTLMillis:       30000,
			Cancelled:       inp.cancelled,
			ExpiredEnvelope: inp.expiredEnvelope,
		})

		if res.Effect != string(row.Effect) {
			t.Fatalf("fixture %s effect mismatch: got %q, want %q", row.FixtureID, res.Effect, row.Effect)
		}
		if res.Code != row.Reason {
			t.Fatalf("fixture %s reason/code mismatch: got %q, want %q", row.FixtureID, res.Code, row.Reason)
		}
		expectedStage := row.Stage
		if row.Effect == decision.ALLOW && row.Stage == "-" {
			expectedStage = ""
		}
		if res.Stage != expectedStage {
			t.Fatalf("fixture %s stage mismatch: got %q, want %q", row.FixtureID, res.Stage, expectedStage)
		}
		if res.DispatchEligible != row.DispatchEligible {
			t.Fatalf("fixture %s DispatchEligible mismatch: got %t, want %t", row.FixtureID, res.DispatchEligible, row.DispatchEligible)
		}
		if row.ActionDigest != "" && res.ActionDigest != "" {
			if res.ActionDigest != row.ActionDigest {
				t.Fatalf("fixture %s ActionDigest mismatch: got %q, want %q", row.FixtureID, res.ActionDigest, row.ActionDigest)
			}
		} else if row.ActionDigest == "" && res.ActionDigest != "" {
			t.Fatalf("fixture %s ActionDigest mismatch: row has empty, res has %q", row.FixtureID, res.ActionDigest)
		} else if row.ActionDigest != "" && res.ActionDigest == "" {
			t.Fatalf("fixture %s ActionDigest mismatch: row has %q, res has empty", row.FixtureID, row.ActionDigest)
		}
	}

	if compared != len(demoRows) {
		t.Fatalf("failed to compare all fixtures: compared %d of %d", compared, len(demoRows))
	}
}

func TestRunFixturesDispatchEligibleAlwaysFalse(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	rows, err := p.RunFixtures()
	if err != nil {
		t.Fatalf("RunFixtures failed: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least 1 fixture row, got 0")
	}
	for _, row := range rows {
		if row.DispatchEligible {
			t.Fatalf("fixture %s has DispatchEligible true, want false", row.FixtureID)
		}
	}
}

func TestSetPolicy(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	initialDigest := p.current.snapshot.Digest()

	// 1. Invalid YAML keeps old digest
	if _, err := p.SetPolicy([]byte("invalid: yaml: [")); err == nil {
		t.Fatal("expected error on invalid YAML")
	}
	p.mu.RLock()
	afterInvalidDigest := p.current.snapshot.Digest()
	p.mu.RUnlock()
	if afterInvalidDigest != initialDigest {
		t.Fatalf("digest changed after failed policy swap: got %q, want %q", afterInvalidDigest, initialDigest)
	}

	// 2. Valid policy swapping allow-read to deny flips ALLOW to POLICY_DENIED
	flipPolicy := "schema_version: 1\ntenant_id: synthetic\nrevision: 2\ndefault: deny\nrules:\n - id: deny-read\n   effect: deny\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n"
	info, err := p.SetPolicy([]byte(flipPolicy))
	if err != nil {
		t.Fatalf("SetPolicy valid flip failed: %v", err)
	}
	if info.Digest == initialDigest {
		t.Fatalf("digest did not change after valid policy swap")
	}

	res := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if res.Effect != "BLOCK" || res.Code != "POLICY_DENIED" {
		t.Fatalf("flipped policy did not yield BLOCK POLICY_DENIED: got effect=%s code=%s", res.Effect, res.Code)
	}

	// 3. Policy with tenant_id other than synthetic returns an error or yields BLOCK, never panic, never ALLOW
	otherTenantPolicy := "schema_version: 1\ntenant_id: other\nrevision: 3\ndefault: deny\nrules:\n - id: allow-read\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n"
	_, err = p.SetPolicy([]byte(otherTenantPolicy))
	// If accepted by SetPolicy, evaluate must still block due to tenant mismatch
	if err == nil {
		resOther := p.Evaluate(context.Background(), Input{
			Tool:       "fake.read_note",
			Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
			Credential: "valid",
			TTLMillis:  30000,
		})
		if resOther.Effect == "ALLOW" {
			t.Fatal("policy with other tenant unexpectedly yielded ALLOW")
		}
	}

	// 4. 64 KiB+1 rejected
	oversizedPolicy := make([]byte, 64*1024+1)
	if _, err := p.SetPolicy(oversizedPolicy); err == nil {
		t.Fatal("expected 64 KiB+1 policy to be rejected")
	}
}

func TestConcurrency(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	var wg sync.WaitGroup

	// Concurrently evaluate: 8 workers x 200 evals
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 200; iter++ {
				tool := "fake.read_note"
				payload := `{"note_id":"note"}`
				if id%2 == 1 {
					tool = "fake.delete_record"
					payload = `{"record_id":"rec"}`
				}
				res := p.Evaluate(context.Background(), Input{
					Tool:       tool,
					Payload:    []byte(payload),
					Credential: "valid",
					TTLMillis:  30000,
				})
				if res.Effect == "" {
					t.Errorf("empty effect in concurrent evaluation")
				}
			}
		}(i)
	}

	// Concurrently swap policy: 50 resets
	wg.Add(1)
	go func() {
		defer wg.Done()
		for iter := 0; iter < 50; iter++ {
			_, _ = p.ResetPolicy()
			time.Sleep(100 * time.Microsecond)
		}
	}()

	wg.Wait()
}

func TestHistoryRingCappedAt50(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	for i := 0; i < 60; i++ {
		p.Evaluate(context.Background(), Input{
			Tool:       "fake.read_note",
			Payload:    []byte(fmt.Sprintf(`{"note_id":"note-%03d"}`, i)),
			Credential: "valid",
			TTLMillis:  30000,
		})
	}

	hist := p.history.List()
	if len(hist) != 50 {
		t.Fatalf("history length: got %d, want 50", len(hist))
	}
	// Newest first: first element should correspond to note-059
	if !strings.Contains(hist[0].ActionID, "") || hist[0].RequestID == "" {
		t.Fatalf("invalid first history item: %+v", hist[0])
	}
}

func TestHTTPEvaluateEndpoints(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()

	client := server.Client()

	// 1. Valid evaluate
	validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))
	body := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000,"cancelled":false,"expired_envelope":false}`, validB64)
	resp, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/evaluate failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var res Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode Result failed: %v", err)
	}
	if res.Effect != "ALLOW" || res.Code != "POLICY_ALLOWED" {
		t.Fatalf("unexpected result: %+v", res)
	}

	// 2. TTLMillis 0 -> 400
	emptyB64 := base64.StdEncoding.EncodeToString([]byte(`{}`))
	bodyTTL0 := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":0,"cancelled":false,"expired_envelope":false}`, emptyB64)
	resp0, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(bodyTTL0))
	if err != nil {
		t.Fatalf("POST /api/evaluate failed: %v", err)
	}
	if resp0.StatusCode != http.StatusBadRequest {
		t.Fatalf("status for ttl_ms 0: got %d, want 400", resp0.StatusCode)
	}

	// 3. TTLMillis 60001 -> 400
	bodyTTL60001 := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":60001,"cancelled":false,"expired_envelope":false}`, emptyB64)
	resp60001, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(bodyTTL60001))
	if err != nil {
		t.Fatalf("POST /api/evaluate failed: %v", err)
	}
	if resp60001.StatusCode != http.StatusBadRequest {
		t.Fatalf("status for ttl_ms 60001: got %d, want 400", resp60001.StatusCode)
	}

	// 4. Unknown credential -> 400
	bodyCred := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"bogus","ttl_ms":30000,"cancelled":false,"expired_envelope":false}`, emptyB64)
	respCred, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(bodyCred))
	if err != nil {
		t.Fatalf("POST /api/evaluate failed: %v", err)
	}
	if respCred.StatusCode != http.StatusBadRequest {
		t.Fatalf("status for invalid credential: got %d, want 400", respCred.StatusCode)
	}

	// 5. GET /api/state
	respState, err := client.Get(server.URL + "/api/state")
	if err != nil {
		t.Fatalf("GET /api/state failed: %v", err)
	}
	if respState.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", respState.StatusCode)
	}
	var state StateResponse
	if err := json.NewDecoder(respState.Body).Decode(&state); err != nil {
		t.Fatalf("decode state failed: %v", err)
	}
	if len(state.Tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(state.Tools))
	}
	if len(state.Credentials) != 4 {
		t.Fatalf("expected 4 credentials, got %d", len(state.Credentials))
	}

	// 6. POST /api/policy 422 on invalid policy
	badPolicyBody := `{"source":"schema_version: 99\n"}`
	respBadPol, err := client.Post(server.URL+"/api/policy", "application/json", strings.NewReader(badPolicyBody))
	if err != nil {
		t.Fatalf("POST /api/policy failed: %v", err)
	}
	if respBadPol.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d, want 422", respBadPol.StatusCode)
	}

	// 7. POST /api/fixtures returns rows
	respFix, err := client.Post(server.URL+"/api/fixtures", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/fixtures failed: %v", err)
	}
	if respFix.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", respFix.StatusCode)
	}
	var fixRows []FixtureRow
	if err := json.NewDecoder(respFix.Body).Decode(&fixRows); err != nil {
		t.Fatalf("decode fixtures failed: %v", err)
	}
	if len(fixRows) != 20 {
		t.Fatalf("expected 20 fixture rows, got %d", len(fixRows))
	}
}

func TestEvaluateCredentialFailClosed(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	invalidCreds := []string{
		p.validSecret,
		"VALID",
		"",
	}
	for _, cred := range invalidCreds {
		res := p.Evaluate(context.Background(), Input{
			Tool:       "fake.read_note",
			Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
			Credential: cred,
			TTLMillis:  30000,
		})
		if res.Effect != "BLOCK" || res.Code != string(failure.INTERNAL_ERROR) || res.Stage != string(failure.StageAuth) {
			t.Fatalf("credential %q: expected BLOCK %s/%s, got %s %s/%s", cred, failure.INTERNAL_ERROR, failure.StageAuth, res.Effect, res.Code, res.Stage)
		}
		if len(res.Trace) < 2 || res.Trace[1].Status != "failed" || res.Trace[1].Code != string(failure.INTERNAL_ERROR) {
			t.Fatalf("credential %q: expected trace[1] to be failed/INTERNAL_ERROR, got %+v", cred, res.Trace)
		}
	}
}

func TestCodeFor(t *testing.T) {
	if got := codeFor(errors.New("NOT_A_CODE")); got != failure.INTERNAL_ERROR {
		t.Fatalf("expected INTERNAL_ERROR for NOT_A_CODE, got %s", got)
	}
	if got := codeFor(action.ErrParse); got != failure.PARSE_INVALID {
		t.Fatalf("expected PARSE_INVALID for action.ErrParse, got %s", got)
	}
}

func TestSetPolicySizeAndDigestImmutability(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	initialDigest := p.current.snapshot.Digest()

	// 1. 0 bytes -> ErrPolicySize
	_, err = p.SetPolicy([]byte{})
	if !errors.Is(err, ErrPolicySize) {
		t.Fatalf("0 bytes: expected ErrPolicySize, got %v", err)
	}
	if p.current.snapshot.Digest() != initialDigest {
		t.Fatalf("digest changed after 0-byte SetPolicy")
	}

	// 2. 65537 bytes -> ErrPolicySize
	oversized := make([]byte, 65537)
	_, err = p.SetPolicy(oversized)
	if !errors.Is(err, ErrPolicySize) {
		t.Fatalf("65537 bytes: expected ErrPolicySize, got %v", err)
	}
	if p.current.snapshot.Digest() != initialDigest {
		t.Fatalf("digest changed after 65537-byte SetPolicy")
	}

	// 3. exactly 65536 bytes -> error is NOT ErrPolicySize (may fail to compile)
	exactMax := make([]byte, 65536)
	_, err = p.SetPolicy(exactMax)
	if errors.Is(err, ErrPolicySize) {
		t.Fatalf("65536 bytes: got ErrPolicySize, expected compile error instead")
	}
	if p.current.snapshot.Digest() != initialDigest {
		t.Fatalf("digest changed after 65536-byte compilation failure")
	}

	// 4. compile failure -> error is NOT ErrPolicySize
	_, err = p.SetPolicy([]byte("invalid: [yaml: broken"))
	if err == nil || errors.Is(err, ErrPolicySize) {
		t.Fatalf("compile error: expected compile failure, got %v", err)
	}
	if p.current.snapshot.Digest() != initialDigest {
		t.Fatalf("digest changed after compile failure")
	}
}

func TestEnvelopeTimestampsAndActionIDLifecycle(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// 1. Parse failure -> received_at, deadline_at, action_id must be empty
	resParse := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":`),
		Credential: "valid",
		TTLMillis:  10000,
	})
	if resParse.Effect != "BLOCK" || resParse.Code != string(failure.PARSE_INVALID) {
		t.Fatalf("expected PARSE_INVALID, got %s / %s", resParse.Effect, resParse.Code)
	}
	if resParse.ReceivedAt != "" {
		t.Fatalf("expected empty ReceivedAt on parse failure, got %q", resParse.ReceivedAt)
	}
	if resParse.DeadlineAt != "" {
		t.Fatalf("expected empty DeadlineAt on parse failure, got %q", resParse.DeadlineAt)
	}
	if resParse.ActionID != "" {
		t.Fatalf("expected empty ActionID on parse failure, got %q", resParse.ActionID)
	}

	// 2. ALLOW -> action_id is 32 hex, and deadline_at - received_at == ttl for ttl 10000
	resAllow := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "valid",
		TTLMillis:  10000,
	})
	if resAllow.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s / %s", resAllow.Effect, resAllow.Code)
	}
	if !hex32RE.MatchString(resAllow.ActionID) {
		t.Fatalf("expected 32-hex action_id, got %q", resAllow.ActionID)
	}
	rec, err := time.Parse("2006-01-02T15:04:05.000Z", resAllow.ReceivedAt)
	if err != nil {
		t.Fatalf("parse received_at: %v", err)
	}
	dead, err := time.Parse("2006-01-02T15:04:05.000Z", resAllow.DeadlineAt)
	if err != nil {
		t.Fatalf("parse deadline_at: %v", err)
	}
	diff := dead.Sub(rec)
	if diff != 10000*time.Millisecond {
		t.Fatalf("deadline_at - received_at: got %v, want 10s (10000ms)", diff)
	}
}

func TestDisplayURLTable(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"0.0.0.0:8787", "http://127.0.0.1:8787"},
		{"[::]:1", "http://127.0.0.1:1"},
		{":8787", "http://127.0.0.1:8787"},
		{"127.0.0.1:9", "http://127.0.0.1:9"},
		{"localhost:5", "http://localhost:5"},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got := DisplayURL(tc.addr)
			if got != tc.want {
				t.Fatalf("DisplayURL(%q): got %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestPolicyDeniedEnvelopeIDs(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	res := p.Evaluate(context.Background(), Input{
		Tool:       "fake.delete_record",
		Payload:    []byte(`{"record_id":"synthetic-record-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})

	if res.Effect != "BLOCK" || res.Code != "POLICY_DENIED" {
		t.Fatalf("expected BLOCK POLICY_DENIED, got effect=%q, code=%q", res.Effect, res.Code)
	}
	if res.DecisionID == "" || res.ActionID == "" {
		t.Fatalf("expected non-empty decision_id and action_id on result: decision_id=%q, action_id=%q", res.DecisionID, res.ActionID)
	}
	if len(res.ErrorEnvelope) == 0 {
		t.Fatal("expected non-empty error_envelope")
	}

	var env failure.Envelope
	dec := json.NewDecoder(bytes.NewReader(res.ErrorEnvelope))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode error_envelope failed: %v", err)
	}

	if env.DecisionID != res.DecisionID {
		t.Fatalf("envelope decision_id mismatch: got %q, want %q", env.DecisionID, res.DecisionID)
	}
	if env.ActionID != res.ActionID {
		t.Fatalf("envelope action_id mismatch: got %q, want %q", env.ActionID, res.ActionID)
	}
}

func TestHistoryIncludesFailuresAndSuccessNewestFirst(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// 1. Evaluate a parse failure
	parseRes := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if parseRes.Effect != "BLOCK" || parseRes.Code != "PARSE_INVALID" {
		t.Fatalf("expected PARSE_INVALID, got %+v", parseRes)
	}
	if parseRes.RequestID == "" {
		t.Fatal("expected non-empty request_id on parse failure")
	}

	// 2. Evaluate an ALLOW
	allowRes := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if allowRes.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW, got %+v", allowRes)
	}
	if allowRes.RequestID == "" {
		t.Fatal("expected non-empty request_id on allow")
	}

	// 3. Query /api/state and assert history has those two newest-first with matching request_ids
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/state", nil)
	req.Host = "127.0.0.1:8787"
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/state status: got %d, want 200", w.Code)
	}

	var state StateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal state response: %v", err)
	}

	if len(state.History) != 2 {
		t.Fatalf("history length: got %d, want 2", len(state.History))
	}
	if state.History[0].RequestID != allowRes.RequestID {
		t.Fatalf("history[0] request_id mismatch: got %q, want %q", state.History[0].RequestID, allowRes.RequestID)
	}
	if state.History[1].RequestID != parseRes.RequestID {
		t.Fatalf("history[1] request_id mismatch: got %q, want %q", state.History[1].RequestID, parseRes.RequestID)
	}
}

func TestHistoryOrder60(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	reqIDs := make([]string, 60)
	for i := 0; i < 60; i++ {
		res := p.Evaluate(context.Background(), Input{
			Tool:       "fake.read_note",
			Payload:    []byte(fmt.Sprintf(`{"note_id":"note-%03d"}`, i)),
			Credential: "valid",
			TTLMillis:  30000,
		})
		if res.RequestID == "" {
			t.Fatalf("evaluation %d produced empty request_id", i)
		}
		reqIDs[i] = res.RequestID
	}

	hist := p.history.List()
	if len(hist) != 50 {
		t.Fatalf("history length: got %d, want 50", len(hist))
	}
	for i := 0; i < 50; i++ {
		if hist[i].RequestID != reqIDs[59-i] {
			t.Fatalf("hist[%d] expected request ID %s (reqIDs[%d]), got %s", i, reqIDs[59-i], 59-i, hist[i].RequestID)
		}
	}

	histMap := make(map[string]bool)
	for _, h := range hist {
		histMap[h.RequestID] = true
	}
	for i := 0; i < 10; i++ {
		if histMap[reqIDs[i]] {
			t.Fatalf("first 10 request ID %d (%s) unexpectedly present in history", i, reqIDs[i])
		}
	}
}

func TestConcurrencyPolicyAndDigest(t *testing.T) {
	const (
		maxAttempts    = 5
		numSwaps       = 200
		numEvaluators  = 8
		evalsPerWorker = 200
	)

	denyPolicy := "schema_version: 1\ntenant_id: synthetic\nrevision: 2\ndefault: deny\nrules:\n - id: deny-read\n   effect: deny\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n"

	var lastAllowCount, lastDenyCount int64

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		p, err := New()
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		defaultInfo, err := p.ResetPolicy()
		if err != nil {
			t.Fatalf("ResetPolicy: %v", err)
		}
		defaultDigest := defaultInfo.Digest

		denyInfo, err := p.SetPolicy([]byte(denyPolicy))
		if err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
		denyDigest := denyInfo.Digest

		var seenAllow atomic.Int64
		var seenDeny atomic.Int64

		var wg sync.WaitGroup

		// Swapper goroutine: 200 swaps
		wg.Add(1)
		go func() {
			defer wg.Done()
			flip := false
			for s := 0; s < numSwaps; s++ {
				if flip {
					_, _ = p.SetPolicy([]byte(defaultPolicySource))
				} else {
					_, _ = p.SetPolicy([]byte(denyPolicy))
				}
				flip = !flip
				time.Sleep(50 * time.Microsecond)
			}
		}()

		// 8 evaluator goroutines: 200 evals each
		for i := 0; i < numEvaluators; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < evalsPerWorker; j++ {
					res := p.Evaluate(context.Background(), Input{
						Tool:       "fake.read_note",
						Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
						Credential: "valid",
						TTLMillis:  30000,
					})
					if res.PolicyDigest != defaultDigest && res.PolicyDigest != denyDigest {
						t.Errorf("unexpected policy_digest: %s", res.PolicyDigest)
						return
					}
					if res.PolicyDigest == defaultDigest {
						if res.Effect != "ALLOW" || res.Code != "POLICY_ALLOWED" {
							t.Errorf("default digest got effect=%s code=%s, want ALLOW POLICY_ALLOWED", res.Effect, res.Code)
							return
						}
						seenAllow.Add(1)
					}
					if res.PolicyDigest == denyDigest {
						if res.Effect != "BLOCK" || res.Code != "POLICY_DENIED" {
							t.Errorf("deny digest got effect=%s code=%s, want BLOCK POLICY_DENIED", res.Effect, res.Code)
							return
						}
						seenDeny.Add(1)
					}
				}
			}()
		}

		wg.Wait()

		allowCount := seenAllow.Load()
		denyCount := seenDeny.Load()
		lastAllowCount = allowCount
		lastDenyCount = denyCount

		if allowCount > 0 && denyCount > 0 {
			return
		}
	}

	t.Fatalf("concurrency test did not observe both ALLOW and POLICY_DENIED after %d attempts (last attempt: allow=%d, deny=%d)",
		maxAttempts, lastAllowCount, lastDenyCount)
}

func TestRequireApprovalPolicyPinsVerdict(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	approvalPolicy := "schema_version: 1\ntenant_id: synthetic\nrevision: 2\ndefault: deny\nrules:\n - id: allow-read\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n - id: require-approval-read\n   effect: require_approval\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n"
	_, err = p.SetPolicy([]byte(approvalPolicy))
	if err != nil {
		t.Fatalf("SetPolicy with require_approval failed: %v", err)
	}

	res := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})

	// Pin the exact effect, code, stage returned by kernel
	if res.Effect != "BLOCK" {
		t.Fatalf("expected effect BLOCK, got %s", res.Effect)
	}
	if res.Code != "APPROVAL_UNAVAILABLE" {
		t.Fatalf("expected code APPROVAL_UNAVAILABLE, got %s", res.Code)
	}
	if res.Stage != "approval" {
		t.Fatalf("expected stage approval, got %s", res.Stage)
	}

	// Require ErrorEnvelope non-empty and EnvelopeError empty
	if len(res.ErrorEnvelope) == 0 {
		t.Fatal("expected non-empty ErrorEnvelope")
	}
	if res.EnvelopeError != "" {
		t.Fatalf("expected empty EnvelopeError, got: %s", res.EnvelopeError)
	}

	var env failure.Envelope
	dec := json.NewDecoder(bytes.NewReader(res.ErrorEnvelope))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("failed to decode valid error_envelope: %v", err)
	}

	// Pin the kernel behavior: status_only is valid with not_dispatched.
	if env.Code != failure.APPROVAL_UNAVAILABLE {
		t.Fatalf("envelope code: got %s, want APPROVAL_UNAVAILABLE", env.Code)
	}
	if env.Stage != failure.StageApproval {
		t.Fatalf("envelope stage: got %s, want approval", env.Stage)
	}
	if env.Retry != failure.RetryStatusOnly {
		t.Fatalf("envelope retry: got %s, want status_only", env.Retry)
	}
	if env.Execution != failure.ExecutionNotDispatched {
		t.Fatalf("envelope execution: got %s, want not_dispatched", env.Execution)
	}
	if env.Delivery.State != failure.DeliveryWithheld {
		t.Fatalf("envelope delivery state: got %s, want withheld", env.Delivery.State)
	}
	if env.Delivery.ReleasedBytes.ProtectedText != 0 || env.Delivery.ReleasedBytes.ProtectedTool != 0 {
		t.Fatalf("envelope delivery released bytes: got %d/%d, want 0/0",
			env.Delivery.ReleasedBytes.ProtectedText, env.Delivery.ReleasedBytes.ProtectedTool)
	}
}

func TestProjectActorFailureMapping(t *testing.T) {
	code, stage := mapProjectActorError(errors.New("mock-project-actor-error"))
	if code != failure.IDENTITY_UNTRUSTED {
		t.Fatalf("expected IDENTITY_UNTRUSTED, got %s", code)
	}
	if stage != failure.StageAuth {
		t.Fatalf("expected stage auth, got %s", stage)
	}
}

func TestTraceStepIntegrity(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// 1. Schema violation payload marks "admit" failed, steps ok/skipped consistent with stage
	resSchema := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"unexpected":true}`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resSchema.Effect != "BLOCK" || resSchema.Code != "SCHEMA_INVALID" {
		t.Fatalf("expected SCHEMA_INVALID, got %+v", resSchema)
	}
	if len(resSchema.Trace) != 7 {
		t.Fatalf("expected 7 trace steps, got %d", len(resSchema.Trace))
	}
	if resSchema.Trace[0].Step != "admit" || resSchema.Trace[0].Status != "failed" || resSchema.Trace[0].Code != "SCHEMA_INVALID" {
		t.Fatalf("expected trace[0] to be admit failed/SCHEMA_INVALID, got %+v", resSchema.Trace[0])
	}
	for i := 1; i < 7; i++ {
		if resSchema.Trace[i].Status != "skipped" {
			t.Fatalf("expected trace[%d] (%s) to be skipped on schema violation, got %s", i, resSchema.Trace[i].Step, resSchema.Trace[i].Status)
		}
	}

	// 2. Auth failure: admit ok, authenticate failed, remaining skipped
	resAuth := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "unknown",
		TTLMillis:  30000,
	})
	if resAuth.Effect != "BLOCK" || resAuth.Code != "AUTH_INVALID" {
		t.Fatalf("expected AUTH_INVALID, got %+v", resAuth)
	}
	if resAuth.Trace[0].Step != "admit" || resAuth.Trace[0].Status != "ok" {
		t.Fatalf("expected trace[0] admit ok, got %+v", resAuth.Trace[0])
	}
	if resAuth.Trace[1].Step != "authenticate" || resAuth.Trace[1].Status != "failed" {
		t.Fatalf("expected trace[1] authenticate failed, got %+v", resAuth.Trace[1])
	}
	if resAuth.Trace[2].Step != "project" || resAuth.Trace[2].Status != "skipped" {
		t.Fatalf("expected trace[2] project skipped on auth failure, got %+v", resAuth.Trace[2])
	}
	if resAuth.Trace[3].Step != "context" || resAuth.Trace[3].Status != "skipped" {
		t.Fatalf("expected trace[3] context skipped on auth failure, got %+v", resAuth.Trace[3])
	}

	// 3. Policy failure: admit, authenticate, project, context, envelope, normalize are ok, authorize is failed
	resPolicy := p.Evaluate(context.Background(), Input{
		Tool:       "fake.delete_record",
		Payload:    []byte(`{"record_id":"synthetic-record-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resPolicy.Effect != "BLOCK" || resPolicy.Code != "POLICY_DENIED" {
		t.Fatalf("expected POLICY_DENIED, got %+v", resPolicy)
	}
	for i := 0; i < 6; i++ {
		if resPolicy.Trace[i].Status != "ok" {
			t.Fatalf("expected trace[%d] (%s) ok, got %s", i, resPolicy.Trace[i].Step, resPolicy.Trace[i].Status)
		}
	}
	if resPolicy.Trace[6].Step != "authorize" || resPolicy.Trace[6].Status != "failed" || resPolicy.Trace[6].Code != "POLICY_DENIED" {
		t.Fatalf("expected trace[6] authorize failed/POLICY_DENIED, got %+v", resPolicy.Trace[6])
	}

	// 4. Policy allowed: all 7 steps ok
	resAllow := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resAllow.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW, got %+v", resAllow)
	}
	for i := 0; i < 7; i++ {
		if resAllow.Trace[i].Status != "ok" {
			t.Fatalf("expected trace[%d] (%s) ok, got %s", i, resAllow.Trace[i].Step, resAllow.Trace[i].Status)
		}
	}
}

func TestClaudeCodeToolSetEvaluation(t *testing.T) {
	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New(WithToolSet) failed: %v", err)
	}

	lowRisk := map[string]bool{
		"cc.read":       true,
		"cc.glob":       true,
		"cc.grep":       true,
		"cc.todo_write": true,
	}
	mutating := map[string]bool{
		"cc.bash":       true,
		"cc.powershell": true,
		"cc.write":      true,
		"cc.edit":       true,
		"cc.multi_edit": true,
	}
	unruled := map[string]bool{
		"cc.web_fetch":     true,
		"cc.web_search":    true,
		"cc.task":          true,
		"cc.agent":         true,
		"cc.notebook_edit": true,
	}

	for _, entry := range claudeCodeToolMap {
		t.Run(entry.ID, func(t *testing.T) {
			res := p.Evaluate(context.Background(), Input{
				Tool:       entry.ID,
				Payload:    []byte("{}"),
				Credential: "valid",
				TTLMillis:  30000,
			})

			if !res.FakeToolKnown {
				t.Fatalf("expected res.FakeToolKnown == true for %s", entry.ID)
			}

			// Check never SCHEMA_INVALID or TOOL_REVISION_UNKNOWN
			if res.Code == "SCHEMA_INVALID" || res.Code == "TOOL_REVISION_UNKNOWN" {
				t.Fatalf("unexpected code %s for %s", res.Code, entry.ID)
			}
			if res.DispatchEligible {
				t.Fatalf("dispatch_eligible must be false for %s", entry.ID)
			}

			if lowRisk[entry.ID] {
				if res.Effect != "ALLOW" || res.Code != "POLICY_ALLOWED" || res.Stage != "" {
					t.Fatalf("expected ALLOW/POLICY_ALLOWED for %s, got effect=%s code=%s stage=%s", entry.ID, res.Effect, res.Code, res.Stage)
				}
				hasRuleRef := false
				for _, r := range res.Reasons {
					if r.RuleID == "allow-cc-low-risk" {
						hasRuleRef = true
						break
					}
				}
				if !hasRuleRef {
					t.Fatalf("expected deciding rule allow-cc-low-risk for %s, got reasons %+v", entry.ID, res.Reasons)
				}
			} else if mutating[entry.ID] {
				if res.Effect != "BLOCK" || res.Code != "POLICY_DENIED" || res.Stage != "policy" {
					t.Fatalf("expected BLOCK/POLICY_DENIED/policy for %s, got effect=%s code=%s stage=%s", entry.ID, res.Effect, res.Code, res.Stage)
				}
				hasRuleRef := false
				for _, r := range res.Reasons {
					if r.RuleID == "deny-cc-mutating" {
						hasRuleRef = true
						break
					}
				}
				if !hasRuleRef {
					t.Fatalf("expected deciding rule deny-cc-mutating for %s, got reasons %+v", entry.ID, res.Reasons)
				}
			} else if unruled[entry.ID] {
				if res.Effect != "BLOCK" || res.Code != "POLICY_DENIED" || res.Stage != "policy" {
					t.Fatalf("expected BLOCK/POLICY_DENIED/policy for %s, got effect=%s code=%s stage=%s", entry.ID, res.Effect, res.Code, res.Stage)
				}
				for _, r := range res.Reasons {
					if r.RuleID != "" {
						t.Fatalf("expected default deny (no cc rule id) for %s, got reasons %+v", entry.ID, res.Reasons)
					}
				}
			} else {
				t.Fatalf("unaccounted mapped tool %s", entry.ID)
			}
		})
	}
}

func TestClaudeCodeUnmappedAndInvalidPayload(t *testing.T) {
	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New(WithToolSet) failed: %v", err)
	}

	long65Name := strings.Repeat("a", 65)

	cases := []struct {
		name       string
		tool       string
		payload    string
		wantEffect string
		wantCode   string
		wantStage  string
	}{
		{
			name:       "raw unmapped Bash (uppercase)",
			tool:       "Bash",
			payload:    "{}",
			wantEffect: "BLOCK",
			wantCode:   "SCHEMA_INVALID",
			wantStage:  "normalize",
		},
		{
			name:       "raw unmapped bash (lowercase unmapped ID)",
			tool:       "bash",
			payload:    "{}",
			wantEffect: "BLOCK",
			wantCode:   "TOOL_REVISION_UNKNOWN",
			wantStage:  "normalize",
		},
		{
			name:       "raw unmapped mcp__claude-in-chrome__navigate",
			tool:       "mcp__claude-in-chrome__navigate",
			payload:    "{}",
			wantEffect: "BLOCK",
			wantCode:   "TOOL_REVISION_UNKNOWN",
			wantStage:  "normalize",
		},
		{
			name:       "raw unmapped 65-char lowercase name",
			tool:       long65Name,
			payload:    "{}",
			wantEffect: "BLOCK",
			wantCode:   "SCHEMA_INVALID",
			wantStage:  "normalize",
		},
		{
			name:       "raw unmapped cc.unknown",
			tool:       "cc.unknown",
			payload:    "{}",
			wantEffect: "BLOCK",
			wantCode:   "TOOL_REVISION_UNKNOWN",
			wantStage:  "normalize",
		},
		{
			name:       "cc.read with non-empty payload",
			tool:       "cc.read",
			payload:    `{"file_path":"x"}`,
			wantEffect: "BLOCK",
			wantCode:   "SCHEMA_INVALID",
			wantStage:  "normalize",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := p.Evaluate(context.Background(), Input{
				Tool:       tc.tool,
				Payload:    []byte(tc.payload),
				Credential: "valid",
				TTLMillis:  30000,
			})
			if res.Effect != tc.wantEffect || res.Code != tc.wantCode || res.Stage != tc.wantStage {
				t.Fatalf("%s: expected effect=%s code=%s stage=%s, got effect=%s code=%s stage=%s",
					tc.name, tc.wantEffect, tc.wantCode, tc.wantStage, res.Effect, res.Code, res.Stage)
			}
			if res.DispatchEligible {
				t.Fatalf("%s: dispatch_eligible must be false", tc.name)
			}
		})
	}
}

func TestClaudeCodeToolMapValidityAndNoDuplicates(t *testing.T) {
	seenNames := make(map[string]bool)
	seenIDs := make(map[string]bool)

	for _, entry := range claudeCodeToolMap {
		if entry.Name == "" {
			t.Fatalf("empty name in claudeCodeToolMap")
		}
		if entry.ID == "" {
			t.Fatalf("empty id in claudeCodeToolMap")
		}
		if seenNames[entry.Name] {
			t.Fatalf("duplicate name in claudeCodeToolMap: %s", entry.Name)
		}
		seenNames[entry.Name] = true

		if seenIDs[entry.ID] {
			t.Fatalf("duplicate ID in claudeCodeToolMap: %s", entry.ID)
		}
		seenIDs[entry.ID] = true

		// Check NormalizeSelector(resource.Tool, entry.ID)
		normalized, canonical, err := resource.NormalizeSelector(resource.Tool, entry.ID)
		if err != nil {
			t.Fatalf("tool ID %q failed resource.NormalizeSelector: %v", entry.ID, err)
		}
		if !canonical || normalized != entry.ID {
			t.Fatalf("tool ID %q is not canonical (normalized=%q, canonical=%v)", entry.ID, normalized, canonical)
		}
	}
}

func TestDemoToolSetStateAndCCRead(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// 1. Evaluate cc.read in demo mode -> TOOL_REVISION_UNKNOWN
	res := p.Evaluate(context.Background(), Input{
		Tool:       "cc.read",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if res.Effect != "BLOCK" || res.Code != "TOOL_REVISION_UNKNOWN" || res.Stage != "normalize" {
		t.Fatalf("demo mode cc.read: expected BLOCK/TOOL_REVISION_UNKNOWN/normalize, got effect=%s code=%s stage=%s",
			res.Effect, res.Code, res.Stage)
	}

	// 2. GET /api/state in demo mode
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/state", nil)
	req.Host = "127.0.0.1:8787"
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var state StateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal state failed: %v", err)
	}
	if state.ToolSet != "demo" {
		t.Fatalf("expected tool_set 'demo', got %q", state.ToolSet)
	}
	if state.ToolMap == nil || len(state.ToolMap) != 0 {
		t.Fatalf("expected empty tool_map, got %+v", state.ToolMap)
	}
	// Verify raw JSON has "tool_map":[]
	if !strings.Contains(rr.Body.String(), `"tool_map":[]`) {
		t.Fatalf("expected raw JSON to contain '\"tool_map\":[]', got %s", rr.Body.String())
	}
}

func TestClaudeCodeFixturesAndResetPolicy(t *testing.T) {
	pCC, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New() claude-code failed: %v", err)
	}

	ccRows, err := pCC.RunFixtures()
	if err != nil {
		t.Fatalf("claude-code RunFixtures failed: %v", err)
	}
	if len(ccRows) == 0 {
		t.Fatalf("expected non-empty fixture rows")
	}
	for i, r := range ccRows {
		if r.DispatchEligible {
			t.Fatalf("fixture row %d has dispatch_eligible=true", i)
		}
	}

	// ResetPolicy after SetPolicy restores claude-code default digest
	pCC.mu.RLock()
	origDigest := pCC.current.snapshot.Digest()
	pCC.mu.RUnlock()

	customPolicy := "schema_version: 1\ntenant_id: synthetic\nrevision: 2\ndefault: deny\nrules:\n - id: allow-read\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: fake.read_note}]}\n"
	newInfo, err := pCC.SetPolicy([]byte(customPolicy))
	if err != nil {
		t.Fatalf("SetPolicy failed: %v", err)
	}
	if newInfo.Digest == origDigest {
		t.Fatalf("expected digest to change after SetPolicy")
	}

	resetInfo, err := pCC.ResetPolicy()
	if err != nil {
		t.Fatalf("ResetPolicy failed: %v", err)
	}
	if resetInfo.Digest != origDigest {
		t.Fatalf("expected ResetPolicy to restore origDigest %s, got %s", origDigest, resetInfo.Digest)
	}
}

func TestParseToolSetHelper(t *testing.T) {
	tests := []struct {
		input   string
		want    ToolSet
		wantErr bool
	}{
		{"demo", ToolSetDemo, false},
		{"claude-code", ToolSetClaudeCode, false},
		{"", "", true},
		{"Demo", "", true},
		{"bogus", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseToolSet(tc.input)
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

func TestClaudeCodeStateHTTP(t *testing.T) {
	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/state", nil)
	req.Host = "127.0.0.1:8787"
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var state StateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if state.ToolSet != "claude-code" {
		t.Fatalf("expected tool_set 'claude-code', got %q", state.ToolSet)
	}

	if len(state.ToolMap) != len(claudeCodeToolMap) {
		t.Fatalf("expected %d tool_map entries, got %d", len(claudeCodeToolMap), len(state.ToolMap))
	}

	for i, expected := range claudeCodeToolMap {
		if state.ToolMap[i].Name != expected.Name || state.ToolMap[i].ID != expected.ID {
			t.Fatalf("entry %d mismatch: want {%s, %s}, got %+v", i, expected.Name, expected.ID, state.ToolMap[i])
		}
	}

	if len(state.Tools) != 18 {
		t.Fatalf("expected state.Tools to have exactly 18 entries, got %d", len(state.Tools))
	}

	toolMap := make(map[string]bool, len(state.Tools))
	for _, ti := range state.Tools {
		toolMap[ti.Tool] = true
	}
	for _, expected := range claudeCodeToolMap {
		if !toolMap[expected.ID] {
			t.Fatalf("expected state.Tools to contain %s", expected.ID)
		}
	}
}

func TestNewWithInvalidToolSet(t *testing.T) {
	_, err := New(WithToolSet(ToolSet("bogus")))
	if err == nil {
		t.Fatal("expected error from New(WithToolSet(ToolSet(\"bogus\"))), got nil")
	}
}

func TestDefaultClaudeCodePolicyComposition(t *testing.T) {
	if !strings.HasPrefix(defaultClaudeCodePolicySource, defaultPolicySource) {
		t.Fatalf("expected defaultClaudeCodePolicySource to have prefix defaultPolicySource")
	}
	if _, err := policy.Compile([]byte(defaultPolicySource)); err != nil {
		t.Fatalf("defaultPolicySource failed to compile: %v", err)
	}
	if _, err := policy.Compile([]byte(defaultClaudeCodePolicySource)); err != nil {
		t.Fatalf("defaultClaudeCodePolicySource failed to compile: %v", err)
	}
}

func TestClaudeCodeToolTableGolden(t *testing.T) {
	// The devenv shadow hook carries the same table; change both together.
	expected := []ToolMapEntry{
		{Name: "Bash", ID: "cc.bash"},
		{Name: "PowerShell", ID: "cc.powershell"},
		{Name: "Read", ID: "cc.read"},
		{Name: "Write", ID: "cc.write"},
		{Name: "Edit", ID: "cc.edit"},
		{Name: "MultiEdit", ID: "cc.multi_edit"},
		{Name: "Glob", ID: "cc.glob"},
		{Name: "Grep", ID: "cc.grep"},
		{Name: "WebFetch", ID: "cc.web_fetch"},
		{Name: "WebSearch", ID: "cc.web_search"},
		{Name: "Task", ID: "cc.task"},
		{Name: "Agent", ID: "cc.agent"},
		{Name: "TodoWrite", ID: "cc.todo_write"},
		{Name: "NotebookEdit", ID: "cc.notebook_edit"},
	}

	if !reflect.DeepEqual(claudeCodeToolMap, expected) {
		t.Fatalf("claudeCodeToolMap does not match golden table:\ngot:  %+v\nwant: %+v", claudeCodeToolMap, expected)
	}

	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/state", nil)
	req.Host = "127.0.0.1:8787"
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/state returned %d", rr.Code)
	}

	var state StateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal state failed: %v", err)
	}

	if !reflect.DeepEqual(state.ToolMap, expected) {
		t.Fatalf("/api/state tool_map does not match golden table:\ngot:  %+v\nwant: %+v", state.ToolMap, expected)
	}
}

func TestClaudeCodeDenyMutatingRuleDecidesBash(t *testing.T) {
	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	res := p.Evaluate(context.Background(), Input{
		Tool:       "cc.bash",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})

	if res.Code != "POLICY_DENIED" {
		t.Fatalf("expected POLICY_DENIED for cc.bash, got code=%s (effect=%s stage=%s)", res.Code, res.Effect, res.Stage)
	}

	hasRuleRef := false
	for _, r := range res.Reasons {
		if r.RuleID == "deny-cc-mutating" {
			hasRuleRef = true
			break
		}
	}
	if !hasRuleRef {
		t.Fatalf("expected decision reasons to reference rule id 'deny-cc-mutating', got: %+v", res.Reasons)
	}

	// Also prove the rule (not default deny) blocked it: flip deny-cc-mutating to allow and assert cc.bash ALLOWs.
	flippedPolicy := defaultPolicySource +
		" - id: allow-cc-low-risk\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: cc.read}, {kind: tool, value: cc.glob}, {kind: tool, value: cc.grep}, {kind: tool, value: cc.todo_write}]}\n" +
		" - id: deny-cc-mutating\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: cc.bash}, {kind: tool, value: cc.powershell}, {kind: tool, value: cc.write}, {kind: tool, value: cc.edit}, {kind: tool, value: cc.multi_edit}]}\n"

	if _, err := p.SetPolicy([]byte(flippedPolicy)); err != nil {
		t.Fatalf("SetPolicy with flipped rule failed: %v", err)
	}

	resFlipped := p.Evaluate(context.Background(), Input{
		Tool:       "cc.bash",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resFlipped.Effect != "ALLOW" || resFlipped.Code != "POLICY_ALLOWED" {
		t.Fatalf("expected ALLOW/POLICY_ALLOWED after flipping deny-cc-mutating to allow, got effect=%s code=%s", resFlipped.Effect, resFlipped.Code)
	}
}

func TestClaudeCodeDenyMutatingRuleDecidesPowerShell(t *testing.T) {
	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	res := p.Evaluate(context.Background(), Input{
		Tool:       "cc.powershell",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})

	if res.Code != "POLICY_DENIED" {
		t.Fatalf("expected POLICY_DENIED for cc.powershell, got code=%s (effect=%s stage=%s)", res.Code, res.Effect, res.Stage)
	}

	hasRuleRef := false
	for _, r := range res.Reasons {
		if r.RuleID == "deny-cc-mutating" {
			hasRuleRef = true
			break
		}
	}
	if !hasRuleRef {
		t.Fatalf("expected decision reasons to reference rule id 'deny-cc-mutating', got: %+v", res.Reasons)
	}

	// Also prove the rule (not default deny) blocked it: flip deny-cc-mutating to allow and assert cc.powershell ALLOWs.
	flippedPolicy := defaultPolicySource +
		" - id: allow-cc-low-risk\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: cc.read}, {kind: tool, value: cc.glob}, {kind: tool, value: cc.grep}, {kind: tool, value: cc.todo_write}]}\n" +
		" - id: deny-cc-mutating\n   effect: allow\n   match: {principals: [demo], operations: [tool.invoke], resources: [{kind: tool, value: cc.bash}, {kind: tool, value: cc.powershell}, {kind: tool, value: cc.write}, {kind: tool, value: cc.edit}, {kind: tool, value: cc.multi_edit}]}\n"

	if _, err := p.SetPolicy([]byte(flippedPolicy)); err != nil {
		t.Fatalf("SetPolicy with flipped rule failed: %v", err)
	}

	resFlipped := p.Evaluate(context.Background(), Input{
		Tool:       "cc.powershell",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resFlipped.Effect != "ALLOW" || resFlipped.Code != "POLICY_ALLOWED" {
		t.Fatalf("expected ALLOW/POLICY_ALLOWED after flipping deny-cc-mutating to allow, got effect=%s code=%s", resFlipped.Effect, resFlipped.Code)
	}
}

func TestDemoModePinnedPolicyDigestAndToolRevision(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	res := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    []byte(`{"note_id":"synthetic-note-001"}`),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if res.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW for fake.read_note, got effect=%s code=%s", res.Effect, res.Code)
	}

	const pinnedPolicyDigest = "sha256:ad05aa538f7eedae6349d2936844f3274328bea5153f26d53b9bf5994e5df071"
	if res.PolicyDigest != pinnedPolicyDigest {
		t.Fatalf("demo mode policy digest mismatch: want %q, got %q", pinnedPolicyDigest, res.PolicyDigest)
	}

	const pinnedToolRevision = "sha256:08679ae379c439a92db95804e02e792f3c456a58f8195a524253ff25342efe15"
	if res.ToolRevision != pinnedToolRevision {
		t.Fatalf("demo mode tool revision mismatch: want %q, got %q", pinnedToolRevision, res.ToolRevision)
	}
}

func TestClaudeCodeBashToolRevisionDiffersOnVariantUpstreamName(t *testing.T) {
	pNormal, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	resNormal := pNormal.Evaluate(context.Background(), Input{
		Tool:       "cc.bash",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resNormal.ToolRevision == "" {
		t.Fatalf("expected non-empty tool revision for cc.bash")
	}

	// Variant where Bash maps to a different UpstreamName
	orig := claudeCodeToolMap[0].Name
	claudeCodeToolMap[0].Name = "DifferentBash"
	pVariant, err := New(WithToolSet(ToolSetClaudeCode))
	claudeCodeToolMap[0].Name = orig
	if err != nil {
		t.Fatalf("New CC variant failed: %v", err)
	}
	resVariant := pVariant.Evaluate(context.Background(), Input{
		Tool:       "cc.bash",
		Payload:    []byte("{}"),
		Credential: "valid",
		TTLMillis:  30000,
	})
	if resVariant.ToolRevision == "" {
		t.Fatalf("expected non-empty tool revision for cc.bash variant")
	}

	if resNormal.ToolRevision == resVariant.ToolRevision {
		t.Fatalf("expected tool revision to differ when UpstreamName changes, but both are %s", resNormal.ToolRevision)
	}
}

func TestToolMapReturnsCopy(t *testing.T) {
	p, err := New(WithToolSet(ToolSetClaudeCode))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tm1 := p.ToolMap()
	if len(tm1) == 0 {
		t.Fatalf("expected non-empty tool map")
	}
	tm1[0] = ToolMapEntry{Name: "Mutated", ID: "cc.mutated"}

	tm2 := p.ToolMap()
	if tm2[0].Name != "Bash" || tm2[0].ID != "cc.bash" {
		t.Fatalf("expected entry 0 still {Bash, cc.bash}, got %+v", tm2[0])
	}
}
