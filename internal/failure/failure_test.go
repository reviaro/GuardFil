package failure

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The fixture pins the closed vocabulary and pre-send retry crosswalk independently
// of the implementation. It contains only the expectations needed by these tests.
type failureExpectations struct {
	Stages       []Stage        `json:"stages"`
	Codes        []Code         `json:"codes"`
	PreSendRetry map[Code]Retry `json:"pre_send_retry"`
}

func loadFailureExpectations(t *testing.T) failureExpectations {
	t.Helper()
	raw, err := os.ReadFile("testdata/failure_expectations.json")
	if err != nil {
		t.Fatalf("read failure expectations: %v", err)
	}
	var expected failureExpectations
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatalf("decode failure expectations: %v", err)
	}
	if len(expected.Stages) == 0 || len(expected.Codes) == 0 || len(expected.PreSendRetry) == 0 {
		t.Fatal("failure expectations must include stages, codes and retries")
	}
	return expected
}

func TestFailureVocabularyParity(t *testing.T) {
	expected := loadFailureExpectations(t)
	foundStages := make(map[Stage]struct{})
	for _, stage := range expected.Stages {
		foundStages[stage] = struct{}{}
	}

	if len(foundStages) != len(validStages) {
		t.Fatalf("stage count mismatch: found %d, expected %d", len(foundStages), len(validStages))
	}
	for s := range validStages {
		if _, ok := foundStages[s]; !ok {
			t.Fatalf("missing stage from fixture: %s", s)
		}
	}
	for s := range foundStages {
		if _, ok := validStages[s]; !ok {
			t.Fatalf("unexpected stage found in fixture: %s", s)
		}
	}

	foundCodes := make(map[Code]struct{})
	for _, code := range expected.Codes {
		foundCodes[code] = struct{}{}
	}

	if len(foundCodes) != len(validCodes) {
		t.Fatalf("code count mismatch: found %d in fixture, package has %d", len(foundCodes), len(validCodes))
	}
	for c := range validCodes {
		if _, ok := foundCodes[c]; !ok {
			t.Fatalf("code %s from package not found in fixture", c)
		}
	}
	for c := range foundCodes {
		if _, ok := validCodes[c]; !ok {
			t.Fatalf("code %s from fixture not found in package", c)
		}
	}
}

func TestValidation(t *testing.T) {
	if len(validCodes) != 39 {
		t.Fatalf("expected exactly 39 codes, got %d", len(validCodes))
	}
	if len(validStages) != 9 {
		t.Fatalf("expected exactly 9 stages, got %d", len(validStages))
	}

	for c := range validCodes {
		if !c.Valid() {
			t.Errorf("expected code %s to be valid", c)
		}
	}
	if Code("NOT_A_CODE").Valid() {
		t.Error("expected NOT_A_CODE to be invalid")
	}
	if Code("").Valid() {
		t.Error("expected empty code to be invalid")
	}

	for s := range validStages {
		if !s.Valid() {
			t.Errorf("expected stage %s to be valid", s)
		}
	}
	if Stage("not_a_stage").Valid() {
		t.Error("expected not_a_stage to be invalid")
	}
	if Stage("").Valid() {
		t.Error("expected empty stage to be invalid")
	}

	for _, r := range []Retry{RetryNever, RetryNewRequestAfterBackoff, RetryStatusOnly} {
		if !r.Valid() {
			t.Errorf("expected retry %s to be valid", r)
		}
	}
	if Retry("unknown").Valid() {
		t.Error("expected unknown retry to be invalid")
	}
	if Retry("").Valid() {
		t.Error("expected empty retry to be invalid")
	}

	for _, e := range []Execution{ExecutionNotDispatched, ExecutionUnknown, ExecutionSucceeded, ExecutionFailed} {
		if !e.Valid() {
			t.Errorf("expected execution %s to be valid", e)
		}
	}
	if Execution("unknown_exec").Valid() {
		t.Error("expected unknown_exec to be invalid")
	}
	if Execution("").Valid() {
		t.Error("expected empty execution to be invalid")
	}

	for _, d := range []DeliveryState{DeliveryWithheld, DeliveryPartial, DeliveryComplete} {
		if !d.Valid() {
			t.Errorf("expected delivery state %s to be valid", d)
		}
	}
	if DeliveryState("unknown_state").Valid() {
		t.Error("expected unknown_state to be invalid")
	}
	if DeliveryState("").Valid() {
		t.Error("expected empty delivery state to be invalid")
	}
}

func TestPreSendRetryCrosswalk(t *testing.T) {
	expected := loadFailureExpectations(t)
	parsedCodes := make(map[Code]struct{})
	for code, wantRetry := range expected.PreSendRetry {
		if !wantRetry.Valid() {
			t.Fatalf("invalid retry %q for code %s in fixture", wantRetry, code)
		}
		parsedCodes[code] = struct{}{}
		got := PreSendRetry(code)
		if got != wantRetry {
			t.Errorf("code %s got retry %q, want %q", code, got, wantRetry)
		}
	}

	if len(parsedCodes) != len(validCodes) {
		t.Fatalf("fixture code count %d != validCodes count %d", len(parsedCodes), len(validCodes))
	}
	for c := range validCodes {
		if _, ok := parsedCodes[c]; !ok {
			t.Errorf("code %s not found in retry fixture", c)
		}
	}

	if PreSendRetry(Code("UNKNOWN_CODE")) != "" {
		t.Errorf("expected unknown code to return empty retry, got %q", PreSendRetry(Code("UNKNOWN_CODE")))
	}
}

func TestEnvelopeValidate(t *testing.T) {
	baseValid := func() Envelope {
		return Envelope{
			SchemaVersion: SchemaVersion,
			Code:          POLICY_DENIED,
			RequestID:     "req-1",
			Stage:         StagePolicy,
			Retry:         RetryNever,
			Execution:     ExecutionNotDispatched,
			Delivery: Delivery{
				State: DeliveryWithheld,
				ReleasedBytes: ReleasedBytes{
					ProtectedText: 0,
					ProtectedTool: 0,
				},
			},
			Message: "Request rejected",
		}
	}

	// SchemaVersion
	{
		env := baseValid()
		if err := env.Validate(); err != nil {
			t.Fatalf("baseValid failed: %v", err)
		}
		env.SchemaVersion = "guardfil.error/2"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for wrong SchemaVersion, got %v", err)
		}
		env.SchemaVersion = ""
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for empty SchemaVersion, got %v", err)
		}
	}

	// Code, Stage, Retry, Execution, DeliveryState
	{
		env := baseValid()
		env.Code = "UNKNOWN"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for invalid code, got %v", err)
		}

		env = baseValid()
		env.Stage = "unknown"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for invalid stage, got %v", err)
		}

		env = baseValid()
		env.Retry = "unknown"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for invalid retry, got %v", err)
		}

		env = baseValid()
		env.Execution = "unknown_exec"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for invalid execution, got %v", err)
		}

		env = baseValid()
		env.Delivery.State = "unknown_state"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ErrInvalidEnvelope for invalid delivery state, got %v", err)
		}
	}

	// Message boundaries: 1 vs 0, 256 vs 257, non-printable
	{
		env := baseValid()
		env.Message = "a"
		if err := env.Validate(); err != nil {
			t.Errorf("expected 1-byte message to be valid, got %v", err)
		}

		env.Message = strings.Repeat("x", 256)
		if err := env.Validate(); err != nil {
			t.Errorf("expected 256-byte message to be valid, got %v", err)
		}

		env.Message = strings.Repeat("x", 257)
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected 257-byte message to be rejected, got %v", err)
		}

		env.Message = ""
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected empty message to be rejected, got %v", err)
		}

		env.Message = "hello\nworld"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected non-printable ASCII (newline) to be rejected, got %v", err)
		}

		env.Message = "hello\x1fworld"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected control char to be rejected, got %v", err)
		}

		env.Message = "hello\x7fworld"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected DEL char to be rejected, got %v", err)
		}
	}

	// retry_after_ms: 0, 1, 60000 accepted; 60001, -1 rejected
	{
		env := baseValid()
		env.Retry = RetryNewRequestAfterBackoff
		env.RetryAfterMS = 0
		if err := env.Validate(); err != nil {
			t.Errorf("expected retry_after_ms=0 to be valid, got %v", err)
		}

		env.RetryAfterMS = 1
		if err := env.Validate(); err != nil {
			t.Errorf("expected retry_after_ms=1 to be valid, got %v", err)
		}

		env.RetryAfterMS = 60000
		if err := env.Validate(); err != nil {
			t.Errorf("expected retry_after_ms=60000 to be valid, got %v", err)
		}

		env.RetryAfterMS = 60001
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected retry_after_ms=60001 to be rejected, got %v", err)
		}

		env.RetryAfterMS = -1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected retry_after_ms=-1 to be rejected, got %v", err)
		}
	}

	// released bytes: MaxReleasedBytes vs MaxReleasedBytes+1, negative
	{
		env := baseValid()
		env.Execution = ExecutionSucceeded
		env.Delivery.State = DeliveryComplete
		env.Delivery.ReleasedBytes.ProtectedText = MaxReleasedBytes
		env.Delivery.ReleasedBytes.ProtectedTool = MaxReleasedBytes
		if err := env.Validate(); err != nil {
			t.Errorf("expected MaxReleasedBytes to be valid, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = MaxReleasedBytes + 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected MaxReleasedBytes+1 ProtectedText to be rejected, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = MaxReleasedBytes
		env.Delivery.ReleasedBytes.ProtectedTool = MaxReleasedBytes + 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected MaxReleasedBytes+1 ProtectedTool to be rejected, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = -1
		env.Delivery.ReleasedBytes.ProtectedTool = 0
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected negative ProtectedText to be rejected, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = -1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected negative ProtectedTool to be rejected, got %v", err)
		}
	}

	// Delivery state invariants
	// Withheld: both 0 accepted; non-zero rejected
	{
		env := baseValid()
		env.Delivery.State = DeliveryWithheld
		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = 0
		if err := env.Validate(); err != nil {
			t.Errorf("expected withheld with 0,0 to be valid, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected withheld with ProtectedText=1 to be rejected, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected withheld with ProtectedTool=1 to be rejected, got %v", err)
		}
	}

	// Partial: sum > 0 accepted; sum == 0 rejected
	{
		env := baseValid()
		env.Execution = ExecutionSucceeded
		env.Delivery.State = DeliveryPartial
		env.Delivery.ReleasedBytes.ProtectedText = 1
		env.Delivery.ReleasedBytes.ProtectedTool = 0
		if err := env.Validate(); err != nil {
			t.Errorf("expected partial with 1,0 to be valid, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = 1
		if err := env.Validate(); err != nil {
			t.Errorf("expected partial with 0,1 to be valid, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = 0
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected partial with 0,0 to be rejected, got %v", err)
		}
	}

	// Complete: accepted as-is (both 0 or non-zero)
	{
		env := baseValid()
		env.Execution = ExecutionSucceeded
		env.Delivery.State = DeliveryComplete
		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = 0
		if err := env.Validate(); err != nil {
			t.Errorf("expected complete with 0,0 to be valid, got %v", err)
		}

		env.Delivery.ReleasedBytes.ProtectedText = 500
		env.Delivery.ReleasedBytes.ProtectedTool = 200
		if err := env.Validate(); err != nil {
			t.Errorf("expected complete with 500,200 to be valid, got %v", err)
		}
	}

	// IDs: request_id required 1..128, bad chars; action_id/decision_id optional 1..128, bad chars
	{
		// request_id
		env := baseValid()
		env.RequestID = "a"
		if err := env.Validate(); err != nil {
			t.Errorf("expected 1-char RequestID to be valid, got %v", err)
		}
		env.RequestID = strings.Repeat("x", 128)
		if err := env.Validate(); err != nil {
			t.Errorf("expected 128-char RequestID to be valid, got %v", err)
		}
		env.RequestID = strings.Repeat("x", 129)
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected 129-char RequestID to be rejected, got %v", err)
		}
		env.RequestID = ""
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected empty RequestID to be rejected, got %v", err)
		}
		env.RequestID = "req with space"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected RequestID with space to be rejected, got %v", err)
		}
		env.RequestID = "req@id"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected RequestID with @ to be rejected, got %v", err)
		}
		env.RequestID = "A-Z.a-z_0:9-"
		if err := env.Validate(); err != nil {
			t.Errorf("expected valid grammar RequestID to be accepted, got %v", err)
		}

		// action_id
		env = baseValid()
		env.ActionID = ""
		if err := env.Validate(); err != nil {
			t.Errorf("expected empty ActionID to be accepted, got %v", err)
		}
		env.ActionID = "a"
		if err := env.Validate(); err != nil {
			t.Errorf("expected 1-char ActionID to be accepted, got %v", err)
		}
		env.ActionID = strings.Repeat("x", 128)
		if err := env.Validate(); err != nil {
			t.Errorf("expected 128-char ActionID to be accepted, got %v", err)
		}
		env.ActionID = strings.Repeat("x", 129)
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected 129-char ActionID to be rejected, got %v", err)
		}
		env.ActionID = "act id"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected ActionID with space to be rejected, got %v", err)
		}

		// decision_id
		env = baseValid()
		env.DecisionID = ""
		if err := env.Validate(); err != nil {
			t.Errorf("expected empty DecisionID to be accepted, got %v", err)
		}
		env.DecisionID = "d"
		if err := env.Validate(); err != nil {
			t.Errorf("expected 1-char DecisionID to be accepted, got %v", err)
		}
		env.DecisionID = strings.Repeat("x", 128)
		if err := env.Validate(); err != nil {
			t.Errorf("expected 128-char DecisionID to be accepted, got %v", err)
		}
		env.DecisionID = strings.Repeat("x", 129)
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected 129-char DecisionID to be rejected, got %v", err)
		}
		env.DecisionID = "dec id"
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected DecisionID with space to be rejected, got %v", err)
		}
	}
}

func TestEnvelopeMarshalJSON(t *testing.T) {
	// Golden JSON for PreDispatch(POLICY_DENIED, StagePolicy, "r-1")
	env, err := PreDispatch(POLICY_DENIED, StagePolicy, "r-1")
	if err != nil {
		t.Fatalf("PreDispatch failed: %v", err)
	}

	data, err := env.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	dataViaJson, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if string(data) != string(dataViaJson) {
		t.Errorf("MarshalJSON and json.Marshal mismatch: %s vs %s", string(data), string(dataViaJson))
	}

	wantGolden := `{"schema_version":"guardfil.error/1","code":"POLICY_DENIED","request_id":"r-1","stage":"policy","retry":"never","execution":"not_dispatched","delivery":{"state":"withheld","released_bytes":{"protected_text":0,"protected_tool":0}},"message":"Request rejected"}`
	if string(data) != wantGolden {
		t.Errorf("golden mismatch:\ngot:  %s\nwant: %s", string(data), wantGolden)
	}

	// Optional fields absent when zero/empty
	if strings.Contains(string(data), "action_id") {
		t.Errorf("expected action_id to be omitted when empty, got %s", string(data))
	}
	if strings.Contains(string(data), "decision_id") {
		t.Errorf("expected decision_id to be omitted when empty, got %s", string(data))
	}
	if strings.Contains(string(data), "retry_after_ms") {
		t.Errorf("expected retry_after_ms to be omitted when 0, got %s", string(data))
	}

	// Optional fields present when set
	envWithOptionals := env
	envWithOptionals.ActionID = "act-123"
	envWithOptionals.DecisionID = "dec-456"
	envWithOptionals.Retry = RetryNewRequestAfterBackoff
	envWithOptionals.RetryAfterMS = 5000
	dataWithOpt, err := envWithOptionals.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON with optionals failed: %v", err)
	}
	if !strings.Contains(string(dataWithOpt), `"action_id":"act-123"`) {
		t.Errorf("expected action_id in output, got %s", string(dataWithOpt))
	}
	if !strings.Contains(string(dataWithOpt), `"decision_id":"dec-456"`) {
		t.Errorf("expected decision_id in output, got %s", string(dataWithOpt))
	}
	if !strings.Contains(string(dataWithOpt), `"retry_after_ms":5000`) {
		t.Errorf("expected retry_after_ms in output, got %s", string(dataWithOpt))
	}

	// Envelope over 2 KiB is refused via JSON escaping:
	// a 256-byte message of "<" (each encodes as \u003c, 6 bytes) plus three 128-byte IDs and retry_after_ms
	envOver := Envelope{
		SchemaVersion: SchemaVersion,
		Code:          POLICY_DENIED,
		RequestID:     strings.Repeat("r", 128),
		Stage:         StagePolicy,
		Retry:         RetryNewRequestAfterBackoff,
		Execution:     ExecutionNotDispatched,
		Delivery: Delivery{
			State: DeliveryWithheld,
			ReleasedBytes: ReleasedBytes{
				ProtectedText: 0,
				ProtectedTool: 0,
			},
		},
		Message:      strings.Repeat("<", 256),
		ActionID:     strings.Repeat("a", 128),
		DecisionID:   strings.Repeat("d", 128),
		RetryAfterMS: 60000,
	}

	// Fields are individually valid
	if err := envOver.Validate(); err != nil {
		t.Fatalf("envOver should pass Validate, got: %v", err)
	}
	// But MarshalJSON refuses it because length > 2048
	if _, err := envOver.MarshalJSON(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected ErrInvalidEnvelope for envelope exceeding 2048 bytes, got %v", err)
	}

	// QA M1: MarshalJSON at exactly 2048 bytes is accepted and at exactly 2049 is refused.
	env2048 := Envelope{
		SchemaVersion: SchemaVersion,
		Code:          POLICY_UNAVAILABLE,
		RequestID:     "r",
		Stage:         StagePolicy,
		Retry:         RetryNewRequestAfterBackoff,
		Execution:     ExecutionNotDispatched,
		Delivery: Delivery{
			State: DeliveryWithheld,
			ReleasedBytes: ReleasedBytes{
				ProtectedText: 0,
				ProtectedTool: 0,
			},
		},
		Message:      strings.Repeat("<", 256),
		ActionID:     "a",
		DecisionID:   "d",
		RetryAfterMS: 60000,
	}

	type Alias Envelope
	rawBase, err := json.Marshal(Alias(env2048))
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	diff := MaxEnvelopeBytes - len(rawBase)
	if diff < 0 {
		t.Fatalf("base length %d exceeds %d", len(rawBase), MaxEnvelopeBytes)
	}
	addAct := diff
	if addAct > 127 {
		addAct = 127
	}
	env2048.ActionID = strings.Repeat("a", 1+addAct)
	diff -= addAct

	addDec := diff
	if addDec > 127 {
		addDec = 127
	}
	env2048.DecisionID = strings.Repeat("d", 1+addDec)
	diff -= addDec

	addReq := diff
	if addReq > 127 {
		addReq = 127
	}
	env2048.RequestID = strings.Repeat("r", 1+addReq)
	diff -= addReq

	if diff != 0 {
		t.Fatalf("failed to pad to exactly 2048 bytes, diff=%d", diff)
	}

	// Verify pre-condition and MarshalJSON acceptance at exactly 2048 bytes
	raw2048, err := json.Marshal(Alias(env2048))
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if len(raw2048) != 2048 {
		t.Fatalf("expected len(raw2048) == 2048, got %d", len(raw2048))
	}
	if err := env2048.Validate(); err != nil {
		t.Fatalf("expected env2048 to pass Validate, got %v", err)
	}
	data2048, err := env2048.MarshalJSON()
	if err != nil {
		t.Fatalf("expected MarshalJSON to accept exactly 2048 bytes, got %v", err)
	}
	if len(data2048) != 2048 {
		t.Fatalf("expected len(data2048) == 2048, got %d", len(data2048))
	}

	// MarshalJSON at exactly 2049 bytes is refused
	env2049 := env2048
	if len(env2049.ActionID) < 128 {
		env2049.ActionID += "a"
	} else if len(env2049.DecisionID) < 128 {
		env2049.DecisionID += "d"
	} else {
		env2049.RequestID += "r"
	}

	raw2049, err := json.Marshal(Alias(env2049))
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if len(raw2049) != 2049 {
		t.Fatalf("expected len(raw2049) == 2049, got %d", len(raw2049))
	}
	if err := env2049.Validate(); err != nil {
		t.Fatalf("expected env2049 to pass Validate, got %v", err)
	}
	if _, err := env2049.MarshalJSON(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected ErrInvalidEnvelope for exactly 2049 bytes, got %v", err)
	}

	// Invalid envelope never marshals
	invalidEnv := env
	invalidEnv.Message = ""
	if _, err := invalidEnv.MarshalJSON(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected ErrInvalidEnvelope when marshaling invalid envelope, got %v", err)
	}
}

func TestEnvelopeValidateCouplingRules(t *testing.T) {
	baseValid := func() Envelope {
		return Envelope{
			SchemaVersion: SchemaVersion,
			Code:          POLICY_DENIED,
			RequestID:     "req-1",
			Stage:         StagePolicy,
			Retry:         RetryNever,
			Execution:     ExecutionNotDispatched,
			Delivery: Delivery{
				State: DeliveryWithheld,
				ReleasedBytes: ReleasedBytes{
					ProtectedText: 0,
					ProtectedTool: 0,
				},
			},
			Message: "Request rejected",
		}
	}

	// Rejections:
	// 1. not_dispatched + partial
	{
		env := baseValid()
		env.Execution = ExecutionNotDispatched
		env.Delivery.State = DeliveryPartial
		env.Delivery.ReleasedBytes.ProtectedText = 10
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected not_dispatched+partial to be rejected, got %v", err)
		}
	}

	// 2. not_dispatched + complete
	{
		env := baseValid()
		env.Execution = ExecutionNotDispatched
		env.Delivery.State = DeliveryComplete
		env.Delivery.ReleasedBytes.ProtectedText = 0
		env.Delivery.ReleasedBytes.ProtectedTool = 0
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected not_dispatched+complete to be rejected, got %v", err)
		}
	}

	// 3. not_dispatched + withheld non-zero
	{
		env := baseValid()
		env.Execution = ExecutionNotDispatched
		env.Delivery.State = DeliveryWithheld
		env.Delivery.ReleasedBytes.ProtectedText = 5
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected not_dispatched+withheld non-zero ProtectedText to be rejected, got %v", err)
		}

		env = baseValid()
		env.Execution = ExecutionNotDispatched
		env.Delivery.State = DeliveryWithheld
		env.Delivery.ReleasedBytes.ProtectedTool = 5
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected not_dispatched+withheld non-zero ProtectedTool to be rejected, got %v", err)
		}
	}

	// 4. unknown + backoff
	{
		env := baseValid()
		env.Execution = ExecutionUnknown
		env.Retry = RetryNewRequestAfterBackoff
		env.RetryAfterMS = 0
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected unknown+backoff to be rejected, got %v", err)
		}
	}

	// 5. unknown + never
	{
		env := baseValid()
		env.Execution = ExecutionUnknown
		env.Retry = RetryNever
		env.RetryAfterMS = 0
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected unknown+never to be rejected, got %v", err)
		}
	}

	// 6. unknown + status_only + retry_after_ms
	{
		env := baseValid()
		env.Execution = ExecutionUnknown
		env.Retry = RetryStatusOnly
		env.RetryAfterMS = 100
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected unknown+status_only+retry_after_ms to be rejected, got %v", err)
		}
	}

	// 7. never + retry_after_ms
	{
		env := baseValid()
		env.Retry = RetryNever
		env.RetryAfterMS = 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected never+retry_after_ms to be rejected, got %v", err)
		}
	}

	// 8. status_only + retry_after_ms
	{
		env := baseValid()
		env.Execution = ExecutionUnknown
		env.Retry = RetryStatusOnly
		env.RetryAfterMS = 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected status_only+retry_after_ms to be rejected, got %v", err)
		}

		env = baseValid()
		env.Execution = ExecutionNotDispatched
		env.Retry = RetryStatusOnly
		env.RetryAfterMS = 1
		if err := env.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("expected status_only+retry_after_ms to be rejected, got %v", err)
		}
	}

	// Acceptances:
	// 9. unknown + status_only + partial with counts
	{
		env := baseValid()
		env.Execution = ExecutionUnknown
		env.Retry = RetryStatusOnly
		env.RetryAfterMS = 0
		env.Delivery.State = DeliveryPartial
		env.Delivery.ReleasedBytes.ProtectedText = 100
		env.Delivery.ReleasedBytes.ProtectedTool = 200
		if err := env.Validate(); err != nil {
			t.Errorf("expected unknown+status_only+partial with counts to be accepted, got %v", err)
		}
	}

	// 10. backoff + retry_after_ms 1 and 60000
	{
		env := baseValid()
		env.Retry = RetryNewRequestAfterBackoff
		env.RetryAfterMS = 1
		if err := env.Validate(); err != nil {
			t.Errorf("expected backoff+retry_after_ms=1 to be accepted, got %v", err)
		}

		env.RetryAfterMS = 60000
		if err := env.Validate(); err != nil {
			t.Errorf("expected backoff+retry_after_ms=60000 to be accepted, got %v", err)
		}
	}
}

func TestPreDispatchInvalidInputs(t *testing.T) {
	// Invalid code returns error
	if _, err := PreDispatch(Code("INVALID_CODE"), StageAuth, "req-1"); err == nil {
		t.Error("expected error for invalid code, got nil")
	}

	// Invalid stage returns error
	if _, err := PreDispatch(AUTH_REQUIRED, Stage("invalid_stage"), "req-1"); err == nil {
		t.Error("expected error for invalid stage, got nil")
	}

	// Invalid request ID returns error
	for _, badID := range []string{"", "has space", "req@bad", strings.Repeat("x", 129)} {
		if _, err := PreDispatch(AUTH_REQUIRED, StageAuth, badID); err == nil {
			t.Errorf("expected error for invalid request ID %q, got nil", badID)
		}
	}

	// Valid inputs succeed
	if _, err := PreDispatch(AUTH_REQUIRED, StageAuth, "valid-req-id"); err != nil {
		t.Errorf("expected valid PreDispatch to succeed, got %v", err)
	}
}
