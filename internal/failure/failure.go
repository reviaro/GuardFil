// Package failure defines the closed code and stage vocabulary for guardfil.error/1.
package failure

import (
	"encoding/json"
	"errors"
)

type Code string

const (
	AUTH_REQUIRED            Code = "AUTH_REQUIRED"
	AUTH_INVALID             Code = "AUTH_INVALID"
	IDENTITY_UNTRUSTED       Code = "IDENTITY_UNTRUSTED"
	AUTH_FORBIDDEN           Code = "AUTH_FORBIDDEN"
	PARSE_INVALID            Code = "PARSE_INVALID"
	CONTROL_CHARACTER        Code = "CONTROL_CHARACTER"
	DECIMAL_LITERAL_INVALID  Code = "DECIMAL_LITERAL_INVALID"
	SCHEMA_INVALID           Code = "SCHEMA_INVALID"
	PROTOCOL_UNSUPPORTED     Code = "PROTOCOL_UNSUPPORTED"
	TOOL_REVISION_UNKNOWN    Code = "TOOL_REVISION_UNKNOWN"
	BINDING_MISMATCH         Code = "BINDING_MISMATCH"
	ASSEMBLY_INCOMPLETE      Code = "ASSEMBLY_INCOMPLETE"
	LIMIT_EXCEEDED           Code = "LIMIT_EXCEEDED"
	POLICY_UNAVAILABLE       Code = "POLICY_UNAVAILABLE"
	POLICY_EVALUATION_FAILED Code = "POLICY_EVALUATION_FAILED"
	POLICY_DENIED            Code = "POLICY_DENIED"
	CHECK_FAILED             Code = "CHECK_FAILED"
	CHECK_TIMEOUT            Code = "CHECK_TIMEOUT"
	CHECK_UNSUPPORTED        Code = "CHECK_UNSUPPORTED"
	EVIDENCE_INVALID         Code = "EVIDENCE_INVALID"
	OVERLOADED               Code = "OVERLOADED"
	DEADLINE_EXCEEDED        Code = "DEADLINE_EXCEEDED"
	AUDIT_UNAVAILABLE        Code = "AUDIT_UNAVAILABLE"
	APPROVAL_PENDING         Code = "APPROVAL_PENDING"
	APPROVAL_UNAVAILABLE     Code = "APPROVAL_UNAVAILABLE"
	APPROVAL_REJECTED        Code = "APPROVAL_REJECTED"
	APPROVAL_EXPIRED         Code = "APPROVAL_EXPIRED"
	APPROVAL_STALE           Code = "APPROVAL_STALE"
	APPROVAL_CONSUMED        Code = "APPROVAL_CONSUMED"
	TRANSFORM_UNAVAILABLE    Code = "TRANSFORM_UNAVAILABLE"
	TRANSFORM_FAILED         Code = "TRANSFORM_FAILED"
	IDEMPOTENCY_CONFLICT     Code = "IDEMPOTENCY_CONFLICT"
	CANCELLED                Code = "CANCELLED"
	UPSTREAM_TIMEOUT         Code = "UPSTREAM_TIMEOUT"
	UPSTREAM_ERROR           Code = "UPSTREAM_ERROR"
	RECOVERY_REQUIRED        Code = "RECOVERY_REQUIRED"
	STATE_UNAVAILABLE        Code = "STATE_UNAVAILABLE"
	AUTHORIZATION_STALE      Code = "AUTHORIZATION_STALE"
	INTERNAL_ERROR           Code = "INTERNAL_ERROR"
)

type Stage string

const (
	StageAuth      Stage = "auth"
	StageParse     Stage = "parse"
	StageNormalize Stage = "normalize"
	StagePolicy    Stage = "policy"
	StageAnalysis  Stage = "analysis"
	StageApproval  Stage = "approval"
	StageAdmission Stage = "admission"
	StageUpstream  Stage = "upstream"
	StageRecovery  Stage = "recovery"
)

type Retry string

const (
	RetryNever                  Retry = "never"
	RetryNewRequestAfterBackoff Retry = "new_request_after_backoff"
	RetryStatusOnly             Retry = "status_only"
)

func (r Retry) Valid() bool {
	switch r {
	case RetryNever, RetryNewRequestAfterBackoff, RetryStatusOnly:
		return true
	default:
		return false
	}
}

type Execution string

const (
	ExecutionNotDispatched Execution = "not_dispatched"
	ExecutionUnknown       Execution = "unknown"
	ExecutionSucceeded     Execution = "succeeded"
	ExecutionFailed        Execution = "failed"
)

func (e Execution) Valid() bool {
	switch e {
	case ExecutionNotDispatched, ExecutionUnknown, ExecutionSucceeded, ExecutionFailed:
		return true
	default:
		return false
	}
}

type DeliveryState string

const (
	DeliveryWithheld DeliveryState = "withheld"
	DeliveryPartial  DeliveryState = "partial"
	DeliveryComplete DeliveryState = "complete"
)

func (d DeliveryState) Valid() bool {
	switch d {
	case DeliveryWithheld, DeliveryPartial, DeliveryComplete:
		return true
	default:
		return false
	}
}

type ReleasedBytes struct {
	ProtectedText int64 `json:"protected_text"`
	ProtectedTool int64 `json:"protected_tool"`
}

type Delivery struct {
	State         DeliveryState `json:"state"`
	ReleasedBytes ReleasedBytes `json:"released_bytes"`
}

const SchemaVersion = "guardfil.error/1"
const MaxEnvelopeBytes = 2048
const MaxReleasedBytes int64 = 1 << 20

var ErrInvalidEnvelope = errors.New("invalid envelope")

type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Code          Code      `json:"code"`
	RequestID     string    `json:"request_id"`
	Stage         Stage     `json:"stage"`
	Retry         Retry     `json:"retry"`
	Execution     Execution `json:"execution"`
	Delivery      Delivery  `json:"delivery"`
	Message       string    `json:"message"`
	ActionID      string    `json:"action_id,omitempty"`
	DecisionID    string    `json:"decision_id,omitempty"`
	RetryAfterMS  int       `json:"retry_after_ms,omitempty"`
}

func ValidID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
}

func validMessage(s string) bool {
	if len(s) < 1 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

func (e Envelope) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return ErrInvalidEnvelope
	}
	if !e.Code.Valid() || !e.Stage.Valid() || !e.Retry.Valid() || !e.Execution.Valid() || !e.Delivery.State.Valid() {
		return ErrInvalidEnvelope
	}
	if !ValidID(e.RequestID) {
		return ErrInvalidEnvelope
	}
	if e.ActionID != "" && !ValidID(e.ActionID) {
		return ErrInvalidEnvelope
	}
	if e.DecisionID != "" && !ValidID(e.DecisionID) {
		return ErrInvalidEnvelope
	}
	if !validMessage(e.Message) {
		return ErrInvalidEnvelope
	}
	if e.RetryAfterMS < 0 || e.RetryAfterMS > 60000 {
		return ErrInvalidEnvelope
	}
	pt := e.Delivery.ReleasedBytes.ProtectedText
	pto := e.Delivery.ReleasedBytes.ProtectedTool
	if pt < 0 || pt > MaxReleasedBytes || pto < 0 || pto > MaxReleasedBytes {
		return ErrInvalidEnvelope
	}
	switch e.Delivery.State {
	case DeliveryWithheld:
		if pt != 0 || pto != 0 {
			return ErrInvalidEnvelope
		}
	case DeliveryPartial:
		if pt+pto <= 0 {
			return ErrInvalidEnvelope
		}
	case DeliveryComplete:
		// accepted as-is (no evidence model yet)
	default:
		return ErrInvalidEnvelope
	}
	if e.Execution == ExecutionNotDispatched {
		if e.Delivery.State != DeliveryWithheld || pt != 0 || pto != 0 {
			return ErrInvalidEnvelope
		}
	}
	if e.Execution == ExecutionUnknown {
		if e.Retry != RetryStatusOnly || e.RetryAfterMS != 0 {
			return ErrInvalidEnvelope
		}
	}
	if e.RetryAfterMS != 0 && e.Retry != RetryNewRequestAfterBackoff {
		return ErrInvalidEnvelope
	}
	return nil
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	type Alias Envelope
	b, err := json.Marshal(Alias(e))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxEnvelopeBytes {
		return nil, ErrInvalidEnvelope
	}
	return b, nil
}

var retryMap = map[Code]Retry{
	AUTH_REQUIRED:            RetryNever,
	AUTH_INVALID:             RetryNever,
	IDENTITY_UNTRUSTED:       RetryNever,
	AUTH_FORBIDDEN:           RetryNever,
	PARSE_INVALID:            RetryNever,
	CONTROL_CHARACTER:        RetryNever,
	DECIMAL_LITERAL_INVALID:  RetryNever,
	SCHEMA_INVALID:           RetryNever,
	PROTOCOL_UNSUPPORTED:     RetryNever,
	TOOL_REVISION_UNKNOWN:    RetryNever,
	BINDING_MISMATCH:         RetryNever,
	ASSEMBLY_INCOMPLETE:      RetryNever,
	LIMIT_EXCEEDED:           RetryNever,
	POLICY_UNAVAILABLE:       RetryNewRequestAfterBackoff,
	POLICY_EVALUATION_FAILED: RetryNewRequestAfterBackoff,
	POLICY_DENIED:            RetryNever,
	CHECK_FAILED:             RetryNewRequestAfterBackoff,
	CHECK_TIMEOUT:            RetryNewRequestAfterBackoff,
	CHECK_UNSUPPORTED:        RetryNever,
	EVIDENCE_INVALID:         RetryNever,
	OVERLOADED:               RetryNewRequestAfterBackoff,
	DEADLINE_EXCEEDED:        RetryNewRequestAfterBackoff,
	AUDIT_UNAVAILABLE:        RetryNewRequestAfterBackoff,
	APPROVAL_PENDING:         RetryStatusOnly,
	APPROVAL_UNAVAILABLE:     RetryStatusOnly,
	APPROVAL_REJECTED:        RetryNever,
	APPROVAL_EXPIRED:         RetryNever,
	APPROVAL_STALE:           RetryStatusOnly,
	APPROVAL_CONSUMED:        RetryStatusOnly,
	TRANSFORM_UNAVAILABLE:    RetryNever,
	TRANSFORM_FAILED:         RetryNever,
	IDEMPOTENCY_CONFLICT:     RetryNever,
	CANCELLED:                RetryNever,
	UPSTREAM_TIMEOUT:         RetryNewRequestAfterBackoff,
	UPSTREAM_ERROR:           RetryNewRequestAfterBackoff,
	RECOVERY_REQUIRED:        RetryStatusOnly,
	STATE_UNAVAILABLE:        RetryStatusOnly,
	AUTHORIZATION_STALE:      RetryNewRequestAfterBackoff,
	INTERNAL_ERROR:           RetryNever,
}

// PreSendRetry returns the retry for a pre-send / not_dispatched envelope only;
// post-dispatch outcomes (execution unknown) are status_only and must not use it.
func PreSendRetry(c Code) Retry {
	return retryMap[c]
}

const PreDispatchMessage = "Request rejected"

func PreDispatch(code Code, stage Stage, requestID string) (Envelope, error) {
	e := Envelope{
		SchemaVersion: SchemaVersion,
		Code:          code,
		RequestID:     requestID,
		Stage:         stage,
		Retry:         PreSendRetry(code),
		Execution:     ExecutionNotDispatched,
		Delivery: Delivery{
			State: DeliveryWithheld,
			ReleasedBytes: ReleasedBytes{
				ProtectedText: 0,
				ProtectedTool: 0,
			},
		},
		Message: PreDispatchMessage,
	}
	if err := e.Validate(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

var validCodes = map[Code]struct{}{
	AUTH_REQUIRED:            {},
	AUTH_INVALID:             {},
	IDENTITY_UNTRUSTED:       {},
	AUTH_FORBIDDEN:           {},
	PARSE_INVALID:            {},
	CONTROL_CHARACTER:        {},
	DECIMAL_LITERAL_INVALID:  {},
	SCHEMA_INVALID:           {},
	PROTOCOL_UNSUPPORTED:     {},
	TOOL_REVISION_UNKNOWN:    {},
	BINDING_MISMATCH:         {},
	ASSEMBLY_INCOMPLETE:      {},
	LIMIT_EXCEEDED:           {},
	POLICY_UNAVAILABLE:       {},
	POLICY_EVALUATION_FAILED: {},
	POLICY_DENIED:            {},
	CHECK_FAILED:             {},
	CHECK_TIMEOUT:            {},
	CHECK_UNSUPPORTED:        {},
	EVIDENCE_INVALID:         {},
	OVERLOADED:               {},
	DEADLINE_EXCEEDED:        {},
	AUDIT_UNAVAILABLE:        {},
	APPROVAL_PENDING:         {},
	APPROVAL_UNAVAILABLE:     {},
	APPROVAL_REJECTED:        {},
	APPROVAL_EXPIRED:         {},
	APPROVAL_STALE:           {},
	APPROVAL_CONSUMED:        {},
	TRANSFORM_UNAVAILABLE:    {},
	TRANSFORM_FAILED:         {},
	IDEMPOTENCY_CONFLICT:     {},
	CANCELLED:                {},
	UPSTREAM_TIMEOUT:         {},
	UPSTREAM_ERROR:           {},
	RECOVERY_REQUIRED:        {},
	STATE_UNAVAILABLE:        {},
	AUTHORIZATION_STALE:      {},
	INTERNAL_ERROR:           {},
}

var validStages = map[Stage]struct{}{
	StageAuth:      {},
	StageParse:     {},
	StageNormalize: {},
	StagePolicy:    {},
	StageAnalysis:  {},
	StageApproval:  {},
	StageAdmission: {},
	StageUpstream:  {},
	StageRecovery:  {},
}

func (c Code) Valid() bool {
	_, ok := validCodes[c]
	return ok
}

func (s Stage) Valid() bool {
	_, ok := validStages[s]
	return ok
}
