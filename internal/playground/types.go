package playground

import (
	"encoding/json"

	"github.com/reviaro/guardfil/internal/decision"
)

// Input carries untrusted caller parameters for playground evaluation.
type Input struct {
	Tool            string
	Payload         []byte
	Credential      string
	TTLMillis       int64
	Cancelled       bool
	ExpiredEnvelope bool
}

// TraceStep records an ordered execution step in the advisory pipeline.
type TraceStep struct {
	Step   string `json:"step"`
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
}

// Result is the JSON-serializable evaluation result emitted by the playground.
type Result struct {
	Synthetic        bool              `json:"synthetic"`
	RequestID        string            `json:"request_id"`
	Tool             string            `json:"tool"`
	Credential       string            `json:"credential,omitempty"`
	FakeToolKnown    bool              `json:"fake_tool_known"`
	Effect           string            `json:"effect"`
	Code             string            `json:"code"`
	Stage            string            `json:"stage"`
	Reasons          []decision.Reason `json:"reasons"`
	DecisionID       string            `json:"decision_id"`
	ActionID         string            `json:"action_id"`
	ActionDigest     string            `json:"action_digest"`
	ToolRevision     string            `json:"tool_revision"`
	Boundary         string            `json:"boundary"`
	RevocationEpoch  uint64            `json:"revocation_epoch"`
	PolicyDigest     string            `json:"policy_digest"`
	PolicyRevision   uint64            `json:"policy_revision"`
	EvaluatedAt      string            `json:"evaluated_at"`
	ExpiresAt        string            `json:"expires_at"`
	ReceivedAt       string            `json:"received_at"`
	DeadlineAt       string            `json:"deadline_at"`
	DispatchEligible bool              `json:"dispatch_eligible"`
	Trace            []TraceStep       `json:"trace"`
	ErrorEnvelope    json.RawMessage   `json:"error_envelope"`
	EnvelopeError    string            `json:"envelope_error,omitempty"`
}

// PolicyInfo describes the active policy document and its compiled metadata.
type PolicyInfo struct {
	Source   string `json:"source"`
	Digest   string `json:"digest"`
	Revision uint64 `json:"revision"`
}

// FixtureRow represents one red-team synthetic fixture row from advisorydemo.
type FixtureRow struct {
	FixtureID        string          `json:"fixture_id"`
	Tool             string          `json:"tool"`
	Effect           decision.Effect `json:"effect"`
	Stage            string          `json:"stage"`
	Auth             string          `json:"auth"`
	Reason           string          `json:"reason"`
	ActionDigest     string          `json:"action_digest"`
	DispatchEligible bool            `json:"dispatch_eligible"`
}

// ToolInfo describes a fake tool known to the playground catalog.
type ToolInfo struct {
	Tool       string            `json:"tool"`
	InRegistry bool              `json:"in_registry"`
	Fields     map[string]string `json:"fields"`
}

// CountersInfo contains parsed telemetry counters for JSON reporting.
type CountersInfo struct {
	Requests         uint64 `json:"requests"`
	Rejections       uint64 `json:"rejections"`
	Allows           uint64 `json:"allows"`
	AuthorityBlocks  uint64 `json:"authority_blocks"`
	PolicyBlocks     uint64 `json:"policy_blocks"`
	ObligationBlocks uint64 `json:"obligation_blocks"`
}

// ToolMapEntry maps a Claude Code tool name to its kernel tool ID.
type ToolMapEntry struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// StateResponse is returned by GET /api/state.
type StateResponse struct {
	Policy       PolicyInfo     `json:"policy"`
	Tools        []ToolInfo     `json:"tools"`
	Credentials  []string       `json:"credentials"`
	Counters     *CountersInfo  `json:"counters,omitempty"`
	CountersText string         `json:"counters_text"`
	History      []Result       `json:"history"`
	ToolSet      string         `json:"tool_set"`
	ToolMap      []ToolMapEntry `json:"tool_map"`
}
