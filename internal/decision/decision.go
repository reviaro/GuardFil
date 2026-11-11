// Package decision is the only internal composition point for evaluation.
// It never creates an executable result on parser, policy, deadline or panic.
package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/identity"
	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/source"
	"github.com/reviaro/guardfil/internal/telemetry"
)

// EvaluationBudget is the maximum time budget allocated for an Authorize evaluation.
const EvaluationBudget = 500 * time.Millisecond

type Effect string

const (
	ALLOW Effect = "ALLOW"
	BLOCK Effect = "BLOCK"
)

type ReasonCode string

const (
	allowReason ReasonCode = "POLICY_ALLOWED"
	// monitorReason marks an ALLOW that a monitor rule permitted: the caller
	// must record the call as monitored.
	monitorReason ReasonCode = "POLICY_MONITORED"
	// filterReason marks an ALLOW that carries a filter obligation: the
	// caller must pass the call's result through GuardFil's filter.
	filterReason ReasonCode = "POLICY_FILTERED"
)

type Reason struct {
	Code   ReasonCode `json:"code"`
	RuleID string     `json:"rule_id,omitempty"`
}

func makeReasons(code ReasonCode, ruleIDs []string) []Reason {
	if len(ruleIDs) == 0 {
		return []Reason{{Code: code, RuleID: ""}}
	}
	reasons := make([]Reason, len(ruleIDs))
	for i, id := range ruleIDs {
		reasons[i] = Reason{Code: code, RuleID: id}
	}
	sort.Slice(reasons, func(i, j int) bool {
		if reasons[i].Code != reasons[j].Code {
			return reasons[i].Code < reasons[j].Code
		}
		return reasons[i].RuleID < reasons[j].RuleID
	})
	dedup := reasons[:1]
	for i := 1; i < len(reasons); i++ {
		if reasons[i] != dedup[len(dedup)-1] {
			dedup = append(dedup, reasons[i])
		}
	}
	if len(dedup) > 32 {
		dedup = dedup[:32]
	}
	return dedup
}

type Decision struct {
	DecisionID, ActionID, ToolRevision, Boundary string
	RevocationEpoch                              uint64
	SchemaVersion, ActionDigest, PolicyDigest    string
	PolicyRevision                               uint64
	EvaluatedAt, ExpiresAt                       time.Time
	Effect                                       Effect
	Stage                                        failure.Stage
	Reasons                                      []Reason
	// Filter lists the sanitize rules whose filter obligation applies to the
	// call's result (set only for an engine built WithFilterSupport).
	Filter           []string
	dispatchEligible bool
}

func (d Decision) Code() failure.Code {
	if d.Effect == ALLOW {
		return ""
	}
	if len(d.Reasons) == 0 {
		return ""
	}
	return failure.Code(d.Reasons[0].Code)
}

// DispatchEligible is deliberately a non-capability in P1.2. A policy ALLOW
// is diagnostic only; P1.4 must issue a separately sealed admission receipt.
func (d Decision) DispatchEligible() bool { return false }

var (
	testPostEvaluateHook func()
)

type Option func(*engineConfiguration)

// WithClock overrides the clock used by the Engine.
func WithClock(c source.Clock) Option {
	return func(cfg *engineConfiguration) {
		cfg.clock = c
	}
}

// WithIDSource overrides the IDSource used by the Engine.
func WithIDSource(ids source.IDSource) Option {
	return func(cfg *engineConfiguration) {
		cfg.ids = ids
	}
}

// WithFilterSupport declares that the caller filters the call's result.  A
// sanitize rule then permits the call with a filter obligation (Decision.Filter)
// instead of blocking it as TRANSFORM_UNAVAILABLE.
func WithFilterSupport() Option {
	return func(cfg *engineConfiguration) {
		cfg.filter = true
	}
}

type Engine struct {
	// Policy and Now remain only so the pre-remediation API continues to
	// compile and fail closed. Authorize uses the private configuration created
	// by NewEngine and the process clock; caller-selected time and policy fields
	// cannot mint a positive decision.
	Policy policy.Snapshot
	Now    func() time.Time
	sealed *engineConfiguration
}

type engineConfiguration struct {
	policy   policy.Snapshot
	registry *identity.Registry
	counters *telemetry.Counters
	clock    source.Clock
	ids      source.IDSource
	filter   bool
}

var ErrNonAllow = errors.New("non-allow decision")

// NewEngine creates the only engine form capable of returning ALLOW. The
// policy snapshot and identity registry are captured behind a private boundary
// so later mutation of exported compatibility fields has no effect.
func NewEngine(snapshot policy.Snapshot, registry *identity.Registry, opts ...Option) (Engine, error) {
	return NewEngineWithTelemetry(snapshot, registry, nil, opts...)
}

// NewEngineWithTelemetry lets the integration layer share the kernel's
// fixed-cardinality counters with the management endpoint.
func NewEngineWithTelemetry(snapshot policy.Snapshot, registry *identity.Registry, counters *telemetry.Counters, opts ...Option) (Engine, error) {
	if snapshot.Digest() == "" || snapshot.Revision() == 0 || registry == nil {
		return Engine{}, ErrNonAllow
	}
	if counters == nil {
		counters = &telemetry.Counters{}
	}
	cfg := &engineConfiguration{
		policy:   snapshot,
		registry: registry,
		counters: counters,
		clock:    source.System{},
		ids:      source.Random{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.clock == nil || cfg.ids == nil {
		return Engine{}, ErrNonAllow
	}
	return Engine{
		Policy: snapshot,
		sealed: cfg,
	}, nil
}

// Decide is the deprecated pre-remediation API. Its caller-selected Action,
// tenant, principal, operation, resource, deadline, policy, and clock cannot
// establish authority, so it is permanently fail-closed. Use Authorize with a
// normalized resource-bound Action and authenticated PrincipalContext.
func (e Engine) Decide(ctx context.Context, a action.Action, tenant, principal, operation, resource string, deadline time.Time) (Decision, error) {
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}
	base := blocked(a.TrustedDigest(), e.Policy, now, failure.IDENTITY_UNTRUSTED, failure.StageAuth)
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return e.reject(base, failure.CANCELLED, failure.StagePolicy)
		}
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}
	if deadline.IsZero() || !now.Before(deadline) {
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}
	e.recordBlock(failure.IDENTITY_UNTRUSTED)
	return base, ErrNonAllow
}

// Authorize evaluates only trusted values: the operation/resource/digest come
// from the sealed Action, the tenant/principal come from the registry-issued
// PrincipalContext, and the registry is rechecked live before a positive
// result. Approval, sanitization, and evidence obligations remain non-allow
// until dedicated independently reviewed gates exist.
//
// ALLOW does not vouch for which action.Registry/route/executor formed the Action;
// a future dispatch gate must verify registry provenance.
func (e Engine) Authorize(ctx context.Context, a action.Action, principal identity.PrincipalContext) (Decision, error) {
	if e.sealed == nil || e.sealed.registry == nil || e.sealed.clock == nil || e.sealed.ids == nil {
		now := time.Now().UTC()
		var snapshot policy.Snapshot
		if e.sealed != nil {
			snapshot = e.sealed.policy
		}
		base := blocked(a.TrustedDigest(), snapshot, now, failure.POLICY_UNAVAILABLE, failure.StagePolicy)
		return e.reject(base, failure.POLICY_UNAVAILABLE, failure.StagePolicy)
	}

	clock := e.sealed.clock
	now := clock.Now()
	decisionID, err := e.sealed.ids.NewID()
	if err != nil || !failure.ValidID(decisionID) {
		base := blocked(a.TrustedDigest(), e.sealed.policy, now.UTC(), failure.INTERNAL_ERROR, failure.StagePolicy)
		return e.reject(base, failure.INTERNAL_ERROR, failure.StagePolicy)
	}

	base := blocked(a.TrustedDigest(), e.sealed.policy, now.UTC(), failure.POLICY_EVALUATION_FAILED, failure.StagePolicy)
	base.DecisionID = decisionID

	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return e.reject(base, failure.CANCELLED, failure.StagePolicy)
		}
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}

	if !a.Authorizable() {
		return e.reject(base, failure.BINDING_MISMATCH, failure.StageNormalize)
	}

	if env, ok := a.TrustedEnvelope(); ok {
		base.ActionID = env.ActionID
	}
	if tc, ok := a.TrustedContext(); ok {
		base.ToolRevision = tc.ToolRevision()
		base.Boundary = string(tc.Boundary())
	}

	receivedAt, deadline, ok := a.TrustedDeadline()
	if !ok {
		return e.reject(base, failure.BINDING_MISMATCH, failure.StageNormalize)
	}

	if now.Before(receivedAt) {
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}

	if !now.Before(deadline) {
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}

	budget := now.Add(EvaluationBudget)
	if deadline.Before(budget) {
		budget = deadline
	}

	actor, err := action.ProjectActor(principal)
	if err != nil {
		return e.reject(base, failure.IDENTITY_UNTRUSTED, failure.StageAuth)
	}

	if !a.BoundActorMatches(actor) {
		return e.reject(base, failure.BINDING_MISMATCH, failure.StageNormalize)
	}

	operation := a.TrustedSecurityOperation()
	if operation == "" {
		return e.reject(base, failure.PROTOCOL_UNSUPPORTED, failure.StageNormalize)
	}

	if err := e.sealed.registry.Validate(principal, operation, a.TrustedResourceKind(), a.TrustedResource(), now); err != nil {
		switch {
		case errors.Is(err, identity.ErrForbidden):
			return e.reject(base, failure.AUTH_FORBIDDEN, failure.StageAuth)
		case errors.Is(err, identity.ErrStale):
			return e.reject(base, failure.AUTHORIZATION_STALE, failure.StageAuth)
		default:
			return e.reject(base, failure.AUTH_INVALID, failure.StageAuth)
		}
	}

	base.RevocationEpoch = principal.RevocationEpoch()

	r, err := e.sealed.policy.EvaluateArgs(policy.Input{
		TenantID:     principal.TenantID(),
		PrincipalID:  principal.PrincipalID(),
		Operation:    operation,
		ResourceKind: a.TrustedResourceKind(),
		Resource:     a.TrustedResource(),
	}, topLevelNumbers(a.TrustedPayload()))
	if err != nil {
		return e.reject(base, failure.POLICY_EVALUATION_FAILED, failure.StagePolicy)
	}

	// With filter support a sanitize rule is a grant with an obligation, kept
	// through an approval: the result is filtered whether or not the owner was asked.
	filtering := r.RequiresSanitization && e.sealed.filter
	// Filtering can satisfy an obligation without supplying authorization:
	// an unknown amount must not turn a restrictive sanitize rule into a grant.
	granted := r.Allowed || (filtering && (r.SanitizationGrants || len(r.AllowRules) > 0 || len(r.MonitorRules) > 0))
	if filtering {
		base.Filter = r.SanitizeRules
	}
	switch {
	case r.Denied:
		return e.reject(base, failure.POLICY_DENIED, failure.StagePolicy, r.DenyRules...)
	case len(r.Checks) > 0:
		return e.reject(base, failure.CHECK_UNSUPPORTED, failure.StageAnalysis, r.CheckRules...)
	case r.RequiresSanitization && !filtering:
		return e.reject(base, failure.TRANSFORM_UNAVAILABLE, failure.StagePolicy, r.SanitizeRules...)
	case r.RequiresApproval:
		return e.reject(base, failure.APPROVAL_UNAVAILABLE, failure.StageApproval, r.ApprovalRules...)
	case !granted:
		return e.reject(base, failure.POLICY_DENIED, failure.StagePolicy)
	}

	if testPostEvaluateHook != nil {
		testPostEvaluateHook()
	}
	freshNow := clock.Now()
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return e.reject(base, failure.CANCELLED, failure.StagePolicy)
		}
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}
	if !freshNow.Before(budget) {
		return e.reject(base, failure.DEADLINE_EXCEEDED, failure.StagePolicy)
	}

	base.Effect = ALLOW
	base.Stage = ""
	if r.Monitored {
		base.Reasons = makeReasons(monitorReason, r.MonitorRules)
		if len(r.AllowRules) > 0 {
			base.Reasons = append(makeReasons(allowReason, r.AllowRules), base.Reasons...)
		}
		if len(base.Reasons) > 32 {
			base.Reasons = base.Reasons[:32]
		}
	} else if filtering {
		// r.Monitored is false here: a sanitize obligation is not plain monitoring.
		base.Reasons = makeReasons(filterReason, r.SanitizeRules)
		if len(r.AllowRules) > 0 {
			base.Reasons = append(makeReasons(allowReason, r.AllowRules), base.Reasons...)
		}
		if len(base.Reasons) > 32 {
			base.Reasons = base.Reasons[:32]
		}
	} else {
		base.Reasons = makeReasons(allowReason, r.AllowRules)
	}
	exp := now.Add(30 * time.Second)
	if deadline.Before(exp) {
		exp = deadline
	}
	if principal.ExpiresAt().Before(exp) {
		exp = principal.ExpiresAt()
	}
	base.ExpiresAt = exp.UTC()
	e.sealed.counters.DecisionAllow()
	return base, nil
}

func (e Engine) reject(base Decision, code failure.Code, stage failure.Stage, ruleIDs ...string) (Decision, error) {
	base.Effect = BLOCK
	base.Stage = stage
	base.Reasons = makeReasons(ReasonCode(code), ruleIDs)
	e.recordBlock(code)
	return base, ErrNonAllow
}

func (e Engine) recordBlock(code failure.Code) {
	if e.sealed != nil && e.sealed.counters != nil {
		e.sealed.counters.DecisionBlock(code)
	}
}

func blocked(actionDigest string, snapshot policy.Snapshot, now time.Time, code failure.Code, stage failure.Stage, ruleIDs ...string) Decision {
	var policyDigest string
	var policyRevision uint64
	if snapshot.Digest() != "" {
		policyDigest = snapshot.Digest()
		policyRevision = snapshot.Revision()
	}
	return Decision{
		SchemaVersion:  "guardfil.decision/1",
		ActionDigest:   actionDigest,
		PolicyDigest:   policyDigest,
		PolicyRevision: policyRevision,
		EvaluatedAt:    now,
		ExpiresAt:      now,
		Effect:         BLOCK,
		Stage:          stage,
		Reasons:        makeReasons(ReasonCode(code), ruleIDs),
	}
}

// topLevelNumbers returns a payload object's top-level numeric members as their
// exact tokens (nil if the payload is not an object).  Nested values are not
// selectable by amount conditions.
func topLevelNumbers(payload []byte) map[string]string {
	if len(payload) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	var m map[string]any
	if d.Decode(&m) != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range m {
		if n, ok := v.(json.Number); ok {
			out[k] = string(n)
		}
	}
	return out
}
