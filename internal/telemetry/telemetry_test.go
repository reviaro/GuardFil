package telemetry

import (
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/failure"
)

func TestDecisionBlockClassification(t *testing.T) {
	c := &Counters{}

	// Policy class
	c.DecisionBlock(failure.POLICY_DENIED)
	c.DecisionBlock(failure.POLICY_EVALUATION_FAILED)
	c.DecisionBlock(failure.POLICY_UNAVAILABLE)

	// Obligation class
	c.DecisionBlock(failure.APPROVAL_UNAVAILABLE)
	c.DecisionBlock(failure.TRANSFORM_UNAVAILABLE)
	c.DecisionBlock(failure.CHECK_UNSUPPORTED)

	// Authority class
	c.DecisionBlock(failure.IDENTITY_UNTRUSTED)
	c.DecisionBlock(failure.BINDING_MISMATCH)
	c.DecisionBlock(failure.AUTH_FORBIDDEN)
	c.DecisionBlock(failure.AUTHORIZATION_STALE)
	c.DecisionBlock(failure.AUTH_INVALID)
	c.DecisionBlock(failure.PROTOCOL_UNSUPPORTED)
	c.DecisionBlock(failure.DEADLINE_EXCEEDED)
	c.DecisionBlock(failure.CANCELLED)

	prom := c.Prometheus()

	if !strings.Contains(prom, "guardfil_decision_policy_blocks_total 3\n") {
		t.Errorf("expected 3 policy blocks in prometheus metrics, got:\n%s", prom)
	}
	if !strings.Contains(prom, "guardfil_decision_obligation_blocks_total 3\n") {
		t.Errorf("expected 3 obligation blocks (including CHECK_UNSUPPORTED) in prometheus metrics, got:\n%s", prom)
	}
	if !strings.Contains(prom, "guardfil_decision_authority_blocks_total 8\n") {
		t.Errorf("expected 8 authority blocks in prometheus metrics, got:\n%s", prom)
	}
}
