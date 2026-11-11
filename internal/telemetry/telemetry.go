package telemetry

import (
	"sync/atomic"

	"github.com/reviaro/guardfil/internal/failure"
)

// Counters deliberately have no unbounded request/user/path labels.
type Counters struct {
	requests         atomic.Uint64
	rejected         atomic.Uint64
	decisionAllows   atomic.Uint64
	authorityBlocks  atomic.Uint64
	policyBlocks     atomic.Uint64
	obligationBlocks atomic.Uint64
}

func (c *Counters) Request() { c.requests.Add(1) }
func (c *Counters) Reject()  { c.rejected.Add(1) }

func (c *Counters) DecisionAllow() { c.decisionAllows.Add(1) }

// DecisionBlock maps a closed reason set to fixed-cardinality counters. Raw
// identity, tenant, resource, digest, and request values are never labels.
func (c *Counters) DecisionBlock(code failure.Code) {
	switch code {
	case failure.POLICY_DENIED, failure.POLICY_EVALUATION_FAILED, failure.POLICY_UNAVAILABLE:
		c.policyBlocks.Add(1)
	case failure.APPROVAL_UNAVAILABLE, failure.TRANSFORM_UNAVAILABLE, failure.CHECK_UNSUPPORTED:
		c.obligationBlocks.Add(1)
	default:
		c.authorityBlocks.Add(1)
	}
}

func (c *Counters) Prometheus() string {
	return "# TYPE guardfil_requests_total counter\n" +
		"guardfil_requests_total " + utoa(c.requests.Load()) + "\n" +
		"# TYPE guardfil_rejections_total counter\n" +
		"guardfil_rejections_total " + utoa(c.rejected.Load()) + "\n" +
		"# TYPE guardfil_decision_allows_total counter\n" +
		"guardfil_decision_allows_total " + utoa(c.decisionAllows.Load()) + "\n" +
		"# TYPE guardfil_decision_authority_blocks_total counter\n" +
		"guardfil_decision_authority_blocks_total " + utoa(c.authorityBlocks.Load()) + "\n" +
		"# TYPE guardfil_decision_policy_blocks_total counter\n" +
		"guardfil_decision_policy_blocks_total " + utoa(c.policyBlocks.Load()) + "\n" +
		"# TYPE guardfil_decision_obligation_blocks_total counter\n" +
		"guardfil_decision_obligation_blocks_total " + utoa(c.obligationBlocks.Load()) + "\n"
}

func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	b := make([]byte, 0, 20)
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
