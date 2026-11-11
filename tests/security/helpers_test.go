package security_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/identity"
)

func normalizeActionForTest(t testing.TB, principal identity.PrincipalContext, op, resource string, raw []byte, schema action.Schema) (action.Action, error) {
	t.Helper()
	actor, err := action.ProjectActor(principal)
	if err != nil {
		t.Fatalf("ProjectActor failed: %v", err)
	}

	var routes []action.Route
	var tools []action.Tool
	if op == "tool.invoke" {
		tools = []action.Tool{{
			ToolID:        resource,
			UpstreamID:    "up-1",
			UpstreamName:  resource,
			PayloadSchema: "ps-1",
			Schema:        schema,
		}}
		routes = []action.Route{{
			RouteID:           "route-1",
			ExecutorID:        "exec-1",
			Operation:         op,
			ResolutionProfile: "res-1",
			Tools:             []string{resource},
		}}
	} else {
		routes = []action.Route{{
			RouteID:           "route-1",
			ExecutorID:        "exec-1",
			Operation:         op,
			ResolutionProfile: "res-1",
			PayloadSchema:     "ps-1",
			Schema:            schema,
		}}
	}

	reg, err := action.NewRegistry(
		[]action.Profile{{
			Protocol:        "decision_api",
			ProfileID:       "prof-1",
			AdapterRevision: "sha256:" + strings.Repeat("a", 64),
		}},
		routes,
		tools,
		nil,
	)
	if err != nil {
		t.Fatalf("action.NewRegistry failed: %v", err)
	}

	ctx, err := reg.Context(action.Advisory, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	clk := fakeClock{now: time.Now()}
	ids := fakeIDSource{id: "act-1"}
	env, err := action.NewEnvelope(clk, ids, "req-1", "", "", 30*time.Second)
	if err != nil {
		t.Fatalf("action.NewEnvelope failed: %v", err)
	}

	return action.NormalizeAction(ctx, actor, resource, raw, env, nil)
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}

type fakeIDSource struct {
	id string
}

func (s fakeIDSource) NewID() (string, error) {
	return s.id, nil
}

func TestLegacyNormalizeRequestActionRejectedByAuthorize(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	engine, principal := p12URLAuthorizer(t, "https://example.com/a", "https://example.com/a", now)
	schema := action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}
	legacy, err := action.NormalizeRequest("http.request", "https://example.com/a", []byte(`{"n":1}`), schema)
	if err != nil {
		t.Fatalf("NormalizeRequest failed: %v", err)
	}
	d, err := engine.Authorize(context.Background(), legacy, principal)
	if err == nil || d.Effect == decision.ALLOW || d.DispatchEligible() || d.Code() != failure.BINDING_MISMATCH || d.Stage != failure.StageNormalize {
		t.Fatalf("expected BINDING_MISMATCH for legacy NormalizeRequest action, got decision=%+v error=%v", d, err)
	}
}
