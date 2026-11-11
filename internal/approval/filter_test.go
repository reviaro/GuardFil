package approval

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

const filterPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: filter-portfolio
    effect: sanitize
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.get_quote}]
  - id: ask-orders
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.place_order}]
  - id: filter-orders
    effect: sanitize
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.place_order}]
`

func TestFilterObligation(t *testing.T) {
	c := mustCatalog(t)
	quote := `{"server":"stockapp","tool":"get_quote","arguments":{"symbol":"ACME"}`
	out := EvaluateWithCatalog([]byte(filterPolicy), c, []byte(quote+`}`))
	if out.Effect != "BLOCK" || out.Reasons[0] != "TRANSFORM_UNAVAILABLE" || out.Filter != nil {
		t.Fatalf("no can_filter: %+v", out)
	}
	out = EvaluateWithCatalog([]byte(filterPolicy), c, []byte(quote+`,"can_filter":true}`))
	if out.Effect != "ALLOW" || out.Reasons[0] != "POLICY_FILTERED" || len(out.Filter) != 1 || out.Filter[0] != "filter-portfolio" {
		t.Fatalf("can_filter: %+v", out)
	}
	for _, bad := range []string{`,"can_filter":false}`, `,"can_filter":1}`, `,"extra":true}`} {
		if out := EvaluateWithCatalog([]byte(filterPolicy), c, []byte(quote+bad)); out.Effect != "BLOCK" || out.Reasons[0] != "SCHEMA_INVALID" {
			t.Errorf("%s: %+v", bad, out)
		}
	}
	// Approval and filter: held, and the obligation survives the owner's yes.
	order := `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"A","side":"buy","quantity":1},"can_filter":true}`
	out = EvaluateWithCatalog([]byte(filterPolicy), c, []byte(order))
	if out.Effect != "BLOCK" || out.Reasons[0] != "APPROVAL_UNAVAILABLE" || len(out.Filter) != 1 {
		t.Fatalf("approval+filter: %+v", out)
	}
	var log bytes.Buffer
	s, _ := NewService([]byte(filterPolicy), &log)
	if err := s.SetCatalog(c); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableAsk(5e9); err != nil {
		t.Fatal(err)
	}
	done := make(chan Output, 1)
	go func() { done <- s.Decide([]byte(order)) }()
	for len(s.Pending()) == 0 {
	}
	_ = s.Answer(s.Pending()[0].ID, true)
	if out := <-done; out.Effect != "ALLOW" || len(out.Filter) != 1 || out.Filter[0] != "filter-orders" {
		t.Fatalf("granted: %+v", out)
	}
}

func TestFilterRequestOverSocket(t *testing.T) {
	var log bytes.Buffer
	s, _ := NewService([]byte(filterPolicy), &log)
	a, b := net.Pipe()
	go s.Handle(b)
	req, _ := json.Marshal(map[string]string{"kind": "filter", "tool": "stockapp.get_portfolio",
		"content": `{"cash":"100.00","api_key":"live-abc-123456","note":"AKIAIOSFODNN7EXAMPLE"}`})
	go func() { _, _ = a.Write(append(req, '\n')) }()
	var got struct {
		Content    string `json:"content"`
		Redactions int    `json:"redactions"`
	}
	if err := json.NewDecoder(a).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Redactions != 2 || strings.Contains(got.Content, "live-abc") || strings.Contains(got.Content, "AKIA") ||
		!strings.Contains(got.Content, `"cash":"100.00"`) {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(log.String(), "live-abc") || !strings.Contains(log.String(), `"redactions":2`) {
		t.Fatalf("log: %s", log.String())
	}
	// MCP method tool identifier (e.g. notes.tools/list):
	aMcp, bMcp := net.Pipe()
	go s.Handle(bMcp)
	reqMcp, _ := json.Marshal(map[string]string{"kind": "filter", "tool": "notes.tools/list",
		"content": `{"tools":[{"name":"t","api_key":"live-abc-123456"}]}`})
	go func() { _, _ = aMcp.Write(append(reqMcp, '\n')) }()
	var gotMcp struct {
		Content    string `json:"content"`
		Redactions int    `json:"redactions"`
	}
	if err := json.NewDecoder(aMcp).Decode(&gotMcp); err != nil {
		t.Fatal(err)
	}
	if gotMcp.Redactions != 1 || strings.Contains(gotMcp.Content, "live-abc-123456") {
		t.Fatalf("mcp tool filter failed: %+v", gotMcp)
	}
	// Malformed filter request: an error, never a decision.
	a2, b2 := net.Pipe()
	go s.Handle(b2)
	go func() { _, _ = a2.Write([]byte(`{"kind":"filter","tool":"x","content":"y"}` + "\n")) }()
	var e map[string]string
	_ = json.NewDecoder(a2).Decode(&e)
	if e["error"] == "" {
		t.Fatalf("%v", e)
	}
}
