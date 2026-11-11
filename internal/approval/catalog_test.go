package approval

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const stockCatalog = `catalog_version: 1
tools:
  - id: stockapp.place_order
    description: Place an order
    arguments:
      symbol:      {type: string, required: true, max_length: 12}
      side:        {type: string, required: true, enum: [buy, sell]}
      quantity:    {type: integer, required: true}
      limit_price: {type: decimal}
      dry_run:     {type: boolean}
  - id: stockapp.get_quote
    arguments:
      symbol: {type: string, required: true}
`

const stockPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-quotes
    effect: allow
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
`

func mustCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := ParseCatalog([]byte(stockCatalog))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogParse(t *testing.T) {
	c := mustCatalog(t)
	if ts := c.Tools(); len(ts) != 2 || ts[0].ID != "stockapp.get_quote" || !c.Has("stockapp.place_order") {
		t.Fatalf("tools: %+v", ts)
	}
	if !strings.HasPrefix(c.Digest(), "sha256:") {
		t.Fatal(c.Digest())
	}
	bad := map[string]string{
		"version":   "catalog_version: 2\ntools: [{id: a.b}]\n",
		"no tools":  "catalog_version: 1\ntools: []\n",
		"bad id":    "catalog_version: 1\ntools: [{id: nodot}]\n",
		"reserved":  "catalog_version: 1\ntools: [{id: codex.exec_command}]\n",
		"duplicate": "catalog_version: 1\ntools: [{id: a.b}, {id: a.b}]\n",
		"type":      "catalog_version: 1\ntools: [{id: a.b, arguments: {x: {type: float}}}]\n",
		"arg name":  "catalog_version: 1\ntools: [{id: a.b, arguments: {X: {type: string}}}]\n",
		"enum int":  "catalog_version: 1\ntools: [{id: a.b, arguments: {x: {type: integer, enum: [a]}}}]\n",
		"unknown":   "catalog_version: 1\ntools: [{id: a.b, extra: 1}]\n",
	}
	for name, doc := range bad {
		if _, err := ParseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCatalogToolDecisions(t *testing.T) {
	c := mustCatalog(t)
	pol := []byte(stockPolicy)
	cases := []struct {
		name, req, effect, reason string
	}{
		{"quote allowed", `{"server":"stockapp","tool":"get_quote","arguments":{"symbol":"ACME"}}`, "ALLOW", "POLICY_ALLOWED"},
		{"order needs approval", `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ACME","side":"buy","quantity":10,"limit_price":12.50}}`, "BLOCK", "APPROVAL_UNAVAILABLE"},
		{"missing required", `{"server":"stockapp","tool":"get_quote","arguments":{}}`, "BLOCK", "SCHEMA_INVALID"},
		{"unknown argument", `{"server":"stockapp","tool":"get_quote","arguments":{"symbol":"A","x":1}}`, "BLOCK", "SCHEMA_INVALID"},
		{"enum", `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"A","side":"short","quantity":1}}`, "BLOCK", "SCHEMA_INVALID"},
		{"wrong type", `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"A","side":"buy","quantity":"1"}}`, "BLOCK", "SCHEMA_INVALID"},
		{"not integer", `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"A","side":"buy","quantity":1.5}}`, "BLOCK", ""},
		{"too long", `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ABCDEFGHIJKLM","side":"buy","quantity":1}}`, "BLOCK", "LIMIT_EXCEEDED"},
		{"not in catalog", `{"server":"stockapp","tool":"withdraw","arguments":{}}`, "BLOCK", ""},
	}
	for _, tc := range cases {
		out := EvaluateWithCatalog(pol, c, []byte(tc.req))
		if out.Effect != tc.effect || (tc.reason != "" && out.Reasons[0] != tc.reason) {
			t.Errorf("%s: %+v", tc.name, out)
		}
	}
	// Without the catalog the same allowed call is blocked: unknown tool.
	if out := Evaluate(pol, []byte(cases[0].req)); out.Effect != "BLOCK" {
		t.Fatalf("no catalog: %+v", out)
	}
}

func TestServiceUsesCatalog(t *testing.T) {
	var log bytes.Buffer
	s, err := NewService([]byte(stockPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	req := []byte(`{"server":"stockapp","tool":"get_quote","arguments":{"symbol":"ACME"}}`)
	if out := s.Decide(req); out.Effect != "BLOCK" {
		t.Fatalf("before catalog: %+v", out)
	}
	if err := s.SetCatalog(mustCatalog(t)); err != nil {
		t.Fatal(err)
	}
	if out := s.Decide(req); out.Effect != "ALLOW" {
		t.Fatalf("with catalog: %+v", out)
	}
	if !strings.Contains(log.String(), `"tool":"stockapp.get_quote"`) || strings.Contains(log.String(), "ACME") {
		t.Fatalf("log: %s", log.String())
	}
}

func TestExampleStockApp(t *testing.T) {
	cat, err := os.ReadFile("../../deployments/example/approval/stockapp-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := os.ReadFile("../../deployments/example/approval/stockapp-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCatalog(cat)
	if err != nil {
		t.Fatal(err)
	}
	for req, want := range map[string]string{
		`{"server":"stockapp","tool":"get_quote","arguments":{"symbol":"ACME"}}`:                                                   "ALLOW POLICY_ALLOWED",
		`{"server":"stockapp","tool":"get_portfolio","arguments":{}}`:                                                              "BLOCK TRANSFORM_UNAVAILABLE",
		`{"server":"stockapp","tool":"get_portfolio","arguments":{},"can_filter":true}`:                                            "ALLOW POLICY_FILTERED",
		`{"server":"stockapp","tool":"cancel_order","arguments":{"order_id":"o-1"}}`:                                               "ALLOW POLICY_MONITORED",
		`{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ACME","side":"buy","quantity":5}}`:                       "BLOCK APPROVAL_UNAVAILABLE",
		`{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ACME","side":"buy","quantity":5,"limit_price":12.50}}`:   "ALLOW POLICY_MONITORED",
		`{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ACME","side":"buy","quantity":500,"limit_price":12.50}}`: "BLOCK APPROVAL_UNAVAILABLE",
		`{"server":"stockapp","tool":"withdraw_funds","arguments":{"amount":100.00,"destination":"acct-9"}}`:                       "BLOCK POLICY_DENIED",
		`{"server":"stockapp","tool":"transfer_shares","arguments":{}}`:                                                            "BLOCK",
	} {
		out := EvaluateWithCatalog(pol, c, []byte(req))
		if got := out.Effect + " " + strings.Join(out.Reasons, " "); !strings.HasPrefix(got, want) {
			t.Errorf("%s: got %s, want %s", req, got, want)
		}
	}
}

const amountPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-orders
    effect: allow
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.place_order}]
  - id: ask-big-orders
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.place_order}]
      decimal: [{field: quantity*limit_price, operator: ">", value: "1000"}]
`

func TestAmountRuleThroughKernel(t *testing.T) {
	c := mustCatalog(t)
	order := func(args string) string {
		return `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ACME","side":"buy",` + args + `}}`
	}
	for args, want := range map[string]string{
		`"quantity":10,"limit_price":12.50`:   "ALLOW POLICY_ALLOWED",
		`"quantity":80,"limit_price":12.50`:   "ALLOW POLICY_ALLOWED", // exactly 1000
		`"quantity":80,"limit_price":12.5001`: "BLOCK APPROVAL_UNAVAILABLE",
		`"quantity":1000,"limit_price":1.01`:  "BLOCK APPROVAL_UNAVAILABLE",
		`"quantity":5`:                        "BLOCK APPROVAL_UNAVAILABLE", // market order: no price, ask
	} {
		out := EvaluateWithCatalog([]byte(amountPolicy), c, []byte(order(args)))
		if got := out.Effect + " " + strings.Join(out.Reasons, " "); got != want {
			t.Errorf("%s: got %s, want %s", args, got, want)
		}
	}
}

func TestAmountFieldsCheckedAgainstCatalog(t *testing.T) {
	var log bytes.Buffer
	s, err := NewService([]byte(amountPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCatalog(nil); err == nil {
		t.Fatal("amount rule without catalog accepted")
	}
	if err := s.SetCatalog(mustCatalog(t)); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(amountPolicy, "quantity*limit_price", "quantity*symbol", 1)
	if _, err := s.SetPolicy([]byte(bad)); err == nil || !strings.Contains(err.Error(), `"symbol"`) {
		t.Fatalf("string field: %v", err)
	}
	other := strings.Replace(amountPolicy, "value: stockapp.place_order}]\n      decimal", "value: stockapp.other}]\n      decimal", 1)
	if _, err := s.SetPolicy([]byte(other)); err == nil {
		t.Fatal("tool not in catalog accepted")
	}
	if _, err := s.SetPolicy([]byte(amountPolicy)); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogBounds(t *testing.T) {
	cat, err := os.ReadFile("../../deployments/example/approval/stockapp-catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCatalog(cat)
	if err != nil {
		t.Fatal(err)
	}
	order := func(q, p string) string {
		return `{"server":"stockapp","tool":"place_order","arguments":{"symbol":"ACME","side":"buy","quantity":` + q + `,"limit_price":` + p + `}}`
	}
	for _, tc := range []struct{ q, p, want string }{
		{"5000", "-12.50", "LIMIT_EXCEEDED"}, // a negative price no longer makes a big order look small
		{"5000", "0", "LIMIT_EXCEEDED"},
		{"0", "12.50", "LIMIT_EXCEEDED"},
		{"-5", "12.50", "LIMIT_EXCEEDED"},
		{"1000001", "1", "LIMIT_EXCEEDED"},
		{"5000", "0.009", "LIMIT_EXCEEDED"},
		{"1", "0.01", "POLICY_ALLOWED"}, // exactly at min: passes the catalog (then the ALLOW below is only checked for the reason class)
	} {
		out := EvaluateWithCatalog([]byte(stockPolicy), c, []byte(order(tc.q, tc.p)))
		if tc.want == "LIMIT_EXCEEDED" && (out.Effect != "BLOCK" || out.Reasons[0] != "LIMIT_EXCEEDED") {
			t.Errorf("%s @ %s: %+v", tc.q, tc.p, out)
		}
		if tc.want != "LIMIT_EXCEEDED" && out.Reasons[0] == "LIMIT_EXCEEDED" {
			t.Errorf("%s @ %s at the bound was refused: %+v", tc.q, tc.p, out)
		}
	}
	for name, doc := range map[string]string{
		"bound on string": "catalog_version: 1\ntools: [{id: a.b, arguments: {x: {type: string, min: \"1\"}}}]\n",
		"bad literal":     "catalog_version: 1\ntools: [{id: a.b, arguments: {x: {type: decimal, min: \"1,0\"}}}]\n",
		"min above max":   "catalog_version: 1\ntools: [{id: a.b, arguments: {x: {type: integer, min: \"5\", max: \"1\"}}}]\n",
	} {
		if _, err := ParseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A catalog file can hold several documents: the agents' catalog and an app's.
func TestCatalogMultipleDocuments(t *testing.T) {
	two := "catalog_version: 1\ntools: [{id: claude.read}]\n---\n" + stockCatalog
	c, err := ParseCatalog([]byte(two))
	if err != nil || !c.Has("claude.read") || !c.Has("stockapp.place_order") || len(c.Tools()) != 3 {
		t.Fatalf("merged: %v %+v", err, c)
	}
	for name, doc := range map[string]string{
		"duplicate across documents": stockCatalog + "---\n" + stockCatalog,
		"bad version in second":      stockCatalog + "---\ncatalog_version: 2\ntools: [{id: a.b}]\n",
		"empty second":               stockCatalog + "---\ncatalog_version: 1\ntools: []\n",
		"unknown key in second":      stockCatalog + "---\ncatalog_version: 1\ntools: [{id: a.b}]\nextra: 1\n",
		"empty file":                 "",
	} {
		if _, err := ParseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
