package policy

import (
	"strings"
	"testing"
)

func amountPolicy(preds string, extra string) []byte {
	return []byte(`schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-orders
    effect: allow
    match:
      principals: [app]
      operations: [tool.invoke]
      resources: [{kind: tool, value: shop.order}]
  - id: ask-big
    effect: require_approval
    match:
      principals: [app]
      operations: [tool.invoke]
      resources: [{kind: tool, value: shop.order}]
      decimal:
` + preds + extra)
}

const orderIn = "shop.order"

func eval(t *testing.T, raw []byte, nums map[string]string) Result {
	t.Helper()
	s, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.EvaluateArgs(Input{"acme", "app", "tool.invoke", "tool", orderIn}, nums)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDecimalOrderValue(t *testing.T) {
	raw := amountPolicy(`        - {field: quantity*limit_price, operator: ">", value: "1000"}
`, "")
	cases := []struct {
		nums map[string]string
		ask  bool
	}{
		{map[string]string{"quantity": "10", "limit_price": "12.50"}, false},  // 125
		{map[string]string{"quantity": "80", "limit_price": "12.50"}, false},  // exactly 1000
		{map[string]string{"quantity": "80", "limit_price": "12.5001"}, true}, // 1000.008
		{map[string]string{"quantity": "100", "limit_price": "1E+1"}, false},  // 1000
		{map[string]string{"quantity": "3", "limit_price": "333.334"}, true},  // 1000.002
		{map[string]string{"quantity": "3", "limit_price": "333.333"}, false}, // 999.999
		{map[string]string{"quantity": "10"}, true},                           // no price: unknown, fail closed
		{nil, true}, // no arguments at all
		{map[string]string{"quantity": "-5", "limit_price": "1000"}, false}, // negative value
	}
	for _, c := range cases {
		r := eval(t, raw, c.nums)
		if r.RequiresApproval != c.ask || r.Allowed == c.ask {
			t.Errorf("%v: ask=%v allowed=%v", c.nums, r.RequiresApproval, r.Allowed)
		}
	}
}

func TestDecimalExactEquality(t *testing.T) {
	raw := amountPolicy(`        - {field: limit_price, operator: "==", value: "0.10"}
`, "")
	if r := eval(t, raw, map[string]string{"limit_price": "0.1"}); !r.RequiresApproval {
		t.Fatal("0.1 == 0.10 must hold")
	}
	// 0.1+0.2 style float error cannot happen: 0.30000000000000004 != 0.3
	raw = amountPolicy(`        - {field: limit_price, operator: "<=", value: "0.3"}
`, "")
	if r := eval(t, raw, map[string]string{"limit_price": "0.30000000000000004"}); r.RequiresApproval {
		t.Fatal("exact comparison expected")
	}
}

func TestDecimalAndOfPredicates(t *testing.T) {
	raw := amountPolicy(`        - {field: quantity, operator: ">=", value: "10"}
        - {field: quantity, operator: "<", value: "20"}
`, "")
	for q, ask := range map[string]bool{"9": false, "10": true, "19": true, "20": false} {
		if r := eval(t, raw, map[string]string{"quantity": q}); r.RequiresApproval != ask {
			t.Errorf("quantity %s: ask=%v", q, r.RequiresApproval)
		}
	}
}

func TestDecimalUnknownNeverGrants(t *testing.T) {
	// An allow rule with an amount condition does not grant a call without the argument.
	raw := []byte(`schema_version: 1
tenant_id: acme
revision: 1
default: deny
rules:
  - id: allow-small
    effect: allow
    match:
      principals: [app]
      operations: [tool.invoke]
      resources: [{kind: tool, value: shop.order}]
      decimal: [{field: quantity, operator: "<=", value: "5"}]
  - id: deny-huge
    effect: deny
    match:
      principals: [app]
      operations: [tool.invoke]
      resources: [{kind: tool, value: shop.order}]
      decimal: [{field: quantity, operator: ">", value: "1000000"}]
`)
	if r := eval(t, raw, map[string]string{"quantity": "5"}); !r.Allowed {
		t.Fatalf("small: %+v", r)
	}
	if r := eval(t, raw, map[string]string{"quantity": "6"}); r.Allowed || r.Denied {
		t.Fatalf("medium: %+v", r)
	}
	if r := eval(t, raw, map[string]string{"quantity": "2000000"}); !r.Denied {
		t.Fatalf("huge: %+v", r)
	}
	if r := eval(t, raw, nil); r.Allowed || !r.Denied {
		t.Fatalf("absent: %+v", r)
	}
	// Plain Evaluate has no arguments: never allowed by an amount rule.
	s, _ := Compile(raw)
	if r, _ := s.Evaluate(Input{"acme", "app", "tool.invoke", "tool", orderIn}); r.Allowed {
		t.Fatalf("Evaluate: %+v", r)
	}
}

func TestDecimalCompileRejects(t *testing.T) {
	bad := map[string]string{
		"unquoted":      `{field: quantity, operator: ">", value: 1000}`,
		"float literal": `{field: quantity, operator: ">", value: 1000.5}`,
		"operator":      `{field: quantity, operator: "=>", value: "1"}`,
		"leading zero":  `{field: quantity, operator: ">", value: "01"}`,
		"neg zero":      `{field: quantity, operator: ">", value: "-0.0"}`,
		"comma":         `{field: quantity, operator: ">", value: "1,000"}`,
		"exponent":      `{field: quantity, operator: ">", value: "1e40"}`,
		"nan":           `{field: quantity, operator: ">", value: "NaN"}`,
		"field":         `{field: Quantity, operator: ">", value: "1"}`,
		"three factors": `{field: a*b*c, operator: ">", value: "1"}`,
		"pointer":       `{field: /args/quantity, operator: ">", value: "1"}`,
		"unknown key":   `{field: quantity, operator: ">", value: "1", unit: usd}`,
	}
	for name, p := range bad {
		raw := amountPolicy("        - "+p+"\n", "")
		if _, err := Compile(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Compile(amountPolicy("        []\n", "")); err == nil {
		t.Error("empty decimal list accepted")
	}
	// Amount conditions only on tool calls.
	file := strings.ReplaceAll(string(amountPolicy(`        - {field: size, operator: ">", value: "1"}
`, "")), "operations: [tool.invoke]\n      resources: [{kind: tool, value: shop.order}]\n      decimal",
		"operations: [filesystem.write]\n      resources: [{kind: path, value: /w/**}]\n      decimal")
	if _, err := Compile([]byte(file)); err == nil {
		t.Error("file rule with amount accepted")
	}
}

func TestDecimalFields(t *testing.T) {
	s, err := Compile(amountPolicy(`        - {field: quantity*limit_price, operator: ">", value: "1000"}
`, ""))
	if err != nil {
		t.Fatal(err)
	}
	got := s.DecimalFields()
	if len(got) != 2 || got[0] != (ToolField{"ask-big", "shop.order", "quantity"}) || got[1].Field != "limit_price" {
		t.Fatalf("%+v", got)
	}
}
