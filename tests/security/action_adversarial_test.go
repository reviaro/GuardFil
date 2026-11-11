package security_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
	"github.com/reviaro/guardfil/internal/decision"
)

// TestRejectsTrailingJSONDocument ensures an admitted payload is exactly
// one JSON text. Otherwise, downstream consumers that retain the original
// request can observe attacker-controlled content absent from the sealed form.
func TestRejectsTrailingJSONDocument(t *testing.T) {
	schema := action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}}
	for _, raw := range [][]byte{
		[]byte(`{"n":1}{"privileged":true}`),
		[]byte(`{"n":1} null`),
	} {
		if got, err := action.NormalizePayload("fs.read", raw, schema); err == nil {
			t.Fatalf("trailing JSON document admitted as sealed payload %q: %+v", raw, got)
		}
	}
}

func TestStrictUnicodeAndRecursiveSchema(t *testing.T) {
	t.Run("strict-unicode", func(t *testing.T) {
		schema := action.Schema{Fields: map[string]action.FieldType{"text": action.String}}
		for _, raw := range [][]byte{
			{'{', '"', 't', 'e', 'x', 't', '"', ':', '"', 0xff, '"', '}'},
			[]byte(`{"text":"\ud800"}`),
			[]byte(`{"text":"\udc00"}`),
			[]byte(`{"text":"\ud800x"}`),
		} {
			if _, err := action.NormalizePayload("fs.read", raw, schema); err == nil {
				t.Fatalf("non-scalar Unicode input admitted: %q", raw)
			}
		}
		if _, err := action.NormalizePayload("fs.read", []byte(`{"text":"\ud83d\ude00"}`), schema); err != nil {
			t.Fatalf("valid Unicode scalar rejected: %v", err)
		}
	})

	t.Run("closed-recursive-schema", func(t *testing.T) {
		item := action.Field{Type: action.Object, Properties: map[string]action.Field{
			"id":    {Type: action.Integer},
			"label": {Type: action.String},
		}}
		schema := action.Schema{RecursiveFields: map[string]action.Field{
			"items": {Type: action.Array, Items: &item},
		}}
		for _, raw := range [][]byte{
			[]byte(`{"items":[{"id":1,"admin":true}]}`),
			[]byte(`{"items":[{"id":1.0,"label":"x"}]}`),
			[]byte(`{"items":{"id":1,"label":"x"}}`),
		} {
			if _, err := action.NormalizePayload("fs.read", raw, schema); err == nil {
				t.Fatalf("out-of-schema nested payload admitted: %s", raw)
			}
		}
		if _, err := action.NormalizePayload("fs.read", []byte(`{"items":[{"id":1,"label":"x"}]}`), schema); err != nil {
			t.Fatalf("registered recursive payload rejected: %v", err)
		}
	})
}

// Action v1.1 bounds every object to 256 members. The profile must not make
// this limit contingent on a particular registered schema's field count.
func TestRejectsObjectMemberBudgetOverflow(t *testing.T) {
	fields := make(map[string]action.FieldType, 257)
	var raw strings.Builder
	raw.WriteByte('{')
	for i := 0; i < 257; i++ {
		if i != 0 {
			raw.WriteByte(',')
		}
		name := "f" + strconv.Itoa(i)
		fields[name] = action.Boolean
		raw.WriteString(`"` + name + `":true`)
	}
	raw.WriteByte('}')
	if _, err := action.NormalizePayload("fs.read", []byte(raw.String()), action.Schema{Fields: fields}); err == nil {
		t.Fatal("257-member object bypassed Action v1.1 object-member budget")
	}
}

func TestRejectsStringBudgetOverflow(t *testing.T) {
	raw := []byte(`{"text":"` + strings.Repeat("a", (256<<10)+1) + `"}`)
	schema := action.Schema{Fields: map[string]action.FieldType{"text": action.String}}
	if _, err := action.NormalizePayload("fs.read", raw, schema); err == nil {
		t.Fatal("string over the 256 KiB Action v1.1 limit was admitted")
	}
}

func TestAllowDecisionCannotAdvertiseDispatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	engine, principal := p12URLAuthorizer(t, "https://example.com/a", "https://example.com/a", now)
	a, err := normalizeActionForTest(t, principal, "http.request", "https://example.com/a", []byte(`{"n":1}`), action.Schema{Fields: map[string]action.FieldType{"n": action.Integer}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := engine.Authorize(context.Background(), a, principal)
	if err != nil || d.Effect != decision.ALLOW {
		t.Fatalf("expected diagnostic allow: decision=%+v error=%v", d, err)
	}
	if d.DispatchEligible() {
		t.Fatalf("P1.2 ALLOW remained dispatchable: %+v", d)
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsDispatchField(encoded) {
		t.Fatalf("decision serialization exposed a dispatch capability: %s", encoded)
	}
}

func containsDispatchField(encoded []byte) bool {
	var fields map[string]any
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	for name := range fields {
		if strings.EqualFold(name, "dispatchEligible") {
			return true
		}
	}
	return false
}
