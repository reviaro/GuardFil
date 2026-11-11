package action

import "testing"

func BenchmarkNormalizePayloadDecimal(b *testing.B) {
	raw := []byte(`{"temperature":0.10,"enabled":true}`)
	schema := Schema{Fields: map[string]FieldType{"temperature": Number, "enabled": Boolean}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := NormalizePayload("llm.request", raw, schema); err != nil {
			b.Fatal(err)
		}
	}
}
