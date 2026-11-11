package security_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/action"
)

// TestActionParserBounds is an independent regression for commit 1249f74.
// It verifies limits at their exact boundary and asserts parser failure (rather
// than later schema failure) for an over-limit nested object and decoded string.
func TestActionParserBounds(t *testing.T) {
	t.Run("256 members remains admissible", func(t *testing.T) {
		fields := make(map[string]action.FieldType, 256)
		var raw strings.Builder
		raw.WriteByte('{')
		for i := 0; i < 256; i++ {
			if i > 0 {
				raw.WriteByte(',')
			}
			key := "k" + strconv.Itoa(i)
			fields[key] = action.Boolean
			raw.WriteString(`"` + key + `":true`)
		}
		raw.WriteByte('}')
		got, err := action.NormalizePayload("fs.read", []byte(raw.String()), action.Schema{Fields: fields})
		if err != nil || !got.Valid() {
			t.Fatalf("256-member boundary rejected: action=%+v error=%v", got, err)
		}
	})

	t.Run("257 members fail in parser", func(t *testing.T) {
		members := make([]string, 257)
		for i := range members {
			members[i] = `"k` + strconv.Itoa(i) + `":true`
		}
		_, err := action.NormalizePayload("fs.read", []byte(`{`+strings.Join(members, ",")+`}`), action.Schema{})
		if !errors.Is(err, action.ErrParse) {
			t.Fatalf("257-member object did not fail before schema/canonicalization: %v", err)
		}
	})

	t.Run("nested 257 members fail in parser", func(t *testing.T) {
		members := make([]string, 257)
		for i := range members {
			members[i] = `"k` + strconv.Itoa(i) + `":true`
		}
		raw := `{"nested":{` + strings.Join(members, ",") + `}}`
		_, err := action.NormalizePayload("fs.read", []byte(raw), action.Schema{Fields: map[string]action.FieldType{"nested": action.Object}})
		if !errors.Is(err, action.ErrParse) {
			t.Fatalf("nested 257-member object did not fail before schema/canonicalization: %v", err)
		}
	})

	t.Run("decoded string boundary and escaped overflow", func(t *testing.T) {
		schema := action.Schema{Fields: map[string]action.FieldType{"text": action.String}}
		atLimit := []byte(`{"text":"` + strings.Repeat(`\"`, 256<<10) + `"}`)
		if got, err := action.NormalizePayload("fs.read", atLimit, schema); err != nil || !got.Valid() {
			t.Fatalf("256 KiB decoded string boundary rejected: action=%+v error=%v", got, err)
		}
		overLimit := []byte(`{"text":"` + strings.Repeat(`\"`, (256<<10)+1) + `"}`)
		_, err := action.NormalizePayload("fs.read", overLimit, schema)
		if !errors.Is(err, action.ErrParse) {
			t.Fatalf("escaped decoded string >256 KiB did not fail before schema/canonicalization: %v", err)
		}
	})
}
