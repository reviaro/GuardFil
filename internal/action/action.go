// Package action normalizes untrusted JSON into immutable, digest-bound values.
package action

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	resourceid "github.com/reviaro/guardfil/internal/resource"
)

const Version = "guardfil.action/1.1"

var (
	ErrParse = errors.New("PARSE_INVALID")
	// ErrControl: a string holds a character it may not carry (NUL, carriage
	// return or invalid UTF-8 in a value; also a newline or tab in a key).
	ErrControl  = errors.New("CONTROL_CHARACTER")
	ErrDecimal  = errors.New("DECIMAL_LITERAL_INVALID")
	ErrSchema   = errors.New("SCHEMA_INVALID")
	ErrLimit    = errors.New("LIMIT_EXCEEDED")
	ErrInternal = errors.New("INTERNAL_ERROR")
)

type FieldType string

const (
	Number  FieldType = "number"
	Integer FieldType = "integer"
	String  FieldType = "string"
	Boolean FieldType = "boolean"
	Object  FieldType = "object"
	Array   FieldType = "array"
)

// Field is the bounded registered recursive payload schema. Objects are closed
// and arrays require an item field. Fields remains for the original flat
// profile; RecursiveFields adds nested registered payloads without a dynamic
// map or callback escape hatch.
type Field struct {
	Type       FieldType
	Properties map[string]Field
	Items      *Field
}
type Schema struct {
	Fields          map[string]FieldType
	RecursiveFields map[string]Field
}

// Action is a read-only-by-validation projection. The exported fields are kept
// for diagnostic compatibility, but they are not authority: only values
// carrying the package-private seal created by NormalizeRequest or NormalizeAction
// are eligible for authorization. Any caller mutation invalidates that seal.
type Action struct {
	SchemaVersion string
	Operation     string
	ResourceKind  string
	Resource      string
	Payload       []byte
	Digest        string
	seal          *sealedAction
}

type sealedAction struct {
	schemaVersion  string
	operation      string
	resourceKind   string
	resource       string
	payload        string
	digest         string
	authorizable   bool
	resourceReady  bool
	trustedContext *trustedContextData
}

var numberRE = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

func validOperation(op string) bool {
	_, ok := SecurityOperation(op)
	return ok
}

// SecurityOperation maps an Action operation to its exact Security registered
// operation name. It returns false for any operation outside the closed Action
// operation enum.
func SecurityOperation(op string) (string, bool) {
	switch op {
	case "fs.read":
		return "filesystem.read", true
	case "fs.write":
		return "filesystem.write", true
	case "llm.request":
		return "llm.request", true
	case "tool.invoke":
		return "tool.invoke", true
	case "shell.execute":
		return "shell.execute", true
	case "http.request":
		return "http.request", true
	default:
		return "", false
	}
}

// NormalizePayload is the compatibility normalizer for payload-only callers.
// Its result cannot be authorized because it has no trusted resource or context binding;
// use NormalizeAction at an admitted protocol boundary for authorization.
func NormalizePayload(operation string, raw []byte, schema Schema) (Action, error) {
	return normalize(operation, resourceid.KindForOperation(operation), "", false, raw, schema)
}

// NormalizeRequest parses, admits, and normalizes caller-controlled request selectors.
// Its result cannot be authorized and has no action_digest (D1); use NormalizeAction
// at an admitted protocol boundary for authorization.
func NormalizeRequest(operation, resource string, raw []byte, schema Schema) (Action, error) {
	kind := resourceid.KindForOperation(operation)
	if kind == "" {
		return Action{}, ErrSchema
	}
	normalized, canonicalResource, err := resourceid.NormalizeSelector(kind, resource)
	if err != nil {
		return Action{}, ErrSchema
	}
	return normalize(operation, kind, normalized, canonicalResource, raw, schema)
}

func parseAndAdmitPayload(raw []byte, schema Schema) (any, []byte, error) {
	if len(raw) > 1<<20 {
		return nil, nil, ErrLimit
	}
	if !validJSONText(raw) || !json.Valid(raw) {
		return nil, nil, ErrParse
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	v, e := parse(d, 0)
	if e != nil {
		return nil, nil, e
	}
	if d.More() {
		return nil, nil, ErrParse
	}
	o, ok := v.(obj)
	if !ok {
		return nil, nil, ErrSchema
	}
	for k, x := range o {
		if field, recursive := schema.RecursiveFields[k]; recursive {
			if _, duplicate := schema.Fields[k]; duplicate || admitField(x, field, 0) != nil {
				return nil, nil, ErrSchema
			}
			continue
		}
		typ, known := schema.Fields[k]
		if !known {
			return nil, nil, ErrSchema
		}
		if e := admit(x, typ); e != nil {
			return nil, nil, e
		}
	}
	c := canonical(v)
	if len(c) > 1<<20 {
		return nil, nil, ErrLimit
	}
	return v, c, nil
}

func normalize(operation, kind, resource string, resourceReady bool, raw []byte, schema Schema) (Action, error) {
	if !validOperation(operation) {
		return Action{}, ErrSchema
	}
	_, c, err := parseAndAdmitPayload(raw, schema)
	if err != nil {
		return Action{}, err
	}
	seal := &sealedAction{
		schemaVersion: Version,
		operation:     operation,
		resourceKind:  kind,
		resource:      resource,
		payload:       string(c),
		digest:        "",
		authorizable:  false,
		resourceReady: resourceReady,
	}
	return Action{
		SchemaVersion: Version,
		Operation:     operation,
		ResourceKind:  kind,
		Resource:      resource,
		Payload:       append([]byte(nil), c...),
		Digest:        "",
		seal:          seal,
	}, nil
}

func admitField(v any, field Field, depth int) error {
	if depth > 16 {
		return ErrSchema
	}
	switch field.Type {
	case Object:
		o, ok := v.(obj)
		if !ok || len(field.Properties) == 0 {
			return ErrSchema
		}
		for key, child := range o {
			spec, known := field.Properties[key]
			if !known || admitField(child, spec, depth+1) != nil {
				return ErrSchema
			}
		}
	case Array:
		if field.Items == nil {
			return ErrSchema
		}
		values, ok := v.([]any)
		if !ok {
			return ErrSchema
		}
		for _, value := range values {
			if admitField(value, *field.Items, depth+1) != nil {
				return ErrSchema
			}
		}
	case Number, Integer, String, Boolean:
		return admit(v, field.Type)
	default:
		return ErrSchema
	}
	return nil
}

// validJSONText rejects encodings encoding/json would otherwise repair.
// Unpaired UTF-16 surrogates must not collapse into U+FFFD.
func validJSONText(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if !inString {
			if raw[i] == '"' {
				inString = true
			}
			continue
		}
		if raw[i] == '"' {
			inString = false
			continue
		}
		if raw[i] < 0x20 {
			return false
		}
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			if !strings.ContainsRune(`"\\/bfnrt`, rune(raw[i])) {
				return false
			}
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		v, ok := hex4(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		if v >= 0xD800 && v <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := hex4(raw[i+3 : i+7])
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		} else if v >= 0xDC00 && v <= 0xDFFF {
			return false
		}
	}
	return !inString
}

func hex4(b []byte) (uint16, bool) {
	var n uint16
	for _, c := range b {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}

// Valid reports whether the Action still exactly matches the trusted value
// produced by this package. It never treats a caller-supplied digest as proof.
func (a Action) Valid() bool {
	return a.seal != nil &&
		a.SchemaVersion == a.seal.schemaVersion &&
		a.Operation == a.seal.operation &&
		a.ResourceKind == a.seal.resourceKind &&
		a.Resource == a.seal.resource &&
		string(a.Payload) == a.seal.payload &&
		a.Digest == a.seal.digest
}

// Protocol Review Notice: Action digest binding per rule 5:
//   action_digest = "sha256:" || hex(SHA256(UTF8("GuardFil.Action.v1\n") || canonical(binding)))
// where binding consists EXACTLY of schema_version, boundary, actor,
// source.protocol/profile/adapter_revision, operation, target, payload,
// payload_schema, tool_revision, and provenance.
// Excluded from binding (correlation only): action_id, request_id, parent_action_id,
// source.message_id, source.wire_digest, received_at, deadline_at, idempotency_key, action_digest.

// Authorizable reports whether the Action is eligible for authorization.
// Only Actions produced by NormalizeAction are authorizable (D1);
// NormalizeRequest/NormalizePayload produce non-authorizable helper Actions.
func (a Action) Authorizable() bool {
	return a.Valid() && a.seal.authorizable && a.seal.resourceReady && a.seal.resourceKind != "" && a.seal.resource != "" && a.seal.digest != ""
}

// BoundActorMatches reports whether the Action's bound actor matches the provided actor's
// canonical projection. It returns false if the Action is not authorizable or if the provided
// actor has no canonical bytes.
func (a Action) BoundActorMatches(actor Actor) bool {
	if !a.Authorizable() || a.seal == nil || a.seal.trustedContext == nil {
		return false
	}
	if len(actor.canonical) == 0 {
		return false
	}
	return bytes.Equal(a.seal.trustedContext.actor.canonical, actor.canonical)
}

func (a Action) TrustedOperation() string {
	if !a.Valid() {
		return ""
	}
	return a.seal.operation
}

func (a Action) TrustedSecurityOperation() string {
	if !a.Authorizable() {
		return ""
	}
	op, _ := SecurityOperation(a.seal.operation)
	return op
}

func (a Action) TrustedResource() string {
	if !a.Authorizable() {
		return ""
	}
	return a.seal.resource
}

func (a Action) TrustedResourceKind() string {
	if !a.Authorizable() {
		return ""
	}
	return a.seal.resourceKind
}

// TrustedPayload returns the sealed canonical payload (decimal tokens kept
// byte-for-byte), or nil if the Action is not authorizable.
func (a Action) TrustedPayload() []byte {
	if !a.Authorizable() {
		return nil
	}
	return []byte(a.seal.payload)
}

// ValidDecimal reports whether s is a bounded Action decimal literal (at most
// 34 significant digits, 40 bytes, exponent within ±32, no negative zero).
func ValidDecimal(s string) bool { return decimal(s) == nil }

func (a Action) TrustedDigest() string {
	if !a.Valid() {
		return ""
	}
	return a.seal.digest
}

// TrustedContext returns the immutable trusted ActionContext bound during
// NormalizeAction, or (ActionContext{}, false) if the Action was created by
// NormalizeRequest/NormalizePayload, if it is not authorizable, or if any
// exported field was mutated.
//
// The runtime correlation envelope is NEVER bound into action_digest (rule 5 excludes it permanently,
// correlation only). Read the context only via TrustedContext().
func (a Action) TrustedContext() (ActionContext, bool) {
	if !a.Authorizable() || a.seal == nil || a.seal.trustedContext == nil {
		return ActionContext{}, false
	}
	tc := a.seal.trustedContext
	return ActionContext{
		boundary:          tc.boundary,
		protocol:          tc.protocol,
		profile:           tc.profile,
		adapterRevision:   tc.adapterRevision,
		routeID:           tc.routeID,
		executorID:        tc.executorID,
		targetKind:        tc.targetKind,
		resolutionProfile: tc.resolutionProfile,
		payloadSchema:     tc.payloadSchema,
		toolRevision:      tc.toolRevision,
	}, true
}

// TrustedEnvelope returns the runtime correlation envelope bound during
// NormalizeAction, or (Envelope{}, false) if the Action was created by
// NormalizeRequest/NormalizePayload, if it is not authorizable, or if any
// exported field was mutated.
//
// The runtime correlation envelope is NEVER bound into action_digest (rule 5 excludes it permanently,
// correlation only). Read the envelope only via TrustedEnvelope().
func (a Action) TrustedEnvelope() (Envelope, bool) {
	if !a.Authorizable() || a.seal == nil || a.seal.trustedContext == nil {
		return Envelope{}, false
	}
	return a.seal.trustedContext.envelope, true
}

// TrustedDeadline returns the runtime received_at and deadline timestamps bound
// during NormalizeAction, or (time.Time{}, time.Time{}, false) if the Action
// was not created by NormalizeAction or has been invalidated.
func (a Action) TrustedDeadline() (receivedAt, deadline time.Time, ok bool) {
	if !a.Authorizable() || a.seal == nil || a.seal.trustedContext == nil || !a.seal.trustedContext.hasDeadline {
		return time.Time{}, time.Time{}, false
	}
	return a.seal.trustedContext.receivedAt, a.seal.trustedContext.deadline, true
}

// TrustedProvenance returns the normalized trusted provenance entries bound during
// NormalizeAction, or (nil, false) if the Action was created by
// NormalizeRequest/NormalizePayload, if it is not authorizable, or if any
// exported field was mutated. If no provenance evidence was provided during NormalizeAction,
// it returns an empty non-nil slice and true. An empty result means provenance is UNKNOWN,
// never clean; an entry without parents has unknown lineage.
//
// The runtime correlation envelope is NEVER bound into action_digest (rule 5 excludes it permanently,
// correlation only). Read the provenance only via TrustedProvenance().
func (a Action) TrustedProvenance() ([]ProvenanceEntry, bool) {
	if !a.Authorizable() || a.seal == nil || a.seal.trustedContext == nil {
		return nil, false
	}
	prov := a.seal.trustedContext.provenance
	if len(prov) == 0 {
		return []ProvenanceEntry{}, true
	}
	res := make([]ProvenanceEntry, len(prov))
	for i, entry := range prov {
		res[i] = entry
		if len(entry.parentEvidenceIDs) > 0 {
			res[i].parentEvidenceIDs = append([]string(nil), entry.parentEvidenceIDs...)
		}
	}
	return res, true
}

type obj map[string]any
type num string

func parse(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrLimit
	}
	d.UseNumber()
	t, e := d.Token()
	if e != nil {
		return nil, ErrParse
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			o := obj{}
			for d.More() {
				if len(o) >= 256 {
					return nil, ErrParse
				}
				k, e := d.Token()
				if e != nil {
					return nil, ErrParse
				}
				ks, ok := k.(string)
				if !ok || len(ks) > 256<<10 {
					return nil, ErrParse
				}
				if !utf8ok(ks) {
					return nil, ErrControl
				}
				if _, dup := o[ks]; dup {
					return nil, ErrParse
				}
				z, e := parse(d, depth+1)
				if e != nil {
					return nil, e
				}
				o[ks] = z
			}
			_, e = d.Token()
			return o, e
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= 1024 {
					return nil, ErrParse
				}
				z, e := parse(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, z)
			}
			_, e = d.Token()
			return a, e
		}
	case string:
		if len(x) > 256<<10 {
			return nil, ErrParse
		}
		if !textOK(x) {
			return nil, ErrControl
		}
		return x, nil
	case json.Number:
		return num(x), nil
	case bool:
		return x, nil
	case nil:
		return nil, ErrParse
	}
	return nil, ErrParse
}
func utf8ok(s string) bool {
	return strings.ToValidUTF8(s, "\x00") == s && !strings.ContainsAny(s, "\x00\n\r\t")
}

// textOK admits an argument value.  Newline and tab are allowed, so
// multi-line commands and text are judged by policy; NUL, carriage return
// (which can hide text on a terminal) and invalid UTF-8 stay refused.  Keys
// use utf8ok, and IDs, paths and resource selectors their own stricter checks.
func textOK(s string) bool {
	return strings.ToValidUTF8(s, "\x00") == s && !strings.ContainsAny(s, "\x00\r")
}
func admit(v any, t FieldType) error {
	switch x := v.(type) {
	case num:
		if e := decimal(string(x)); e != nil {
			return e
		}
		if t == Integer && !safeInt(string(x)) {
			return ErrSchema
		}
		if t != Number && t != Integer {
			return ErrSchema
		}
	case string:
		if t != String {
			return ErrSchema
		}
	case bool:
		if t != Boolean {
			return ErrSchema
		}
	default:
		return ErrSchema
	}
	return nil
}
func decimal(s string) error {
	if len(s) > 40 || !numberRE.MatchString(s) {
		return ErrDecimal
	}
	parts := strings.FieldsFunc(strings.TrimPrefix(s, "-"), func(r rune) bool { return r == '.' || r == 'e' || r == 'E' || r == '+' || r == '-' })
	digits := 0
	allzero := true
	for _, p := range parts[:1] {
		digits += len(p)
		for _, c := range p {
			if c != '0' {
				allzero = false
			}
		}
	}
	if strings.Contains(s, ".") {
		f := strings.Split(strings.Split(strings.TrimPrefix(s, "-"), "e")[0], "E")[0]
		f = strings.Split(f, ".")[1]
		digits += len(f)
		for _, c := range f {
			if c != '0' {
				allzero = false
			}
		}
	}
	if digits > 34 || (strings.HasPrefix(s, "-") && allzero) {
		return ErrDecimal
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		n, e := strconv.Atoi(s[i+1:])
		if e != nil || n > 32 || n < -32 {
			return ErrDecimal
		}
	}
	return nil
}
func safeInt(s string) bool {
	if strings.ContainsAny(s, ".eE") {
		return false
	}
	n, e := strconv.ParseInt(s, 10, 64)
	return e == nil && n >= -9007199254740991 && n <= 9007199254740991
}

const hexDigits = "0123456789abcdef"

func appendCanonicalString(dst []byte, s string) []byte {
	if dst == nil {
		dst = make([]byte, 0, len(s)+2)
	}
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			dst = append(dst, '\\', '"')
		case c == '\\':
			dst = append(dst, '\\', '\\')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	dst = append(dst, '"')
	return dst
}

func canonical(v any) []byte {
	switch x := v.(type) {
	case obj:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var b bytes.Buffer
		b.WriteByte('{')
		for i, k := range ks {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(appendCanonicalString(nil, k))
			b.WriteByte(':')
			b.Write(canonical(x[k]))
		}
		b.WriteByte('}')
		return b.Bytes()
	case []any:
		var b bytes.Buffer
		b.WriteByte('[')
		for i, z := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(canonical(z))
		}
		b.WriteByte(']')
		return b.Bytes()
	case string:
		return appendCanonicalString(nil, x)
	case bool:
		return []byte(strconv.FormatBool(x))
	case num:
		return []byte(x)
	default:
		panic(fmt.Sprintf("unsupported %T", v))
	}
}
func NumericFieldDigest(field, token string) (string, error) {
	if e := decimal(token); e != nil {
		return "", e
	}
	c := []byte(`{"field":` + strconv.Quote(field) + `,"token":` + token + `}`)
	h := sha256.Sum256(append([]byte("GuardFil.ActionNumericField.v1.1\n"), c...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
