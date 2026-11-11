package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/reviaro/guardfil/internal/action"
)

// A tool catalog lists an application's tools and the arguments each takes, so
// GuardFil can decide calls to them (an app's built-in agent asking before it
// runs a tool, or an outside agent using the app's API).  Arguments are checked
// before the kernel sees them: unknown or missing arguments, wrong types and
// values outside an enum are blocked.  Decimals stay exact decimal literals.
//
//	catalog_version: 1
//	tools:
//	  - id: stockapp.place_order
//	    description: Place an order
//	    arguments:
//	      symbol:      {type: string, required: true, max_length: 12}
//	      side:        {type: string, required: true, enum: [buy, sell]}
//	      quantity:    {type: integer, required: true}
//	      limit_price: {type: decimal}

const (
	maxCatalogBytes     = 256 * 1024
	maxCatalogTools     = 256
	maxToolArguments    = 32
	defaultStringLength = 1024
	maxStringLength     = MaxPayloadBytes
	maxEnumValues       = 64
)

var (
	catalogToolID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{1,64}$`)
	catalogArg    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	argTypes      = map[string]action.FieldType{
		"string": action.String, "integer": action.Integer, "decimal": action.Number, "boolean": action.Boolean,
	}
)

// ArgSpec describes one tool argument.
type ArgSpec struct {
	Type      string   `yaml:"type" json:"type"`
	Required  bool     `yaml:"required" json:"required,omitempty"`
	Enum      []string `yaml:"enum" json:"enum,omitempty"`
	MaxLength int      `yaml:"max_length" json:"max_length,omitempty"`
	// Min and Max bound an integer or decimal argument (quoted decimal
	// literals, compared exactly).  Bound amounts that amount rules multiply:
	// a negative price would make any order's value look small.
	Min string `yaml:"min" json:"min,omitempty"`
	Max string `yaml:"max" json:"max,omitempty"`
}

// ToolSpec is one catalog entry.
type ToolSpec struct {
	ID          string             `yaml:"id" json:"id"`
	Description string             `yaml:"description" json:"description,omitempty"`
	Arguments   map[string]ArgSpec `yaml:"arguments" json:"arguments"`
}

type catalogDoc struct {
	CatalogVersion int        `yaml:"catalog_version"`
	Tools          []ToolSpec `yaml:"tools"`
}

// Catalog is a validated, immutable tool catalog.
type Catalog struct {
	tools  map[string]ToolSpec
	order  []string
	digest string
}

// ParseCatalog validates a catalog document.
func ParseCatalog(raw []byte) (*Catalog, error) {
	if len(raw) > maxCatalogBytes {
		return nil, errors.New("tool catalog too large")
	}
	// A catalog file may hold several YAML documents (separated by ---), for
	// example the agents' catalog followed by an app's; their tools are merged
	// and a tool listed twice is refused.
	var doc catalogDoc
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	for n := 0; ; n++ {
		var part catalogDoc
		err := dec.Decode(&part)
		if errors.Is(err, io.EOF) && n > 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tool catalog: %v", err)
		}
		if part.CatalogVersion != 1 {
			return nil, errors.New("tool catalog: catalog_version must be 1")
		}
		if len(part.Tools) == 0 {
			return nil, fmt.Errorf("tool catalog: 1 to %d tools", maxCatalogTools)
		}
		doc.Tools = append(doc.Tools, part.Tools...)
	}
	if len(doc.Tools) == 0 || len(doc.Tools) > maxCatalogTools {
		return nil, fmt.Errorf("tool catalog: 1 to %d tools", maxCatalogTools)
	}
	c := &Catalog{tools: map[string]ToolSpec{}}
	for _, t := range doc.Tools {
		if !catalogToolID.MatchString(t.ID) {
			return nil, fmt.Errorf("tool catalog: id %q must be app.tool (letters, digits, _ and -)", t.ID)
		}
		if t.ID == shellToolID || t.ID == canaryToolID {
			return nil, fmt.Errorf("tool catalog: %s is reserved", t.ID)
		}
		if _, dup := c.tools[t.ID]; dup {
			return nil, fmt.Errorf("tool catalog: duplicate tool %s", t.ID)
		}
		if len(t.Arguments) > maxToolArguments || !utf8.ValidString(t.Description) || len(t.Description) > 1024 {
			return nil, fmt.Errorf("tool catalog: %s: at most %d arguments and a short description", t.ID, maxToolArguments)
		}
		for name, a := range t.Arguments {
			if !catalogArg.MatchString(name) {
				return nil, fmt.Errorf("tool catalog: %s: argument name %q must be lower_snake_case", t.ID, name)
			}
			if _, ok := argTypes[a.Type]; !ok {
				return nil, fmt.Errorf("tool catalog: %s.%s: type must be string, integer, decimal or boolean", t.ID, name)
			}
			if a.Type != "string" && (len(a.Enum) > 0 || a.MaxLength != 0) {
				return nil, fmt.Errorf("tool catalog: %s.%s: enum and max_length are for strings", t.ID, name)
			}
			if len(a.Enum) > maxEnumValues || a.MaxLength < 0 || a.MaxLength > maxStringLength {
				return nil, fmt.Errorf("tool catalog: %s.%s: enum or max_length out of range", t.ID, name)
			}
			if (a.Min != "" || a.Max != "") && a.Type != "integer" && a.Type != "decimal" {
				return nil, fmt.Errorf("tool catalog: %s.%s: min and max are for integer and decimal", t.ID, name)
			}
			for _, b := range []string{a.Min, a.Max} {
				if b != "" && !action.ValidDecimal(b) {
					return nil, fmt.Errorf("tool catalog: %s.%s: min/max must be a plain number in quotes", t.ID, name)
				}
			}
			if a.Min != "" && a.Max != "" && ratOf(a.Min).Cmp(ratOf(a.Max)) > 0 {
				return nil, fmt.Errorf("tool catalog: %s.%s: min is above max", t.ID, name)
			}
		}
		if t.Arguments == nil {
			t.Arguments = map[string]ArgSpec{}
		}
		c.tools[t.ID] = t
		c.order = append(c.order, t.ID)
	}
	sort.Strings(c.order)
	sum := sha256.Sum256(raw)
	c.digest = "sha256:" + hex.EncodeToString(sum[:])
	return c, nil
}

// Digest identifies the catalog bytes.
func (c *Catalog) Digest() string {
	if c == nil {
		return ""
	}
	return c.digest
}

// Has reports whether the catalog lists the tool.
func (c *Catalog) Has(id string) bool {
	if c == nil {
		return false
	}
	_, ok := c.tools[id]
	return ok
}

// Tools lists the catalog's tools sorted by id.
func (c *Catalog) Tools() []ToolSpec {
	if c == nil {
		return []ToolSpec{}
	}
	out := make([]ToolSpec, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.tools[id])
	}
	return out
}

func (c *Catalog) schema(id string) action.Schema {
	s := action.Schema{Fields: map[string]action.FieldType{}}
	for name, a := range c.tools[id].Arguments {
		s.Fields[name] = argTypes[a.Type]
	}
	return s
}

// check validates a call's arguments against the catalog entry and returns the
// kernel schema.  The kernel separately admits the types (and decimal literals).
func (c *Catalog) check(id string, args []byte) (action.Schema, error) {
	t := c.tools[id]
	d := json.NewDecoder(bytes.NewReader(args))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil || m == nil || d.More() {
		return action.Schema{}, action.ErrSchema
	}
	for name, v := range m {
		a, ok := t.Arguments[name]
		if !ok {
			return action.Schema{}, action.ErrSchema
		}
		switch a.Type {
		case "string":
			s, ok := v.(string)
			if !ok {
				return action.Schema{}, action.ErrSchema
			}
			limit := a.MaxLength
			if limit == 0 {
				limit = defaultStringLength
			}
			if utf8.RuneCountInString(s) > limit {
				return action.Schema{}, action.ErrLimit
			}
			if len(a.Enum) > 0 && !contains(a.Enum, s) {
				return action.Schema{}, action.ErrSchema
			}
		case "integer", "decimal":
			n, ok := v.(json.Number)
			if !ok {
				return action.Schema{}, action.ErrSchema
			}
			if a.Min != "" || a.Max != "" {
				x, ok := new(big.Rat).SetString(string(n))
				if !ok || !action.ValidDecimal(string(n)) {
					return action.Schema{}, action.ErrSchema
				}
				if (a.Min != "" && x.Cmp(ratOf(a.Min)) < 0) || (a.Max != "" && x.Cmp(ratOf(a.Max)) > 0) {
					return action.Schema{}, action.ErrLimit
				}
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return action.Schema{}, action.ErrSchema
			}
		}
	}
	for name, a := range t.Arguments {
		if _, ok := m[name]; a.Required && !ok {
			return action.Schema{}, action.ErrSchema
		}
	}
	return c.schema(id), nil
}

func ratOf(s string) *big.Rat {
	r, _ := new(big.Rat).SetString(s)
	return r
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
