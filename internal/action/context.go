package action

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	resourceid "github.com/reviaro/guardfil/internal/resource"
)

var (
	ErrProtocolUnsupported = errors.New("PROTOCOL_UNSUPPORTED")
	ErrToolRevisionUnknown = errors.New("TOOL_REVISION_UNKNOWN")
)

type Boundary string

const (
	ProposalFilter   Boundary = "proposal_filter"
	Advisory         Boundary = "advisory"
	ExecutionGateway Boundary = "execution_gateway"
)

type Profile struct {
	Protocol        string
	ProfileID       string
	AdapterRevision string
}

type Route struct {
	RouteID           string
	ExecutorID        string
	Operation         string
	ResolutionProfile string
	PayloadSchema     string
	Schema            Schema
	Tools             []string
}

type Tool struct {
	ToolID        string
	UpstreamID    string
	UpstreamName  string
	PayloadSchema string
	Schema        Schema
}

type Origin string

const (
	OriginTransport  Origin = "transport"
	OriginClient     Origin = "client"
	OriginModel      Origin = "model"
	OriginToolOutput Origin = "tool_output"
	OriginDetector   Origin = "detector"
)

type Trust string

const (
	TrustUntrusted           Trust = "untrusted"
	TrustAuthenticatedSource Trust = "authenticated_source"
	TrustVerifiedRuntime     Trust = "verified_runtime"
)

// runtimeVerifiedProtocols defines protocols that are NOT caller-facing and may carry
// verified_runtime producers (currently none).
//
// Security gate: openai_compatible/mcp are caller-facing too and must not be added
// without producer attestation.
var runtimeVerifiedProtocols = map[string]bool{}

// Producer represents an evidence producer registered with a Registry.
// Producers are bound to the transport profiles that authenticate them;
// evidence cannot borrow another profile's producer.
type Producer struct {
	ProducerID       string
	ProducerRevision string
	Profiles         []string
	Origin           Origin
	Trust            Trust
}

type trustedContextData struct {
	boundary          Boundary
	protocol          string
	profile           string
	adapterRevision   string
	routeID           string
	executorID        string
	targetKind        string
	resolutionProfile string
	payloadSchema     string
	toolRevision      string
	envelope          Envelope
	provenance        []ProvenanceEntry
	actor             Actor
	receivedAt        time.Time
	deadline          time.Time
	hasDeadline       bool
}

// ActionContext is an immutable value type carrying the trusted runtime context
// bound to an Action during NormalizeAction.
type ActionContext struct {
	boundary          Boundary
	protocol          string
	profile           string
	adapterRevision   string
	routeID           string
	executorID        string
	targetKind        string
	resolutionProfile string
	payloadSchema     string
	toolRevision      string
}

func (ac ActionContext) Boundary() Boundary         { return ac.boundary }
func (ac ActionContext) Protocol() string           { return ac.protocol }
func (ac ActionContext) Profile() string            { return ac.profile }
func (ac ActionContext) AdapterRevision() string    { return ac.adapterRevision }
func (ac ActionContext) RouteID() string            { return ac.routeID }
func (ac ActionContext) ExecutorID() string         { return ac.executorID }
func (ac ActionContext) TargetResourceKind() string { return ac.targetKind }
func (ac ActionContext) ResolutionProfile() string  { return ac.resolutionProfile }
func (ac ActionContext) PayloadSchema() string      { return ac.payloadSchema }
func (ac ActionContext) ToolRevision() string       { return ac.toolRevision }

type registeredProducer struct {
	producerID       string
	producerRevision string
	profiles         map[string]struct{}
	origin           Origin
	trust            Trust
}

type registeredProfile struct {
	protocol        string
	profileID       string
	adapterRevision string
}

type registeredRoute struct {
	routeID           string
	executorID        string
	operation         string
	targetKind        string
	resolutionProfile string
	payloadSchema     string
	schema            Schema
	tools             []string
	toolRevision      string
}

type registeredTool struct {
	toolID        string
	upstreamID    string
	upstreamName  string
	payloadSchema string
	schema        Schema
	toolRevision  string
}

// Registry stores trusted profiles, routes, and tools.
type Registry struct {
	profiles  map[string]registeredProfile
	routes    map[string]registeredRoute
	tools     map[string]registeredTool
	producers map[string]registeredProducer
}

// Context carries runtime binding for an Action boundary, profile, and route.
type Context struct {
	registry *Registry
	boundary Boundary
	profile  registeredProfile
	route    registeredRoute
}

func (c Context) Boundary() Boundary         { return c.boundary }
func (c Context) Protocol() string           { return c.profile.protocol }
func (c Context) Profile() string            { return c.profile.profileID }
func (c Context) AdapterRevision() string    { return c.profile.adapterRevision }
func (c Context) RouteID() string            { return c.route.routeID }
func (c Context) ExecutorID() string         { return c.route.executorID }
func (c Context) TargetResourceKind() string { return c.route.targetKind }
func (c Context) ResolutionProfile() string  { return c.route.resolutionProfile }

const toolRevisionPrefix = "GuardFil.ToolRevision.v1\n"

// ToolRevision digest definition:
// For each Tool:
//
//	toolRevision = "sha256:" + hex(SHA256("GuardFil.ToolRevision.v1\n" || canonical(entry)))
//	where entry is the closed object:
//	{"payload_schema": PayloadSchema, "schema": <canonical schema object>, "tool_id": ToolID, "upstream_id": UpstreamID, "upstream_name": UpstreamName}
//
// For each non-tool Route:
//
//	toolRevision = "sha256:" + hex(SHA256("GuardFil.ToolRevision.v1\n" || canonical(entry)))
//	where entry is the closed object:
//	{"executor_id": ExecutorID, "operation": Operation, "payload_schema": PayloadSchema, "resolution_profile": ResolutionProfile, "route_id": RouteID, "schema": <canonical schema object>}
//
// Canonical schema object:
//
//	{"fields": {name: type string}, "recursive_fields": {name: field}}
//	where field = {"type": t} plus "properties": {name: field} when present (len > 0)
//	and "items": field when present (Items != nil); omit absent members, never emit null.
//	Top-level "fields" and "recursive_fields" have a fixed closed shape, emitted as {} when empty.
//
// Protocol Review Notice: This digest definition specifies the immutable canonical encoding
// of registered tool and non-tool route schemas; changes require Protocol review and version bump.
func computeToolRevision(entry obj) string {
	c := canonical(entry)
	h := sha256.Sum256(append([]byte(toolRevisionPrefix), c...))
	return "sha256:" + hex.EncodeToString(h[:])
}

func canonicalSchemaObj(s Schema) obj {
	fieldsObj := obj{}
	for k, v := range s.Fields {
		fieldsObj[k] = string(v)
	}
	recFieldsObj := obj{}
	for k, v := range s.RecursiveFields {
		recFieldsObj[k] = canonicalFieldObj(v)
	}
	return obj{
		"fields":           fieldsObj,
		"recursive_fields": recFieldsObj,
	}
}

func canonicalFieldObj(f Field) obj {
	res := obj{
		"type": string(f.Type),
	}
	if len(f.Properties) > 0 {
		props := obj{}
		for k, v := range f.Properties {
			props[k] = canonicalFieldObj(v)
		}
		res["properties"] = props
	}
	if f.Items != nil {
		res["items"] = canonicalFieldObj(*f.Items)
	}
	return res
}

func deepCopySchema(s Schema) (Schema, error) {
	var fields map[string]FieldType
	if s.Fields != nil {
		fields = make(map[string]FieldType, len(s.Fields))
		for k, v := range s.Fields {
			fields[k] = v
		}
	}
	var recFields map[string]Field
	if s.RecursiveFields != nil {
		recFields = make(map[string]Field, len(s.RecursiveFields))
		var nodeCount int
		for k, v := range s.RecursiveFields {
			cp, err := deepCopyField(v, 0, &nodeCount)
			if err != nil {
				return Schema{}, err
			}
			recFields[k] = cp
		}
	}
	return Schema{
		Fields:          fields,
		RecursiveFields: recFields,
	}, nil
}

func deepCopyField(f Field, depth int, nodeCount *int) (Field, error) {
	if depth > 16 {
		return Field{}, ErrSchema
	}
	*nodeCount++
	if *nodeCount > 4096 {
		return Field{}, ErrSchema
	}
	cp := Field{
		Type: f.Type,
	}
	if f.Properties != nil {
		cp.Properties = make(map[string]Field, len(f.Properties))
		for k, v := range f.Properties {
			child, err := deepCopyField(v, depth+1, nodeCount)
			if err != nil {
				return Field{}, err
			}
			cp.Properties[k] = child
		}
	}
	if f.Items != nil {
		child, err := deepCopyField(*f.Items, depth+1, nodeCount)
		if err != nil {
			return Field{}, err
		}
		cp.Items = &child
	}
	return cp, nil
}

func validRuneRestrictions(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	for _, r := range s {
		switch {
		case r >= 0x0080 && r <= 0x009F:
			return false
		case r >= 0x200B && r <= 0x200F:
			return false
		case r >= 0x202A && r <= 0x202E:
			return false
		case r >= 0x2066 && r <= 0x2069:
			return false
		case r == 0xFEFF:
			return false
		}
	}
	return true
}

func validUpstreamName(s string) bool {
	if len(s) < 1 || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	return validRuneRestrictions(s)
}

func validGeneralID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
}

func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for i := 7; i < 71; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validateSchema(s Schema) error {
	for k, ft := range s.Fields {
		if !utf8ok(k) || len(k) > 256<<10 {
			return ErrSchema
		}
		if ft != Number && ft != Integer && ft != String && ft != Boolean {
			return ErrSchema
		}
	}
	for k, rf := range s.RecursiveFields {
		if !utf8ok(k) || len(k) > 256<<10 {
			return ErrSchema
		}
		if _, dup := s.Fields[k]; dup {
			return ErrSchema
		}
		if rf.Type != Object && rf.Type != Array {
			return ErrSchema
		}
		if err := validateField(rf, 0); err != nil {
			return err
		}
	}
	return nil
}

func validateField(f Field, depth int) error {
	if depth > 16 {
		return ErrSchema
	}
	switch f.Type {
	case Object:
		if len(f.Properties) == 0 || f.Items != nil {
			return ErrSchema
		}
		for k, child := range f.Properties {
			if !utf8ok(k) || len(k) > 256<<10 {
				return ErrSchema
			}
			if err := validateField(child, depth+1); err != nil {
				return err
			}
		}
	case Array:
		if f.Items == nil || len(f.Properties) > 0 {
			return ErrSchema
		}
		if err := validateField(*f.Items, depth+1); err != nil {
			return err
		}
	case Number, Integer, String, Boolean:
		if len(f.Properties) > 0 || f.Items != nil {
			return ErrSchema
		}
	default:
		return ErrSchema
	}
	return nil
}

// NewRegistry validates and builds an immutable registry of trusted profiles,
// routes, tools, and producers. Caller mutations after NewRegistry do not affect registered schemas or producers.
func NewRegistry(profiles []Profile, routes []Route, tools []Tool, producers []Producer) (*Registry, error) {
	if len(profiles) < 1 || len(profiles) > 64 {
		return nil, ErrSchema
	}
	if len(routes) < 1 || len(routes) > 1024 {
		return nil, ErrSchema
	}
	if len(tools) > 1024 {
		return nil, ErrSchema
	}
	if len(producers) > 256 {
		return nil, ErrSchema
	}

	regProfiles := make(map[string]registeredProfile, len(profiles))
	for _, p := range profiles {
		switch p.Protocol {
		case "decision_api":
		case "openai_compatible", "mcp":
			return nil, ErrProtocolUnsupported
		default:
			return nil, ErrSchema
		}
		if !validGeneralID(p.ProfileID) {
			return nil, ErrSchema
		}
		if !validDigest(p.AdapterRevision) {
			return nil, ErrSchema
		}
		if _, exists := regProfiles[p.ProfileID]; exists {
			return nil, ErrSchema
		}
		regProfiles[p.ProfileID] = registeredProfile{
			protocol:        p.Protocol,
			profileID:       p.ProfileID,
			adapterRevision: p.AdapterRevision,
		}
	}

	regProducers := make(map[string]registeredProducer, len(producers))
	for _, p := range producers {
		if !validGeneralID(p.ProducerID) {
			return nil, ErrSchema
		}
		if !validDigest(p.ProducerRevision) {
			return nil, ErrSchema
		}
		if len(p.Profiles) < 1 || len(p.Profiles) > 64 {
			return nil, ErrSchema
		}
		seenProfs := make(map[string]struct{}, len(p.Profiles))
		for _, profID := range p.Profiles {
			if _, exists := regProfiles[profID]; !exists {
				return nil, ErrSchema
			}
			if _, dup := seenProfs[profID]; dup {
				return nil, ErrSchema
			}
			seenProfs[profID] = struct{}{}
		}
		switch p.Origin {
		case OriginTransport, OriginClient, OriginModel, OriginToolOutput, OriginDetector:
		default:
			return nil, ErrSchema
		}
		switch p.Trust {
		case TrustUntrusted, TrustAuthenticatedSource, TrustVerifiedRuntime:
		default:
			return nil, ErrSchema
		}
		// Security Review Notice: Fail-closed trust ceiling allows Trust == verified_runtime
		// only for Origin transport or detector. Externally produced content (client, model,
		// tool_output) can never be runtime-verified ("authenticated source does not make content safe").
		// Security gate condition: caller-facing profiles cannot claim runtime-verified evidence
		// until producer attestation exists. A producer with Trust verified_runtime whose Profiles
		// include any profile whose protocol is not in the allow-list is rejected.
		// openai_compatible/mcp are caller-facing too and must not be added without producer attestation (Security gate).
		if p.Trust == TrustVerifiedRuntime {
			if p.Origin != OriginTransport && p.Origin != OriginDetector {
				return nil, ErrSchema
			}
			for profID := range seenProfs {
				if !runtimeVerifiedProtocols[regProfiles[profID].protocol] {
					return nil, ErrSchema
				}
			}
		}
		if _, exists := regProducers[p.ProducerID]; exists {
			return nil, ErrSchema
		}
		regProducers[p.ProducerID] = registeredProducer{
			producerID:       p.ProducerID,
			producerRevision: p.ProducerRevision,
			profiles:         seenProfs,
			origin:           p.Origin,
			trust:            p.Trust,
		}
	}

	type upstreamToolKey struct {
		id   string
		name string
	}
	seenUpstream := make(map[upstreamToolKey]struct{}, len(tools))
	regTools := make(map[string]registeredTool, len(tools))
	for _, t := range tools {
		if err := resourceid.ValidatePattern(resourceid.Tool, t.ToolID); err != nil {
			return nil, ErrSchema
		}
		norm, isCanonical, err := resourceid.NormalizeSelector(resourceid.Tool, t.ToolID)
		if err != nil || !isCanonical || norm != t.ToolID {
			return nil, ErrSchema
		}
		if !validGeneralID(t.UpstreamID) {
			return nil, ErrSchema
		}
		if !validUpstreamName(t.UpstreamName) {
			return nil, ErrSchema
		}
		if !validGeneralID(t.PayloadSchema) {
			return nil, ErrSchema
		}
		if _, exists := regTools[t.ToolID]; exists {
			return nil, ErrSchema
		}
		upKey := upstreamToolKey{id: t.UpstreamID, name: t.UpstreamName}
		if _, exists := seenUpstream[upKey]; exists {
			return nil, ErrSchema
		}
		seenUpstream[upKey] = struct{}{}
		toolSchema, err := deepCopySchema(t.Schema)
		if err != nil {
			return nil, ErrSchema
		}
		if err := validateSchema(toolSchema); err != nil {
			return nil, ErrSchema
		}
		entry := obj{
			"payload_schema": t.PayloadSchema,
			"schema":         canonicalSchemaObj(toolSchema),
			"tool_id":        t.ToolID,
			"upstream_id":    t.UpstreamID,
			"upstream_name":  t.UpstreamName,
		}
		rev := computeToolRevision(entry)
		regTools[t.ToolID] = registeredTool{
			toolID:        t.ToolID,
			upstreamID:    t.UpstreamID,
			upstreamName:  t.UpstreamName,
			payloadSchema: t.PayloadSchema,
			schema:        toolSchema,
			toolRevision:  rev,
		}
	}

	regRoutes := make(map[string]registeredRoute, len(routes))
	for _, r := range routes {
		if !validGeneralID(r.RouteID) || !validGeneralID(r.ExecutorID) || !validGeneralID(r.ResolutionProfile) {
			return nil, ErrSchema
		}
		if _, exists := regRoutes[r.RouteID]; exists {
			return nil, ErrSchema
		}

		selKind := resourceid.KindForOperation(r.Operation)
		if selKind == "" {
			return nil, ErrSchema
		}
		var targetKind string
		switch selKind {
		case resourceid.Path:
			targetKind = "filesystem"
		case resourceid.URL:
			targetKind = "http"
		case resourceid.Tool:
			targetKind = "tool"
		case resourceid.Command:
			targetKind = "shell"
		}

		var routeTools []string
		var routeSchema Schema
		var rev string
		if r.Operation == "tool.invoke" {
			if len(r.Tools) < 1 || len(r.Tools) > 1024 {
				return nil, ErrSchema
			}
			routeTools = make([]string, len(r.Tools))
			seen := make(map[string]struct{}, len(r.Tools))
			for i, tID := range r.Tools {
				if _, dup := seen[tID]; dup {
					return nil, ErrSchema
				}
				seen[tID] = struct{}{}
				if _, registered := regTools[tID]; !registered {
					return nil, ErrSchema
				}
				routeTools[i] = tID
			}
			if r.PayloadSchema != "" || len(r.Schema.Fields) > 0 || len(r.Schema.RecursiveFields) > 0 {
				return nil, ErrSchema
			}
		} else {
			if len(r.Tools) > 0 {
				return nil, ErrSchema
			}
			if !validGeneralID(r.PayloadSchema) {
				return nil, ErrSchema
			}
			if len(r.Schema.Fields) == 0 && len(r.Schema.RecursiveFields) == 0 {
				return nil, ErrSchema
			}
			var err error
			routeSchema, err = deepCopySchema(r.Schema)
			if err != nil {
				return nil, ErrSchema
			}
			if err := validateSchema(routeSchema); err != nil {
				return nil, ErrSchema
			}
			entry := obj{
				"executor_id":        r.ExecutorID,
				"operation":          r.Operation,
				"payload_schema":     r.PayloadSchema,
				"resolution_profile": r.ResolutionProfile,
				"route_id":           r.RouteID,
				"schema":             canonicalSchemaObj(routeSchema),
			}
			rev = computeToolRevision(entry)
		}

		regRoutes[r.RouteID] = registeredRoute{
			routeID:           r.RouteID,
			executorID:        r.ExecutorID,
			operation:         r.Operation,
			targetKind:        targetKind,
			resolutionProfile: r.ResolutionProfile,
			payloadSchema:     r.PayloadSchema,
			schema:            routeSchema,
			tools:             routeTools,
			toolRevision:      rev,
		}
	}

	return &Registry{
		profiles:  regProfiles,
		routes:    regRoutes,
		tools:     regTools,
		producers: regProducers,
	}, nil
}

// Context looks up an immutable Context for a given boundary, profile, and route.
func (r *Registry) Context(boundary Boundary, profileID, routeID string) (Context, error) {
	if r == nil {
		return Context{}, ErrSchema
	}
	switch boundary {
	case ProposalFilter, Advisory:
	case ExecutionGateway:
		return Context{}, ErrSchema
	default:
		return Context{}, ErrSchema
	}

	prof, ok := r.profiles[profileID]
	if !ok {
		return Context{}, ErrProtocolUnsupported
	}
	route, ok := r.routes[routeID]
	if !ok {
		return Context{}, ErrSchema
	}

	return Context{
		registry: r,
		boundary: boundary,
		profile:  prof,
		route:    route,
	}, nil
}

// NormalizeAction validates untrusted payload bytes under the trusted context
// configured for the boundary and route, binds the actor and normalized provenance
// entries into action_digest per rule 5, and binds the correlation envelope.
//
// The runtime correlation envelope is NEVER bound into action_digest (rule 5 excludes it permanently,
// correlation only). Read them only via
// TrustedContext(), TrustedEnvelope(), and TrustedProvenance().
func NormalizeAction(ctx Context, actor Actor, resource string, raw []byte, env MintedEnvelope, evidence []Evidence) (Action, error) {
	if !env.valid {
		return Action{}, ErrSchema
	}
	if ctx.registry == nil {
		return Action{}, ErrSchema
	}
	if len(actor.canonical) == 0 {
		return Action{}, ErrSchema
	}
	normEvidence, err := validateAndNormalizeEvidence(ctx.registry, ctx.profile.profileID, evidence)
	if err != nil {
		return Action{}, err
	}

	operation := ctx.route.operation
	kind := resourceid.KindForOperation(operation)
	if kind == "" {
		return Action{}, ErrSchema
	}
	normalized, canonicalResource, err := resourceid.NormalizeSelector(kind, resource)
	if err != nil {
		return Action{}, ErrSchema
	}

	var schema Schema
	var payloadSchema string
	var toolRevision string

	if operation == "tool.invoke" {
		allowed := false
		for _, tID := range ctx.route.tools {
			if tID == normalized {
				allowed = true
				break
			}
		}
		if !allowed {
			return Action{}, ErrToolRevisionUnknown
		}
		tool := ctx.registry.tools[normalized]
		schema = tool.schema
		payloadSchema = tool.payloadSchema
		toolRevision = tool.toolRevision
	} else {
		schema = ctx.route.schema
		payloadSchema = ctx.route.payloadSchema
		toolRevision = ctx.route.toolRevision
	}

	v, c, err := parseAndAdmitPayload(raw, schema)
	if err != nil {
		return Action{}, err
	}

	provArray := make([]any, len(normEvidence))
	for i, pe := range normEvidence {
		entryObj := obj{
			"content_digest":    pe.contentDigest,
			"id":                pe.id,
			"location":          pe.location,
			"observed_at":       pe.observedAt,
			"origin":            string(pe.origin),
			"producer_id":       pe.producerID,
			"producer_revision": pe.producerRevision,
			"trust":             string(pe.trust),
		}
		if len(pe.parentEvidenceIDs) > 0 {
			pids := make([]any, len(pe.parentEvidenceIDs))
			for j, pid := range pe.parentEvidenceIDs {
				pids[j] = pid
			}
			entryObj["parent_evidence_ids"] = pids
		}
		provArray[i] = entryObj
	}

	bindingObj := obj{
		"actor":          actor.obj,
		"boundary":       string(ctx.boundary),
		"operation":      operation,
		"payload":        v,
		"payload_schema": payloadSchema,
		"provenance":     provArray,
		"schema_version": Version,
		"source": obj{
			"adapter_revision": ctx.profile.adapterRevision,
			"profile":          ctx.profile.profileID,
			"protocol":         ctx.profile.protocol,
		},
		"target": obj{
			"executor_id":        ctx.route.executorID,
			"resolution_profile": ctx.route.resolutionProfile,
			"resource":           normalized,
			"resource_kind":      ctx.route.targetKind,
			"route_id":           ctx.route.routeID,
		},
		"tool_revision": toolRevision,
	}

	var digest string
	if canonicalResource {
		bindingBytes := canonical(bindingObj)
		h := sha256.Sum256(append([]byte("GuardFil.Action.v1\n"), bindingBytes...))
		digest = "sha256:" + hex.EncodeToString(h[:])
	}

	seal := &sealedAction{
		schemaVersion: Version,
		operation:     operation,
		resourceKind:  kind,
		resource:      normalized,
		payload:       string(c),
		digest:        digest,
		authorizable:  canonicalResource,
		resourceReady: canonicalResource,
		trustedContext: &trustedContextData{
			boundary:          ctx.boundary,
			protocol:          ctx.profile.protocol,
			profile:           ctx.profile.profileID,
			adapterRevision:   ctx.profile.adapterRevision,
			routeID:           ctx.route.routeID,
			executorID:        ctx.route.executorID,
			targetKind:        ctx.route.targetKind,
			resolutionProfile: ctx.route.resolutionProfile,
			payloadSchema:     payloadSchema,
			toolRevision:      toolRevision,
			envelope:          env.env,
			provenance:        normEvidence,
			actor:             actor,
			receivedAt:        env.receivedAt,
			deadline:          env.deadline,
			hasDeadline:       true,
		},
	}

	return Action{
		SchemaVersion: Version,
		Operation:     operation,
		ResourceKind:  kind,
		Resource:      normalized,
		Payload:       append([]byte(nil), c...),
		Digest:        digest,
		seal:          seal,
	}, nil
}
