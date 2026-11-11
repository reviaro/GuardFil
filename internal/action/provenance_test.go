package action_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/action"
)

const (
	provTestDigestA = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	provTestDigestB = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	provObservedAt  = "2026-10-14T12:00:00.000Z"
)

func provTestProfile() action.Profile {
	return action.Profile{
		Protocol:        "decision_api",
		ProfileID:       "prof-1",
		AdapterRevision: provTestDigestA,
	}
}

func provTestRoute() action.Route {
	return action.Route{
		RouteID:           "route-1",
		ExecutorID:        "exec-1",
		Operation:         "tool.invoke",
		ResolutionProfile: "res-1",
		Tools:             []string{"tool-1"},
	}
}

func provTestTool() action.Tool {
	return action.Tool{
		ToolID:        "tool-1",
		UpstreamID:    "upstream-1",
		UpstreamName:  "tool-1",
		PayloadSchema: "schema-1",
		Schema: action.Schema{
			Fields: map[string]action.FieldType{
				"arg": action.String,
			},
		},
	}
}

func provTestRegistry(t *testing.T, producers []action.Producer) *action.Registry {
	t.Helper()
	reg, err := action.NewRegistry(
		[]action.Profile{provTestProfile()},
		[]action.Route{provTestRoute()},
		[]action.Tool{provTestTool()},
		producers,
	)
	if err != nil {
		t.Fatalf("provTestRegistry failed: %v", err)
	}
	return reg
}

// 1. Producer table: valid registry builds with 0 and with several producers;
// >256, duplicate ID, bad ID, bad/uppercase digest, unknown/capitalized origin or trust -> ErrSchema;
// verified_runtime with client/model/tool_output -> ErrSchema; with transport/detector ok;
// untrusted and authenticated_source ok for all five origins.
func TestProducerRegistryTable(t *testing.T) {
	// 0 producers: nil and empty slice both succeed
	if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, nil); err != nil {
		t.Fatalf("expected 0 producers (nil) to succeed, got %v", err)
	}
	if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, []action.Producer{}); err != nil {
		t.Fatalf("expected 0 producers (empty slice) to succeed, got %v", err)
	}

	// Several valid producers
	p1 := action.Producer{ProducerID: "prod-1", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: action.OriginTransport, Trust: action.TrustAuthenticatedSource}
	p2 := action.Producer{ProducerID: "prod-2", ProducerRevision: provTestDigestB, Profiles: []string{"prof-1"}, Origin: action.OriginClient, Trust: action.TrustAuthenticatedSource}
	p3 := action.Producer{ProducerID: "prod-3", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: action.OriginDetector, Trust: action.TrustAuthenticatedSource}
	if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, []action.Producer{p1, p2, p3}); err != nil {
		t.Fatalf("expected valid several producers to succeed, got %v", err)
	}

	// >256 producers -> ErrSchema
	manyProducers := make([]action.Producer, 257)
	for i := range manyProducers {
		manyProducers[i] = action.Producer{
			ProducerID:       fmt.Sprintf("prod-%04d", i),
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustUntrusted,
		}
	}
	if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, manyProducers); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for 257 producers, got %v", err)
	}

	// Duplicate ID -> ErrSchema
	dupP := []action.Producer{
		{ProducerID: "prod-dup", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: action.OriginTransport, Trust: action.TrustUntrusted},
		{ProducerID: "prod-dup", ProducerRevision: provTestDigestB, Profiles: []string{"prof-1"}, Origin: action.OriginClient, Trust: action.TrustUntrusted},
	}
	if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, dupP); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for duplicate producer ID, got %v", err)
	}

	// Bad ID -> ErrSchema
	badIDs := []string{"", "bad with spaces", "bad@char", strings.Repeat("a", 129), "bad#id"}
	for _, badID := range badIDs {
		p := []action.Producer{{ProducerID: badID, ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: action.OriginTransport, Trust: action.TrustUntrusted}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, p); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad producer ID %q, got %v", badID, err)
		}
	}

	// Bad/uppercase digest -> ErrSchema
	badDigests := []string{
		"sha256:" + strings.ToUpper("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		"sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"not-a-digest",
		"sha256:0123",
		"",
	}
	for _, badDig := range badDigests {
		p := []action.Producer{{ProducerID: "p-1", ProducerRevision: badDig, Profiles: []string{"prof-1"}, Origin: action.OriginTransport, Trust: action.TrustUntrusted}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, p); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad producer revision %q, got %v", badDig, err)
		}
	}

	// Unknown/capitalized origin or trust -> ErrSchema
	badOrigins := []action.Origin{"Transport", "CLIENT", "unknown", "tool", ""}
	for _, badOrig := range badOrigins {
		p := []action.Producer{{ProducerID: "p-1", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: badOrig, Trust: action.TrustUntrusted}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, p); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad origin %q, got %v", badOrig, err)
		}
	}
	badTrusts := []action.Trust{"Untrusted", "VERIFIED_RUNTIME", "trusted", "authenticated", ""}
	for _, badTrust := range badTrusts {
		p := []action.Producer{{ProducerID: "p-1", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: action.OriginTransport, Trust: badTrust}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, p); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad trust %q, got %v", badTrust, err)
		}
	}

	// verified_runtime with client/model/tool_output -> ErrSchema
	forbiddenVR := []action.Origin{action.OriginClient, action.OriginModel, action.OriginToolOutput}
	for _, orig := range forbiddenVR {
		p := []action.Producer{{ProducerID: "p-vr-fail", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: orig, Trust: action.TrustVerifiedRuntime}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, p); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for verified_runtime with origin %q, got %v", orig, err)
		}
	}

	// verified_runtime is rejected for any profile not in runtimeVerifiedProtocols allow-list
	allowedVR := []action.Origin{action.OriginTransport, action.OriginDetector}
	for _, orig := range allowedVR {
		p := []action.Producer{{ProducerID: "p-vr-fail", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: orig, Trust: action.TrustVerifiedRuntime}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, p); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for verified_runtime on decision_api with origin %q, got %v", orig, err)
		}
	}

	// untrusted and authenticated_source ok for all five origins
	allOrigins := []action.Origin{
		action.OriginTransport,
		action.OriginClient,
		action.OriginModel,
		action.OriginToolOutput,
		action.OriginDetector,
	}
	for _, orig := range allOrigins {
		pUntrusted := []action.Producer{{ProducerID: "p-u", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: orig, Trust: action.TrustUntrusted}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, pUntrusted); err != nil {
			t.Fatalf("expected untrusted with origin %q to succeed, got %v", orig, err)
		}

		pAuthSource := []action.Producer{{ProducerID: "p-as", ProducerRevision: provTestDigestA, Profiles: []string{"prof-1"}, Origin: orig, Trust: action.TrustAuthenticatedSource}}
		if _, err := action.NewRegistry([]action.Profile{provTestProfile()}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, pAuthSource); err != nil {
			t.Fatalf("expected authenticated_source with origin %q to succeed, got %v", orig, err)
		}
	}
}

// 2. Trust derivation: two producers with different trust; entries get origin/trust/producer_revision
// from the registry; Evidence has no field that can set them.
func TestTrustDerivation(t *testing.T) {
	producers := []action.Producer{
		{
			ProducerID:       "p-det",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginDetector,
			Trust:            action.TrustUntrusted,
		},
		{
			ProducerID:       "p-cli",
			ProducerRevision: provTestDigestB,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginClient,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg := provTestRegistry(t, producers)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	contentDigest1 := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	contentDigest2 := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	ev1 := action.Evidence{
		ID:            "ev-1",
		ProducerID:    "p-det",
		ContentDigest: contentDigest1,
		Location:      "/det/result",
		ObservedAt:    provObservedAt,
	}
	ev2 := action.Evidence{
		ID:            "ev-2",
		ProducerID:    "p-cli",
		ContentDigest: contentDigest2,
		Location:      "/cli/input",
		ObservedAt:    provObservedAt,
	}

	act, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", []byte(`{"arg":"test"}`), defaultTestEnvelope, []action.Evidence{ev1, ev2})
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}

	prov, ok := act.TrustedProvenance()
	if !ok || len(prov) != 2 {
		t.Fatalf("TrustedProvenance failed or len != 2: ok=%v, len=%d", ok, len(prov))
	}

	// Sorted by ID: ev-1, then ev-2
	e0 := prov[0]
	if e0.ID() != "ev-1" || e0.Origin() != action.OriginDetector || e0.Trust() != action.TrustUntrusted ||
		e0.ProducerID() != "p-det" || e0.ProducerRevision() != provTestDigestA || e0.ContentDigest() != contentDigest1 ||
		e0.Location() != "/det/result" || e0.ObservedAt() != provObservedAt {
		t.Fatalf("unexpected entry 0 values: %+v", e0)
	}
	if e0.ProducerRevision() == e0.ContentDigest() {
		t.Fatalf("expected producer revision %q to differ from content digest %q", e0.ProducerRevision(), e0.ContentDigest())
	}
	if e0.ProducerRevision() != provTestDigestA {
		t.Fatalf("assert ProducerRevision() == registered revision: got %q, want %q", e0.ProducerRevision(), provTestDigestA)
	}

	e1 := prov[1]
	if e1.ID() != "ev-2" || e1.Origin() != action.OriginClient || e1.Trust() != action.TrustAuthenticatedSource ||
		e1.ProducerID() != "p-cli" || e1.ProducerRevision() != provTestDigestB || e1.ContentDigest() != contentDigest2 ||
		e1.Location() != "/cli/input" || e1.ObservedAt() != provObservedAt {
		t.Fatalf("unexpected entry 1 values: %+v", e1)
	}
	if e1.ProducerRevision() == e1.ContentDigest() {
		t.Fatalf("expected producer revision %q to differ from content digest %q", e1.ProducerRevision(), e1.ContentDigest())
	}
	if e1.ProducerRevision() != provTestDigestB {
		t.Fatalf("assert ProducerRevision() == registered revision: got %q, want %q", e1.ProducerRevision(), provTestDigestB)
	}
}

// 3. Evidence rejections: unknown producer, bad ID, bad content_digest, 9 parents, duplicate parent,
// self-parent, bad parent ID, duplicate entry IDs, 65 entries, location without leading '/', "~2",
// trailing "~", 513 bytes, "\n" and 0x7F in location, invalid UTF-8 -> ErrSchema.
// Location "" , "/", "/a~0b~1c", 512 bytes ok. Parent referencing an id not in the set is ok.
func TestEvidenceRejections(t *testing.T) {
	producers := []action.Producer{
		{
			ProducerID:       "p-ok",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg := provTestRegistry(t, producers)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	basePayload := []byte(`{"arg":"test"}`)
	baseEv := action.Evidence{
		ID:            "ev-ok",
		ProducerID:    "p-ok",
		ContentDigest: provTestDigestA,
		Location:      "/valid",
		ObservedAt:    provObservedAt,
	}

	// Unknown producer
	evUnknownProd := baseEv
	evUnknownProd.ProducerID = "p-unknown"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evUnknownProd}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for unknown producer, got %v", err)
	}

	// Bad ID
	for _, badID := range []string{"", "bad id", "bad@id", strings.Repeat("a", 129)} {
		evBadID := baseEv
		evBadID.ID = badID
		if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evBadID}); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad ID %q, got %v", badID, err)
		}
	}

	// Bad content_digest
	for _, badDig := range []string{"bad", strings.ToUpper(provTestDigestA), "sha512:abc", ""} {
		evBadDig := baseEv
		evBadDig.ContentDigest = badDig
		if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evBadDig}); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad content_digest %q, got %v", badDig, err)
		}
	}

	// 9 parents
	ev9Parents := baseEv
	ev9Parents.ParentEvidenceIDs = []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{ev9Parents}); !errors.Is(err, action.ErrLimit) {
		t.Fatalf("expected ErrLimit for 9 parents, got %v", err)
	}

	// Duplicate parent
	evDupParent := baseEv
	evDupParent.ParentEvidenceIDs = []string{"p1", "p1"}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evDupParent}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for duplicate parent ID, got %v", err)
	}

	// Self-parent
	evSelfParent := baseEv
	evSelfParent.ID = "self-id"
	evSelfParent.ParentEvidenceIDs = []string{"self-id"}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evSelfParent}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for self-parent, got %v", err)
	}

	// Bad parent ID
	evBadParentID := baseEv
	evBadParentID.ParentEvidenceIDs = []string{"bad parent id"}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evBadParentID}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for bad parent ID, got %v", err)
	}

	// Duplicate entry IDs across the set
	evDup1 := baseEv
	evDup1.ID = "dup-id"
	evDup2 := baseEv
	evDup2.ID = "dup-id"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evDup1, evDup2}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for duplicate entry IDs, got %v", err)
	}

	// 65 entries
	manyEv := make([]action.Evidence, 65)
	for i := range manyEv {
		manyEv[i] = baseEv
		manyEv[i].ID = fmt.Sprintf("ev-%03d", i)
	}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, manyEv); !errors.Is(err, action.ErrLimit) {
		t.Fatalf("expected ErrLimit for 65 evidence entries, got %v", err)
	}

	// Location without leading '/'
	evNoLeadSlash := baseEv
	evNoLeadSlash.Location = "no-leading-slash"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evNoLeadSlash}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location without leading '/', got %v", err)
	}

	// Location with "~2"
	evTilde2 := baseEv
	evTilde2.Location = "/a~2b"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evTilde2}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with ~2, got %v", err)
	}

	// Location with trailing "~"
	evTrailTilde := baseEv
	evTrailTilde.Location = "/a~"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evTrailTilde}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with trailing ~, got %v", err)
	}

	// Location 513 bytes
	ev513 := baseEv
	ev513.Location = "/" + strings.Repeat("x", 512)
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{ev513}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location of 513 bytes, got %v", err)
	}

	// Location with '\n' and 0x7F
	evNewline := baseEv
	evNewline.Location = "/a\nb"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evNewline}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with newline, got %v", err)
	}
	evDel := baseEv
	evDel.Location = "/a\x7fb"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evDel}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with 0x7F, got %v", err)
	}

	// Location with 0x00 and 0x1F
	ev00 := baseEv
	ev00.Location = "/a\x00b"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{ev00}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with 0x00, got %v", err)
	}
	ev1F := baseEv
	ev1F.Location = "/a\x1fb"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{ev1F}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with 0x1F, got %v", err)
	}

	// Invalid UTF-8 in location
	evBadUTF8 := baseEv
	evBadUTF8.Location = "/a\xff\xfeb"
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evBadUTF8}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for location with invalid UTF-8, got %v", err)
	}

	// Valid location edge cases: "", "/", "/a~0b~1c", 512 bytes ok
	validLocs := []string{
		"",
		"/",
		"/a~0b~1c",
		"/" + strings.Repeat("a", 511),
	}
	for _, loc := range validLocs {
		evLoc := baseEv
		evLoc.Location = loc
		if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evLoc}); err != nil {
			t.Fatalf("expected valid location %q to succeed, got %v", loc, err)
		}
	}

	// Parent referencing an ID not in the set is ok (missing lineage means unknown, does not require resolution)
	evExtParent := baseEv
	evExtParent.ParentEvidenceIDs = []string{"some-external-parent-id"}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", basePayload, defaultTestEnvelope, []action.Evidence{evExtParent}); err != nil {
		t.Fatalf("expected external parent ID to be admitted, got %v", err)
	}
}

// 4. Timestamps: "2026-10-14T12:00:00.000Z" ok; reject ".00Z", ".0000Z", no fraction,
// "+00:00", lowercase "z"/"t", "2026-02-30...", "24:00:00", leading/trailing space.
func TestTimestamps(t *testing.T) {
	producers := []action.Producer{
		{
			ProducerID:       "p-1",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg := provTestRegistry(t, producers)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	payload := []byte(`{"arg":"test"}`)

	// Valid timestamp succeeds
	validEv := action.Evidence{
		ID:            "ev-1",
		ProducerID:    "p-1",
		ContentDigest: provTestDigestA,
		Location:      "/a",
		ObservedAt:    "2026-10-14T12:00:00.000Z",
	}
	validEnv := defaultTestEnvelope
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, validEnv, []action.Evidence{validEv}); err != nil {
		t.Fatalf("expected valid timestamp to succeed, got %v", err)
	}

	invalidTimestamps := []string{
		"2026-10-14T12:00:00.00Z",       // .00Z
		"2026-10-14T12:00:00.0000Z",     // .0000Z
		"2026-10-14T12:00:00Z",          // no fraction
		"2026-10-14T12:00:00.000+00:00", // +00:00
		"2026-10-14T12:00:00.000z",      // lowercase z
		"2026-10-14t12:00:00.000Z",      // lowercase t
		"2026-02-30T12:00:00.000Z",      // non-existent calendar date
		"2026-10-14T24:00:00.000Z",      // 24:00:00
		" 2026-10-14T12:00:00.000Z",     // leading space
		"2026-10-14T12:00:00.000Z ",     // trailing space
		"2026-10-14T12:00:00,000Z",      // comma separator rejected by format round-trip
		"2026-10-14T12:00:00.+12Z",      // +12Z rejected by format round-trip
	}

	for _, ts := range invalidTimestamps {
		// Test in Evidence.ObservedAt
		badEv := validEv
		badEv.ObservedAt = ts
		if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, validEnv, []action.Evidence{badEv}); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for invalid timestamp %q in Evidence.ObservedAt, got %v", ts, err)
		}
	}
}

// 5. Envelope: runtime minted envelope validation, IDSource error, ttl bounds,
// ParentActionID == ActionID, optional fields, zero MintedEnvelope, and TrustedDeadline round-trip.
func TestEnvelopeValidation(t *testing.T) {
	reg := provTestRegistry(t, nil)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}
	payload := []byte(`{"arg":"test"}`)
	clk := fakeClock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	ids := fakeIDSource{id: "act-1"}

	// Missing/empty ActionID from IDSource -> ErrInternal
	if _, err := action.NewEnvelope(clk, fakeIDSource{id: ""}, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for empty ActionID, got %v", err)
	}

	// IDSource error -> ErrInternal
	if _, err := action.NewEnvelope(clk, fakeIDSource{err: errors.New("entropy error")}, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for IDSource error, got %v", err)
	}

	// IDSource error with valid ID returned -> ErrInternal
	if _, err := action.NewEnvelope(clk, fakeIDSource{id: "act-valid-1", err: errors.New("entropy error")}, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for IDSource returning valid id with error, got %v", err)
	}

	// nil Clock or nil IDSource -> ErrInternal
	if _, err := action.NewEnvelope(nil, ids, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for nil clock, got %v", err)
	}
	if _, err := action.NewEnvelope(clk, nil, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for nil IDSource, got %v", err)
	}

	// Clock in year 10000 -> ErrInternal
	clk10k := fakeClock{now: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := action.NewEnvelope(clk10k, ids, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for clock in year 10000, got %v", err)
	}

	// Clock crossing year 9999 boundary -> ErrInternal
	clkCrossing := fakeClock{now: time.Date(9999, 12, 31, 23, 59, 50, 0, time.UTC)}
	if _, err := action.NewEnvelope(clkCrossing, ids, "req-1", "", "", 15*time.Second); !errors.Is(err, action.ErrInternal) {
		t.Fatalf("expected ErrInternal for ttl crossing year 9999 boundary, got %v", err)
	}

	// Missing/empty RequestID -> ErrSchema
	if _, err := action.NewEnvelope(clk, ids, "", "", "", time.Second); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for missing RequestID, got %v", err)
	}

	// Bad IDs
	for _, badID := range []string{"bad id with spaces", "bad@id", strings.Repeat("a", 129)} {
		if _, err := action.NewEnvelope(clk, fakeIDSource{id: badID}, "req-1", "", "", time.Second); !errors.Is(err, action.ErrInternal) {
			t.Fatalf("expected ErrInternal for bad ActionID %q, got %v", badID, err)
		}

		if _, err := action.NewEnvelope(clk, ids, badID, "", "", time.Second); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for bad RequestID %q, got %v", badID, err)
		}
	}

	// ParentActionID == ActionID -> ErrSchema
	if _, err := action.NewEnvelope(clk, ids, "req-1", "act-1", "", time.Second); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for ParentActionID == ActionID, got %v", err)
	}

	// Bad ParentActionID -> ErrSchema
	if _, err := action.NewEnvelope(clk, ids, "req-1", "bad@parent", "", time.Second); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for bad ParentActionID, got %v", err)
	}

	// ttl 0 and negative -> ErrSchema
	if _, err := action.NewEnvelope(clk, ids, "req-1", "", "", 0); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for ttl 0, got %v", err)
	}
	if _, err := action.NewEnvelope(clk, ids, "req-1", "", "", -time.Second); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for negative ttl, got %v", err)
	}

	// ttl exactly 30 s -> deadline == receivedAt+30 s
	env30, err := action.NewEnvelope(clk, ids, "req-1", "", "", 30*time.Second)
	if err != nil {
		t.Fatalf("NewEnvelope 30s failed: %v", err)
	}
	act30, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env30, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	rec30, dead30, ok := act30.TrustedDeadline()
	if !ok || !dead30.Equal(rec30.Add(30*time.Second)) || dead30.Sub(rec30) != 30*time.Second {
		t.Fatalf("expected ttl 30s deadline == receivedAt+30s exactly: rec=%v dead=%v sub=%v", rec30, dead30, dead30.Sub(rec30))
	}

	// ttl 30 s + 1 ns -> deadline == receivedAt+30 s (clamped to MaxRequestLifetime and ms floored)
	env30Plus1ns, err := action.NewEnvelope(clk, ids, "req-1", "", "", 30*time.Second+time.Nanosecond)
	if err != nil {
		t.Fatalf("NewEnvelope 30s+1ns failed: %v", err)
	}
	act30Plus1ns, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env30Plus1ns, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	rec30Plus1ns, dead30Plus1ns, ok := act30Plus1ns.TrustedDeadline()
	if !ok || !dead30Plus1ns.Equal(rec30Plus1ns.Add(30*time.Second)) || dead30Plus1ns.Sub(rec30Plus1ns) != 30*time.Second {
		t.Fatalf("expected ttl 30s+1ns to clamp to receivedAt+30s exactly: rec=%v dead=%v sub=%v", rec30Plus1ns, dead30Plus1ns, dead30Plus1ns.Sub(rec30Plus1ns))
	}

	// ttl 30 s + 1 ms -> deadline == receivedAt+30 s (clamped to MaxRequestLifetime) and Envelope.DeadlineAt formatted
	env30Plus1ms, err := action.NewEnvelope(clk, ids, "req-1", "", "", 30*time.Second+time.Millisecond)
	if err != nil {
		t.Fatalf("NewEnvelope 30s+1ms failed: %v", err)
	}
	act30Plus1ms, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env30Plus1ms, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	rec30Plus1ms, dead30Plus1ms, ok := act30Plus1ms.TrustedDeadline()
	te30Plus1ms, okEnv30Plus1ms := act30Plus1ms.TrustedEnvelope()
	wantDead30Plus1ms := rec30Plus1ms.Add(30 * time.Second)
	wantDeadlineAt30Plus1ms := wantDead30Plus1ms.UTC().Format("2006-01-02T15:04:05.000Z")
	if rec30Plus1ms.Nanosecond()%int(time.Millisecond) != 0 {
		t.Fatalf("expected receivedAt with zero sub-ms nanos, got %v", rec30Plus1ms)
	}
	if !ok || !dead30Plus1ms.Equal(wantDead30Plus1ms) || dead30Plus1ms.Sub(rec30Plus1ms) != 30*time.Second {
		t.Fatalf("expected ttl 30s+1ms to clamp to receivedAt+30s exactly: rec=%v dead=%v sub=%v", rec30Plus1ms, dead30Plus1ms, dead30Plus1ms.Sub(rec30Plus1ms))
	}
	if !okEnv30Plus1ms || te30Plus1ms.DeadlineAt != wantDeadlineAt30Plus1ms || te30Plus1ms.DeadlineAt != dead30Plus1ms.UTC().Format("2006-01-02T15:04:05.000Z") {
		t.Fatalf("expected ttl 30s+1ms Envelope.DeadlineAt == %q, got ok=%v DeadlineAt=%q", wantDeadlineAt30Plus1ms, okEnv30Plus1ms, te30Plus1ms.DeadlineAt)
	}

	// ttl 31 s -> deadline == receivedAt+30 s exactly (clamped to MaxRequestLifetime) and Envelope.DeadlineAt formatted
	env31, err := action.NewEnvelope(clk, ids, "req-1", "", "", 31*time.Second)
	if err != nil {
		t.Fatalf("NewEnvelope 31s failed: %v", err)
	}
	act31, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env31, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	rec31, dead31, ok := act31.TrustedDeadline()
	te31, okEnv31 := act31.TrustedEnvelope()
	wantDead31 := rec31.Add(30 * time.Second)
	wantDeadlineAt31 := wantDead31.UTC().Format("2006-01-02T15:04:05.000Z")
	if rec31.Nanosecond()%int(time.Millisecond) != 0 {
		t.Fatalf("expected receivedAt with zero sub-ms nanos, got %v", rec31)
	}
	if !ok || !dead31.Equal(wantDead31) || dead31.Sub(rec31) != 30*time.Second {
		t.Fatalf("expected ttl 31s to clamp to receivedAt+30s exactly: rec=%v dead=%v sub=%v", rec31, dead31, dead31.Sub(rec31))
	}
	if !okEnv31 || te31.DeadlineAt != wantDeadlineAt31 || te31.DeadlineAt != dead31.UTC().Format("2006-01-02T15:04:05.000Z") {
		t.Fatalf("expected ttl 31s Envelope.DeadlineAt == %q, got ok=%v DeadlineAt=%q", wantDeadlineAt31, okEnv31, te31.DeadlineAt)
	}

	// ttl 10 s -> deadline == receivedAt+10 s
	env10, err := action.NewEnvelope(clk, ids, "req-1", "", "", 10*time.Second)
	if err != nil {
		t.Fatalf("NewEnvelope 10s failed: %v", err)
	}
	act10, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env10, nil)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	rec10, dead10, ok := act10.TrustedDeadline()
	if !ok || !dead10.Equal(rec10.Add(10*time.Second)) || dead10.Sub(rec10) != 10*time.Second {
		t.Fatalf("expected ttl 10s deadline == receivedAt+10s: rec=%v dead=%v sub=%v", rec10, dead10, dead10.Sub(rec10))
	}

	// Zero/unminted MintedEnvelope -> ErrSchema
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, action.MintedEnvelope{}, nil); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for zero MintedEnvelope, got %v", err)
	}

	// Optional fields empty ok
	envEmptyOptional, err := action.NewEnvelope(clk, ids, "req-1", "", "", time.Second)
	if err != nil {
		t.Fatalf("NewEnvelope empty optional failed: %v", err)
	}
	act, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, envEmptyOptional, nil)
	if err != nil {
		t.Fatalf("expected empty optional envelope fields to succeed, got %v", err)
	}
	te, ok := act.TrustedEnvelope()
	if !ok || te.ParentActionID != "" || te.IdempotencyKey != "" {
		t.Fatalf("expected empty optional fields preserved, got ok=%v te=%+v", ok, te)
	}

	// Valid IdempotencyKey and ParentActionID ok
	envWithOptional, err := action.NewEnvelope(clk, ids, "req-1", "parent-act-1", "idemp-key-1", time.Second)
	if err != nil {
		t.Fatalf("NewEnvelope with optional failed: %v", err)
	}
	actOpt, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, envWithOptional, nil)
	if err != nil {
		t.Fatalf("expected valid optional envelope fields to succeed, got %v", err)
	}
	teOpt, ok := actOpt.TrustedEnvelope()
	wantEnv := action.Envelope{
		ActionID:       "act-1",
		RequestID:      "req-1",
		ParentActionID: "parent-act-1",
		ReceivedAt:     "2026-10-14T12:00:00.000Z",
		DeadlineAt:     "2026-10-14T12:00:01.000Z",
		IdempotencyKey: "idemp-key-1",
	}
	if !ok || teOpt != wantEnv {
		t.Fatalf("full round-trip mismatch with all six fields set: got %+v, want %+v", teOpt, wantEnv)
	}

	// TrustedDeadline round-trips
	recOpt, deadOpt, ok := actOpt.TrustedDeadline()
	if !ok || !recOpt.Equal(clk.Now()) || !deadOpt.Equal(clk.Now().Add(time.Second)) {
		t.Fatalf("TrustedDeadline round-trip failed: ok=%v rec=%v dead=%v", ok, recOpt, deadOpt)
	}

	// Bad IdempotencyKey -> ErrSchema
	if _, err := action.NewEnvelope(clk, ids, "req-1", "", "bad key with spaces", time.Second); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for bad IdempotencyKey, got %v", err)
	}
}

// 6. Sorting: same evidence in two input orders -> identical TrustedProvenance.
func TestEvidenceSorting(t *testing.T) {
	producers := []action.Producer{
		{
			ProducerID:       "p-1",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginDetector,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg := provTestRegistry(t, producers)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}
	payload := []byte(`{"arg":"test"}`)

	evAlpha1 := action.Evidence{ID: "alpha", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"z", "a"}}
	evBeta1 := action.Evidence{ID: "beta", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/b", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"y", "b"}}
	evGamma1 := action.Evidence{ID: "gamma", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/c", ObservedAt: provObservedAt}

	evAlpha2 := action.Evidence{ID: "alpha", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"a", "z"}}
	evBeta2 := action.Evidence{ID: "beta", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/b", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"b", "y"}}
	evGamma2 := action.Evidence{ID: "gamma", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/c", ObservedAt: provObservedAt}

	order1 := []action.Evidence{evGamma1, evAlpha1, evBeta1}
	order2 := []action.Evidence{evBeta2, evGamma2, evAlpha2}

	act1, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, order1)
	if err != nil {
		t.Fatalf("NormalizeAction order1 failed: %v", err)
	}
	act2, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, order2)
	if err != nil {
		t.Fatalf("NormalizeAction order2 failed: %v", err)
	}

	prov1, ok1 := act1.TrustedProvenance()
	prov2, ok2 := act2.TrustedProvenance()
	if !ok1 || !ok2 {
		t.Fatalf("TrustedProvenance failed: ok1=%v, ok2=%v", ok1, ok2)
	}
	if len(prov1) != 3 || len(prov2) != 3 {
		t.Fatalf("unexpected length: len(prov1)=%d, len(prov2)=%d", len(prov1), len(prov2))
	}

	for i := range prov1 {
		p1Parents := prov1[i].ParentEvidenceIDs()
		p2Parents := prov2[i].ParentEvidenceIDs()
		if len(p1Parents) != len(p2Parents) {
			t.Fatalf("parent count mismatch at %d: %v vs %v", i, p1Parents, p2Parents)
		}
		for j := range p1Parents {
			if p1Parents[j] != p2Parents[j] {
				t.Fatalf("parent ID mismatch at %d,%d: %v vs %v", i, j, p1Parents, p2Parents)
			}
		}
		if prov1[i].ID() != prov2[i].ID() ||
			prov1[i].Origin() != prov2[i].Origin() ||
			prov1[i].Trust() != prov2[i].Trust() ||
			prov1[i].ProducerID() != prov2[i].ProducerID() ||
			prov1[i].ProducerRevision() != prov2[i].ProducerRevision() ||
			prov1[i].ContentDigest() != prov2[i].ContentDigest() ||
			prov1[i].Location() != prov2[i].Location() ||
			prov1[i].ObservedAt() != prov2[i].ObservedAt() {
			t.Fatalf("provenance mismatch at index %d: %+v vs %+v", i, prov1[i], prov2[i])
		}
	}
	// Verify sorted order: alpha, beta, gamma
	if prov1[0].ID() != "alpha" || prov1[1].ID() != "beta" || prov1[2].ID() != "gamma" {
		t.Fatalf("not sorted by byte order: %s, %s, %s", prov1[0].ID(), prov1[1].ID(), prov1[2].ID())
	}
	// Verify two parents ["z","a"] sorted to ["a","z"]
	alphaParents := prov1[0].ParentEvidenceIDs()
	if len(alphaParents) != 2 || alphaParents[0] != "a" || alphaParents[1] != "z" {
		t.Fatalf("expected parents [a, z], got %v", alphaParents)
	}
}

// 7. Copies: mutating input Evidence/ParentEvidenceIDs/Envelope after NormalizeAction,
// and mutating slices returned by the accessors, does not change later accessor results.
// Mutating Producer input after NewRegistry does not change derived trust.
func TestCopiesAndImmutability(t *testing.T) {
	// Mutating Producer input after NewRegistry
	prof1 := provTestProfile()
	prof2 := action.Profile{Protocol: "decision_api", ProfileID: "prof-2", AdapterRevision: provTestDigestA}
	producers := []action.Producer{
		{
			ProducerID:       "p-mut",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg, err := action.NewRegistry([]action.Profile{prof1, prof2}, []action.Route{provTestRoute()}, []action.Tool{provTestTool()}, producers)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}
	// Caller mutates producer slice: Trust, Origin, ProducerRevision, and Profiles
	producers[0].Trust = action.TrustUntrusted
	producers[0].Origin = action.OriginClient
	producers[0].ProducerRevision = provTestDigestB
	producers[0].Profiles[0] = "prof-2"
	producers[0].Profiles = append(producers[0].Profiles, "prof-extra")

	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	payload := []byte(`{"arg":"test"}`)
	inputParents := []string{"parent-1"}
	inputEv := []action.Evidence{
		{
			ID:                "ev-orig",
			ProducerID:        "p-mut",
			ContentDigest:     provTestDigestA,
			Location:          "/orig",
			ObservedAt:        provObservedAt,
			ParentEvidenceIDs: inputParents,
		},
	}
	inputEnv := defaultTestEnvelope

	act, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, inputEnv, inputEv)
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}

	// Verify profile binding was not changed by mutating input Profiles to prof-2:
	// A context on prof-2 must still reject evidence from p-mut with ErrSchema
	ctx2, err := reg.Context(action.ProposalFilter, "prof-2", "route-1")
	if err != nil {
		t.Fatalf("reg.Context(prof-2) failed: %v", err)
	}
	if _, err := action.NormalizeAction(ctx2, defaultTestActor, "tool-1", payload, inputEnv, inputEv); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema on prof-2 context because p-mut was registered for prof-1 only, got %v", err)
	}

	// Mutate input Evidence slice and fields
	inputEv[0].ID = "ev-mutated"
	inputEv[0].Location = "/mutated"
	inputParents[0] = "mutated-parent"

	// Verify act remains untouched
	te, ok := act.TrustedEnvelope()
	if !ok || te.ActionID != defaultTestEnvelopeActionID {
		t.Fatalf("unexpected TrustedEnvelope ActionID: got %q, want %q", te.ActionID, defaultTestEnvelopeActionID)
	}
	// Mutating a returned TrustedEnvelope copy cannot affect internal state; property is guaranteed by the sealed type.

	prov, ok := act.TrustedProvenance()
	if !ok || len(prov) != 1 {
		t.Fatalf("TrustedProvenance failed: ok=%v len=%d", ok, len(prov))
	}
	if prov[0].ID() != "ev-orig" || prov[0].Location() != "/orig" {
		t.Fatalf("mutating input Evidence affected TrustedProvenance: got ID=%q, Loc=%q", prov[0].ID(), prov[0].Location())
	}
	if prov[0].Trust() != action.TrustAuthenticatedSource || prov[0].Origin() != action.OriginTransport || prov[0].ProducerRevision() != provTestDigestA {
		t.Fatalf("mutating input Producer affected registered Trust/Origin/Revision: got Trust=%s Origin=%s Rev=%s", prov[0].Trust(), prov[0].Origin(), prov[0].ProducerRevision())
	}
	parentsRet := prov[0].ParentEvidenceIDs()
	if len(parentsRet) != 1 || parentsRet[0] != "parent-1" {
		t.Fatalf("mutating input ParentEvidenceIDs affected entry: got %v", parentsRet)
	}

	// Mutating slices returned by accessors
	prov[0] = action.ProvenanceEntry{}
	parentsRet[0] = "mutated-again"

	// Call accessors again and verify internal state remained unchanged
	prov2, ok := act.TrustedProvenance()
	if !ok || len(prov2) != 1 {
		t.Fatalf("second TrustedProvenance call failed")
	}
	if prov2[0].ID() != "ev-orig" {
		t.Fatalf("mutating slice returned by TrustedProvenance corrupted internal state: got ID=%q", prov2[0].ID())
	}
	parents2 := prov2[0].ParentEvidenceIDs()
	if len(parents2) != 1 || parents2[0] != "parent-1" {
		t.Fatalf("mutating slice returned by ParentEvidenceIDs corrupted internal state: got %v", parents2)
	}
}

// 8. Accessors absent for NormalizeRequest/NormalizePayload and after mutating Action.Payload;
// empty-evidence gives (non-nil empty, true).
func TestAccessorsAbsentAndEmptyEvidence(t *testing.T) {
	producers := []action.Producer{
		{
			ProducerID:       "p-1",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg := provTestRegistry(t, producers)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	payload := []byte(`{"arg":"test"}`)
	schema := action.Schema{
		Fields: map[string]action.FieldType{
			"arg": action.String,
		},
	}

	// NormalizeRequest: accessors return false / zero
	actReq, err := action.NormalizeRequest("tool.invoke", "tool-1", payload, schema)
	if err != nil {
		t.Fatalf("NormalizeRequest failed: %v", err)
	}
	if _, ok := actReq.TrustedEnvelope(); ok {
		t.Fatalf("expected TrustedEnvelope to be false for NormalizeRequest")
	}
	if p, ok := actReq.TrustedProvenance(); ok || p != nil {
		t.Fatalf("expected TrustedProvenance to be (nil, false) for NormalizeRequest, got (%v, %v)", p, ok)
	}

	// NormalizePayload: accessors return false / zero
	actPayload, err := action.NormalizePayload("tool.invoke", payload, schema)
	if err != nil {
		t.Fatalf("NormalizePayload failed: %v", err)
	}
	if _, ok := actPayload.TrustedEnvelope(); ok {
		t.Fatalf("expected TrustedEnvelope to be false for NormalizePayload")
	}
	if p, ok := actPayload.TrustedProvenance(); ok || p != nil {
		t.Fatalf("expected TrustedProvenance to be (nil, false) for NormalizePayload, got (%v, %v)", p, ok)
	}

	// After mutating Action.Payload: accessors return false / zero
	ev := action.Evidence{ID: "e-1", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt}
	act, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{ev})
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	act.Payload = []byte(`{"arg":"mutated"}`)
	if _, ok := act.TrustedEnvelope(); ok {
		t.Fatalf("expected TrustedEnvelope to be false after Payload mutation")
	}
	if p, ok := act.TrustedProvenance(); ok || p != nil {
		t.Fatalf("expected TrustedProvenance to be (nil, false) after Payload mutation, got (%v, %v)", p, ok)
	}

	// Empty evidence (nil): gives (non-nil empty slice, true)
	actNilEv, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, nil)
	if err != nil {
		t.Fatalf("NormalizeAction nil evidence failed: %v", err)
	}
	provNil, ok := actNilEv.TrustedProvenance()
	if !ok || provNil == nil || len(provNil) != 0 {
		t.Fatalf("expected (non-nil empty slice, true) for nil evidence, got (%v, %v, len=%d)", provNil, ok, len(provNil))
	}

	// Empty evidence ([]action.Evidence{}): gives (non-nil empty slice, true)
	actEmptyEv, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{})
	if err != nil {
		t.Fatalf("NormalizeAction empty slice evidence failed: %v", err)
	}
	provEmpty, ok := actEmptyEv.TrustedProvenance()
	if !ok || provEmpty == nil || len(provEmpty) != 0 {
		t.Fatalf("expected (non-nil empty slice, true) for empty slice evidence, got (%v, %v, len=%d)", provEmpty, ok, len(provEmpty))
	}
}

// 9. Digest unchanged: assert that NormalizeAction's digest equals NormalizeRequest's digest
// for the same op/resource/payload/schema, with and without evidence, and with two different envelopes.
func TestActionDigestUnchangedWithEvidenceAndEnvelopes(t *testing.T) {
	producers := []action.Producer{
		{
			ProducerID:       "p-1",
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginDetector,
			Trust:            action.TrustAuthenticatedSource,
		},
		{
			ProducerID:       "p-2",
			ProducerRevision: provTestDigestB,
			Profiles:         []string{"prof-1"},
			Origin:           action.OriginClient,
			Trust:            action.TrustAuthenticatedSource,
		},
	}
	reg := provTestRegistry(t, producers)
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}

	payload := []byte(`{"arg":"canonical-test"}`)
	schema := action.Schema{
		Fields: map[string]action.FieldType{
			"arg": action.String,
		},
	}

	actReq, err := action.NormalizeRequest("tool.invoke", "tool-1", payload, schema)
	if err != nil {
		t.Fatalf("NormalizeRequest failed: %v", err)
	}

	env1, err := action.NewEnvelope(fakeClock{now: time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)}, fakeIDSource{id: "act-envelope-1"}, "req-envelope-1", "", "", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewEnvelope env1 failed: %v", err)
	}
	env2, err := action.NewEnvelope(fakeClock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}, fakeIDSource{id: "act-envelope-2"}, "req-envelope-2", "parent-act-0", "idemp-custom-key", time.Minute)
	if err != nil {
		t.Fatalf("NewEnvelope env2 failed: %v", err)
	}

	evList := []action.Evidence{
		{
			ID:                "ev-1",
			ProducerID:        "p-1",
			ContentDigest:     provTestDigestA,
			Location:          "/arg",
			ObservedAt:        "2026-10-14T10:00:00.000Z",
			ParentEvidenceIDs: []string{"root-evidence"},
		},
		{
			ID:            "ev-2",
			ProducerID:    "p-2",
			ContentDigest: provTestDigestB,
			Location:      "",
			ObservedAt:    "2026-10-14T10:01:00.000Z",
		},
	}

	// 1. Without evidence, env1
	actNoEvEnv1, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env1, nil)
	if err != nil {
		t.Fatalf("NormalizeAction without evidence, env1 failed: %v", err)
	}
	if actReq.Digest != "" || actReq.Authorizable() {
		t.Fatalf("expected NormalizeRequest digest empty and Authorizable false")
	}
	if actNoEvEnv1.Digest == "" || !actNoEvEnv1.Authorizable() {
		t.Fatalf("expected NormalizeAction digest non-empty and Authorizable true")
	}

	// 2. Without evidence, env2: envelope invariance
	actNoEvEnv2, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env2, nil)
	if err != nil {
		t.Fatalf("NormalizeAction without evidence, env2 failed: %v", err)
	}
	if actNoEvEnv2.Digest != actNoEvEnv1.Digest {
		t.Fatalf("envelope invariance violated without evidence: %s vs %s", actNoEvEnv2.Digest, actNoEvEnv1.Digest)
	}

	// 3. With evidence, env1: evidence changes digest
	actEvEnv1, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env1, evList)
	if err != nil {
		t.Fatalf("NormalizeAction with evidence, env1 failed: %v", err)
	}
	if actEvEnv1.Digest == actNoEvEnv1.Digest {
		t.Fatalf("expected evidence to change action_digest in S6")
	}

	// 4. With evidence, env2: envelope invariance with evidence
	actEvEnv2, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, env2, evList)
	if err != nil {
		t.Fatalf("NormalizeAction with evidence, env2 failed: %v", err)
	}
	if actEvEnv2.Digest != actEvEnv1.Digest {
		t.Fatalf("envelope invariance violated with evidence: %s vs %s", actEvEnv2.Digest, actEvEnv1.Digest)
	}
}

func TestProducerProfileBinding(t *testing.T) {
	p1 := action.Profile{Protocol: "decision_api", ProfileID: "prof-1", AdapterRevision: provTestDigestA}
	p2 := action.Profile{Protocol: "decision_api", ProfileID: "prof-2", AdapterRevision: provTestDigestA}
	route1 := provTestRoute()
	route2 := provTestRoute()
	route2.RouteID = "route-2"
	tools := []action.Tool{provTestTool()}

	// Producer bound to prof-1 only
	producerP1 := action.Producer{
		ProducerID:       "prod-p1",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{"prof-1"},
		Origin:           action.OriginTransport,
		Trust:            action.TrustAuthenticatedSource,
	}

	reg, err := action.NewRegistry([]action.Profile{p1, p2}, []action.Route{route1, route2}, tools, []action.Producer{producerP1})
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	// Context on prof-1: Evidence from prod-p1 succeeds
	ctxP1, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context(prof-1) failed: %v", err)
	}
	ev := action.Evidence{
		ID:            "ev-1",
		ProducerID:    "prod-p1",
		ContentDigest: provTestDigestA,
		Location:      "/a",
		ObservedAt:    provObservedAt,
	}
	if _, err := action.NormalizeAction(ctxP1, defaultTestActor, "tool-1", []byte(`{"arg":"test"}`), defaultTestEnvelope, []action.Evidence{ev}); err != nil {
		t.Fatalf("expected evidence for bound profile prof-1 to succeed, got %v", err)
	}

	// Context on prof-2: Evidence from prod-p1 must fail with ErrSchema
	ctxP2, err := reg.Context(action.ProposalFilter, "prof-2", "route-1")
	if err != nil {
		t.Fatalf("reg.Context(prof-2) failed: %v", err)
	}
	if _, err := action.NormalizeAction(ctxP2, defaultTestActor, "tool-1", []byte(`{"arg":"test"}`), defaultTestEnvelope, []action.Evidence{ev}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for producer evidence on unbound profile prof-2, got %v", err)
	}

	// Producer with empty Profiles -> ErrSchema
	prodEmptyProfiles := action.Producer{
		ProducerID:       "p-empty",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{},
		Origin:           action.OriginTransport,
		Trust:            action.TrustAuthenticatedSource,
	}
	if _, err := action.NewRegistry([]action.Profile{p1}, []action.Route{route1}, tools, []action.Producer{prodEmptyProfiles}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for empty Profiles, got %v", err)
	}

	// Producer with unregistered profile -> ErrSchema
	prodUnregProfile := action.Producer{
		ProducerID:       "p-unreg",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{"prof-unregistered"},
		Origin:           action.OriginTransport,
		Trust:            action.TrustAuthenticatedSource,
	}
	if _, err := action.NewRegistry([]action.Profile{p1}, []action.Route{route1}, tools, []action.Producer{prodUnregProfile}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for unregistered profile, got %v", err)
	}

	// Producer with duplicate profile -> ErrSchema
	prodDupProfile := action.Producer{
		ProducerID:       "p-dup-prof",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{"prof-1", "prof-1"},
		Origin:           action.OriginTransport,
		Trust:            action.TrustAuthenticatedSource,
	}
	if _, err := action.NewRegistry([]action.Profile{p1}, []action.Route{route1}, tools, []action.Producer{prodDupProfile}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for duplicate profile in Profiles, got %v", err)
	}
}

func TestEvidenceParentOrderingAndCycles(t *testing.T) {
	prod := action.Producer{
		ProducerID:       "p-1",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{"prof-1"},
		Origin:           action.OriginDetector,
		Trust:            action.TrustAuthenticatedSource,
	}
	reg := provTestRegistry(t, []action.Producer{prod})
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}
	payload := []byte(`{"arg":"test"}`)

	// Parent order: input ["z", "a"] -> ParentEvidenceIDs() == ["a", "z"]
	evUnsortedParents := action.Evidence{
		ID:                "ev-test",
		ProducerID:        "p-1",
		ContentDigest:     provTestDigestA,
		Location:          "/test",
		ObservedAt:        provObservedAt,
		ParentEvidenceIDs: []string{"z", "a"},
	}
	act, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{evUnsortedParents})
	if err != nil {
		t.Fatalf("NormalizeAction failed: %v", err)
	}
	prov, ok := act.TrustedProvenance()
	if !ok || len(prov) != 1 {
		t.Fatalf("TrustedProvenance failed: ok=%v len=%d", ok, len(prov))
	}
	pids := prov[0].ParentEvidenceIDs()
	if len(pids) != 2 || pids[0] != "a" || pids[1] != "z" {
		t.Fatalf("expected parent evidence IDs sorted byte order [a, z], got %v", pids)
	}

	// Cycles: A->B, B->A rejected
	evA := action.Evidence{ID: "A", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"B"}}
	evB := action.Evidence{ID: "B", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/b", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"A"}}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{evA, evB}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for cycle A->B, B->A, got %v", err)
	}

	// Cycles: A->B, B->C, C->A rejected
	ev3A := action.Evidence{ID: "A", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"B"}}
	ev3B := action.Evidence{ID: "B", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/b", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"C"}}
	ev3C := action.Evidence{ID: "C", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/c", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"A"}}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{ev3A, ev3B, ev3C}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for 3-node cycle A->B, B->C, C->A, got %v", err)
	}

	// A->B, B->C ok (DAG)
	evDagA := action.Evidence{ID: "A", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"B"}}
	evDagB := action.Evidence{ID: "B", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/b", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"C"}}
	evDagC := action.Evidence{ID: "C", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/c", ObservedAt: provObservedAt, ParentEvidenceIDs: nil}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{evDagA, evDagB, evDagC}); err != nil {
		t.Fatalf("expected valid DAG A->B, B->C to succeed, got %v", err)
	}

	// A->outside ok
	evOutside := action.Evidence{ID: "A", ProducerID: "p-1", ContentDigest: provTestDigestA, Location: "/a", ObservedAt: provObservedAt, ParentEvidenceIDs: []string{"outside-id"}}
	if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{evOutside}); err != nil {
		t.Fatalf("expected parent outside set to succeed, got %v", err)
	}
}

func TestLocationRuneRestrictions(t *testing.T) {
	prod := action.Producer{
		ProducerID:       "p-1",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{"prof-1"},
		Origin:           action.OriginDetector,
		Trust:            action.TrustAuthenticatedSource,
	}
	reg := provTestRegistry(t, []action.Producer{prod})
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}
	payload := []byte(`{"arg":"test"}`)

	badLocations := []string{
		"/path/\u202Etest", // bidi override (U+202E)
		"/path/\u200Btest", // zero-width space (U+200B)
		"/path/\u0085test", // C1 control NEXT LINE (U+0085)
		"/path/\uFEFFtest", // BOM (U+FEFF)
	}
	for _, badLoc := range badLocations {
		ev := action.Evidence{
			ID:            "ev-bad-loc",
			ProducerID:    "p-1",
			ContentDigest: provTestDigestA,
			Location:      badLoc,
			ObservedAt:    provObservedAt,
		}
		if _, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{ev}); !errors.Is(err, action.ErrSchema) {
			t.Fatalf("expected ErrSchema for location containing restricted rune %q, got %v", badLoc, err)
		}
	}
}

func TestEvidenceLocationRangeEdges(t *testing.T) {
	prod := action.Producer{
		ProducerID:       "p-1",
		ProducerRevision: provTestDigestA,
		Profiles:         []string{"prof-1"},
		Origin:           action.OriginDetector,
		Trust:            action.TrustAuthenticatedSource,
	}
	reg := provTestRegistry(t, []action.Producer{prod})
	ctx, err := reg.Context(action.ProposalFilter, "prof-1", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}
	payload := []byte(`{"arg":"test"}`)

	tests := []struct {
		name     string
		location string
		wantErr  bool
	}{
		// Range edges rejected
		{name: "rejected U+0080", location: "/a\u0080b", wantErr: true},
		{name: "rejected U+009F", location: "/a\u009fb", wantErr: true},
		{name: "rejected U+200B", location: "/a\u200bb", wantErr: true},
		{name: "rejected U+200F", location: "/a\u200fb", wantErr: true},
		{name: "rejected U+202A", location: "/a\u202ab", wantErr: true},
		{name: "rejected U+202E", location: "/a\u202eb", wantErr: true},
		{name: "rejected U+2066", location: "/a\u2066b", wantErr: true},
		{name: "rejected U+2069", location: "/a\u2069b", wantErr: true},
		{name: "rejected U+FEFF", location: "/a\ufeffb", wantErr: true},

		// Accepted locations
		{name: "accepted /é", location: "/é", wantErr: false},
		{name: "accepted /a\\u00a0b (U+00A0)", location: "/a\u00a0b", wantErr: false},
		{name: "accepted /a\\u2010b (U+2010)", location: "/a\u2010b", wantErr: false},
		{name: "accepted /a\\u2070b", location: "/a\u2070b", wantErr: false},
		{name: "accepted /日本", location: "/日本", wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := action.Evidence{
				ID:            "ev-loc-edge",
				ProducerID:    "p-1",
				ContentDigest: provTestDigestA,
				Location:      tc.location,
				ObservedAt:    provObservedAt,
			}
			act, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{ev})
			if tc.wantErr {
				if !errors.Is(err, action.ErrSchema) {
					t.Fatalf("expected ErrSchema for location %q, got %v", tc.location, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected location %q to succeed, got %v", tc.location, err)
				}
				prov, ok := act.TrustedProvenance()
				if !ok || len(prov) != 1 {
					t.Fatalf("expected 1 provenance entry for %q, got ok=%v prov=%v", tc.location, ok, prov)
				}
				if prov[0].Location() != tc.location {
					t.Fatalf("expected location %q, got %q", tc.location, prov[0].Location())
				}
			}
		})
	}
}

func TestBoundaryLimits(t *testing.T) {
	// Build 64 valid profiles: prof-00 to prof-63
	profiles64 := make([]action.Profile, 64)
	for i := 0; i < 64; i++ {
		profiles64[i] = action.Profile{
			Protocol:        "decision_api",
			ProfileID:       fmt.Sprintf("prof-%02d", i),
			AdapterRevision: provTestDigestA,
		}
	}
	route := provTestRoute()
	route.ResolutionProfile = "prof-00"
	tool := provTestTool()

	// 1. Exactly 64 producer profiles on a producer: accepted
	profList64 := make([]string, 64)
	for i := 0; i < 64; i++ {
		profList64[i] = fmt.Sprintf("prof-%02d", i)
	}
	prodWith64Profiles := action.Producer{
		ProducerID:       "p-limits-64",
		ProducerRevision: provTestDigestA,
		Profiles:         profList64,
		Origin:           action.OriginTransport,
		Trust:            action.TrustAuthenticatedSource,
	}

	// 2. Exactly 256 producers: accepted
	producers256 := make([]action.Producer, 256)
	producers256[0] = prodWith64Profiles
	for i := 1; i < 256; i++ {
		producers256[i] = action.Producer{
			ProducerID:       fmt.Sprintf("p-%03d", i),
			ProducerRevision: provTestDigestA,
			Profiles:         []string{"prof-00"},
			Origin:           action.OriginTransport,
			Trust:            action.TrustAuthenticatedSource,
		}
	}
	reg256, err := action.NewRegistry(profiles64, []action.Route{route}, []action.Tool{tool}, producers256)
	if err != nil {
		t.Fatalf("expected 256 producers and 64 profiles to succeed, got %v", err)
	}

	// 3. Reject 65 producer profiles: ErrSchema.
	// The 64-profile cap on a producer is defence in depth and unreachable because registries hold
	// at most 64 unique profiles; rejection comes from the unregistered 65th entry. Keep the assertion.
	profList65 := make([]string, 65)
	for i := 0; i < 64; i++ {
		profList65[i] = fmt.Sprintf("prof-%02d", i)
	}
	profList65[64] = "prof-64" // unregistered entry (defence-in-depth cap unreachable; registries hold at most 64 unique profiles)
	prodWith65Profiles := action.Producer{
		ProducerID:       "p-limits-65",
		ProducerRevision: provTestDigestA,
		Profiles:         profList65,
		Origin:           action.OriginTransport,
		Trust:            action.TrustAuthenticatedSource,
	}
	if _, err := action.NewRegistry(profiles64, []action.Route{route}, []action.Tool{tool}, []action.Producer{prodWith65Profiles}); !errors.Is(err, action.ErrSchema) {
		t.Fatalf("expected ErrSchema for producer with 65 profiles, got %v", err)
	}

	// Context on prof-00
	ctx, err := reg256.Context(action.ProposalFilter, "prof-00", "route-1")
	if err != nil {
		t.Fatalf("reg.Context failed: %v", err)
	}
	payload := []byte(`{"arg":"test"}`)

	// 4. Exactly 64 evidence entries: accepted
	ev64 := make([]action.Evidence, 64)
	for i := 0; i < 64; i++ {
		ev64[i] = action.Evidence{
			ID:            fmt.Sprintf("ev-%02d", i),
			ProducerID:    "p-limits-64",
			ContentDigest: provTestDigestA,
			Location:      fmt.Sprintf("/loc/%02d", i),
			ObservedAt:    provObservedAt,
		}
	}
	act64, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, ev64)
	if err != nil {
		t.Fatalf("expected exactly 64 evidence entries to succeed, got %v", err)
	}
	prov64, ok := act64.TrustedProvenance()
	if !ok || len(prov64) != 64 {
		t.Fatalf("expected TrustedProvenance with 64 entries, got ok=%v len=%d", ok, len(prov64))
	}

	// 5. Exactly 8 parents: accepted
	parents8 := make([]string, 8)
	for i := 0; i < 8; i++ {
		parents8[i] = fmt.Sprintf("ext-parent-%d", i)
	}
	evWith8Parents := action.Evidence{
		ID:                "ev-8-parents",
		ProducerID:        "p-limits-64",
		ContentDigest:     provTestDigestA,
		Location:          "/parents8",
		ObservedAt:        provObservedAt,
		ParentEvidenceIDs: parents8,
	}
	act8, err := action.NormalizeAction(ctx, defaultTestActor, "tool-1", payload, defaultTestEnvelope, []action.Evidence{evWith8Parents})
	if err != nil {
		t.Fatalf("expected exactly 8 parents to succeed, got %v", err)
	}
	prov8, ok := act8.TrustedProvenance()
	if !ok || len(prov8) != 1 || len(prov8[0].ParentEvidenceIDs()) != 8 {
		t.Fatalf("expected entry with 8 parents, got ok=%v prov=%+v", ok, prov8)
	}
}
