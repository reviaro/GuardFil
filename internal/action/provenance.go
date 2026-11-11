package action

import (
	"sort"
	"time"
	"unicode/utf8"

	"github.com/reviaro/guardfil/internal/source"
)

const timestampLayout = "2006-01-02T15:04:05.000Z"

// MaxRequestLifetime bounds the maximum lifetime of a request envelope.
const MaxRequestLifetime = 30 * time.Second

func validTimestamp(s string) bool {
	if len(s) != 24 || s[10] != 'T' || s[23] != 'Z' {
		return false
	}
	t, err := time.Parse(timestampLayout, s)
	if err != nil {
		return false
	}
	return t.Format(timestampLayout) == s
}

// Security / Protocol Notice: Every invalid envelope, producer, or evidence input maps
// to SCHEMA_INVALID (ErrSchema) deliberately in this slice; error-code projection is reviewed in S7.

func validLocation(loc string) bool {
	if len(loc) > 512 || !utf8.ValidString(loc) {
		return false
	}
	if !validRuneRestrictions(loc) {
		return false
	}
	if loc == "" {
		return true
	}
	if loc[0] != '/' {
		return false
	}
	for i := 0; i < len(loc); i++ {
		if loc[i] == '~' {
			if i+1 >= len(loc) {
				return false
			}
			next := loc[i+1]
			if next != '0' && next != '1' {
				return false
			}
			i++
		}
	}
	return true
}

// Envelope is the read-only projection of the runtime correlation envelope.
// Rule 5 excludes all envelope fields from action_digest binding: they are
// correlation only, never authority. ReceivedAt and DeadlineAt are minted by
// the runtime clock via NewEnvelope and are no longer caller-supplied.
// Read the envelope only via Action.TrustedEnvelope().
type Envelope struct {
	ActionID       string
	RequestID      string
	ParentActionID string
	ReceivedAt     string
	DeadlineAt     string
	IdempotencyKey string
}

// MintedEnvelope is the sealed runtime-minted envelope type carrying trusted
// timestamps and correlation identifiers. It can only be constructed via NewEnvelope.
type MintedEnvelope struct {
	env        Envelope
	receivedAt time.Time
	deadline   time.Time
	valid      bool
}

// NewEnvelope mints a sealed runtime correlation envelope using the provided
// clock and ID source.
func NewEnvelope(clock source.Clock, ids source.IDSource, requestID, parentActionID, idempotencyKey string, ttl time.Duration) (MintedEnvelope, error) {
	if clock == nil || ids == nil {
		return MintedEnvelope{}, ErrInternal
	}
	if !validGeneralID(requestID) {
		return MintedEnvelope{}, ErrSchema
	}
	actionID, err := ids.NewID()
	if err != nil {
		return MintedEnvelope{}, ErrInternal
	}
	if !validGeneralID(actionID) {
		return MintedEnvelope{}, ErrInternal
	}
	if parentActionID != "" {
		if !validGeneralID(parentActionID) || parentActionID == actionID {
			return MintedEnvelope{}, ErrSchema
		}
	}
	if idempotencyKey != "" {
		if !validGeneralID(idempotencyKey) {
			return MintedEnvelope{}, ErrSchema
		}
	}
	if ttl <= 0 {
		return MintedEnvelope{}, ErrSchema
	}
	if ttl > MaxRequestLifetime {
		ttl = MaxRequestLifetime
	}
	receivedAt := clock.Now()
	deadline := receivedAt.Add(ttl)
	deadline = deadline.Add(-time.Duration(deadline.Nanosecond() % int(time.Millisecond)))

	receivedAtStr := receivedAt.UTC().Format(timestampLayout)
	deadlineAtStr := deadline.UTC().Format(timestampLayout)

	if !validTimestamp(receivedAtStr) || !validTimestamp(deadlineAtStr) || deadlineAtStr < receivedAtStr {
		return MintedEnvelope{}, ErrInternal
	}

	return MintedEnvelope{
		env: Envelope{
			ActionID:       actionID,
			RequestID:      requestID,
			ParentActionID: parentActionID,
			ReceivedAt:     receivedAtStr,
			DeadlineAt:     deadlineAtStr,
			IdempotencyKey: idempotencyKey,
		},
		receivedAt: receivedAt,
		deadline:   deadline,
		valid:      true,
	}, nil
}

// Evidence is runtime-internal input representing observed evidence.
// Origin and Trust are assigned from the registered producer, never supplied here.
type Evidence struct {
	ID                string
	ProducerID        string
	ContentDigest     string
	Location          string
	ObservedAt        string
	ParentEvidenceIDs []string
}

// ProvenanceEntry is an immutable normalized evidence record.
// An empty provenance result means provenance is UNKNOWN, never clean;
// an entry without parents has unknown lineage.
type ProvenanceEntry struct {
	id                string
	origin            Origin
	trust             Trust
	producerID        string
	producerRevision  string
	contentDigest     string
	location          string
	observedAt        string
	parentEvidenceIDs []string
}

func (pe ProvenanceEntry) ID() string               { return pe.id }
func (pe ProvenanceEntry) Origin() Origin           { return pe.origin }
func (pe ProvenanceEntry) Trust() Trust             { return pe.trust }
func (pe ProvenanceEntry) ProducerID() string       { return pe.producerID }
func (pe ProvenanceEntry) ProducerRevision() string { return pe.producerRevision }
func (pe ProvenanceEntry) ContentDigest() string    { return pe.contentDigest }
func (pe ProvenanceEntry) Location() string         { return pe.location }
func (pe ProvenanceEntry) ObservedAt() string       { return pe.observedAt }
func (pe ProvenanceEntry) ParentEvidenceIDs() []string {
	if len(pe.parentEvidenceIDs) == 0 {
		return nil
	}
	cp := make([]string, len(pe.parentEvidenceIDs))
	copy(cp, pe.parentEvidenceIDs)
	return cp
}

// validateAndNormalizeEvidence validates an evidence set against registered producers and schema constraints,
// enforces profile binding, rejects parent cycles within the set, and applies both canonical orders:
//  1. Provenance entries are sorted in ascending byte order by Evidence ID.
//  2. Parent evidence IDs within each entry are sorted in ascending byte order.
//
// These canonical orders become binding rules in S6.
func validateAndNormalizeEvidence(reg *Registry, profileID string, evidence []Evidence) ([]ProvenanceEntry, error) {
	if len(evidence) > 64 {
		return nil, ErrLimit
	}
	if len(evidence) == 0 {
		return nil, nil
	}

	seenIDs := make(map[string]struct{}, len(evidence))
	entries := make([]ProvenanceEntry, len(evidence))

	for i, e := range evidence {
		if !validGeneralID(e.ID) {
			return nil, ErrSchema
		}
		if _, dup := seenIDs[e.ID]; dup {
			return nil, ErrSchema
		}
		seenIDs[e.ID] = struct{}{}

		prod, ok := reg.producers[e.ProducerID]
		if !ok {
			return nil, ErrSchema
		}
		if _, bound := prod.profiles[profileID]; !bound {
			return nil, ErrSchema
		}

		if !validDigest(e.ContentDigest) {
			return nil, ErrSchema
		}

		if !validTimestamp(e.ObservedAt) {
			return nil, ErrSchema
		}

		if !validLocation(e.Location) {
			return nil, ErrSchema
		}

		if len(e.ParentEvidenceIDs) > 8 {
			return nil, ErrLimit
		}
		var parentsCopy []string
		if len(e.ParentEvidenceIDs) > 0 {
			seenParents := make(map[string]struct{}, len(e.ParentEvidenceIDs))
			parentsCopy = make([]string, len(e.ParentEvidenceIDs))
			for j, pid := range e.ParentEvidenceIDs {
				if !validGeneralID(pid) {
					return nil, ErrSchema
				}
				if pid == e.ID {
					return nil, ErrSchema
				}
				if _, dup := seenParents[pid]; dup {
					return nil, ErrSchema
				}
				seenParents[pid] = struct{}{}
				parentsCopy[j] = pid
			}
			sort.Strings(parentsCopy)
		}

		entries[i] = ProvenanceEntry{
			id:                e.ID,
			origin:            prod.origin,
			trust:             prod.trust,
			producerID:        prod.producerID,
			producerRevision:  prod.producerRevision,
			contentDigest:     e.ContentDigest,
			location:          e.Location,
			observedAt:        e.ObservedAt,
			parentEvidenceIDs: parentsCopy,
		}
	}

	// Reject any cycle among parents referencing IDs inside the same evidence set (DFS over <=64 nodes).
	// Parents outside the set remain allowed (missing lineage = unknown).
	adj := make(map[string][]string, len(entries))
	for i := range entries {
		var internalParents []string
		for _, pid := range entries[i].parentEvidenceIDs {
			if _, inSet := seenIDs[pid]; inSet {
				internalParents = append(internalParents, pid)
			}
		}
		adj[entries[i].id] = internalParents
	}

	const (
		nodeUnvisited = 0
		nodeVisiting  = 1
		nodeVisited   = 2
	)
	state := make(map[string]int, len(entries))
	var hasCycle func(curr string) bool
	hasCycle = func(curr string) bool {
		state[curr] = nodeVisiting
		for _, next := range adj[curr] {
			if state[next] == nodeVisiting {
				return true
			}
			if state[next] == nodeUnvisited {
				if hasCycle(next) {
					return true
				}
			}
		}
		state[curr] = nodeVisited
		return false
	}

	for i := range entries {
		if state[entries[i].id] == nodeUnvisited {
			if hasCycle(entries[i].id) {
				return nil, ErrSchema
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].id < entries[j].id
	})

	return entries, nil
}
