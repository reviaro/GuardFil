package playground

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func parseCounters(text string) *CountersInfo {
	info := &CountersInfo{}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		val, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		switch parts[0] {
		case "guardfil_requests_total":
			info.Requests = val
		case "guardfil_rejections_total":
			info.Rejections = val
		case "guardfil_decision_allows_total":
			info.Allows = val
		case "guardfil_decision_authority_blocks_total":
			info.AuthorityBlocks = val
		case "guardfil_decision_policy_blocks_total":
			info.PolicyBlocks = val
		case "guardfil_decision_obligation_blocks_total":
			info.ObligationBlocks = val
		}
	}
	return info
}

func (p *Playground) catalogTools() []ToolInfo {
	names := make([]string, 0, len(p.tools))
	for name := range p.tools {
		names = append(names, name)
	}
	sort.Strings(names)

	tools := make([]ToolInfo, len(names))
	for i, name := range names {
		ft := p.tools[name]
		fields := make(map[string]string, len(ft.schema.Fields))
		for fname, ftype := range ft.schema.Fields {
			fields[fname] = string(ftype)
		}
		tools[i] = ToolInfo{
			Tool:       name,
			InRegistry: ft.inRegistry,
			Fields:     fields,
		}
	}
	return tools
}

func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if _, ok := v.(*struct{}); ok && errors.Is(err, io.EOF) {
			return true
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "bad request")
		return false
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "trailing data")
		return false
	}
	return true
}

// Handler returns the HTTP handler exposing the playground API and assets.
func (p *Playground) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(appJS)
	})

	mux.HandleFunc("/app.css", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(appCSS)
	})

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		p.mu.RLock()
		pi := PolicyInfo{
			Source:   p.current.policySource,
			Digest:   p.current.snapshot.Digest(),
			Revision: p.current.snapshot.Revision(),
		}
		p.mu.RUnlock()

		promText := p.counters.Prometheus()
		resp := StateResponse{
			Policy:       pi,
			Tools:        p.catalogTools(),
			Credentials:  []string{"valid", "expired", "unknown", "none"},
			Counters:     parseCounters(promText),
			CountersText: promText,
			History:      p.history.List(),
			ToolSet:      p.ToolSet(),
			ToolMap:      p.ToolMap(),
		}
		writeJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("/api/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Tool            string `json:"tool"`
			PayloadB64      []byte `json:"payload_b64"`
			Credential      string `json:"credential"`
			TTLMillis       int64  `json:"ttl_ms"`
			Cancelled       bool   `json:"cancelled"`
			ExpiredEnvelope bool   `json:"expired_envelope"`
		}
		if !decodeStrict(w, r, &req) {
			return
		}

		switch req.Credential {
		case "valid", "expired", "unknown", "none":
		default:
			writeError(w, http.StatusBadRequest, "invalid credential")
			return
		}

		if req.TTLMillis < 1 || req.TTLMillis > 60000 {
			writeError(w, http.StatusBadRequest, "invalid ttl_ms")
			return
		}

		result := p.Evaluate(r.Context(), Input{
			Tool:            req.Tool,
			Payload:         req.PayloadB64,
			Credential:      req.Credential,
			TTLMillis:       req.TTLMillis,
			Cancelled:       req.Cancelled,
			ExpiredEnvelope: req.ExpiredEnvelope,
		})
		writeJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Source string `json:"source"`
		}
		if !decodeStrict(w, r, &req) {
			return
		}

		info, err := p.SetPolicy([]byte(req.Source))
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, info)
	})

	mux.HandleFunc("/api/policy/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct{}
		if !decodeStrict(w, r, &req) {
			return
		}
		info, err := p.ResetPolicy()
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, info)
	})

	mux.HandleFunc("/api/fixtures", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct{}
		if !decodeStrict(w, r, &req) {
			return
		}
		rows, err := p.RunFixtures()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rows)
	})

	return hardeningMiddleware(mux)
}
