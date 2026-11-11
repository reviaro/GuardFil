package messages

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reviaro/guardfil/internal/broker/boundary"
	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/egress"
)

const (
	Provider              = "anthropic"
	Model                 = "claude-sonnet-5-5"
	Host                  = "api.anthropic.com"
	AnthropicVersion      = "2023-06-01"
	CacheWriteFactor      = 2
	InputMarginTokens     = 512
	MaxSessionRequests    = 64
	DefaultMaxRequests    = 24
	MaxFrameBytes         = 4 << 20 // 4 MiB
	ProviderCeilingMicros = budget.GlobalCeilingMicros
	ProviderTimeoutSec    = 150 * time.Second
)

var (
	AllowedFields = map[string]bool{
		"model": true, "messages": true, "system": true, "max_tokens": true, "metadata": true,
		"stop_sequences": true, "stream": true, "temperature": true, "top_p": true, "top_k": true,
		"tools": true, "tool_choice": true, "thinking": true,
	}
	StrippedFields = map[string]bool{
		"context_management": true, "output_config": true,
	}
	CountFields  = []string{"model", "messages", "system", "tools", "tool_choice"}
	ContentTypes = map[string]bool{
		"text": true, "image": true, "document": true, "tool_use": true, "tool_result": true,
		"thinking": true, "redacted_thinking": true,
	}
	ToolChoiceTypes = map[string]bool{
		"auto": true, "any": true, "tool": true, "none": true,
	}
	RetryStatuses = map[int]bool{
		429: true, 500: true, 502: true, 503: true, 504: true, 529: true,
	}
	UnbilledStatuses = map[int]bool{
		400: true, 401: true, 403: true, 404: true, 413: true, 422: true, 429: true,
		500: true, 502: true, 503: true, 504: true, 529: true,
	}
	RetryDelays = []time.Duration{
		5 * time.Second, 15 * time.Second, 30 * time.Second, 65 * time.Second,
	}
)

type RefusedError struct {
	Msg string
}

func (e RefusedError) Error() string {
	return e.Msg
}

func makeErrorPayload(status int, kind string, message string) (int, []byte) {
	errObj := map[string]any{
		"type": "error",
		"error": map[string]string{
			"type":    kind,
			"message": "GuardFil broker: " + message,
		},
	}
	payload, _ := json.Marshal(errObj)
	return status, payload
}

// CheckRequest validates inbound request against allowlist and boundaries.
func CheckRequest(req map[string]any) (map[string]any, error) {
	if req == nil {
		return nil, RefusedError{Msg: "the body must be a JSON object"}
	}
	if err := boundary.RemoteInputError(req); err != nil {
		return nil, RefusedError{Msg: err.Error()}
	}

	var extra []string
	for k := range req {
		if !AllowedFields[k] && !StrippedFields[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		return nil, RefusedError{Msg: fmt.Sprintf("field(s) not allowed: %s", strings.Join(extra, ", "))}
	}

	modelVal, _ := req["model"].(string)
	if !budget.AllowedModel("anthropic", modelVal) {
		return nil, RefusedError{Msg: budget.NotAllowedMessage("anthropic", modelVal)}
	}

	rawMsgs, ok := req["messages"].([]any)
	if !ok || len(rawMsgs) == 0 {
		return nil, RefusedError{Msg: "messages must be a non-empty list"}
	}

	var cleanedMsgs []map[string]any
	for _, mVal := range rawMsgs {
		m, ok := mVal.(map[string]any)
		if !ok {
			return nil, RefusedError{Msg: "each message must be an object"}
		}
		role, _ := m["role"].(string)
		if role != "user" && role != "assistant" && role != "system" {
			return nil, RefusedError{Msg: "each message needs role user, assistant or system"}
		}
		content := m["content"]
		if role == "system" {
			if cList, ok := content.([]any); ok {
				for _, bVal := range cList {
					bMap, ok := bVal.(map[string]any)
					if !ok || bMap["type"] != "text" {
						return nil, RefusedError{Msg: "a system message may hold only text"}
					}
				}
			}
		}
		if cList, ok := content.([]any); ok {
			for _, bVal := range cList {
				bMap, ok := bVal.(map[string]any)
				if !ok {
					return nil, RefusedError{Msg: "content block is not an object"}
				}
				bType, _ := bMap["type"].(string)
				if !ContentTypes[bType] {
					return nil, RefusedError{Msg: fmt.Sprintf("content block type %q is not allowed", bType)}
				}
			}
		} else if _, ok := content.(string); !ok {
			return nil, RefusedError{Msg: "message content must be text or a list of blocks"}
		}

		cleanedMsgs = append(cleanedMsgs, map[string]any{
			"role":    role,
			"content": content,
		})
	}

	if toolsVal, exists := req["tools"]; exists && toolsVal != nil {
		toolsList, ok := toolsVal.([]any)
		if !ok {
			return nil, RefusedError{Msg: "tools must be a list"}
		}
		for _, tVal := range toolsList {
			tMap, ok := tVal.(map[string]any)
			if !ok {
				return nil, RefusedError{Msg: "each tool must be an object"}
			}
			tType, _ := tMap["type"].(string)
			if tType == "" {
				tType = "custom"
			}
			if tType != "custom" || tMap["input_schema"] == nil {
				return nil, RefusedError{Msg: fmt.Sprintf("only client tools are allowed; provider-side tool %q refused", tType)}
			}
		}
	}

	if tcVal, exists := req["tool_choice"]; exists && tcVal != nil {
		tcMap, ok := tcVal.(map[string]any)
		if !ok {
			return nil, RefusedError{Msg: "tool_choice type not allowed"}
		}
		tcType, _ := tcMap["type"].(string)
		if !ToolChoiceTypes[tcType] {
			return nil, RefusedError{Msg: "tool_choice type not allowed"}
		}
	}

	out := make(map[string]any)
	for k, v := range req {
		if !StrippedFields[k] {
			out[k] = v
		}
	}
	out["messages"] = cleanedMsgs
	delete(out, "thinking")
	delete(out, "stream")

	mt := toInt(out["max_tokens"])
	if mt < 1 {
		return nil, RefusedError{Msg: "max_tokens must be a positive integer"}
	}
	if mt > budget.MaxOutputTokens {
		mt = budget.MaxOutputTokens
	}
	out["max_tokens"] = mt
	return out, nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

// BillableInput calculates the input tokens as the ledger counts them.
func BillableInput(usage map[string]any) (int, error) {
	n := func(k string) int {
		return toInt(usage[k])
	}
	writes := CacheWriteFactor * n("cache_creation_input_tokens")
	if split, ok := usage["cache_creation"].(map[string]any); ok {
		m5 := toInt(split["ephemeral_5m_input_tokens"])
		h1 := toInt(split["ephemeral_1h_input_tokens"])
		if m5 >= 0 && h1 >= 0 && m5+h1 == n("cache_creation_input_tokens") {
			writes = int(math.Ceil(float64(m5)*5.0/4.0)) + 2*h1
		}
	}
	cacheRead := n("cache_read_input_tokens")
	readTokens := int(math.Ceil(float64(cacheRead) / 10.0))
	return n("input_tokens") + writes + readTokens, nil
}

// Reservation calculates the worst case reservation amount for the built-in model.
func Reservation(countedInput int, maxTokens int) int {
	return ReservationForModel(Model, countedInput, maxTokens)
}

// ReservationForModel calculates the worst case reservation amount for model.
func ReservationForModel(model string, countedInput int, maxTokens int) int {
	rate := budget.ModelRates[model]
	rin := rate.InputRateMicros
	rout := rate.OutputRateMicros
	amount := (CacheWriteFactor*countedInput+InputMarginTokens)*rin + maxTokens*rout
	if amount < budget.MinReservationMicros {
		return budget.MinReservationMicros
	}
	return amount
}

// SSE reconstructs the event stream that Anthropic would have sent for a complete message.
func SSE(msg map[string]any) []byte {
	ev := func(name string, data any) string {
		enc, _ := json.Marshal(data)
		return fmt.Sprintf("event: %s\ndata: %s\n\n", name, string(enc))
	}

	var parts []string
	usage := make(map[string]any)
	if u, ok := msg["usage"].(map[string]any); ok {
		for k, v := range u {
			usage[k] = v
		}
	}

	start := make(map[string]any)
	for k, v := range msg {
		if k != "content" && k != "stop_reason" && k != "stop_sequence" {
			start[k] = v
		}
	}
	start["content"] = []any{}
	start["stop_reason"] = nil
	start["stop_sequence"] = nil
	startUsage := make(map[string]any)
	for k, v := range usage {
		startUsage[k] = v
	}
	startUsage["output_tokens"] = 1
	start["usage"] = startUsage

	parts = append(parts, ev("message_start", map[string]any{
		"type":    "message_start",
		"message": start,
	}))

	if content, ok := msg["content"].([]any); ok {
		for i, bVal := range content {
			b, ok := bVal.(map[string]any)
			if !ok {
				continue
			}
			t, _ := b["type"].(string)
			var first, delta any
			if t == "text" {
				txt, _ := b["text"].(string)
				first = map[string]any{"type": "text", "text": ""}
				delta = map[string]any{"type": "text_delta", "text": txt}
			} else if t == "tool_use" {
				first = map[string]any{
					"type":  "tool_use",
					"id":    b["id"],
					"name":  b["name"],
					"input": map[string]any{},
				}
				argsEnc, _ := json.Marshal(b["input"])
				delta = map[string]any{
					"type":         "input_json_delta",
					"partial_json": string(argsEnc),
				}
			} else {
				first = b
				delta = nil
			}
			parts = append(parts, ev("content_block_start", map[string]any{
				"type":          "content_block_start",
				"index":         i,
				"content_block": first,
			}))
			if delta != nil {
				parts = append(parts, ev("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": i,
					"delta": delta,
				}))
			}
			parts = append(parts, ev("content_block_stop", map[string]any{
				"type":  "content_block_stop",
				"index": i,
			}))
		}
	}

	parts = append(parts, ev("message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   msg["stop_reason"],
			"stop_sequence": msg["stop_sequence"],
		},
		"usage": map[string]any{
			"output_tokens": usage["output_tokens"],
		},
	}))
	parts = append(parts, ev("message_stop", map[string]any{
		"type": "message_stop",
	}))

	return []byte(strings.Join(parts, ""))
}

type TransportFunc func(path string, headers map[string]string, body []byte) (int, []byte, error)

func DefaultHTTPSTransport(apiKey string) TransportFunc {
	client := &http.Client{Timeout: ProviderTimeoutSec}
	return func(path string, headers map[string]string, body []byte) (int, []byte, error) {
		req, err := http.NewRequest(http.MethodPost, "https://"+Host+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", AnthropicVersion)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		rbody, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, nil, err
		}
		return resp.StatusCode, rbody, nil
	}
}

type MessagesBrokerServer struct {
	CloudGuard    egress.Guard // configured by the host before serving
	ledger        *budget.BudgetLedger
	key           string
	label         string
	maxRequests   int
	transport     TransportFunc
	priorMicros   int
	evidencePath  string
	count         int
	stopped       bool
	busy          bool
	stopRequested bool
	mu            sync.Mutex
	sleepFn       func(time.Duration)
}

func NewMessagesBrokerServer(
	ledger *budget.BudgetLedger,
	key string,
	label string,
	maxRequests int,
	transport TransportFunc,
	priorMicros int,
	evidencePath string,
) (*MessagesBrokerServer, error) {
	if maxRequests < 1 || maxRequests > MaxSessionRequests {
		return nil, errors.New("max_requests out of range")
	}
	if transport == nil {
		transport = DefaultHTTPSTransport(key)
	}
	s := &MessagesBrokerServer{
		ledger:       ledger,
		key:          key,
		label:        label,
		maxRequests:  maxRequests,
		transport:    transport,
		priorMicros:  priorMicros,
		evidencePath: evidencePath,
		sleepFn:      time.Sleep,
	}
	s.transport = func(path string, headers map[string]string, body []byte) (int, []byte, error) {
		if err := s.CloudGuard.Check(); err != nil {
			return http.StatusForbidden, egress.ErrorBody(err), nil
		}
		return transport(path, headers, body)
	}
	return s, nil
}

func (s *MessagesBrokerServer) sendWithRetries(path string, headers map[string]string, body []byte) (int, []byte, error) {
	status, rbody, err := s.transport(path, headers, body)
	if err != nil {
		return status, rbody, err
	}
	for _, delay := range RetryDelays {
		if !RetryStatuses[status] {
			break
		}
		s.sleepFn(delay)
		status, rbody, err = s.transport(path, headers, body)
		if err != nil {
			return status, rbody, err
		}
	}
	return status, rbody, nil
}

func (s *MessagesBrokerServer) HandleFrame(raw []byte) (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return makeErrorPayload(http.StatusServiceUnavailable, "api_error", "stopped after a ledger or provider failure")
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var rawReq map[string]any
	if err := d.Decode(&rawReq); err != nil {
		return makeErrorPayload(http.StatusBadRequest, "invalid_request_error", "the body must be a JSON object")
	}

	wantsStream := rawReq["stream"] == true
	out, err := CheckRequest(rawReq)
	if err != nil {
		return makeErrorPayload(http.StatusBadRequest, "invalid_request_error", err.Error())
	}
	model, _ := out["model"].(string) // checked by CheckRequest: built in or on the owner's list
	if err := s.CloudGuard.Check(); err != nil {
		return http.StatusForbidden, egress.ErrorBody(err)
	}

	if s.count >= s.maxRequests {
		return makeErrorPayload(http.StatusTooManyRequests, "rate_limit_error", "this session's request limit is reached")
	}

	outBody, _ := json.Marshal(out)
	h := sha256.Sum256(outBody)
	digest := "sha256:" + hex.EncodeToString(h[:])

	countObj := make(map[string]any)
	for _, k := range CountFields {
		if v, ok := out[k]; ok {
			countObj[k] = v
		}
	}
	countBody, _ := json.Marshal(countObj)

	status, cbody, err := s.transport("/v1/messages/count_tokens", nil, countBody)
	if err != nil {
		return makeErrorPayload(http.StatusBadGateway, "api_error", "Anthropic unreachable (count_tokens; nothing was spent)")
	}
	if status != 200 {
		return status, cbody
	}

	var countReply map[string]any
	if err := json.Unmarshal(cbody, &countReply); err != nil || countReply["input_tokens"] == nil {
		return makeErrorPayload(http.StatusBadGateway, "api_error", "count_tokens reply unusable; nothing was spent")
	}
	countedInput := toInt(countReply["input_tokens"])

	amount := ReservationForModel(model, countedInput, toInt(out["max_tokens"]))
	if amount > budget.ReservationAmountMicros {
		return makeErrorPayload(http.StatusBadRequest, "invalid_request_error", "request too large for one reservation")
	}

	s.count++
	requestID := fmt.Sprintf("messages-%s-%d", s.label, s.count)

	st, err := s.ledger.GetStatus()
	over := false
	if err != nil || s.priorMicros+st.TotalEncumberedMicros+amount > ProviderCeilingMicros {
		over = true
	}
	if over {
		return makeErrorPayload(http.StatusTooManyRequests, "rate_limit_error", "Anthropic's $2 would be exceeded")
	}

	permit, err := s.ledger.Reserve(requestID, digest, amount)
	if err != nil {
		s.stopped = true
		return makeErrorPayload(http.StatusTooManyRequests, "rate_limit_error", "the $2 ledger refused the request")
	}

	status, rbody, err := s.sendWithRetries("/v1/messages", nil, outBody)
	if err != nil {
		_, _ = s.ledger.RecordFailure(permit, "REQUEST_TRANSPORT_FAILURE")
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", "Anthropic unreachable")
	}

	if status != 200 {
		if !UnbilledStatuses[status] {
			_, _ = s.ledger.RecordFailure(permit, "INVALID_RECEIPT_EVIDENCE")
			s.stopped = true
			return makeErrorPayload(http.StatusBadGateway, "api_error", fmt.Sprintf("unexpected Anthropic status %d", status))
		}
		zeroReceipt := &budget.Receipt{
			Status:        budget.TerminalStatusCompleted,
			ResponseID:    fmt.Sprintf("unbilled-%d-%s", status, requestID),
			RequestID:     requestID,
			RequestDigest: digest,
			Model:         model,
			ServiceTier:   budget.ModelRates[model].ServiceTier,
			InputTokens:   0,
			OutputTokens:  0,
			TotalTokens:   0,
		}
		if _, err := s.ledger.Settle(permit, zeroReceipt); err != nil {
			s.stopped = true
			return makeErrorPayload(http.StatusBadGateway, "api_error", "the ledger could not settle the request")
		}
		return status, rbody
	}

	d2 := json.NewDecoder(bytes.NewReader(rbody))
	d2.UseNumber()
	var msg map[string]any
	if err := d2.Decode(&msg); err != nil || msg["type"] != "message" {
		_, _ = s.ledger.RecordFailure(permit, "RECEIPT_SCHEMA_VIOLATION")
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", "Anthropic reply unusable")
	}

	msgID, ok := msg["id"].(string)
	if !ok || msgID == "" || strings.TrimSpace(msgID) == "" {
		_, _ = s.ledger.RecordFailure(permit, "INVALID_RESPONSE_ID")
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", "Anthropic reply unusable: missing or invalid id")
	}

	requestedModel, _ := out["model"].(string)
	replyModel, ok := msg["model"].(string)
	if !ok || replyModel != requestedModel {
		_, _ = s.ledger.RecordFailure(permit, "RECEIPT_MODEL_MISMATCH")
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", fmt.Sprintf("Anthropic reply model mismatch: got %q, expected %q", replyModel, requestedModel))
	}

	usage, _ := msg["usage"].(map[string]any)
	if usage == nil || usage["output_tokens"] == nil {
		_, _ = s.ledger.RecordFailure(permit, "RECEIPT_SCHEMA_VIOLATION")
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", "Anthropic reply unusable")
	}
	inTok, err := BillableInput(usage)
	if err != nil {
		_, _ = s.ledger.RecordFailure(permit, "RECEIPT_SCHEMA_VIOLATION")
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", "Anthropic reply unusable")
	}
	outTok := toInt(usage["output_tokens"])
	tier, _ := usage["service_tier"].(string)
	if tier == "" {
		tier = budget.ModelRates[model].ServiceTier
	}

	receipt := &budget.Receipt{
		Status:        budget.TerminalStatusCompleted,
		ResponseID:    msgID,
		RequestID:     requestID,
		RequestDigest: digest,
		Model:         model,
		ServiceTier:   tier,
		InputTokens:   inTok,
		OutputTokens:  outTok,
		TotalTokens:   inTok + outTok,
	}

	if _, err := s.ledger.Settle(permit, receipt); err != nil {
		s.stopped = true
		return makeErrorPayload(http.StatusBadGateway, "api_error", "the ledger could not settle the request")
	}

	if wantsStream {
		return 200, SSE(msg)
	}
	resBody, _ := json.Marshal(msg)
	return 200, resBody
}

func (s *MessagesBrokerServer) Serve(sockPath string) error {
	_ = os.Remove(sockPath)
	oldMask := syscall.Umask(0077)
	l, err := net.Listen("unix", sockPath)
	syscall.Umask(oldMask)
	if err != nil {
		return err
	}
	defer func() {
		_ = l.Close()
		_ = os.Remove(sockPath)
	}()

	fmt.Println("MESSAGES_BROKER_READY")
	_ = os.Stdout.Sync()

	for {
		conn, err := l.Accept()
		if err != nil {
			if s.stopRequested {
				break
			}
			return err
		}

		s.busy = true
		s.handleConn(conn)
		s.busy = false

		if s.stopRequested {
			break
		}
	}
	return nil
}

func (s *MessagesBrokerServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > MaxFrameBytes {
		st, body := makeErrorPayload(http.StatusRequestEntityTooLarge, "invalid_request_error", "request too large")
		s.writeReply(conn, st, body)
		return
	}

	reqBody := make([]byte, length)
	if _, err := io.ReadFull(conn, reqBody); err != nil {
		return
	}

	status, replyBody := s.HandleFrame(reqBody)
	_ = conn.SetDeadline(time.Now().Add(ProviderTimeoutSec))
	s.writeReply(conn, status, replyBody)
}

func (s *MessagesBrokerServer) writeReply(conn net.Conn, status int, body []byte) {
	var replyHdr [8]byte
	binary.BigEndian.PutUint32(replyHdr[0:4], uint32(status))
	binary.BigEndian.PutUint32(replyHdr[4:8], uint32(len(body)))
	_, _ = conn.Write(replyHdr[:])
	_, _ = conn.Write(body)
}

func (s *MessagesBrokerServer) RequestStop() {
	s.stopRequested = true
}

func RunMessagesBroker(sockdir string, label string, maxRequests int, evidencePath string) error {
	guard, err := egress.FromEnv()
	if err != nil {
		return err
	}
	if sockdir != "" {
		if err := os.MkdirAll(sockdir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(sockdir, 0700); err != nil {
			return err
		}
	}
	keyDir := filepath.Join(os.Getenv("HOME"), ".config/guardfil/credentials.d")
	keyFile := filepath.Join(keyDir, "anthropic-api-key")
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no Anthropic key at %s\n", keyFile)
		return err
	}
	key := strings.TrimSpace(string(keyData))

	stateRoot := filepath.Join(os.Getenv("HOME"), ".local/state/guardfil")
	ledgerRoot := filepath.Join(stateRoot, "anthropic-experiment")
	ledger, err := budget.OpenOrInitLedger(ledgerRoot, true, "guardfil-m4-anthropic")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open Anthropic ledger: %v\n", err)
		return err
	}
	defer ledger.Close()

	st, err := ledger.GetStatus()
	if err != nil || !st.CanReserve() {
		fmt.Fprintf(os.Stderr, "the Anthropic ledger cannot reserve\n")
		return errors.New("anthropic ledger cannot reserve")
	}

	srv, err := NewMessagesBrokerServer(ledger, key, label, maxRequests, nil, 0, evidencePath)
	if err != nil {
		return err
	}
	srv.CloudGuard = guard

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		srv.RequestStop()
	}()

	sockPath := filepath.Join(sockdir, "broker.sock")
	defer func() {
		st, _ := ledger.GetStatus()
		totalSpend := 0
		if st != nil {
			totalSpend = st.TotalSpendMicros
		}
		fmt.Printf("MESSAGES_BROKER_DONE requests=%d anthropic_total_micros=%d\n", srv.count, totalSpend)
	}()

	return srv.Serve(sockPath)
}
