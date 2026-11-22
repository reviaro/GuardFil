package responses

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reviaro/guardfil/internal/broker/boundary"
	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/egress"
)

const (
	PinnedModel                  = "gpt-6-luna"
	PinnedServiceTier            = "default"
	DefaultMaxOutputTokens       = 1024
	MinOutputTokens              = 16
	MaxOutputTokens              = 1024
	MaxRequestFrameBytes         = 4 * 1024 * 1024  // 4 MiB
	MaxStreamResponseBytes       = 16 * 1024 * 1024 // 16 MiB
	StreamDeadlineSec            = 120 * time.Second
	PreflightDeadlineSec         = 30 * time.Second
	PreflightMaxBytes            = 64 * 1024
	PreflightMaxInputTokens      = 150_000
	ReservationInputMarginTokens = 4096
	MaxSessionRequests           = 64
	DefaultMaxRequests           = 3
	EvidenceFilePrefix           = "live-broker-"
)

var (
	caseLabelRegex       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	safeDiagResponseIDRe = regexp.MustCompile(`^resp[_-][A-Za-z0-9_-]{1,96}$`)

	allowedUpstreamErrorTypes = map[string]bool{
		"invalid_request_error": true,
		"authentication_error":  true,
		"permission_error":      true,
		"not_found_error":       true,
		"rate_limit_error":      true,
		"server_error":          true,
		"api_error":             true,
		"overloaded_error":      true,
		"timeout_error":         true,
		"tokens":                true,
		"requests":              true,
		"insufficient_quota":    true,
		"billing_error":         true,
		"content_filter":        true,
	}

	allowedUpstreamErrorCodes = map[string]bool{
		"server_error":                true,
		"internal_error":              true,
		"rate_limit_exceeded":         true,
		"insufficient_quota":          true,
		"invalid_api_key":             true,
		"model_not_found":             true,
		"context_length_exceeded":     true,
		"max_tokens":                  true,
		"invalid_request_error":       true,
		"invalid_value":               true,
		"missing_required_parameter":  true,
		"unsupported_parameter":       true,
		"content_policy_violation":    true,
		"content_filter":              true,
		"service_unavailable":         true,
		"timeout":                     true,
		"stream_error":                true,
		"response_failed":             true,
		"vector_store_timeout":        true,
		"image_parse_error":           true,
		"previous_response_not_found": true,
		"billing_hard_limit_reached":  true,
		"account_deactivated":         true,
		"invalid_encrypted_content":   true,
	}

	allowedServiceTiers = map[string]bool{
		"default":  true,
		"standard": true,
		"auto":     true,
		"flex":     true,
		"priority": true,
		"scale":    true,
	}

	forbiddenHostedToolExact = map[string]bool{
		"file_search": true, "code_interpreter": true, "image_generation": true, "mcp": true,
	}
	forbiddenHostedToolPrefixes = []string{"web_search", "computer_use"}
	forbiddenSSEEvents          = map[string]bool{
		"response.failed": true, "error": true,
	}
	preflightKeys = map[string]bool{
		"model": true, "input": true, "instructions": true, "tools": true,
		"tool_choice": true, "parallel_tool_calls": true, "reasoning": true,
		"text": true, "truncation": true, "previous_response_id": true, "conversation": true,
	}
)

type ValidationResult struct {
	OutboundBytes           []byte
	Digest                  string
	InsertedFields          []string
	ToolTypeNames           []string
	OutboundMaxOutputTokens int
	ErrorReason             string
	// Model is the requested model: the built-in one or one from the owner's model list.
	Model string
}

func isForbiddenHostedToolType(t string) bool {
	if forbiddenHostedToolExact[t] {
		return true
	}
	for _, prefix := range forbiddenHostedToolPrefixes {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

func collectAndValidateTools(toolsList any, seenTypes map[string]bool) string {
	tools, ok := toolsList.([]any)
	if !ok {
		return "tools must be a list"
	}
	for _, toolItem := range tools {
		tool, ok := toolItem.(map[string]any)
		if !ok {
			return "each tool must be an object"
		}
		tType, ok := tool["type"].(string)
		if !ok || strings.TrimSpace(tType) == "" {
			return "tool missing valid string type"
		}
		seenTypes[tType] = true
		if isForbiddenHostedToolType(tType) {
			return fmt.Sprintf("forbidden hosted tool type: %s", tType)
		}
		if tType != "function" && tType != "custom" && tType != "namespace" && tType != "local_shell" {
			return "only client-side tools are allowed"
		}
		if nested, ok := tool["tools"]; ok && nested != nil {
			if err := collectAndValidateTools(nested, seenTypes); err != "" {
				return err
			}
		}
	}
	return ""
}

func checkDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		isObject     bool
		expectingKey bool
		keys         map[string]bool
	}
	var stack []frame

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{isObject: true, expectingKey: true, keys: make(map[string]bool)})
			case '}':
				if len(stack) == 0 || !stack[len(stack)-1].isObject {
					return errors.New("unmatched '}'")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].isObject {
					stack[len(stack)-1].expectingKey = true
				}
			case '[':
				stack = append(stack, frame{isObject: false})
			case ']':
				if len(stack) == 0 || stack[len(stack)-1].isObject {
					return errors.New("unmatched ']'")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].isObject {
					stack[len(stack)-1].expectingKey = true
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].isObject {
				top := &stack[len(stack)-1]
				if top.expectingKey {
					if top.keys[t] {
						return fmt.Errorf("duplicate JSON key: %q", t)
					}
					top.keys[t] = true
					top.expectingKey = false
				} else {
					top.expectingKey = true
				}
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1].isObject {
				stack[len(stack)-1].expectingKey = true
			}
		}
	}
	return nil
}

// ValidateAndPrepareRequest validates inbound JSON body, inserts defaults, and returns outbound bytes and digest.
func ValidateAndPrepareRequest(rawBody []byte) ValidationResult {
	var res ValidationResult
	if len(rawBody) > MaxRequestFrameBytes {
		res.ErrorReason = "request exceeds 4 MiB limit"
		return res
	}

	if err := checkDuplicateJSONKeys(rawBody); err != nil {
		res.ErrorReason = err.Error()
		return res
	}

	d := json.NewDecoder(bytes.NewReader(rawBody))
	d.UseNumber()
	var obj map[string]any
	if err := d.Decode(&obj); err != nil {
		res.ErrorReason = "invalid JSON"
		return res
	}

	// Stored provider state (a dashboard prompt with its own tools and
	// instructions, an earlier response, a conversation) would reach the model
	// without the request checks below; storing this conversation on the
	// provider's side is refused too. Codex works statelessly.
	for _, k := range []string{"prompt", "previous_response_id", "conversation"} {
		if _, ok := obj[k]; ok {
			res.ErrorReason = "stored provider state is not allowed: " + k
			return res
		}
	}
	if v, ok := obj["store"]; ok && v != false {
		res.ErrorReason = "store must be false"
		return res
	}

	if err := boundary.RemoteInputError(obj); err != nil {
		res.ErrorReason = err.Error()
		return res
	}

	seenToolTypes := make(map[string]bool)
	var toolErr string
	if tools, exists := obj["tools"]; exists && tools != nil {
		toolErr = collectAndValidateTools(tools, seenToolTypes)
	}

	if toolErr == "" {
		if inputList, ok := obj["input"].([]any); ok {
			for _, itemVal := range inputList {
				if item, ok := itemVal.(map[string]any); ok && item["type"] == "additional_tools" {
					if nTools, exists := item["tools"]; exists && nTools != nil {
						toolErr = collectAndValidateTools(nTools, seenToolTypes)
						if toolErr != "" {
							break
						}
					}
				}
			}
		}
	}

	if toolErr == "" {
		if tc, ok := obj["tool_choice"].(map[string]any); ok {
			if tcType, ok := tc["type"].(string); ok && isForbiddenHostedToolType(tcType) {
				seenToolTypes[tcType] = true
				toolErr = fmt.Sprintf("forbidden hosted tool_choice type: %s", tcType)
			}
		}
	}

	for k := range seenToolTypes {
		res.ToolTypeNames = append(res.ToolTypeNames, k)
	}
	sort.Strings(res.ToolTypeNames)

	if toolErr != "" {
		res.ErrorReason = toolErr
		return res
	}

	modelVal, _ := obj["model"].(string)
	if !budget.AllowedModel("openai", modelVal) {
		res.ErrorReason = budget.NotAllowedMessage("openai", modelVal)
		return res
	}
	res.Model = modelVal

	if reasoning, exists := obj["reasoning"]; exists && reasoning != nil {
		rMap, ok := reasoning.(map[string]any)
		if !ok || rMap["effort"] != "none" {
			res.ErrorReason = "reasoning.effort must be none"
			return res
		}
	}

	if obj["stream"] != true {
		res.ErrorReason = "stream must be true"
		return res
	}

	if bg, exists := obj["background"]; exists && bg != nil && bg != false {
		res.ErrorReason = "background mode is forbidden"
		return res
	}

	var inserted []string
	if _, exists := obj["service_tier"]; !exists {
		obj["service_tier"] = PinnedServiceTier
		inserted = append(inserted, "service_tier")
	} else {
		if stVal, ok := obj["service_tier"].(string); !ok || stVal != PinnedServiceTier {
			res.ErrorReason = "service_tier must be default"
			return res
		}
	}

	mot := DefaultMaxOutputTokens
	if _, exists := obj["max_output_tokens"]; !exists {
		obj["max_output_tokens"] = DefaultMaxOutputTokens
		inserted = append(inserted, "max_output_tokens")
	} else {
		val := obj["max_output_tokens"]
		n, ok := parseStrictInt(val)
		if !ok || n < MinOutputTokens || n > MaxOutputTokens {
			res.ErrorReason = "max_output_tokens must be int 16..1024"
			return res
		}
		mot = n
		obj["max_output_tokens"] = n
	}

	sort.Strings(inserted)
	res.InsertedFields = inserted
	res.OutboundMaxOutputTokens = mot

	outBytes, _ := json.Marshal(obj)
	h := sha256.Sum256(outBytes)
	res.Digest = hex.EncodeToString(h[:])
	res.OutboundBytes = outBytes
	return res
}

func isBool(v any) bool {
	_, ok := v.(bool)
	return ok
}

func parseStrictInt(v any) (int, bool) {
	if isBool(v) || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n != math.Trunc(n) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		s := n.String()
		if strings.Contains(s, ".") || strings.Contains(s, "e") || strings.Contains(s, "E") {
			return 0, false
		}
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// ReservationFor sizes the reservation for the built-in model.
func ReservationFor(countedInput int) int {
	amount, _ := ReservationForModel(PinnedModel, countedInput)
	return amount
}

// ReservationForModel sizes the reservation from the model's prices: the
// estimated input plus the output cap. ok is false when the request could cost
// more than one reservation may hold (or its size is unknown for a model whose
// worst case the cap cannot cover); the broker then refuses it rather than
// reserve less than it could cost.
func ReservationForModel(model string, countedInput int) (int, bool) {
	rate, priced := budget.ModelRates[model]
	if !priced {
		return 0, false
	}
	rin, rout := rate.InputRateMicros, rate.OutputRateMicros
	if rin <= 0 || rout <= 0 {
		return 0, false
	}
	if countedInput < 0 {
		if countedInput != -1 {
			return 0, false
		}
		// Unknown size: reserve the most one reservation may hold, which covers
		// the largest accepted input only at the built-in model's prices.
		if (budget.MaxInputTokens*rin + MaxOutputTokens*rout) > budget.ReservationAmountMicros {
			return 0, false
		}
		return budget.ReservationAmountMicros, true
	}
	if countedInput > budget.MaxInputTokens {
		return 0, false
	}
	if countedInput*rin+MaxOutputTokens*rout > budget.ReservationAmountMicros {
		return 0, false
	}
	estInput := int(math.Ceil(float64(countedInput)*5.0/4.0)) + ReservationInputMarginTokens
	if estInput > budget.MaxInputTokens {
		estInput = budget.MaxInputTokens
	}
	amount := estInput*rin + MaxOutputTokens*rout
	if amount < budget.MinReservationMicros {
		return budget.MinReservationMicros, true
	}
	if amount > budget.ReservationAmountMicros {
		return 0, false
	}
	return amount, true
}

type GetTransportFunc func(key string) (int, map[string]string, []byte, error)
type CountTransportFunc func(bodyBytes []byte, key string) (int, map[string]string, []byte, error)
type PostTransportFunc func(bodyBytes []byte, key string) (int, map[string]string, []byte, error)

func DefaultGetTransport(key string) (int, map[string]string, []byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models/"+PinnedModel, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, PreflightMaxBytes+1))
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	return resp.StatusCode, headers, raw, nil
}

func DefaultCountTransport(bodyBytes []byte, key string) (int, map[string]string, []byte, error) {
	client := &http.Client{Timeout: PreflightDeadlineSec}
	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses/input_tokens", bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, PreflightMaxBytes+1))
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	return resp.StatusCode, headers, raw, nil
}

func DefaultPostTransport(bodyBytes []byte, key string) (int, map[string]string, []byte, error) {
	client := &http.Client{Timeout: StreamDeadlineSec}
	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxStreamResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	return resp.StatusCode, headers, raw, nil
}

func CheckKey(key string, transport GetTransportFunc) error {
	if transport == nil {
		transport = DefaultGetTransport
	}
	status, _, raw, err := transport(key)
	if err != nil {
		return fmt.Errorf("transport error: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("key check failed: HTTP %d", status)
	}
	if len(raw) > PreflightMaxBytes {
		return errors.New("key check response too large")
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("key check invalid JSON: %w", err)
	}
	if id, _ := data["id"].(string); id != PinnedModel {
		return fmt.Errorf("key check model mismatch: %s", id)
	}
	return nil
}

func PreflightInputTokens(outboundBytes []byte, key string, transport CountTransportFunc) (bool, int, int, string) {
	var obj map[string]any
	_ = json.Unmarshal(outboundBytes, &obj)

	filtered := make(map[string]any)
	for k, v := range obj {
		if preflightKeys[k] {
			filtered[k] = v
		}
	}
	filteredBytes, _ := json.Marshal(filtered)

	status, _, raw, err := transport(filteredBytes, key)
	if err != nil {
		return false, 0, 0, "PREFLIGHT_TRANSPORT_FAILURE"
	}
	if status != 200 {
		return false, status, 0, "PREFLIGHT_PROVIDER_REJECTED"
	}
	if len(raw) > PreflightMaxBytes {
		return false, status, 0, "PREFLIGHT_RESPONSE_TOO_LARGE"
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var resp map[string]any
	if err := d.Decode(&resp); err != nil {
		return false, status, 0, "PREFLIGHT_RESPONSE_INVALID"
	}

	if resp["object"] != "response.input_tokens" {
		return false, status, 0, "PREFLIGHT_RESPONSE_INVALID"
	}
	n, ok := parseStrictInt(resp["input_tokens"])
	if !ok || n < 0 {
		return false, status, 0, "PREFLIGHT_RESPONSE_INVALID"
	}
	if n > PreflightMaxInputTokens {
		return false, status, n, "PREFLIGHT_INPUT_TOO_LARGE"
	}
	return true, status, n, "PREFLIGHT_OK"
}

type ParsedSSEMetadata struct {
	ResponseID   string
	Model        string
	ServiceTier  string
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

type SSEDiagnostic struct {
	ResponseID  string
	Model       string
	ServiceTier string
	ErrorType   string
	ErrorCode   string
}

func containsSecretShape(s string) bool {
	return strings.Contains(s, "sk-") || strings.Contains(s, "sess-")
}

func safeDiagErrorType(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	if allowedUpstreamErrorTypes[trimmed] {
		return trimmed
	}
	return "other"
}

func safeDiagErrorCode(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	if allowedUpstreamErrorCodes[trimmed] {
		return trimmed
	}
	return "other"
}

func safeDiagID(v any) string {
	s, ok := v.(string)
	if !ok || !safeDiagResponseIDRe.MatchString(s) || containsSecretShape(s) {
		return ""
	}
	return s
}

func safeDiagModel(v any, requestedModel string) string {
	s, ok := v.(string)
	if !ok || s == "" || containsSecretShape(s) {
		return ""
	}
	if s == requestedModel {
		return s
	}
	if _, known := budget.ModelRates[s]; known {
		return s
	}
	return ""
}

func safeDiagServiceTier(v any) string {
	s, ok := v.(string)
	if !ok || !allowedServiceTiers[s] {
		return ""
	}
	return s
}

func scrubDiagSecret(val string, secret string) string {
	if val == "" {
		return ""
	}
	if containsSecretShape(val) {
		return ""
	}
	if secret != "" && strings.Contains(val, secret) {
		return ""
	}
	return val
}

func extractSafeSSEError(dataObj map[string]any) (errType string, errCode string) {
	if t := safeDiagErrorType(dataObj["error_type"]); t != "" {
		errType = t
	}
	if c := safeDiagErrorCode(dataObj["code"]); c != "" {
		errCode = c
	}
	if errObj, ok := dataObj["error"].(map[string]any); ok && errObj != nil {
		if errType == "" {
			errType = safeDiagErrorType(errObj["type"])
		}
		if errCode == "" {
			errCode = safeDiagErrorCode(errObj["code"])
		}
	}
	if respObj, ok := dataObj["response"].(map[string]any); ok && respObj != nil {
		if errObj, ok := respObj["error"].(map[string]any); ok && errObj != nil {
			if errType == "" {
				errType = safeDiagErrorType(errObj["type"])
			}
			if errCode == "" {
				errCode = safeDiagErrorCode(errObj["code"])
			}
		}
	}
	return errType, errCode
}

// UnbilledStatuses are provider statuses for a request that was refused or
// failed before it was processed, and is not billed: they settle at zero.
var UnbilledStatuses = map[int]bool{400: true, 401: true, 403: true, 404: true, 413: true, 422: true,
	429: true, 500: true, 502: true, 503: true, 504: true, 529: true}

func ParseAndValidateSSE(httpStatus int, headers map[string]string, rawBody []byte, outboundMaxOutputTokens int) (bool, *ParsedSSEMetadata, map[string]int, string) {
	return ParseAndValidateSSEFor(PinnedModel, httpStatus, headers, rawBody, outboundMaxOutputTokens)
}

// ParseAndValidateSSEFor is ParseAndValidateSSE for a requested model; the
// reply must name exactly that model (list the provider's exact model id).
func ParseAndValidateSSEFor(model string, httpStatus int, headers map[string]string, rawBody []byte, outboundMaxOutputTokens int) (bool, *ParsedSSEMetadata, map[string]int, string) {
	ok, meta, counts, reason, _ := ParseAndValidateSSEDetailed(model, httpStatus, headers, rawBody, outboundMaxOutputTokens)
	return ok, meta, counts, reason
}

// ParseAndValidateSSEDetailed parses and validates an OpenAI Responses SSE
// stream while capturing bounded, secret-free response and upstream error
// diagnostic metadata for fail-closed failures.
func ParseAndValidateSSEDetailed(model string, httpStatus int, headers map[string]string, rawBody []byte, outboundMaxOutputTokens int) (bool, *ParsedSSEMetadata, map[string]int, string, *SSEDiagnostic) {
	counts := make(map[string]int)
	diag := &SSEDiagnostic{}
	if httpStatus != 200 {
		return false, nil, counts, fmt.Sprintf("expected HTTP 200, got %d", httpStatus), diag
	}
	if len(rawBody) > MaxStreamResponseBytes {
		return false, nil, counts, "SSE body exceeds 16 MiB limit", diag
	}

	text := string(rawBody)
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	if strings.Contains(normalized, "\r") {
		return false, nil, counts, "lone CR in SSE stream", diag
	}
	if strings.TrimSpace(normalized) == "" {
		return false, nil, counts, "empty SSE stream", diag
	}

	blocks := strings.Split(normalized, "\n\n")
	var completedResp map[string]any
	sawCompleted := false
	terminalType := ""
	sawDone := false

	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		if sawDone {
			return false, nil, counts, "trailing data after [DONE]", diag
		}

		lines := strings.Split(block, "\n")
		var eventHeader string
		var dataLines []string

		for _, line := range lines {
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, ":") {
				if sawCompleted {
					return false, nil, counts, "comment after terminal event", diag
				}
				continue
			}
			if strings.HasPrefix(line, "event:") {
				if eventHeader != "" {
					return false, nil, counts, "duplicate event: line in SSE block", diag
				}
				eventHeader = strings.TrimSpace(line[len("event:"):])
				if eventHeader == "" {
					return false, nil, counts, "empty event: header in SSE block", diag
				}
			} else if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(line[len("data:"):]))
			} else {
				return false, nil, counts, "malformed line in SSE block", diag
			}
		}

		if len(dataLines) == 0 {
			if eventHeader != "" {
				return false, nil, counts, "event header without data line", diag
			}
			continue
		}
		if len(dataLines) != 1 {
			return false, nil, counts, "multiple data lines in single SSE event", diag
		}

		dataStr := dataLines[0]
		if dataStr == "[DONE]" {
			if !sawCompleted {
				return false, nil, counts, "[DONE] before response.completed", diag
			}
			if eventHeader != "" && eventHeader != "done" {
				return false, nil, counts, "unexpected event header on [DONE]", diag
			}
			sawDone = true
			continue
		}

		var dataObj map[string]any
		if err := json.Unmarshal([]byte(dataStr), &dataObj); err != nil {
			return false, nil, counts, "malformed JSON in SSE data", diag
		}

		evType, _ := dataObj["type"].(string)
		if evType == "" {
			return false, nil, counts, "SSE JSON object missing string type", diag
		}
		if eventHeader != "" && eventHeader != evType {
			return false, nil, counts, "SSE event header does not match data.type", diag
		}

		if respObj, ok := dataObj["response"].(map[string]any); ok && respObj != nil {
			if diag.ResponseID == "" {
				diag.ResponseID = safeDiagID(respObj["id"])
			}
			if diag.Model == "" {
				diag.Model = safeDiagModel(respObj["model"], model)
			}
			if diag.ServiceTier == "" {
				diag.ServiceTier = safeDiagServiceTier(respObj["service_tier"])
			}
		}

		counts[evType]++
		if forbiddenSSEEvents[evType] {
			errType, errCode := extractSafeSSEError(dataObj)
			if diag.ErrorType == "" {
				diag.ErrorType = errType
			}
			if diag.ErrorCode == "" {
				diag.ErrorCode = errCode
			}
			return false, nil, counts, fmt.Sprintf("forbidden SSE event: %s", evType), diag
		}
		if sawCompleted {
			return false, nil, counts, "trailing event after response.completed", diag
		}

		// A response cut off at max_output_tokens ends with response.incomplete;
		// it is billed like a completed one and settled from its usage.
		if evType == "response.completed" || evType == "response.incomplete" {
			sawCompleted = true
			terminalType = evType
			respObj, ok := dataObj["response"].(map[string]any)
			if !ok || respObj == nil {
				return false, nil, counts, evType + " missing response object", diag
			}
			completedResp = respObj
		}
	}

	if !sawCompleted || completedResp == nil {
		return false, nil, counts, "missing response.completed event", diag
	}
	if counts["response.completed"]+counts["response.incomplete"] != 1 {
		return false, nil, counts, "expected exactly one terminal response event", diag
	}

	respID, _ := completedResp["id"].(string)
	modelVal, _ := completedResp["model"].(string)
	tierVal, _ := completedResp["service_tier"].(string)
	statusVal, _ := completedResp["status"].(string)

	if completedResp["error"] != nil {
		errType, errCode := extractSafeSSEError(map[string]any{"response": completedResp})
		diag.ErrorType, diag.ErrorCode = errType, errCode
		return false, nil, counts, "terminal response has non-null error", diag
	}
	if terminalType == "response.incomplete" {
		details, _ := completedResp["incomplete_details"].(map[string]any)
		if statusVal != "incomplete" || details == nil || details["reason"] != "max_output_tokens" {
			return false, nil, counts, "incomplete response is not a max_output_tokens cut-off", diag
		}
	} else {
		if statusVal != "completed" {
			return false, nil, counts, "expected status=='completed', got unexpected status", diag
		}
		if completedResp["incomplete_details"] != nil {
			return false, nil, counts, "completed response has non-null incomplete_details", diag
		}
	}
	if respID == "" {
		return false, nil, counts, "invalid response_id", diag
	}
	if modelVal != model {
		return false, nil, counts, "model mismatch", diag
	}
	if tierVal != PinnedServiceTier {
		return false, nil, counts, "service_tier mismatch", diag
	}

	usage, ok := completedResp["usage"].(map[string]any)
	if !ok || usage == nil {
		return false, nil, counts, "missing or non-object usage", diag
	}
	inTok, inOk := parseStrictInt(usage["input_tokens"])
	outTok, outOk := parseStrictInt(usage["output_tokens"])
	totTok, totOk := parseStrictInt(usage["total_tokens"])

	if !inOk || !outOk || !totOk || inTok < 0 || outTok < 0 || totTok < 0 || totTok != inTok+outTok {
		return false, nil, counts, "invalid or inconsistent token counts", diag
	}
	if outTok > outboundMaxOutputTokens || outTok > budget.MaxOutputTokens {
		return false, nil, counts, "output_tokens exceeds bound", diag
	}
	if inTok > budget.MaxInputTokens {
		return false, nil, counts, "input_tokens exceeds bound", diag
	}

	meta := &ParsedSSEMetadata{
		ResponseID:   respID,
		Model:        modelVal,
		ServiceTier:  tierVal,
		InputTokens:  inTok,
		OutputTokens: outTok,
		TotalTokens:  totTok,
	}
	return true, meta, counts, "", diag
}

type ResponsesBrokerServer struct {
	// Set by the host before serving, never by a request from the agent.
	CloudGuard     egress.Guard
	ledger         *budget.BudgetLedger
	key            string
	caseLabel      string
	maxRequests    int
	sockdir        string
	socketPath     string
	experimentRoot string
	getTransport   GetTransportFunc
	countTransport CountTransportFunc
	postTransport  PostTransportFunc

	count         int
	stopRequested bool
	listener      net.Listener
	mu            sync.Mutex
}

func NewResponsesBrokerServer(
	ledger *budget.BudgetLedger,
	key string,
	caseLabel string,
	maxRequests int,
	sockdir string,
	experimentRoot string,
	getTransport GetTransportFunc,
	countTransport CountTransportFunc,
	postTransport PostTransportFunc,
) (*ResponsesBrokerServer, error) {
	if !caseLabelRegex.MatchString(caseLabel) {
		return nil, errors.New("invalid case label")
	}
	if maxRequests < 1 || maxRequests > MaxSessionRequests {
		return nil, errors.New("max_requests out of range")
	}
	if countTransport == nil {
		countTransport = DefaultCountTransport
	}
	if postTransport == nil {
		postTransport = DefaultPostTransport
	}

	s := &ResponsesBrokerServer{
		ledger:         ledger,
		key:            key,
		caseLabel:      caseLabel,
		maxRequests:    maxRequests,
		sockdir:        sockdir,
		experimentRoot: experimentRoot,
		getTransport:   getTransport,
		countTransport: countTransport,
		postTransport:  postTransport,
	}
	s.countTransport = func(body []byte, key string) (int, map[string]string, []byte, error) {
		if err := s.CloudGuard.Check(); err != nil {
			return http.StatusForbidden, nil, egress.ErrorBody(err), nil
		}
		return countTransport(body, key)
	}
	s.postTransport = func(body []byte, key string) (int, map[string]string, []byte, error) {
		if err := s.CloudGuard.Check(); err != nil {
			return http.StatusForbidden, nil, egress.ErrorBody(err), nil
		}
		return postTransport(body, key)
	}
	return s, nil
}

func (s *ResponsesBrokerServer) SocketPath() string {
	return s.socketPath
}

func (s *ResponsesBrokerServer) RequestCounter() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *ResponsesBrokerServer) StopRequested() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopRequested
}

func (s *ResponsesBrokerServer) Ledger() *budget.BudgetLedger {
	return s.ledger
}

func (s *ResponsesBrokerServer) Start() error {
	if s.getTransport != nil {
		if err := CheckKey(s.key, s.getTransport); err != nil {
			return fmt.Errorf("startup key check failed: %w", err)
		}
	}
	if s.sockdir != "" {
		if err := os.MkdirAll(s.sockdir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(s.sockdir, 0700); err != nil {
			return err
		}
		s.socketPath = filepath.Join(s.sockdir, "broker.sock")
		_ = os.Remove(s.socketPath)

		oldMask := syscall.Umask(0077)
		l, err := net.Listen("unix", s.socketPath)
		syscall.Umask(oldMask)
		if err != nil {
			return err
		}
		_ = os.Chmod(s.socketPath, 0600)
		s.listener = l
	}
	return nil
}

func (s *ResponsesBrokerServer) writeEvidence(
	requestID *string,
	requestDigest *string,
	insertedFields []string,
	toolTypeNames []string,
	httpStatus *int,
	responseID *string,
	model *string,
	serviceTier *string,
	usage map[string]int,
	responseBodySHA256 *string,
	eventTypeCounts map[string]int,
	outcomeCode string,
	startUTC string,
	parseError *string,
	upstreamErrorType *string,
	upstreamErrorCode *string,
) {
	if s.experimentRoot == "" {
		return
	}
	endUTC := time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	if insertedFields == nil {
		insertedFields = []string{}
	}
	if toolTypeNames == nil {
		toolTypeNames = []string{}
	}
	if eventTypeCounts == nil {
		eventTypeCounts = map[string]int{}
	}

	var ledgerStatusMap map[string]any
	if s.ledger != nil {
		st, _ := s.ledger.GetStatus()
		if st != nil {
			ledgerStatusMap = map[string]any{
				"experiment_id":              st.ExperimentID,
				"global_ceiling_micros":      st.GlobalCeilingMicros,
				"committed_spend_micros":     st.CommittedSpendMicros,
				"retained_failed_micros":     st.RetainedFailedMicros,
				"total_spend_micros":         st.TotalSpendMicros,
				"pending_reserved_micros":    st.PendingReservedMicros,
				"total_encumbered_micros":    st.TotalEncumberedMicros,
				"remaining_available_micros": st.RemainingAvailableMicros,
				"remaining_budget_micros":    st.RemainingBudgetMicros,
				"total_reservations_count":   st.TotalReservationsCount,
				"settled_requests_count":     st.SettledRequestsCount,
				"has_pending_reservation":    st.HasPendingReservation,
				"pending_request_id":         st.PendingRequestID,
				"halted":                     st.Halted,
				"halt_reason":                st.HaltReason,
				"handle_disabled":            st.HandleDisabled,
				"handle_disabled_reason":     st.HandleDisabledReason,
				"can_reserve":                st.CanReserve(),
			}
		}
	}

	rec := map[string]any{
		"request_id":           requestID,
		"request_digest":       requestDigest,
		"inserted_fields":      insertedFields,
		"tool_type_names":      toolTypeNames,
		"http_status":          httpStatus,
		"response_id":          responseID,
		"model":                model,
		"service_tier":         serviceTier,
		"usage":                usage,
		"response_body_sha256": responseBodySHA256,
		"event_type_counts":    eventTypeCounts,
		"outcome_code":         outcomeCode,
		"parse_error":          parseError,
		"upstream_error_type":  upstreamErrorType,
		"upstream_error_code":  upstreamErrorCode,
		"ledger_status":        ledgerStatusMap,
		"timestamps": map[string]string{
			"started_at_utc":   startUTC,
			"completed_at_utc": endUTC,
		},
	}

	evFile := filepath.Join(s.experimentRoot, fmt.Sprintf("%s%s.jsonl", EvidenceFilePrefix, s.caseLabel))
	_ = os.MkdirAll(s.experimentRoot, 0700)
	line, err := json.Marshal(rec)
	if err == nil {
		f, err := os.OpenFile(evFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
	}
}

func (s *ResponsesBrokerServer) HandleFrameBytes(rawBody []byte) (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	startUTC := time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")

	if s.count >= s.maxRequests {
		s.writeEvidence(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "MAX_REQUESTS_EXCEEDED", startUTC, nil, nil, nil)
		return 429, []byte(`{"error":"max_requests_exceeded"}`)
	}

	val := ValidateAndPrepareRequest(rawBody)
	if val.ErrorReason != "" {
		s.writeEvidence(nil, nil, val.InsertedFields, val.ToolTypeNames, nil, nil, nil, nil, nil, nil, nil, "REFUSED_PRE_RESERVE", startUTC, nil, nil, nil)
		return 400, []byte(`{"error":"request_refused_by_broker"}`)
	}
	if err := s.CloudGuard.Check(); err != nil {
		s.writeEvidence(nil, &val.Digest, nil, nil, nil, nil, nil, nil, nil, nil, nil, "CLOUD_REQUEST_BLOCKED", startUTC, nil, nil, nil)
		return http.StatusForbidden, egress.ErrorBody(err)
	}

	pfOk, pfStatus, pfTokens, pfCode := PreflightInputTokens(val.OutboundBytes, s.key, s.countTransport)
	if !pfOk {
		var statusPtr *int
		if pfStatus > 0 {
			statusPtr = &pfStatus
		}
		s.writeEvidence(nil, &val.Digest, val.InsertedFields, val.ToolTypeNames, statusPtr, nil, nil, nil, nil, nil, nil, pfCode, startUTC, nil, nil, nil)
		return 400, []byte(fmt.Sprintf(`{"error":"request_refused_by_preflight","code":%q}`, pfCode))
	}

	s.count++
	requestID := fmt.Sprintf("live-%s-%d", s.caseLabel, s.count)
	amount, fits := ReservationForModel(val.Model, pfTokens)
	if !fits {
		s.count--
		s.writeEvidence(nil, &val.Digest, val.InsertedFields, val.ToolTypeNames, nil, nil, nil, nil, nil, nil, nil, "REFUSED_RESERVATION_TOO_LARGE", startUTC, nil, nil, nil)
		return 400, []byte(`{"error":"request_refused_by_broker","code":"could cost more than one reservation may hold; shorten the input"}`)
	}

	permit, err := s.ledger.Reserve(requestID, val.Digest, amount)
	if err != nil {
		s.stopRequested = true
		s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, nil, nil, nil, nil, nil, nil, nil, "RESERVE_FAILED", startUTC, nil, nil, nil)
		return 502, []byte(`{"error":"ledger_reserve_failed"}`)
	}

	status, headers, respBytes, err := s.postTransport(val.OutboundBytes, s.key)
	if err != nil {
		_, _ = s.ledger.RecordFailure(permit, "REQUEST_TRANSPORT_FAILURE")
		s.stopRequested = true
		s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, nil, nil, nil, nil, nil, nil, nil, "REQUEST_TRANSPORT_FAILURE", startUTC, nil, nil, nil)
		return 502, []byte(`{"error":"upstream_transport_failure"}`)
	}

	// A status the provider does not bill (it refused the request) is settled
	// at zero, as the Messages broker does, so an agent's malformed request
	// cannot halt the shared ledger. Its error reply is passed back.
	if status != 200 && UnbilledStatuses[status] {
		zero := &budget.Receipt{
			Status:        budget.TerminalStatusCompleted,
			ResponseID:    fmt.Sprintf("unbilled-%d-%s", status, requestID),
			RequestID:     requestID,
			RequestDigest: val.Digest,
			Model:         val.Model,
			ServiceTier:   PinnedServiceTier,
		}
		st := status
		if _, err := s.ledger.Settle(permit, zero); err != nil {
			s.stopRequested = true
			s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, &st, nil, nil, nil, nil, nil, nil, "UNBILLED_SETTLE_FAILED", startUTC, nil, nil, nil)
			return 502, []byte(`{"error":"ledger_settlement_failed"}`)
		}
		s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, &st, nil, nil, nil, nil, nil, nil, "UNBILLED_STATUS", startUTC, nil, nil, nil)
		if len(respBytes) > 64<<10 {
			respBytes = respBytes[:64<<10]
		}
		return status, respBytes
	}

	var respSHA256 *string
	if len(respBytes) > 0 {
		h := sha256.Sum256(respBytes)
		str := hex.EncodeToString(h[:])
		respSHA256 = &str
	}

	isValid, meta, counts, parseReason, diag := ParseAndValidateSSEDetailed(val.Model, status, headers, respBytes, val.OutboundMaxOutputTokens)
	if !isValid || meta == nil {
		_, _ = s.ledger.RecordFailure(permit, "INVALID_RECEIPT_EVIDENCE")
		s.stopRequested = true
		var respID, modelVal, tierVal *string
		if meta != nil {
			if v := scrubDiagSecret(meta.ResponseID, s.key); v != "" {
				respID = &v
			}
			if v := scrubDiagSecret(meta.Model, s.key); v != "" {
				modelVal = &v
			}
			if v := scrubDiagSecret(meta.ServiceTier, s.key); v != "" {
				tierVal = &v
			}
		} else if diag != nil {
			if v := scrubDiagSecret(diag.ResponseID, s.key); v != "" {
				respID = &v
			}
			if v := scrubDiagSecret(diag.Model, s.key); v != "" {
				modelVal = &v
			}
			if v := scrubDiagSecret(diag.ServiceTier, s.key); v != "" {
				tierVal = &v
			}
		}
		safeReason := parseReason
		if safeReason != "" && scrubDiagSecret(safeReason, s.key) == "" {
			safeReason = "invalid_upstream_sse"
		}
		var parseErrPtr, errTypePtr, errCodePtr *string
		if safeReason != "" {
			v := safeReason
			parseErrPtr = &v
		}
		var errTypeStr, errCodeStr, respIDStr string
		if diag != nil {
			errTypeStr = scrubDiagSecret(diag.ErrorType, s.key)
			errCodeStr = scrubDiagSecret(diag.ErrorCode, s.key)
			respIDStr = scrubDiagSecret(diag.ResponseID, s.key)
			if errTypeStr != "" {
				v := errTypeStr
				errTypePtr = &v
			}
			if errCodeStr != "" {
				v := errCodeStr
				errCodePtr = &v
			}
		}
		if respID != nil {
			respIDStr = *respID
		}
		s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, &status, respID, modelVal, tierVal, nil, respSHA256, counts, "INVALID_RECEIPT_EVIDENCE", startUTC, parseErrPtr, errTypePtr, errCodePtr)
		fmt.Fprintf(os.Stderr, "guardfil-broker responses: request=%s outcome=INVALID_RECEIPT_EVIDENCE parse_error=%q upstream_error_type=%q upstream_error_code=%q response_id=%q\n",
			requestID, safeReason, errTypeStr, errCodeStr, respIDStr)
		errReply := map[string]any{"error": "invalid_upstream_sse"}
		if safeReason != "" {
			errReply["detail"] = safeReason
		}
		if errTypeStr != "" {
			errReply["upstream_error_type"] = errTypeStr
		}
		if errCodeStr != "" {
			errReply["upstream_error_code"] = errCodeStr
		}
		replyJSON, _ := json.Marshal(errReply)
		return 502, replyJSON
	}

	receipt := &budget.Receipt{
		Status:        budget.TerminalStatusCompleted,
		ResponseID:    meta.ResponseID,
		RequestID:     requestID,
		RequestDigest: val.Digest,
		Model:         val.Model,
		ServiceTier:   meta.ServiceTier,
		InputTokens:   meta.InputTokens,
		OutputTokens:  meta.OutputTokens,
		TotalTokens:   meta.TotalTokens,
	}

	usageMap := map[string]int{
		"input_tokens":  meta.InputTokens,
		"output_tokens": meta.OutputTokens,
		"total_tokens":  meta.TotalTokens,
	}

	if _, err := s.ledger.Settle(permit, receipt); err != nil {
		_, _ = s.ledger.RecordFailure(permit, "INVALID_RECEIPT_EVIDENCE")
		s.stopRequested = true
		s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, &status, &meta.ResponseID, &meta.Model, &meta.ServiceTier, usageMap, respSHA256, counts, "INVALID_RECEIPT_EVIDENCE", startUTC, nil, nil, nil)
		return 502, []byte(`{"error":"ledger_settlement_failed"}`)
	}

	st, _ := s.ledger.GetStatus()
	if st != nil && st.HandleDisabled {
		s.stopRequested = true
		s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, &status, &meta.ResponseID, &meta.Model, &meta.ServiceTier, usageMap, respSHA256, counts, "SETTLEMENT_COMMITTED_HANDLE_DISABLED", startUTC, nil, nil, nil)
		return 502, []byte(`{"error":"settlement_handle_disabled"}`)
	}

	s.writeEvidence(&requestID, &val.Digest, val.InsertedFields, val.ToolTypeNames, &status, &meta.ResponseID, &meta.Model, &meta.ServiceTier, usageMap, respSHA256, counts, "SUCCESS", startUTC, nil, nil, nil)
	return 200, respBytes
}

func (s *ResponsesBrokerServer) Serve() error {
	if s.listener == nil {
		if err := s.Start(); err != nil {
			return err
		}
	}

	fmt.Printf("READY %s\n", s.socketPath)
	_ = os.Stdout.Sync()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			stopped := s.stopRequested
			s.mu.Unlock()
			if stopped {
				return nil
			}
			return err
		}

		s.handleConn(conn)

		s.mu.Lock()
		stopped := s.stopRequested
		s.mu.Unlock()
		if stopped {
			break
		}
	}
	return nil
}

func (s *ResponsesBrokerServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > MaxRequestFrameBytes {
		s.writeReply(conn, 413, []byte(`{"error":"request_too_large"}`))
		return
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}

	status, replyBody := s.HandleFrameBytes(body)
	_ = conn.SetDeadline(time.Now().Add(StreamDeadlineSec))
	s.writeReply(conn, status, replyBody)
}

func (s *ResponsesBrokerServer) writeReply(conn net.Conn, status int, body []byte) {
	var replyHdr [8]byte
	binary.BigEndian.PutUint32(replyHdr[0:4], uint32(status))
	binary.BigEndian.PutUint32(replyHdr[4:8], uint32(len(body)))
	_, _ = conn.Write(replyHdr[:])
	_, _ = conn.Write(body)
}

func (s *ResponsesBrokerServer) RequestStop() {
	s.mu.Lock()
	s.stopRequested = true
	l := s.listener
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
}

func (s *ResponsesBrokerServer) Close() {
	s.RequestStop()
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath)
	}
	if s.ledger != nil {
		_ = s.ledger.Close()
		s.ledger = nil
	}
}

func canonicalPathForGuard(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	dir := filepath.Dir(abs)
	if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Clean(filepath.Join(resolvedDir, filepath.Base(abs)))
	}
	return filepath.Clean(abs)
}

func isPathEqualOrUnder(candidate, base string) bool {
	if candidate == base {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(candidate, strings.TrimSuffix(base, sep)+sep)
}

func RunResponsesBroker(sockdir string, caseLabel string, maxRequests int, expRoot string, initLedger bool, keyFile string) error {
	guard, err := egress.FromEnv()
	if err != nil {
		return err
	}
	if keyFile == "" {
		keyFile = filepath.Join(os.Getenv("HOME"), ".config/guardfil/credentials.d/openai-api-key")
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", keyFile, err)
	}
	key := strings.TrimSpace(string(keyData))

	var ledger *budget.BudgetLedger
	stateRoot := filepath.Join(os.Getenv("HOME"), ".local/state/guardfil")
	if expRoot == "" {
		ledger, err = budget.OpenProviderLedger(stateRoot, "openai", initLedger)
		if err != nil {
			return fmt.Errorf("failed to open/init openai ledger: %w", err)
		}
		expRoot = filepath.Join(stateRoot, budget.ProviderLedgerSpecs["openai"].TargetDir)
	} else {
		cleanExp := canonicalPathForGuard(expRoot)
		cleanStateRoot := canonicalPathForGuard(stateRoot)
		var matchedProvider string
		var matchedIsLegacy bool
		var matchedExact bool
		for _, p := range budget.SupportedProviders {
			spec := budget.ProviderLedgerSpecs[p]
			legacyPath := canonicalPathForGuard(filepath.Join(cleanStateRoot, spec.LegacyDir))
			targetPath := canonicalPathForGuard(filepath.Join(cleanStateRoot, spec.TargetDir))
			if isPathEqualOrUnder(cleanExp, legacyPath) {
				matchedProvider = p
				matchedIsLegacy = true
				matchedExact = (cleanExp == legacyPath)
				break
			}
			if isPathEqualOrUnder(cleanExp, targetPath) {
				matchedProvider = p
				matchedIsLegacy = false
				matchedExact = (cleanExp == targetPath)
				break
			}
		}
		if matchedProvider != "" {
			if matchedIsLegacy {
				return fmt.Errorf("%w: legacy %s directory %s cannot be opened directly via --experiment-root; run 'guardfil-broker migrate-ledger --provider %s'", budget.ErrLedgerMigrationRequired, matchedProvider, expRoot, matchedProvider)
			}
			if matchedProvider != "openai" || !matchedExact {
				return fmt.Errorf("%w: --experiment-root %s is reserved for %s provider ledger", budget.ErrLedgerSecurity, expRoot, matchedProvider)
			}
			ledger, err = budget.OpenProviderLedger(stateRoot, "openai", initLedger)
			if err != nil {
				return fmt.Errorf("failed to open/init openai ledger: %w", err)
			}
			expRoot = filepath.Join(stateRoot, budget.ProviderLedgerSpecs["openai"].TargetDir)
		} else {
			ledger, err = budget.OpenOrInitLedger(expRoot, initLedger, budget.DefaultExperimentID)
			if err != nil {
				return fmt.Errorf("failed to open/init ledger: %w", err)
			}
		}
	}
	defer ledger.Close()

	srv, err := NewResponsesBrokerServer(ledger, key, caseLabel, maxRequests, sockdir, expRoot, nil, nil, nil)
	if err != nil {
		return err
	}
	defer srv.Close()
	srv.CloudGuard = guard

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		srv.RequestStop()
	}()

	return srv.Serve()
}
