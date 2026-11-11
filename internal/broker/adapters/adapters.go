package adapters

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	MaxMessages     = 200
	MaxTools        = 64
	MaxText         = 200_000
	MaxOutputTokens = 1024
)

var (
	nameRegex  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	modelRegex = regexp.MustCompile(`^(openai|anthropic|gemini):([A-Za-z0-9._-]{1,64})$`)
)

type NeutralError struct {
	Msg string
}

func (e NeutralError) Error() string {
	return e.Msg
}

type HTTPRequest struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

type ToolCall struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type NeutralUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type NeutralReply struct {
	Text        string       `json:"text"`
	ToolCalls   []ToolCall   `json:"tool_calls"`
	Stop        string       `json:"stop"`
	Usage       NeutralUsage `json:"usage"`
	Model       string       `json:"model"`
	ResponseID  string       `json:"response_id"`
	ServiceTier string       `json:"service_tier,omitempty"`
}

type Adapter interface {
	Provider() string
	Build(model string, req map[string]any) (*HTTPRequest, error)
	Auth(key string) map[string]string
	Parse(status int, raw []byte) (*NeutralReply, error)
	Preflight(model string, out *HTTPRequest) (*HTTPRequest, error)
}

// EncodeArguments encodes arguments map with exact numeric literals preserved.
func EncodeArguments(args map[string]any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(args); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// Validate validates a neutral chat request and returns (provider, model, error).
func Validate(req map[string]any) (string, string, error) {
	for k := range req {
		if k != "model" && k != "system" && k != "messages" && k != "tools" && k != "max_output_tokens" {
			return "", "", NeutralError{Msg: "request has unknown fields"}
		}
	}

	modelStr, ok := req["model"].(string)
	if !ok {
		return "", "", NeutralError{Msg: "model must be provider:model with provider openai, anthropic or gemini"}
	}
	m := modelRegex.FindStringSubmatch(modelStr)
	if len(m) != 3 {
		return "", "", NeutralError{Msg: "model must be provider:model with provider openai, anthropic or gemini"}
	}
	provider := m[1]
	model := m[2]

	if sysVal, exists := req["system"]; exists {
		sysStr, ok := sysVal.(string)
		if !ok || len(sysStr) > MaxText {
			return "", "", NeutralError{Msg: "system must be text"}
		}
	}

	rawMsgs, ok := req["messages"].([]any)
	if !ok || len(rawMsgs) < 1 || len(rawMsgs) > MaxMessages {
		return "", "", NeutralError{Msg: fmt.Sprintf("messages: 1 to %d", MaxMessages)}
	}

	for idx, item := range rawMsgs {
		msg, ok := item.(map[string]any)
		if !ok {
			return "", "", NeutralError{Msg: "each message is an object"}
		}
		role, _ := msg["role"].(string)
		content, hasContent := msg["content"]
		if !hasContent {
			content = ""
		}
		contentStr, ok := content.(string)
		if !ok || len(contentStr) > MaxText {
			return "", "", NeutralError{Msg: "message content must be text"}
		}

		switch role {
		case "user":
			for k := range msg {
				if k != "role" && k != "content" {
					return "", "", NeutralError{Msg: "user message: role and content only"}
				}
			}
		case "assistant":
			for k := range msg {
				if k != "role" && k != "content" && k != "tool_calls" {
					return "", "", NeutralError{Msg: "assistant message: role, content, tool_calls"}
				}
			}
			if tcVal, exists := msg["tool_calls"]; exists && tcVal != nil {
				calls, ok := tcVal.([]any)
				if !ok {
					return "", "", NeutralError{Msg: "tool call: id, name, arguments object"}
				}
				for _, cItem := range calls {
					cMap, ok := cItem.(map[string]any)
					if !ok {
						return "", "", NeutralError{Msg: "tool call: id, name, arguments object"}
					}
					id, _ := cMap["id"].(string)
					name, _ := cMap["name"].(string)
					args, hasArgs := cMap["arguments"].(map[string]any)
					if len(cMap) != 3 || !hasArgs || !nameRegex.MatchString(id) || !nameRegex.MatchString(name) || args == nil {
						return "", "", NeutralError{Msg: "tool call: id, name, arguments object"}
					}
				}
			}
		case "tool":
			if len(msg) != 4 {
				return "", "", NeutralError{Msg: "tool message: role, tool_call_id, name, content"}
			}
			tcid, _ := msg["tool_call_id"].(string)
			name, _ := msg["name"].(string)
			if !nameRegex.MatchString(tcid) || !nameRegex.MatchString(name) {
				return "", "", NeutralError{Msg: "tool message: role, tool_call_id, name, content"}
			}
		default:
			return "", "", NeutralError{Msg: "role must be user, assistant or tool"}
		}

		if idx == 0 && role != "user" {
			return "", "", NeutralError{Msg: "the first message must be from the user"}
		}
	}

	if toolsVal, exists := req["tools"]; exists && toolsVal != nil {
		tools, ok := toolsVal.([]any)
		if !ok || len(tools) > MaxTools {
			return "", "", NeutralError{Msg: fmt.Sprintf("tools: at most %d", MaxTools)}
		}
		for _, tItem := range tools {
			tMap, ok := tItem.(map[string]any)
			if !ok {
				return "", "", NeutralError{Msg: "tool: name, description, parameters (JSON schema)"}
			}
			for k := range tMap {
				if k != "name" && k != "description" && k != "parameters" {
					return "", "", NeutralError{Msg: "tool: name, description, parameters (JSON schema)"}
				}
			}
			name, _ := tMap["name"].(string)
			desc, _ := tMap["description"].(string)
			params, hasParams := tMap["parameters"]
			if !nameRegex.MatchString(name) || (hasParams && params != nil && !isMap(params)) || (tMap["description"] != nil && desc == "" && tMap["description"] != "") {
				return "", "", NeutralError{Msg: "tool: name, description, parameters (JSON schema)"}
			}
		}
	}

	if motVal, exists := req["max_output_tokens"]; exists && motVal != nil {
		mot := toInt(motVal)
		if mot < 16 || mot > MaxOutputTokens {
			return "", "", NeutralError{Msg: fmt.Sprintf("max_output_tokens: 16 to %d", MaxOutputTokens)}
		}
	}

	return provider, model, nil
}

func isMap(v any) bool {
	_, ok := v.(map[string]any)
	return ok
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

func toolSchema(t map[string]any) map[string]any {
	if p, ok := t["parameters"].(map[string]any); ok && p != nil {
		return p
	}
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

// ---------------------------------------------------------------------------
// OpenAI Responses Adapter
// ---------------------------------------------------------------------------

type OpenAIResponses struct{}

func (a *OpenAIResponses) Provider() string { return "openai" }

func (a *OpenAIResponses) Build(model string, req map[string]any) (*HTTPRequest, error) {
	rawMsgs := req["messages"].([]any)
	var items []map[string]any

	for _, mItem := range rawMsgs {
		m := mItem.(map[string]any)
		role := m["role"].(string)
		content, _ := m["content"].(string)

		switch role {
		case "user":
			items = append(items, map[string]any{
				"role":    "user",
				"content": []any{map[string]any{"type": "input_text", "text": content}},
			})
		case "assistant":
			if content != "" {
				items = append(items, map[string]any{
					"role":    "assistant",
					"content": []any{map[string]any{"type": "output_text", "text": content}},
				})
			}
			if tcVal, ok := m["tool_calls"].([]any); ok {
				for _, cItem := range tcVal {
					c := cItem.(map[string]any)
					argsStr, _ := EncodeArguments(c["arguments"].(map[string]any))
					items = append(items, map[string]any{
						"type":      "function_call",
						"call_id":   c["id"],
						"name":      c["name"],
						"arguments": argsStr,
					})
				}
			}
		case "tool":
			items = append(items, map[string]any{
				"type":    "function_call_output",
				"call_id": m["tool_call_id"],
				"output":  content,
			})
		}
	}

	mot := MaxOutputTokens
	if motVal, ok := req["max_output_tokens"]; ok && motVal != nil {
		mot = toInt(motVal)
	}

	body := map[string]any{
		"model":             model,
		"input":             items,
		"store":             false,
		"stream":            false,
		"service_tier":      "default",
		"reasoning":         map[string]any{"effort": "none"},
		"max_output_tokens": mot,
	}

	if sys, ok := req["system"].(string); ok && sys != "" {
		body["instructions"] = sys
	}

	if toolsVal, ok := req["tools"].([]any); ok && len(toolsVal) > 0 {
		var toolsList []map[string]any
		for _, tItem := range toolsVal {
			t := tItem.(map[string]any)
			desc, _ := t["description"].(string)
			toolsList = append(toolsList, map[string]any{
				"type":        "function",
				"name":        t["name"],
				"description": desc,
				"parameters":  toolSchema(t),
				"strict":      false,
			})
		}
		body["tools"] = toolsList
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}

	return &HTTPRequest{
		Host:    "api.openai.com",
		Path:    "/v1/responses",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    bytes.TrimSpace(buf.Bytes()),
	}, nil
}

func (a *OpenAIResponses) Auth(key string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + key}
}

func (a *OpenAIResponses) Preflight(model string, out *HTTPRequest) (*HTTPRequest, error) {
	return nil, nil
}

func (a *OpenAIResponses) Parse(status int, raw []byte) (*NeutralReply, error) {
	if status != 200 {
		return nil, NeutralError{Msg: fmt.Sprintf("provider HTTP %d", status)}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil {
		return nil, NeutralError{Msg: "invalid json"}
	}

	st, _ := r["status"].(string)
	if st != "completed" && st != "incomplete" {
		return nil, NeutralError{Msg: "response not completed"}
	}

	var textParts []string
	var calls []ToolCall

	if output, ok := r["output"].([]any); ok {
		for _, itemVal := range output {
			item, ok := itemVal.(map[string]any)
			if !ok {
				continue
			}
			t, _ := item["type"].(string)
			if t == "message" {
				if content, ok := item["content"].([]any); ok {
					for _, cVal := range content {
						c, ok := cVal.(map[string]any)
						if ok && c["type"] == "output_text" {
							if txt, ok := c["text"].(string); ok {
								textParts = append(textParts, txt)
							}
						}
					}
				}
			} else if t == "function_call" {
				callID, _ := item["call_id"].(string)
				name, _ := item["name"].(string)
				argsMap := parseArguments(item["arguments"])
				calls = append(calls, ToolCall{
					ID:        callID,
					Name:      name,
					Arguments: argsMap,
				})
			}
		}
	}

	u, ok := r["usage"].(map[string]any)
	if !ok || u == nil {
		return nil, NeutralError{Msg: "reply has no token usage"}
	}
	inTok := toInt(u["input_tokens"])
	outTok := toInt(u["output_tokens"])
	if inTok < 0 || outTok < 0 || u["input_tokens"] == nil || u["output_tokens"] == nil {
		return nil, NeutralError{Msg: "reply has no token usage"}
	}

	rid, _ := r["id"].(string)
	mName, _ := r["model"].(string)
	if rid == "" || mName == "" {
		return nil, NeutralError{Msg: "reply has no model or id"}
	}

	stop := "end"
	if len(calls) > 0 {
		stop = "tool_calls"
	} else if st == "incomplete" {
		stop = "max_tokens"
	}

	tier, _ := r["service_tier"].(string)
	return &NeutralReply{
		Text:        strings.Join(textParts, ""),
		ToolCalls:   calls,
		Stop:        stop,
		Usage:       NeutralUsage{InputTokens: inTok, OutputTokens: outTok},
		Model:       mName,
		ResponseID:  rid,
		ServiceTier: tier,
	}, nil
}

// ---------------------------------------------------------------------------
// Anthropic Messages Adapter
// ---------------------------------------------------------------------------

type AnthropicMessages struct{}

func (a *AnthropicMessages) Provider() string { return "anthropic" }

func (a *AnthropicMessages) Build(model string, req map[string]any) (*HTTPRequest, error) {
	rawMsgs := req["messages"].([]any)
	var msgs []map[string]any

	addTurn := func(role string, block map[string]any) {
		if len(msgs) > 0 && msgs[len(msgs)-1]["role"] == role {
			lastContent := msgs[len(msgs)-1]["content"].([]any)
			msgs[len(msgs)-1]["content"] = append(lastContent, block)
		} else {
			msgs = append(msgs, map[string]any{
				"role":    role,
				"content": []any{block},
			})
		}
	}

	for _, mItem := range rawMsgs {
		m := mItem.(map[string]any)
		role := m["role"].(string)
		content, _ := m["content"].(string)

		switch role {
		case "user":
			addTurn("user", map[string]any{"type": "text", "text": content})
		case "assistant":
			if content != "" {
				addTurn("assistant", map[string]any{"type": "text", "text": content})
			}
			if tcVal, ok := m["tool_calls"].([]any); ok {
				for _, cItem := range tcVal {
					c := cItem.(map[string]any)
					addTurn("assistant", map[string]any{
						"type":  "tool_use",
						"id":    c["id"],
						"name":  c["name"],
						"input": c["arguments"],
					})
				}
			}
		case "tool":
			addTurn("user", map[string]any{
				"type":        "tool_result",
				"tool_use_id": m["tool_call_id"],
				"content":     content,
			})
		}
	}

	mot := MaxOutputTokens
	if motVal, ok := req["max_output_tokens"]; ok && motVal != nil {
		mot = toInt(motVal)
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": mot,
		"messages":   msgs,
	}

	if sys, ok := req["system"].(string); ok && sys != "" {
		body["system"] = sys
	}

	if toolsVal, ok := req["tools"].([]any); ok && len(toolsVal) > 0 {
		var toolsList []map[string]any
		for _, tItem := range toolsVal {
			t := tItem.(map[string]any)
			desc, _ := t["description"].(string)
			toolsList = append(toolsList, map[string]any{
				"name":         t["name"],
				"description":  desc,
				"input_schema": toolSchema(t),
			})
		}
		body["tools"] = toolsList
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}

	return &HTTPRequest{
		Host: "api.anthropic.com",
		Path: "/v1/messages",
		Headers: map[string]string{
			"Content-Type":      "application/json",
			"anthropic-version": "2023-06-01",
		},
		Body: bytes.TrimSpace(buf.Bytes()),
	}, nil
}

func (a *AnthropicMessages) Auth(key string) map[string]string {
	return map[string]string{"x-api-key": key}
}

func (a *AnthropicMessages) Preflight(model string, out *HTTPRequest) (*HTTPRequest, error) {
	d := json.NewDecoder(bytes.NewReader(out.Body))
	d.UseNumber()
	var body map[string]any
	if err := d.Decode(&body); err != nil {
		return nil, err
	}
	delete(body, "max_tokens")

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range out.Headers {
		headers[k] = v
	}
	return &HTTPRequest{
		Host:    out.Host,
		Path:    "/v1/messages/count_tokens",
		Headers: headers,
		Body:    bytes.TrimSpace(buf.Bytes()),
	}, nil
}

func (a *AnthropicMessages) Parse(status int, raw []byte) (*NeutralReply, error) {
	if status != 200 {
		return nil, NeutralError{Msg: fmt.Sprintf("provider HTTP %d", status)}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil {
		return nil, NeutralError{Msg: "invalid json"}
	}

	if t, _ := r["type"].(string); t != "message" {
		return nil, NeutralError{Msg: "not a message"}
	}

	var textParts []string
	var calls []ToolCall

	if content, ok := r["content"].([]any); ok {
		for _, bVal := range content {
			b, ok := bVal.(map[string]any)
			if !ok {
				continue
			}
			t, _ := b["type"].(string)
			if t == "text" {
				if txt, ok := b["text"].(string); ok {
					textParts = append(textParts, txt)
				}
			} else if t == "tool_use" {
				cid, _ := b["id"].(string)
				name, _ := b["name"].(string)
				argsMap := parseArguments(b["input"])
				calls = append(calls, ToolCall{
					ID:        cid,
					Name:      name,
					Arguments: argsMap,
				})
			}
		}
	}

	u, ok := r["usage"].(map[string]any)
	if !ok || u == nil {
		return nil, NeutralError{Msg: "reply has no token usage"}
	}
	if u["input_tokens"] == nil || u["output_tokens"] == nil {
		return nil, NeutralError{Msg: "reply has no token usage"}
	}
	inTok := toInt(u["input_tokens"])
	outTok := toInt(u["output_tokens"])
	inTok += toInt(u["cache_creation_input_tokens"]) + toInt(u["cache_read_input_tokens"])

	rid, _ := r["id"].(string)
	mName, _ := r["model"].(string)
	if rid == "" || mName == "" {
		return nil, NeutralError{Msg: "reply has no model or id"}
	}

	stopReason, _ := r["stop_reason"].(string)
	stop := "end"
	switch stopReason {
	case "tool_use":
		stop = "tool_calls"
	case "max_tokens":
		stop = "max_tokens"
	}

	tier := "standard"
	if sTier, ok := u["service_tier"].(string); ok && sTier != "" {
		tier = sTier
	}

	return &NeutralReply{
		Text:        strings.Join(textParts, ""),
		ToolCalls:   calls,
		Stop:        stop,
		Usage:       NeutralUsage{InputTokens: inTok, OutputTokens: outTok},
		Model:       mName,
		ResponseID:  rid,
		ServiceTier: tier,
	}, nil
}

// ---------------------------------------------------------------------------
// Gemini GenerateContent Adapter
// ---------------------------------------------------------------------------

type GeminiGenerateContent struct {
	signatures map[string]string
	mu         sync.Mutex
}

func NewGeminiGenerateContent() *GeminiGenerateContent {
	return &GeminiGenerateContent{
		signatures: make(map[string]string),
	}
}

func (a *GeminiGenerateContent) Provider() string { return "gemini" }

func (a *GeminiGenerateContent) Build(model string, req map[string]any) (*HTTPRequest, error) {
	rawMsgs := req["messages"].([]any)
	var contents []map[string]any

	addPart := func(role string, part map[string]any) {
		if len(contents) > 0 && contents[len(contents)-1]["role"] == role {
			lastParts := contents[len(contents)-1]["parts"].([]any)
			contents[len(contents)-1]["parts"] = append(lastParts, part)
		} else {
			contents = append(contents, map[string]any{
				"role":  role,
				"parts": []any{part},
			})
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, mItem := range rawMsgs {
		m := mItem.(map[string]any)
		role := m["role"].(string)
		content, _ := m["content"].(string)

		switch role {
		case "user":
			addPart("user", map[string]any{"text": content})
		case "assistant":
			if content != "" {
				addPart("model", map[string]any{"text": content})
			}
			if tcVal, ok := m["tool_calls"].([]any); ok {
				for _, cItem := range tcVal {
					c := cItem.(map[string]any)
					cid, _ := c["id"].(string)
					sig, hasSig := a.signatures[cid]
					if !hasSig {
						sig = "skip_thought_signature_validator"
					}
					addPart("model", map[string]any{
						"functionCall": map[string]any{
							"id":   cid,
							"name": c["name"],
							"args": c["arguments"],
						},
						"thoughtSignature": sig,
					})
				}
			}
		case "tool":
			tcid, _ := m["tool_call_id"].(string)
			name, _ := m["name"].(string)
			addPart("user", map[string]any{
				"functionResponse": map[string]any{
					"id":   tcid,
					"name": name,
					"response": map[string]any{
						"content": content,
					},
				},
			})
		}
	}

	mot := MaxOutputTokens
	if motVal, ok := req["max_output_tokens"]; ok && motVal != nil {
		mot = toInt(motVal)
	}

	body := map[string]any{
		"contents": contents,
		"generationConfig": map[string]any{
			"maxOutputTokens": mot,
		},
	}

	if sys, ok := req["system"].(string); ok && sys != "" {
		body["systemInstruction"] = map[string]any{
			"parts": []any{map[string]any{"text": sys}},
		}
	}

	if toolsVal, ok := req["tools"].([]any); ok && len(toolsVal) > 0 {
		var decls []map[string]any
		for _, tItem := range toolsVal {
			t := tItem.(map[string]any)
			desc, _ := t["description"].(string)
			decls = append(decls, map[string]any{
				"name":        t["name"],
				"description": desc,
				"parameters":  toolSchema(t),
			})
		}
		body["tools"] = []any{map[string]any{"functionDeclarations": decls}}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}

	return &HTTPRequest{
		Host:    "generativelanguage.googleapis.com",
		Path:    fmt.Sprintf("/v1beta/models/%s:generateContent", model),
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    bytes.TrimSpace(buf.Bytes()),
	}, nil
}

func (a *GeminiGenerateContent) Auth(key string) map[string]string {
	return map[string]string{"x-goog-api-key": key}
}

func (a *GeminiGenerateContent) Preflight(model string, out *HTTPRequest) (*HTTPRequest, error) {
	d := json.NewDecoder(bytes.NewReader(out.Body))
	d.UseNumber()
	var body map[string]any
	if err := d.Decode(&body); err != nil {
		return nil, err
	}
	body["model"] = "models/" + model

	wrapper := map[string]any{
		"generateContentRequest": body,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wrapper); err != nil {
		return nil, err
	}

	return &HTTPRequest{
		Host:    out.Host,
		Path:    fmt.Sprintf("/v1beta/models/%s:countTokens", model),
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    bytes.TrimSpace(buf.Bytes()),
	}, nil
}

func (a *GeminiGenerateContent) Parse(status int, raw []byte) (*NeutralReply, error) {
	if status != 200 {
		return nil, NeutralError{Msg: fmt.Sprintf("provider HTTP %d", status)}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil {
		return nil, NeutralError{Msg: "invalid json"}
	}

	cands, ok := r["candidates"].([]any)
	if !ok || len(cands) == 0 {
		return nil, NeutralError{Msg: "no candidates"}
	}
	cand0, _ := cands[0].(map[string]any)

	var textParts []string
	var calls []ToolCall

	rid, _ := r["responseId"].(string)

	a.mu.Lock()
	defer a.mu.Unlock()

	if content, ok := cand0["content"].(map[string]any); ok {
		if parts, ok := content["parts"].([]any); ok {
			for i, pVal := range parts {
				p, ok := pVal.(map[string]any)
				if !ok {
					continue
				}
				if txt, ok := p["text"].(string); ok && p["thought"] == nil {
					textParts = append(textParts, txt)
				} else if fc, ok := p["functionCall"].(map[string]any); ok {
					cid, _ := fc["id"].(string)
					if cid == "" {
						h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", rid, i)))
						cid = "call_" + hex.EncodeToString(h[:])[:16]
					}
					name, _ := fc["name"].(string)
					argsMap := parseArguments(fc["args"])
					calls = append(calls, ToolCall{
						ID:        cid,
						Name:      name,
						Arguments: argsMap,
					})
					if sig, ok := p["thoughtSignature"].(string); ok && len(a.signatures) < 4096 {
						a.signatures[cid] = sig
					}
				}
			}
		}
	}

	u, ok := r["usageMetadata"].(map[string]any)
	if !ok || u == nil {
		return nil, NeutralError{Msg: "reply has no token usage"}
	}
	if u["promptTokenCount"] == nil {
		return nil, NeutralError{Msg: "reply has no token usage"}
	}
	inTok := toInt(u["promptTokenCount"])
	outTok := toInt(u["candidatesTokenCount"]) + toInt(u["thoughtsTokenCount"])

	mName, _ := r["modelVersion"].(string)
	if rid == "" || mName == "" {
		return nil, NeutralError{Msg: "reply has no model or id"}
	}

	finishReason, _ := cand0["finishReason"].(string)
	stop := "end"
	if len(calls) > 0 {
		stop = "tool_calls"
	} else if finishReason == "MAX_TOKENS" {
		stop = "max_tokens"
	}

	return &NeutralReply{
		Text:        strings.Join(textParts, ""),
		ToolCalls:   calls,
		Stop:        stop,
		Usage:       NeutralUsage{InputTokens: inTok, OutputTokens: outTok},
		Model:       mName,
		ResponseID:  rid,
		ServiceTier: "default",
	}, nil
}

func parseArguments(raw any) map[string]any {
	switch v := raw.(type) {
	case string:
		d := json.NewDecoder(strings.NewReader(v))
		d.UseNumber()
		var res map[string]any
		if err := d.Decode(&res); err == nil {
			return res
		}
		return map[string]any{}
	case map[string]any:
		return v
	default:
		return map[string]any{}
	}
}

// NewAdapters returns map of provider -> Adapter.
func NewAdapters() map[string]Adapter {
	return map[string]Adapter{
		"openai":    &OpenAIResponses{},
		"anthropic": &AnthropicMessages{},
		"gemini":    NewGeminiGenerateContent(),
	}
}
