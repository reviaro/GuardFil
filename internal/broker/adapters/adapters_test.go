package adapters

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func sampleReq() map[string]any {
	return map[string]any{
		"model":  "openai:gpt-6-luna",
		"system": "You trade on paper.",
		"messages": []any{
			map[string]any{"role": "user", "content": "Buy 10 ACME at 12.50"},
			map[string]any{"role": "assistant", "content": "Placing it.", "tool_calls": []any{
				map[string]any{"id": "c1", "name": "place_order", "arguments": map[string]any{
					"symbol":      "ACME",
					"quantity":    json.Number("10"),
					"limit_price": json.Number("12.50"),
				}},
			}},
			map[string]any{"role": "tool", "tool_call_id": "c1", "name": "place_order", "content": `{"ok":true}`},
			map[string]any{"role": "tool", "tool_call_id": "c2", "name": "get_quote", "content": "12.40"},
		},
		"tools": []any{
			map[string]any{
				"name":        "place_order",
				"description": "Place an order",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"symbol": map[string]any{"type": "string"},
					},
				},
			},
		},
		"max_output_tokens": json.Number("256"),
	}
}

var openAIReply = []byte(`{
  "id": "resp_1",
  "status": "completed",
  "model": "gpt-6-luna",
  "service_tier": "default",
  "output": [
    {"type": "message", "content": [{"type": "output_text", "text": "Done."}]},
    {"type": "function_call", "call_id": "call_9", "name": "place_order", "arguments": "{\"symbol\":\"ACME\",\"quantity\":5,\"limit_price\":9.95}"}
  ],
  "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150}
}`)

var anthropicReply = []byte(`{
  "id": "msg_1",
  "type": "message",
  "role": "assistant",
  "model": "claude-sonnet-5-5",
  "content": [
    {"type": "text", "text": "Done."},
    {"type": "tool_use", "id": "toolu_9", "name": "place_order", "input": {"symbol": "ACME", "quantity": 5, "limit_price": 9.95}}
  ],
  "stop_reason": "tool_use",
  "usage": {"input_tokens": 100, "cache_read_input_tokens": 20, "output_tokens": 30}
}`)

var geminiReply = []byte(`{
  "responseId": "r_1",
  "modelVersion": "gemini-flash-latest",
  "candidates": [{
    "content": {
      "role": "model",
      "parts": [
        {"text": "Done."},
        {"functionCall": {"name": "place_order", "args": {"symbol": "ACME", "quantity": 5, "limit_price": 9.95}}}
      ]
    },
    "finishReason": "STOP"
  }],
  "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 25, "thoughtsTokenCount": 5}
}`)

func TestSameReplyFromEveryProvider(t *testing.T) {
	adapters := NewAdapters()

	cases := map[string][]byte{
		"openai":    openAIReply,
		"anthropic": anthropicReply,
		"gemini":    geminiReply,
	}

	for name, raw := range cases {
		a := adapters[name]
		r, err := a.Parse(200, raw)
		if err != nil {
			t.Fatalf("%s parse error: %v", name, err)
		}
		if r.Text != "Done." {
			t.Errorf("%s text: expected Done., got %s", name, r.Text)
		}
		if r.Stop != "tool_calls" {
			t.Errorf("%s stop: expected tool_calls, got %s", name, r.Stop)
		}
		if r.Usage.InputTokens != 120 || r.Usage.OutputTokens != 30 {
			t.Errorf("%s usage mismatch: %+v", name, r.Usage)
		}
		if len(r.ToolCalls) != 1 {
			t.Fatalf("%s expected 1 tool call, got %d", name, len(r.ToolCalls))
		}
		call := r.ToolCalls[0]
		if call.Name != "place_order" {
			t.Errorf("%s call name: %s", name, call.Name)
		}
		lp := call.Arguments["limit_price"]
		lpStr := fmt.Sprint(lp)
		if lpStr != "9.95" {
			t.Errorf("%s limit_price: expected 9.95, got %v", name, lp)
		}
	}
}

func TestOpenAIRequest(t *testing.T) {
	a := &OpenAIResponses{}
	req := sampleReq()
	out, err := a.Build("gpt-6-luna", req)
	if err != nil {
		t.Fatal(err)
	}

	var body map[string]any
	if err := json.Unmarshal(out.Body, &body); err != nil {
		t.Fatal(err)
	}

	if body["instructions"] != "You trade on paper." {
		t.Errorf("instructions mismatch: %v", body["instructions"])
	}
	if body["store"] != false {
		t.Errorf("store mismatch: %v", body["store"])
	}

	inputs := body["input"].([]any)
	if len(inputs) != 5 {
		t.Fatalf("expected 5 input items, got %d", len(inputs))
	}
	// user, assistant, function_call, function_call_output, function_call_output
	types := make([]string, len(inputs))
	for i, in := range inputs {
		inMap := in.(map[string]any)
		if t, ok := inMap["type"].(string); ok {
			types[i] = t
		} else if r, ok := inMap["role"].(string); ok {
			types[i] = r
		}
	}
	expectedTypes := []string{"user", "assistant", "function_call", "function_call_output", "function_call_output"}
	for i := range expectedTypes {
		if types[i] != expectedTypes[i] {
			t.Errorf("type %d: expected %s, got %s", i, expectedTypes[i], types[i])
		}
	}

	fcArgs := inputs[2].(map[string]any)["arguments"].(string)
	if !strings.Contains(fcArgs, `"limit_price":12.50`) && !strings.Contains(fcArgs, `"limit_price":"12.50"`) {
		t.Errorf("expected limit_price in function call arguments, got %s", fcArgs)
	}

	tools := body["tools"].([]any)
	if tools[0].(map[string]any)["type"] != "function" {
		t.Errorf("tool type mismatch: %v", tools[0])
	}
	if toInt(body["max_output_tokens"]) != 256 {
		t.Errorf("max_output_tokens mismatch: %v", body["max_output_tokens"])
	}
}

func TestAnthropicRequest(t *testing.T) {
	a := &AnthropicMessages{}
	req := sampleReq()
	out, err := a.Build("claude-sonnet-5-5", req)
	if err != nil {
		t.Fatal(err)
	}
	if out.Path != "/v1/messages" {
		t.Errorf("path mismatch: %s", out.Path)
	}

	var body map[string]any
	if err := json.Unmarshal(out.Body, &body); err != nil {
		t.Fatal(err)
	}

	msgs := body["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 merged turns, got %d", len(msgs))
	}
	roles := []string{
		msgs[0].(map[string]any)["role"].(string),
		msgs[1].(map[string]any)["role"].(string),
		msgs[2].(map[string]any)["role"].(string),
	}
	if roles[0] != "user" || roles[1] != "assistant" || roles[2] != "user" {
		t.Errorf("roles mismatch: %v", roles)
	}

	// Tool results merged into 3rd message
	content3 := msgs[2].(map[string]any)["content"].([]any)
	if len(content3) != 2 {
		t.Errorf("expected 2 merged tool results, got %d", len(content3))
	}
	if content3[0].(map[string]any)["type"] != "tool_result" {
		t.Errorf("expected tool_result, got %v", content3[0])
	}

	if body["system"] != "You trade on paper." {
		t.Errorf("system mismatch: %v", body["system"])
	}
	if toInt(body["max_tokens"]) != 256 {
		t.Errorf("max_tokens mismatch: %v", body["max_tokens"])
	}
}

func TestGeminiRequest(t *testing.T) {
	a := NewGeminiGenerateContent()
	req := sampleReq()
	out, err := a.Build("gemini-flash-latest", req)
	if err != nil {
		t.Fatal(err)
	}
	if out.Path != "/v1beta/models/gemini-flash-latest:generateContent" {
		t.Errorf("path mismatch: %s", out.Path)
	}

	var body map[string]any
	if err := json.Unmarshal(out.Body, &body); err != nil {
		t.Fatal(err)
	}

	contents := body["contents"].([]any)
	if len(contents) != 3 {
		t.Fatalf("expected 3 contents turns, got %d", len(contents))
	}
	roles := []string{
		contents[0].(map[string]any)["role"].(string),
		contents[1].(map[string]any)["role"].(string),
		contents[2].(map[string]any)["role"].(string),
	}
	if roles[0] != "user" || roles[1] != "model" || roles[2] != "user" {
		t.Errorf("roles mismatch: %v", roles)
	}

	turn1Parts := contents[1].(map[string]any)["parts"].([]any)
	fcFound := false
	for _, p := range turn1Parts {
		if _, ok := p.(map[string]any)["functionCall"]; ok {
			fcFound = true
		}
	}
	if !fcFound {
		t.Errorf("expected functionCall in turn 1 parts, got %v", turn1Parts)
	}

	turn2Parts := contents[2].(map[string]any)["parts"].([]any)
	fResp := turn2Parts[0].(map[string]any)["functionResponse"].(map[string]any)
	respContent := fResp["response"].(map[string]any)["content"]
	if respContent != `{"ok":true}` {
		t.Errorf("response content mismatch: %v", respContent)
	}
}

func TestKeysNeverInBody(t *testing.T) {
	adapters := NewAdapters()
	req := sampleReq()
	secret := "SECRETKEY"

	for name, a := range adapters {
		auth := a.Auth(secret)
		if len(auth) == 0 {
			t.Errorf("%s auth is empty", name)
		}
		out, err := a.Build("m", req)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out.Body), secret) {
			t.Errorf("%s body contains secret key!", name)
		}
	}
}

func TestValidate(t *testing.T) {
	req := sampleReq()
	p, m, err := Validate(req)
	if err != nil || p != "openai" || m != "gpt-6-luna" {
		t.Fatalf("expected openai/gpt-6-luna, got %s/%s (%v)", p, m, err)
	}

	// Bad cases
	badCases := []map[string]any{
		// Missing provider prefix
		map[string]any{"model": "gpt-6-luna", "messages": req["messages"]},
		// Unknown provider
		map[string]any{"model": "azure:x", "messages": req["messages"]},
		// Extra unknown field
		func() map[string]any {
			c := sampleReq()
			c["extra"] = 1
			return c
		}(),
		// max_output_tokens > 1024
		func() map[string]any {
			c := sampleReq()
			c["max_output_tokens"] = 5000
			return c
		}(),
		// empty messages
		map[string]any{"model": "openai:gpt-6-luna", "messages": []any{}},
		// first message assistant
		map[string]any{"model": "openai:gpt-6-luna", "messages": []any{map[string]any{"role": "assistant", "content": "x"}}},
		// invalid tool name with space
		func() map[string]any {
			c := sampleReq()
			c["tools"] = []any{map[string]any{"name": "bad name"}}
			return c
		}(),
	}

	for idx, b := range badCases {
		if _, _, err := Validate(b); err == nil {
			t.Errorf("bad case %d should fail validation, but succeeded", idx)
		}
	}
}
