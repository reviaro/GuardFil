// Package mcpproxy runs a stdio MCP server behind GuardFil's filter.
//
// It sits between an MCP client (the agent) and an MCP server, inside the
// agent's container, and passes JSON-RPC lines between them.  Everything the
// server sends the client is either filtered by GuardFil or withheld:
//
//   - tools/call results: each text item, and any structuredContent, goes
//     through GuardFil's filter socket; items that cannot be read as text
//     (images, audio, resources, unknown types) are replaced by a notice.
//     Other result fields (_meta and the like) are dropped.
//   - other responses (tools/list, resources/read, prompts/get, ...): the
//     whole result is filtered as JSON text, so tool descriptions and
//     resource contents are scanned too, and so is the initialize result
//     (its instructions are free text).  A ping result is forwarded as {}.
//   - error responses: the message and data are filtered.
//   - messages the server starts itself: list-changed notifications pass
//     without params; progress, cancelled and logging notifications are
//     filtered (their message, reason and data are free text); anything else
//     (requests such as sampling or elicitation, unknown notifications) is
//     withheld, and a server request gets a JSON-RPC error back.
//
// If GuardFil cannot filter something, the client gets an error result in its
// place, never the unfiltered text. Each tools/call is authorized against the
// actual arguments before forwarding, independently of runtime approvals or
// server-supplied annotations.
package mcpproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// MaxLine bounds one JSON-RPC message in either direction.
const MaxLine = 4 << 20

// MaxReply bounds one filter-socket reply.
const MaxReply = 4 << 20

// FilterTimeout bounds one filter request.
const FilterTimeout = 30 * time.Second

// Withheld is the tools/call result sent when GuardFil cannot filter one.
var Withheld = map[string]any{
	"content": []any{map[string]any{"type": "text", "text": "GuardFil could not filter this tool result, so it was withheld."}},
	"isError": true,
}

// Notifications that carry no information beyond their name: forwarded
// with any params dropped.
var bareNotifications = map[string]bool{
	"notifications/tools/list_changed":     true,
	"notifications/resources/list_changed": true,
	"notifications/prompts/list_changed":   true,
}

// Notifications forwarded only after their params are filtered: progress
// (message), cancelled (reason) and logging (data) carry free text.
var filteredNotifications = map[string]bool{
	"notifications/progress":  true,
	"notifications/cancelled": true,
	"notifications/message":   true,
}

// FilterFunc filters one text for tool (server.tool or server.method).
type FilterFunc func(tool, text string) (string, error)

// SocketFilter asks GuardFil's session socket (or a legacy filter-only socket).
func SocketFilter(path string) FilterFunc {
	return func(tool, text string) (string, error) {
		conn, err := net.DialTimeout("unix", path, FilterTimeout)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(DecisionTimeout))
		req, err := json.Marshal(map[string]string{"kind": "filter", "tool": tool, "content": text})
		if err != nil {
			return "", err
		}
		if _, err := conn.Write(append(req, '\n')); err != nil {
			return "", err
		}
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		buf, err := io.ReadAll(io.LimitReader(conn, MaxReply+1))
		if err != nil {
			return "", err
		}
		if len(buf) > MaxReply {
			return "", errors.New("filter reply too large")
		}
		// A blocked result comes back as GuardFil's own "withheld" text.
		var out struct {
			Content *string `json:"content"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(buf), &out); err != nil || out.Content == nil {
			return "", errors.New("no filtered content")
		}
		return *out.Content, nil
	}
}

// Proxy carries one client/server pair.
type Proxy struct {
	Server string     // the MCP server's name, as in GuardFil tool IDs (server.tool)
	Filter FilterFunc // usually SocketFilter
	Decide DecideFunc // required for tools/call; nil fails closed
	Log    func(string)

	mu    sync.Mutex
	calls map[string]call // pending client request id -> what was asked
}

type call struct {
	method string
	tool   string
}

func (p *Proxy) logf(format string, a ...any) {
	if p.Log != nil {
		p.Log(fmt.Sprintf(format, a...))
	}
}

// Upstream authorizes tool calls, remembering only forwarded requests.
// replyToClient must share a serialized writer with Downstream.
func (p *Proxy) Upstream(client io.Reader, server, replyToClient io.Writer) error {
	sc := bufio.NewScanner(client)
	sc.Buffer(make([]byte, 64<<10), MaxLine)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		msg, err := canonicalObject(sc.Bytes())
		if err != nil {
			return err
		}
		id := msg["id"]
		hasID := len(id) > 0 && string(id) != "null"
		if hasID && id[0] != '"' && (id[0] < '0' || id[0] > '9') && id[0] != '-' {
			return errors.New("invalid request id")
		}
		var method string
		if json.Unmarshal(msg["method"], &method) != nil || method == "" {
			return errors.New("invalid client method")
		}
		c := call{method: method}
		if method == "tools/call" {
			params, err := canonicalObject(msg["params"])
			if err == nil {
				err = json.Unmarshal(params["name"], &c.tool)
			}
			args := params["arguments"]
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			_, argErr := canonicalObject(args)
			if err != nil || argErr != nil || c.tool == "" || !hasID || p.Decide == nil {
				err = errors.New("unreadable or ungated tool call")
			} else {
				err = p.Decide(p.Server, c.tool, args)
			}
			if err != nil {
				p.logf("blocked tools/call")
				if hasID && replyToClient != nil {
					out := marshal(map[string]any{"jsonrpc": "2.0", "id": id,
						"error": map[string]any{"code": -32000, "message": "GuardFil blocked this tool call"}})
					if _, err := replyToClient.Write(append(out, '\n')); err != nil {
						return err
					}
				}
				continue
			}
			// Forward only the exact name and arguments that policy approved.
			msg = map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`), "id": id,
				"method": json.RawMessage(`"tools/call"`),
				"params": marshal(map[string]any{"name": c.tool, "arguments": args})}
		}
		if hasID {
			p.mu.Lock()
			if p.calls == nil {
				p.calls = map[string]call{}
			}
			if _, exists := p.calls[canonID(id)]; exists || len(p.calls) >= 128 {
				p.mu.Unlock()
				return errors.New("duplicate request id or too many pending requests")
			}
			p.calls[canonID(id)] = c
			p.mu.Unlock()
		}
		if _, err := server.Write(append(marshal(msg), '\n')); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Downstream copies server lines to the client, filtering or withholding each.
// replyToServer receives JSON-RPC errors for server-initiated requests.
func (p *Proxy) Downstream(server io.Reader, client io.Writer, replyToServer io.Writer) error {
	sc := bufio.NewScanner(server)
	sc.Buffer(make([]byte, 64<<10), MaxLine)
	for sc.Scan() {
		out, back := p.handle(sc.Bytes())
		if back != nil && replyToServer != nil {
			if _, err := replyToServer.Write(append(back, '\n')); err != nil {
				return err
			}
		}
		if out != nil {
			if _, err := client.Write(append(out, '\n')); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// handle returns the line for the client (nil: withheld) and an optional
// reply for the server.
func (p *Proxy) handle(line []byte) (toClient, toServer []byte) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		p.logf("withheld a server line that is not a JSON object")
		return nil, nil
	}
	id, hasID := msg["id"]
	hasID = hasID && string(id) != "null"
	var method string
	if raw, ok := msg["method"]; ok {
		if json.Unmarshal(raw, &method) != nil || method == "" {
			p.logf("withheld a server message with a bad method")
			return nil, nil
		}
	}

	if method != "" { // the server started this message
		if hasID {
			p.logf("withheld server request %q", method)
			back, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
				"error": map[string]any{"code": -32601, "message": "not available through GuardFil"}})
			return nil, back
		}
		if bareNotifications[method] {
			return marshal(map[string]string{"jsonrpc": "2.0", "method": method}), nil
		}
		if filteredNotifications[method] {
			label := p.Server + ".log"
			if method != "notifications/message" {
				label = p.Server + "." + strings.TrimPrefix(method, "notifications/")
			}
			raw := msg["params"]
			if len(raw) == 0 {
				raw = json.RawMessage(`{}`)
			}
			params, ok := p.filterJSON(label, raw)
			if !ok {
				return nil, nil
			}
			return marshal(map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`),
				"method": json.RawMessage(strconvQuote(method)), "params": params}), nil
		}
		p.logf("withheld server notification %q", method)
		return nil, nil
	}

	if !hasID {
		p.logf("withheld a server message with neither method nor id")
		return nil, nil
	}
	p.mu.Lock()
	c, known := p.calls[canonID(id)]
	delete(p.calls, canonID(id))
	p.mu.Unlock()
	if !known {
		p.logf("withheld a response to no pending request")
		return nil, nil
	}

	if raw, ok := msg["error"]; ok {
		filtered, ok := p.filterJSON(p.Server+"."+c.label(), raw)
		if !ok {
			filtered = json.RawMessage(`{"code":-32603,"message":"GuardFil could not filter this error, so it was withheld."}`)
		}
		return marshal(map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`), "id": id, "error": filtered}), nil
	}
	raw, ok := msg["result"]
	if !ok {
		p.logf("withheld a response with neither result nor error")
		return nil, nil
	}
	var result json.RawMessage
	switch {
	case c.method == "ping":
		// A ping result is empty by definition; anything else in it is dropped.
		result = json.RawMessage(`{}`)
	case c.method == "tools/call":
		result = p.toolResult(p.Server+"."+c.tool, raw)
	default:
		filtered, ok := p.filterJSON(p.Server+"."+c.method, raw)
		if !ok {
			back, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id,
				"error": map[string]any{"code": -32603, "message": "GuardFil could not filter this result, so it was withheld."}})
			return back, nil
		}
		result = filtered
	}
	return marshal(map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`), "id": id, "result": result}), nil
}

func (c call) label() string {
	if c.method == "tools/call" {
		return c.tool
	}
	return c.method
}

// toolResult rebuilds a tools/call result from filtered parts only.
func (p *Proxy) toolResult(tool string, raw json.RawMessage) json.RawMessage {
	var in struct {
		Content           []json.RawMessage `json:"content"`
		StructuredContent json.RawMessage   `json:"structuredContent"`
		IsError           *bool             `json:"isError"`
	}
	withheld := marshal(Withheld)
	if err := json.Unmarshal(raw, &in); err != nil {
		return withheld
	}
	out := map[string]any{}
	items := make([]any, 0, len(in.Content))
	for _, item := range in.Content {
		var it struct {
			Type string  `json:"type"`
			Text *string `json:"text"`
		}
		if json.Unmarshal(item, &it) == nil && it.Type == "text" && it.Text != nil {
			text, err := p.Filter(tool, *it.Text)
			if err != nil {
				p.logf("could not filter a %s result: %v", tool, err)
				return withheld
			}
			items = append(items, map[string]any{"type": "text", "text": text})
			continue
		}
		kind := it.Type
		if kind == "" {
			kind = "unreadable"
		}
		items = append(items, map[string]any{"type": "text", "text": "[" + kind + " withheld by GuardFil]"})
	}
	out["content"] = items
	if len(in.StructuredContent) > 0 && string(in.StructuredContent) != "null" {
		sc, ok := p.filterJSON(tool, in.StructuredContent)
		if !ok {
			return withheld
		}
		out["structuredContent"] = sc
	}
	if in.IsError != nil {
		out["isError"] = *in.IsError
	}
	return marshal(out)
}

// filterJSON filters a JSON value as text and parses it back.
func (p *Proxy) filterJSON(tool string, raw json.RawMessage) (json.RawMessage, bool) {
	text, err := p.Filter(tool, string(raw))
	if err != nil {
		p.logf("could not filter %s: %v", tool, err)
		return nil, false
	}
	if !json.Valid([]byte(text)) {
		p.logf("filtered %s is not JSON; withheld", tool)
		return nil, false
	}
	return json.RawMessage(text), true
}

func canonID(id json.RawMessage) string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(id))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return string(id)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"GuardFil proxy error"}}`)
	}
	return b
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
