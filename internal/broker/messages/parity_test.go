package messages

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Python generates request variants from Claude Code's real request shape and
// records what broker/messages_broker.check_request does with each; the Go
// CheckRequest must accept and refuse the same ones and send the same body.
const parityScript = `
import copy, json, sys
sys.path.insert(0, sys.argv[1])
from broker.messages_broker import check_request, Refused
from broker.test_messages_broker import CC_REQ

def v(**changes):
    r = copy.deepcopy(CC_REQ)
    for k, x in changes.items():
        if x is DEL:
            r.pop(k, None)
        else:
            r[k] = x
    return r
DEL = object()
img = lambda src: [{"type": "image", "source": src}]
cases = {
  "claude code request": v(),
  "stripped fields": v(context_management={"edits": []}, output_config={"effort": "low"}),
  "unknown field": v(mcp_servers=[{"url": "https://x"}]),
  "container field": v(container="c1"),
  "wrong model": v(model="claude-opus-5-5"),
  "no model": v(model=DEL),
  "empty messages": v(messages=[]),
  "messages not list": v(messages={"role": "user"}),
  "system role text": v(messages=[{"role": "system", "content": [{"type": "text", "text": "s"}]}, {"role": "user", "content": "hi"}]),
  "system role image": v(messages=[{"role": "system", "content": img({"type": "base64", "media_type": "image/png", "data": "aGk="})}]),
  "bad role": v(messages=[{"role": "tool", "content": "x"}]),
  "message extra keys dropped": v(messages=[{"role": "user", "content": "hi", "output_config": {}, "id": "x"}]),
  "content number": v(messages=[{"role": "user", "content": 5}]),
  "content null": v(messages=[{"role": "user", "content": None}]),
  "block bad type": v(messages=[{"role": "user", "content": [{"type": "server_tool_use"}]}]),
  "block not dict": v(messages=[{"role": "user", "content": ["hi"]}]),
  "inline image": v(messages=[{"role": "user", "content": img({"type": "base64", "media_type": "image/png", "data": "aGk="})}]),
  "url image": v(messages=[{"role": "user", "content": img({"type": "url", "url": "https://example.com/a.png"})}]),
  "url doc in tool result": v(messages=[{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": [{"type": "document", "source": {"type": "url", "url": "https://e"}}]}]}]),
  "file_uri anywhere": v(metadata={"user_id": "u", "x": {"file_uri": "gs://b/a"}}),
  "tools not list": v(tools={"name": "Bash"}),
  "tool explicit custom": v(tools=[{"type": "custom", "name": "B", "input_schema": {"type": "object"}}]),
  "tool no schema": v(tools=[{"name": "B"}]),
  "web search tool": v(tools=[{"type": "web_search_20250305", "name": "web_search"}]),
  "code execution tool": v(tools=[{"type": "code_execution_20250825", "name": "code_execution"}]),
  "bash server tool with schema": v(tools=[{"type": "bash_20250124", "name": "bash", "input_schema": {"type": "object"}}]),
  "tool not dict": v(tools=["Bash"]),
  "no tools": v(tools=DEL),
  "tools null": v(tools=None),
  "tool_choice auto": v(tool_choice={"type": "auto"}),
  "tool_choice named": v(tool_choice={"type": "tool", "name": "Bash"}),
  "tool_choice string": v(tool_choice="auto"),
  "tool_choice bad": v(tool_choice={"type": "required"}),
  "max_tokens small": v(max_tokens=5),
  "max_tokens zero": v(max_tokens=0),
  "max_tokens negative": v(max_tokens=-1),
  "max_tokens float": v(max_tokens=5.0),
  "max_tokens bool": v(max_tokens=True),
  "max_tokens string": v(max_tokens="5"),
  "max_tokens huge": v(max_tokens=10**30),
  "no max_tokens": v(max_tokens=DEL),
  "thinking and stream removed": v(thinking={"type": "enabled", "budget_tokens": 1}, stream=False),
  "temperature decimal": v(temperature=0.7),
  "body not object": [1, 2],
}
out = []
for name, req in cases.items():
    try:
        out.append({"name": name, "req": req, "ok": True, "out": check_request(copy.deepcopy(req))})
    except Refused as e:
        out.append({"name": name, "req": req, "ok": False, "err": str(e)})
print(json.dumps(out))
`

func TestCheckRequestParityWithPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	// The Python reference implementation the Go broker was ported from.
	root, _ := filepath.Abs("../testdata/pyref")
	if _, err := os.Stat(filepath.Join(root, "broker", "messages_broker.py")); err != nil {
		t.Fatalf("python reference broker missing: %v", err)
	}
	cmd := exec.Command(py, "-B", "-c", parityScript, root)
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("python: %v\n%s", err, stderr.String())
	}
	var cases []struct {
		Name string          `json:"name"`
		Req  json.RawMessage `json:"req"`
		OK   bool            `json:"ok"`
		Out  json.RawMessage `json:"out"`
		Err  string          `json:"err"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 40 {
		t.Fatalf("only %d parity cases", len(cases))
	}
	for _, c := range cases {
		var req map[string]any
		d := json.NewDecoder(bytes.NewReader(c.Req))
		d.UseNumber()
		decodeErr := d.Decode(&req)
		var got map[string]any
		var gotErr error
		if decodeErr != nil {
			gotErr = decodeErr // not an object: refused
		} else {
			got, gotErr = CheckRequest(req)
		}
		if (gotErr == nil) != c.OK {
			t.Errorf("%s: python ok=%v (%s), go err=%v", c.Name, c.OK, c.Err, gotErr)
			continue
		}
		if c.OK {
			if !sameJSON(t, c.Out, got) {
				gb, _ := json.Marshal(got)
				t.Errorf("%s: outgoing body differs\npython: %s\ngo:     %s", c.Name, c.Out, gb)
			}
		}
	}
}

func sameJSON(t *testing.T, want json.RawMessage, got any) bool {
	t.Helper()
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) any {
		var v any
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	a, _ := json.Marshal(norm(want))
	b, _ := json.Marshal(norm(gb))
	return bytes.Equal(a, b)
}
