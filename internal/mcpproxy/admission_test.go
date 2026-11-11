package mcpproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/reviaro/guardfil/internal/approval"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdmissionChecksActualCallsWithoutRuntimeApproval(t *testing.T) {
	var checked []string
	p := &Proxy{Server: "bank", Decide: func(server, tool string, args json.RawMessage) error {
		checked = append(checked, server+"."+tool+":"+string(args))
		if tool != "quote" {
			return errors.New("denied")
		}
		return nil
	}}
	var up, down bytes.Buffer
	// No observed runtime items or approval callbacks: a readOnlyHint must
	// never be needed to decide whether the real MCP request is checked.
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"withdraw","arguments":{"amount":100}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"quote","arguments":{"amount":9007199254740993}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"withdraw","arguments":{"amount":200}}}
`
	if err := p.Upstream(strings.NewReader(input), &up, &down); err != nil {
		t.Fatal(err)
	}
	if len(checked) != 3 || len(lines(up.String())) != 1 || strings.Contains(up.String(), "withdraw") {
		t.Fatalf("checked=%v forwarded=%s", checked, up.String())
	}
	if !strings.Contains(checked[1], "9007199254740993") || !strings.Contains(up.String(), "9007199254740993") {
		t.Fatalf("amount rounded: %v %s", checked, up.String())
	}
	if len(lines(down.String())) != 2 || len(p.calls) != 1 {
		t.Fatalf("denials=%s pending=%v", down.String(), p.calls)
	}
}

func TestProxyUsesSessionIdentityForAdmissionAndFiltering(t *testing.T) {
	var log bytes.Buffer
	svc, err := approval.NewService([]byte(`schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-agent-a
    effect: allow
    match:
      principals: [agent.a]
      operations: [tool.invoke]
      resources: [{kind: tool, value: notes.quote}]
`), &log)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	cat, err := approval.ParseCatalog([]byte("catalog_version: 1\ntools: [{id: notes.quote}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCatalog(cat); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = svc.ServeWithPrincipal(l, "agent.a"); close(done) }()
	defer func() { _ = l.Close(); <-done }()
	p := &Proxy{Server: "notes", Decide: SocketDecider(path), Filter: SocketFilter(path)}
	var up, down bytes.Buffer
	if err := p.Upstream(strings.NewReader(`{"id":1,"method":"tools/call","params":{"name":"quote","arguments":{}}}`+"\n"), &up, &down); err != nil {
		t.Fatal(err)
	}
	if up.Len() == 0 || down.Len() != 0 {
		t.Fatalf("session call refused: up=%s down=%s", &up, &down)
	}
	if _, err := p.Filter("notes.quote", "public quote"); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	<-done
	// Serve waits for its connection handlers, making log inspection race-free.
	for _, line := range lines(log.String()) {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil || entry["principal"] != "agent.a" {
			t.Fatalf("wrong attribution: %s", line)
		}
	}
	if len(lines(log.String())) != 2 {
		t.Fatalf("missing admission or filter log: %s", &log)
	}
}

func TestAdmissionFailsClosed(t *testing.T) {
	for _, params := range []string{`{"name":"withdraw","arguments":[]}`, `{"name":4}`, `{"name":"withdraw","arguments":null}`} {
		p := &Proxy{Decide: func(string, string, json.RawMessage) error { t.Fatal("invalid call reached policy"); return nil }}
		var up, down bytes.Buffer
		_ = p.Upstream(strings.NewReader(`{"id":1,"method":"tools/call","params":`+params+"}\n"), &up, &down)
		if up.Len() != 0 || !strings.Contains(down.String(), "blocked") {
			t.Fatalf("up=%s down=%s", &up, &down)
		}
	}
	for _, decide := range []DecideFunc{nil, func(string, string, json.RawMessage) error { return errors.New("unavailable") }} {
		p := &Proxy{Decide: decide}
		var up, down bytes.Buffer
		_ = p.Upstream(strings.NewReader(callReq+"\n"), &up, &down)
		if up.Len() != 0 || !strings.Contains(down.String(), "blocked") {
			t.Fatalf("up=%s down=%s", &up, &down)
		}
	}
}

func TestForwardedArgumentsMatchApprovedObject(t *testing.T) {
	var approved string
	p := &Proxy{Decide: func(_ string, tool string, args json.RawMessage) error {
		approved = tool + ":" + string(args)
		return nil
	}}
	var up bytes.Buffer
	err := p.Upstream(strings.NewReader(`{"id":1,"method":"tools/call","unapproved":"drop","params":{"name":"old","name":"new","arguments":{"amount":1,"amount":2},"unapproved":"drop"}}`+"\n"), &up, nil)
	if err != nil {
		t.Fatal(err)
	}
	if approved != `new:{"amount":2}` || strings.Contains(up.String(), "old") || strings.Contains(up.String(), "unapproved") {
		t.Fatalf("approved=%s forwarded=%s", approved, &up)
	}
}

func TestSocketDeciderRequiresAllow(t *testing.T) {
	for _, response := range []string{`{"effect":"ALLOW"}`, `{"effect":"BLOCK"}`, `{}`, `not json`, `{"effect":"ALLOW"} {}`} {
		t.Run(response, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.sock")
			l, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			request := make(chan string, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				b, _ := io.ReadAll(c)
				request <- string(b)
				_, _ = io.WriteString(c, response)
			}()
			err = SocketDecider(path)("bank", "quote", json.RawMessage(`{"amount":9}`))
			if (err == nil) != (response == `{"effect":"ALLOW"}`) {
				t.Fatalf("reply %q: %v", response, err)
			}
			got := <-request
			if !strings.Contains(got, `"server":"bank"`) || !strings.Contains(got, `"can_filter":true`) || !strings.Contains(got, `"amount":9`) {
				t.Fatalf("request=%s", got)
			}
		})
	}
}
