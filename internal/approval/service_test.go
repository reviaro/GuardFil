package approval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const notesPolicy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-notes-writes
    effect: allow
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /workspace/notes/**
  - id: allow-codex-shell
    effect: allow
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: codex.exec_command
`

func newService(t *testing.T) (*Service, *bytes.Buffer) {
	t.Helper()
	var log bytes.Buffer
	s, err := NewService([]byte(notesPolicy), &log)
	if err != nil {
		t.Fatal(err)
	}
	return s, &log
}

func lastEntry(t *testing.T, log *bytes.Buffer) LogEntry {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	var e LogEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
		t.Fatalf("log line %q: %v", lines[len(lines)-1], err)
	}
	return e
}

func TestNewServiceRejectsBadPolicyAndNilLog(t *testing.T) {
	if _, err := NewService([]byte("not: a policy"), &bytes.Buffer{}); err == nil {
		t.Fatal("bad policy admitted")
	}
	if _, err := NewService([]byte(notesPolicy), nil); err == nil {
		t.Fatal("nil log admitted")
	}
}

func TestDecideLogsWithoutPayload(t *testing.T) {
	s, log := newService(t)
	out := s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/notes/a.txt","change":"add"}]}`))
	if out.Effect != "ALLOW" {
		t.Fatalf("notes write: %+v", out)
	}
	e := lastEntry(t, log)
	if e.Kind != "file_write" || e.Effect != "ALLOW" || len(e.Paths) != 1 || e.Paths[0] != "/workspace/notes/a.txt" ||
		e.PolicyDigest != s.PolicyDigest() || len(e.RequestSHA256) != 64 {
		t.Fatalf("entry: %+v", e)
	}

	out = s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/x.canary","change":"add"}]}`))
	if out.Effect != "BLOCK" {
		t.Fatalf("outside write: %+v", out)
	}

	out = s.Decide([]byte(`{"kind":"shell","command":["bash","-lc","echo SECRET-TOKEN"],"cwd":"/workspace"}`))
	if out.Effect != "ALLOW" {
		t.Fatalf("shell: %+v", out)
	}
	e = lastEntry(t, log)
	if e.Kind != "shell" || e.Tool != "codex.exec_command" {
		t.Fatalf("shell entry: %+v", e)
	}
	if strings.Contains(log.String(), "SECRET-TOKEN") || strings.Contains(log.String(), "echo") {
		t.Fatal("command text reached the decision log")
	}

	out = s.Decide([]byte(`{"server":"testmcp","tool":"write_canary","arguments":{"content":"SECRET-ARG"}}`))
	if out.Effect != "BLOCK" { // not allowed by this policy
		t.Fatalf("mcp: %+v", out)
	}
	if e = lastEntry(t, log); e.Kind != "mcp" || e.Tool != "testmcp.write_canary" || strings.Contains(log.String(), "SECRET-ARG") {
		t.Fatalf("mcp entry: %+v", e)
	}

	s.Decide([]byte(`{"kind":"shell"}`))
	if e = lastEntry(t, log); e.Kind != "invalid" || e.Effect != "BLOCK" {
		t.Fatalf("invalid entry: %+v", e)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestDecideBlocksWhenLogFails(t *testing.T) {
	s, err := NewService([]byte(notesPolicy), failWriter{})
	if err != nil {
		t.Fatal(err)
	}
	out := s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/notes/a.txt","change":"add"}]}`))
	if out.Effect != "BLOCK" || out.Reasons[0] != "DECISION_LOG_UNAVAILABLE" {
		t.Fatalf("unlogged decision not blocked: %+v", out)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gfa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func ask(t *testing.T, sock, req string) Output {
	t.Helper()
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(req + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var out Output
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("reply %q: %v", line, err)
	}
	return out
}

func TestServeOverUnixSocket(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "a.sock")
	s, log := newService(t)
	l, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(sock)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()

	if out := ask(t, sock, `{"kind":"file_write","changes":[{"path":"/workspace/notes/a.txt","change":"add"}]}`); out.Effect != "ALLOW" {
		t.Fatalf("allow over socket: %+v", out)
	}
	if out := ask(t, sock, `{"kind":"file_write","changes":[{"path":"/etc/passwd","change":"update"}]}`); out.Effect != "BLOCK" {
		t.Fatalf("block over socket: %+v", out)
	}
	if out := ask(t, sock, strings.Repeat("x", MaxRequestBytes+10)); out.Effect != "BLOCK" || out.Reasons[0] != "REQUEST_TOO_LARGE" {
		t.Fatalf("oversize: %+v", out)
	}
	if n := strings.Count(log.String(), "\n"); n != 2 { // the oversize request is refused before deciding
		t.Fatalf("log lines = %d", n)
	}
	_ = l.Close()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestListenUnixRefusesNonSocket(t *testing.T) {
	dir := shortTempDir(t)
	p := filepath.Join(dir, "a.sock")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(p); err == nil {
		t.Fatal("regular file replaced by socket")
	}
}

func TestListenUnixReplacesStaleSocket(t *testing.T) {
	dir := shortTempDir(t)
	p := filepath.Join(dir, "a.sock")
	l1, err := ListenUnix(p)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash: the file stays, the listener is gone.
	if ul, ok := l1.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = l1.Close()
	l2, err := ListenUnix(p)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	_ = l2.Close()
}

func TestOpenDecisionLog(t *testing.T) {
	dir := shortTempDir(t)
	p := filepath.Join(dir, "decisions.jsonl")
	f, err := OpenDecisionLog(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDecisionLog(link); err == nil {
		t.Fatal("symlink followed")
	}
	loose := filepath.Join(dir, "loose.jsonl")
	if err := os.WriteFile(loose, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDecisionLog(loose); err == nil {
		t.Fatal("group-readable log admitted")
	}
}

func TestMonitorRuleAllowsAndIsLoggedAsMonitored(t *testing.T) {
	pol := notesPolicy + `  - id: watch-tmp-writes
    effect: monitor
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /workspace/tmp/**
  - id: block-secret-writes
    effect: deny
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /workspace/tmp/secret/**
  - id: watch-secret-writes
    effect: monitor
    match:
      principals: [codex-agent]
      operations: [filesystem.write]
      resources:
        - kind: path
          value: /workspace/tmp/secret/**
`
	var log bytes.Buffer
	s, err := NewService([]byte(pol), &log)
	if err != nil {
		t.Fatal(err)
	}
	out := s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/tmp/x","change":"add"}]}`))
	if out.Effect != "ALLOW" || !Monitored(out) || len(out.RuleIDs) != 1 || out.RuleIDs[0] != "watch-tmp-writes" {
		t.Fatalf("monitored write: %+v", out)
	}
	if e := lastEntry(t, &log); !e.Monitored || e.Effect != "ALLOW" {
		t.Fatalf("log entry not marked monitored: %+v", e)
	}
	out = s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/notes/a","change":"add"}]}`))
	if out.Effect != "ALLOW" || Monitored(out) {
		t.Fatalf("plain allow marked monitored: %+v", out)
	}
	if strings.Contains(strings.Split(strings.TrimSpace(log.String()), "\n")[1], "monitored") {
		t.Fatal("plain allow logged as monitored")
	}
	out = s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/tmp/secret/k","change":"add"}]}`))
	if out.Effect != "BLOCK" || Monitored(out) {
		t.Fatalf("deny lost to monitor: %+v", out)
	}
	// A mixed write is ALLOW only if every path is: one monitored path and one allowed path.
	out = s.Decide([]byte(`{"kind":"file_write","changes":[{"path":"/workspace/tmp/y","change":"add"},{"path":"/workspace/notes/b","change":"add"}]}`))
	if out.Effect != "ALLOW" || !Monitored(out) {
		t.Fatalf("mixed write: %+v", out)
	}
}

func TestDetailForOwner(t *testing.T) {
	cases := map[string]string{
		`{"kind":"shell","command":["bash","-lc","echo hi > a.txt"],"cwd":"/workspace"}`: `bash -lc 'echo hi > a.txt'   (in /workspace)`,
		`{"kind":"shell","command":["ls","-la"],"cwd":"/w"}`:                             `ls -la   (in /w)`,
		`{"kind":"shell","command":["echo","it's"],"cwd":"/w"}`:                          `echo 'it'"'"'s'   (in /w)`,
		`{"server":"testmcp","tool":"write_canary","arguments":{"content":"x"}}`:         `{"content":"x"}`,
		`{"kind":"file_write","changes":[{"path":"/workspace/a","change":"add"}]}`:       ``,
		`not json`: ``,
	}
	for in, want := range cases {
		if got := Detail([]byte(in)); got != want {
			t.Errorf("Detail(%s) = %q, want %q", in, got, want)
		}
	}
	long := `{"kind":"shell","command":["echo","` + strings.Repeat("a", 3000) + `"],"cwd":"/w"}`
	if got := []rune(Detail([]byte(long))); len(got) != MaxDetailRunes+1 {
		t.Errorf("long detail has %d runes", len(got))
	}
}
