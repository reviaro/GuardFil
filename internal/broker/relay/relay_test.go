package relay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeBrokerReply struct {
	status int
	body   []byte
}

type fakeBrokerServer struct {
	socketPath          string
	listener            net.Listener
	receivedFrames      [][]byte
	connectionsAccepted int
	replies             []fakeBrokerReply
	mu                  sync.Mutex
	stopCh              chan struct{}
}

func newFakeBrokerServer(t *testing.T, socketPath string, replies []fakeBrokerReply) *fakeBrokerServer {
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket %s: %v", socketPath, err)
	}
	fb := &fakeBrokerServer{
		socketPath: socketPath,
		listener:   l,
		replies:    replies,
		stopCh:     make(chan struct{}),
	}
	go fb.serve()
	return fb
}

func (fb *fakeBrokerServer) serve() {
	for {
		conn, err := fb.listener.Accept()
		if err != nil {
			select {
			case <-fb.stopCh:
				return
			default:
				return
			}
		}

		fb.mu.Lock()
		fb.connectionsAccepted++
		fb.mu.Unlock()

		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))

			var hdr [4]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint32(hdr[:])
			body := make([]byte, length)
			if _, err := io.ReadFull(c, body); err != nil {
				return
			}

			fb.mu.Lock()
			fb.receivedFrames = append(fb.receivedFrames, body)
			status := 200
			replyBody := []byte("data: [DONE]\n\n")
			if len(fb.replies) > 0 {
				r := fb.replies[0]
				fb.replies = fb.replies[1:]
				status = r.status
				replyBody = r.body
			}
			fb.mu.Unlock()

			var replyHdr [8]byte
			binary.BigEndian.PutUint32(replyHdr[0:4], uint32(status))
			binary.BigEndian.PutUint32(replyHdr[4:8], uint32(len(replyBody)))
			_, _ = c.Write(replyHdr[:])
			_, _ = c.Write(replyBody)
		}(conn)
	}
}

func (fb *fakeBrokerServer) close() {
	close(fb.stopCh)
	_ = fb.listener.Close()
}

func TestRelay(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_relay_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "broker.sock")
	fb := newFakeBrokerServer(t, sockPath, []fakeBrokerReply{
		{status: 200, body: []byte("event: response.completed\ndata: {}\n\n")},
	})
	defer fb.close()

	cfg := Config{
		Host:             "127.0.0.1",
		Port:             0,
		SocketPath:       sockPath,
		AllowedPath:      AllowedPathResponses,
		SocketTimeoutSec: 5 * time.Second,
	}
	server := NewServer(cfg)
	if err := server.Listen(); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer server.Close()
	go func() { _ = server.Serve() }()

	port := server.Port()
	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Wrong path refused with 404
	{
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", port), bytes.NewReader([]byte(`{"model":"gpt-6-luna"}`)))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}
		if !resp.Close && resp.Header.Get("Connection") != "close" {
			t.Errorf("expected close, got close=%v header=%s", resp.Close, resp.Header.Get("Connection"))
		}
		var errObj map[string]string
		if err := json.Unmarshal(body, &errObj); err != nil || errObj["error"] == "" {
			t.Errorf("expected json error, got %s", string(body))
		}
	}

	// 2. Wrong methods refused with 405
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d/v1/responses", port), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: expected application/json, got %s", method, ct)
		}
		if !resp.Close && resp.Header.Get("Connection") != "close" {
			t.Errorf("%s: expected close, got close=%v header=%s", method, resp.Close, resp.Header.Get("Connection"))
		}
	}

	fb.mu.Lock()
	if len(fb.receivedFrames) != 0 || fb.connectionsAccepted != 0 {
		t.Errorf("expected 0 frames forwarded, got %d", len(fb.receivedFrames))
	}
	fb.mu.Unlock()

	// 3. Oversize content length refused (413)
	{
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		rawReq := fmt.Sprintf("POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: %d\r\n\r\n", port, MaxRequestBytes+1)
		_, _ = conn.Write([]byte(rawReq))
		respBuf := make([]byte, 4096)
		n, _ := conn.Read(respBuf)
		conn.Close()
		if !bytes.Contains(respBuf[:n], []byte("413")) {
			t.Errorf("expected 413, got %s", string(respBuf[:n]))
		}
	}

	// 4. Chunked transfer encoding refused (400)
	{
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		rawReq := fmt.Sprintf("POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", port)
		_, _ = conn.Write([]byte(rawReq))
		respBuf := make([]byte, 4096)
		n, _ := conn.Read(respBuf)
		conn.Close()
		if !bytes.Contains(respBuf[:n], []byte("400")) {
			t.Errorf("expected 400 for chunked, got %s", string(respBuf[:n]))
		}
	}

	// 5. Missing content length refused (411)
	{
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		rawReq := fmt.Sprintf("POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port)
		_, _ = conn.Write([]byte(rawReq))
		respBuf := make([]byte, 4096)
		n, _ := conn.Read(respBuf)
		conn.Close()
		if !bytes.Contains(respBuf[:n], []byte("411")) {
			t.Errorf("expected 411 for missing content-length, got %s", string(respBuf[:n]))
		}
	}

	// 6. Round trip 200 (SSE) and 400, and Authorization header never forwarded
	ssePayload := []byte("event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
	errPayload := []byte("{\"error\":\"bad_request\"}")

	fb.mu.Lock()
	fb.replies = []fakeBrokerReply{
		{status: 200, body: ssePayload},
		{status: 400, body: errPayload},
	}
	fb.receivedFrames = nil
	fb.mu.Unlock()

	reqBody1 := []byte(`{"model":"gpt-6-luna","stream":true}`)
	secretHeader := "Bearer sk-should-never-reach-broker-99999"

	// Request 1: 200 SSE
	{
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/responses", port), bytes.NewReader(reqBody1))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", secretHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Errorf("expected text/event-stream, got %s", ct)
		}
		if !bytes.Equal(body, ssePayload) {
			t.Errorf("expected %q, got %q", string(ssePayload), string(body))
		}
	}

	// Request 2: 400 JSON error
	{
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/responses", port), bytes.NewReader([]byte(`{}`)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", secretHeader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 400 {
			t.Errorf("expected 400, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}
		if !bytes.Equal(body, errPayload) {
			t.Errorf("expected %q, got %q", string(errPayload), string(body))
		}
	}

	// Check frames received by broker: exactly body bytes, never secretHeader
	fb.mu.Lock()
	if len(fb.receivedFrames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(fb.receivedFrames))
	}
	if !bytes.Equal(fb.receivedFrames[0], reqBody1) {
		t.Errorf("frame 1 mismatch: got %s", string(fb.receivedFrames[0]))
	}
	for i, frame := range fb.receivedFrames {
		if bytes.Contains(frame, []byte(secretHeader)) || bytes.Contains(frame, []byte("sk-should-never-reach")) {
			t.Errorf("frame %d contains secret authorization header!", i)
		}
	}
	fb.mu.Unlock()

	// 7. Path with ?beta=true for messages relay
	cfgMessages := Config{
		Host:             "127.0.0.1",
		Port:             0,
		SocketPath:       sockPath,
		AllowedPath:      AllowedPathMessages,
		SocketTimeoutSec: 5 * time.Second,
	}
	serverMsg := NewServer(cfgMessages)
	if err := serverMsg.Listen(); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer serverMsg.Close()
	go func() { _ = serverMsg.Serve() }()

	fb.mu.Lock()
	fb.replies = []fakeBrokerReply{
		{status: 200, body: []byte(`{"id":"msg_1"}`)},
	}
	fb.mu.Unlock()

	reqMsg, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/messages?beta=true", serverMsg.Port()), bytes.NewReader([]byte(`{"model":"claude-sonnet-5-5"}`)))
	if err != nil {
		t.Fatal(err)
	}
	respMsg, err := client.Do(reqMsg)
	if err != nil {
		t.Fatal(err)
	}
	defer respMsg.Body.Close()
	if respMsg.StatusCode != 200 {
		t.Errorf("expected 200 for messages?beta=true, got %d", respMsg.StatusCode)
	}
	if ct := respMsg.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json for json 200 reply, got %s", ct)
	}
}

// Only the exact origin-form target reaches the broker: an absolute-form
// target, a dot-segment path and CONNECT are refused without a frame.
func TestRelayRefusesNonOriginTargets(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "b.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	frames := make(chan struct{}, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			frames <- struct{}{}
			c.Close()
		}
	}()
	srv := NewServer(Config{Host: "127.0.0.1", Port: 0, AllowedPath: "/v1/responses", SocketPath: sock})
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")
	for _, target := range []string{"http://example.com/v1/responses", "/v1/responses/../files", "/v1//responses",
		"/v1/responses?x=1", "//v1/responses"} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", target)
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if !strings.Contains(line, " 404 ") {
			t.Errorf("%s: %q, want 404", target, strings.TrimSpace(line))
		}
	}
	select {
	case <-frames:
		t.Fatal("a refused request reached the broker")
	default:
	}
}
