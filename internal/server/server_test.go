package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/reviaro/guardfil/internal/config"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/telemetry"
)

func assertEnvelope(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode failure.Code, wantStage failure.Stage, wantClose bool) failure.Envelope {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status code got %d, want %d", w.Code, wantStatus)
	}
	reqIDHeader := w.Header().Get("GuardFil-Request-Id")
	if reqIDHeader == "" {
		t.Fatal("missing GuardFil-Request-Id header")
	}
	if wantClose {
		if w.Header().Get("Connection") != "close" {
			t.Errorf("expected Connection: close, got %q", w.Header().Get("Connection"))
		}
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var env failure.Envelope
	dec := json.NewDecoder(w.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}

	if env.SchemaVersion != failure.SchemaVersion {
		t.Errorf("schema_version got %q, want %q", env.SchemaVersion, failure.SchemaVersion)
	}
	if env.Code != wantCode {
		t.Errorf("code got %q, want %q", env.Code, wantCode)
	}
	if env.Stage != wantStage {
		t.Errorf("stage got %q, want %q", env.Stage, wantStage)
	}
	wantRetry := failure.PreSendRetry(wantCode)
	if env.Retry != wantRetry {
		t.Errorf("retry got %q, want %q", env.Retry, wantRetry)
	}
	if env.Execution != failure.ExecutionNotDispatched {
		t.Errorf("execution got %q, want %q", env.Execution, failure.ExecutionNotDispatched)
	}
	if env.Delivery.State != failure.DeliveryWithheld {
		t.Errorf("delivery state got %q, want %q", env.Delivery.State, failure.DeliveryWithheld)
	}
	if env.Delivery.ReleasedBytes.ProtectedText != 0 || env.Delivery.ReleasedBytes.ProtectedTool != 0 {
		t.Errorf("released bytes got text=%d tool=%d, want 0, 0", env.Delivery.ReleasedBytes.ProtectedText, env.Delivery.ReleasedBytes.ProtectedTool)
	}
	if env.Message != failure.PreDispatchMessage {
		t.Errorf("message got %q, want %q", env.Message, failure.PreDispatchMessage)
	}
	if env.RequestID != reqIDHeader {
		t.Errorf("envelope request_id %q != response header %q", env.RequestID, reqIDHeader)
	}
	return env
}

func assertReadinessNotReady(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	reqIDHeader := w.Header().Get("GuardFil-Request-Id")
	if reqIDHeader == "" {
		t.Fatal("missing GuardFil-Request-Id header")
	}
	var body struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
	}
	dec := json.NewDecoder(w.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("failed to decode readiness body: %v", err)
	}
	if body.Status != "not_ready" {
		t.Errorf("readiness status got %q, want %q", body.Status, "not_ready")
	}
	if body.RequestID != reqIDHeader {
		t.Errorf("readiness request_id %q != header %q", body.RequestID, reqIDHeader)
	}
}

func TestSeparationHealthReadinessMetricsAndUnavailableDecision(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	creds := filepath.Join(d, "credentials")
	_ = os.Mkdir(creds, 0700)
	tok := filepath.Join(creds, "metrics")
	_ = os.WriteFile(tok, []byte("test-token\n"), 0600)
	ready := false
	s, err := New(config.Config{ConfigRoot: d, CredentialsRoot: creds, Data: config.Listener{Address: "127.0.0.1:0"}, Management: config.Listener{Address: "127.0.0.1:1", MetricsTokenFile: tok}, StateDir: d}, &ready, &telemetry.Counters{})
	if err != nil {
		t.Fatal(err)
	}

	// 1. GET /healthz on data
	{
		r := httptest.NewRequest("GET", "/healthz", nil)
		w := httptest.NewRecorder()
		s.data.Handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("GET /healthz got %d want 200", w.Code)
		}
	}

	// 2. GET /readyz on data when not ready -> 503 probe body {status:not_ready, request_id}
	{
		r := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		s.data.Handler.ServeHTTP(w, r)
		assertReadinessNotReady(t, w)
	}

	// Ready path verification
	{
		ready = true
		r := httptest.NewRequest("GET", "/readyz", nil)
		w := httptest.NewRecorder()
		s.data.Handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("GET /readyz (ready) got %d want 200", w.Code)
		}
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["status"] != "ready" || body["request_id"] != w.Header().Get("GuardFil-Request-Id") {
			t.Errorf("unexpected ready body: %+v", body)
		}
		ready = false
	}

	// 3. POST /guardfil/v1/decide -> 503 POLICY_UNAVAILABLE / policy
	{
		r := httptest.NewRequest("POST", "/guardfil/v1/decide", nil)
		w := httptest.NewRecorder()
		s.data.Handler.ServeHTTP(w, r)
		assertEnvelope(t, w, http.StatusServiceUnavailable, failure.POLICY_UNAVAILABLE, failure.StagePolicy, false)
	}

	// 4. GET /metrics on data -> 404
	{
		r := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()
		s.data.Handler.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("GET /metrics on data got %d want 404", w.Code)
		}
	}

	// 5. GET /metrics on management - test all four auth rejection cases:
	// 5a. No Authorization header -> 401 AUTH_REQUIRED / auth
	{
		r := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w, r)
		assertEnvelope(t, w, http.StatusUnauthorized, failure.AUTH_REQUIRED, failure.StageAuth, false)
	}

	// 5b. Empty value Authorization header -> 401 AUTH_REQUIRED / auth
	{
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("Authorization", "")
		w := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w, r)
		assertEnvelope(t, w, http.StatusUnauthorized, failure.AUTH_REQUIRED, failure.StageAuth, false)
	}

	// 5c. "Bearer " with an empty token -> 401 AUTH_REQUIRED / auth
	{
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("Authorization", "Bearer ")
		w := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w, r)
		assertEnvelope(t, w, http.StatusUnauthorized, failure.AUTH_REQUIRED, failure.StageAuth, false)
	}

	// 5d. Any non-empty but wrong credential -> 401 AUTH_INVALID / auth
	{
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w, r)
		assertEnvelope(t, w, http.StatusUnauthorized, failure.AUTH_INVALID, failure.StageAuth, false)

		r2 := httptest.NewRequest("GET", "/metrics", nil)
		r2.Header.Set("Authorization", "wrong-format")
		w2 := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w2, r2)
		assertEnvelope(t, w2, http.StatusUnauthorized, failure.AUTH_INVALID, failure.StageAuth, false)
	}

	// 6. GET /metrics on management with valid token -> 200
	{
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("GET /metrics valid got %d want 200", w.Code)
		}
	}

	// 7. POST /healthz on management -> 405
	{
		r := httptest.NewRequest("POST", "/healthz", nil)
		w := httptest.NewRecorder()
		s.management.Handler.ServeHTTP(w, r)
		if w.Code != 405 {
			t.Errorf("POST /healthz got %d want 405", w.Code)
		}
	}
}

func TestMetricsRealConnectionAuth(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	creds := filepath.Join(d, "credentials")
	_ = os.Mkdir(creds, 0700)
	tokenPath := filepath.Join(creds, "metrics")
	if err := os.WriteFile(tokenPath, []byte("right-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	ready := true
	counters := &telemetry.Counters{}
	c := config.Config{
		ConfigRoot:      d,
		CredentialsRoot: creds,
		StateDir:        d,
		Data:            config.Listener{Address: "127.0.0.1:0"},
		Management: config.Listener{
			Address:          "127.0.0.1:1",
			MetricsTokenFile: tokenPath,
		},
	}
	s, err := New(c, &ready, counters)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(s.management.Handler)
	defer ts.Close()

	sendRaw := func(t *testing.T, authHeader string) (*http.Response, []byte) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("failed to set deadline: %v", err)
		}

		reqStr := "GET /metrics HTTP/1.1\r\n" +
			"Host: " + ts.Listener.Addr().String() + "\r\n" +
			authHeader +
			"Connection: close\r\n\r\n"

		if _, err := io.WriteString(conn, reqStr); err != nil {
			t.Fatalf("failed to write raw request: %v", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		return resp, body
	}

	// 1. "Authorization: Bearer " (trailing space on the wire) -> 401 AUTH_REQUIRED
	{
		resp, body := sendRaw(t, "Authorization: Bearer \r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for Bearer with trailing space, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_REQUIRED || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_REQUIRED/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 2. "Authorization: Bearer" -> AUTH_REQUIRED
	{
		resp, body := sendRaw(t, "Authorization: Bearer\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for Bearer without space, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_REQUIRED || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_REQUIRED/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 3. raw token without scheme -> AUTH_INVALID
	{
		resp, body := sendRaw(t, "Authorization: right-token\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for raw token, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_INVALID || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 4. "Basic x" -> AUTH_INVALID
	{
		resp, body := sendRaw(t, "Authorization: Basic x\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for Basic x, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_INVALID || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 5. "Bearer <right token>" -> 200
	{
		resp, body := sendRaw(t, "Authorization: Bearer right-token\r\n")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for Bearer right-token, got %d: %s", resp.StatusCode, string(body))
		}
	}

	// 6. "Bearer \u00a0" (UTF-8 bytes C2 A0) -> 401 AUTH_INVALID
	{
		resp, body := sendRaw(t, "Authorization: Bearer \u00a0\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for Bearer \\u00a0, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_INVALID || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 7. "Bearer \u3000" -> 401 AUTH_INVALID
	{
		resp, body := sendRaw(t, "Authorization: Bearer \u3000\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for Bearer \\u3000, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_INVALID || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 8. "bearer <right token>" -> 401 AUTH_INVALID
	{
		resp, body := sendRaw(t, "Authorization: bearer right-token\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for bearer right-token, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_INVALID || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 9. "BEARER <right token>" -> 401 AUTH_INVALID
	{
		resp, body := sendRaw(t, "Authorization: BEARER right-token\r\n")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for BEARER right-token, got %d", resp.StatusCode)
		}
		var env failure.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to decode envelope: %v", err)
		}
		if env.Code != failure.AUTH_INVALID || env.Stage != failure.StageAuth {
			t.Fatalf("expected AUTH_INVALID/auth, got code=%s stage=%s", env.Code, env.Stage)
		}
	}

	// 10. direct parseMetricsAuth unit case 'Bearer \t ' -> AUTH_REQUIRED
	{
		code, ok := parseMetricsAuth("Bearer \t ", "right-token")
		if ok {
			t.Fatal("expected ok=false for parseMetricsAuth with 'Bearer \\t '")
		}
		if code != failure.AUTH_REQUIRED {
			t.Fatalf("expected AUTH_REQUIRED, got %s", code)
		}
	}
}

func TestBoundedBodyAndQueryCredentialRejection(t *testing.T) {
	h := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, r, http.StatusRequestEntityTooLarge, failure.LIMIT_EXCEEDED, failure.StageParse, true)
			return
		}
		w.WriteHeader(204)
	}), &telemetry.Counters{})

	// query containing token= -> 400 PARSE_INVALID / parse with Connection: close
	r := httptest.NewRequest("POST", "/x?token=secret", strings.NewReader("x"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertEnvelope(t, w, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)

	for _, n := range []int{config.MaxBodyBytes, config.MaxBodyBytes + 1} {
		r = httptest.NewRequest("POST", "/x", strings.NewReader(strings.Repeat("x", n)))
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 204
		if n > config.MaxBodyBytes {
			want = 413
		}
		if w.Code != want {
			t.Fatalf("size %d got %d", n, w.Code)
		}
	}
}

func TestTrustedRequestIDAndInvalidClientCorrelation(t *testing.T) {
	h := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestID(r) == "" {
			t.Error("missing trusted id")
		}
		w.WriteHeader(204)
	}), &telemetry.Counters{})

	// duplicate GuardFil-Client-Request-Id -> 400 PARSE_INVALID / parse with Connection: close
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("GuardFil-Client-Request-Id", "one")
	r.Header.Add("GuardFil-Client-Request-Id", "two")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertEnvelope(t, w, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)

	// malformed GuardFil-Client-Request-Id -> 400 PARSE_INVALID / parse with Connection: close
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("GuardFil-Client-Request-Id", "invalid id with spaces")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertEnvelope(t, w, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)

	// duplicate Authorization -> 400 PARSE_INVALID / parse with Connection: close
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer tok1")
	r.Header.Add("Authorization", "Bearer tok2")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertEnvelope(t, w, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)

	// valid request -> 204 and trusted ID header
	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("GuardFil-Request-Id") == "" {
		t.Fatalf("trusted ID result %d %q", w.Code, w.Header().Get("GuardFil-Request-Id"))
	}
}

type errorRandReader struct {
	err error
}

func (e errorRandReader) Read(p []byte) (int, error) {
	return 0, e.err
}

func TestRandFailureMiddleware(t *testing.T) {
	counters := &telemetry.Counters{}
	oldReader := randReader
	randReader = errorRandReader{err: errors.New("entropy failure")}
	t.Cleanup(func() {
		randReader = oldReader
	})

	h := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}), counters)

	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	var panicked any
	func() {
		defer func() {
			panicked = recover()
		}()
		h.ServeHTTP(w, r)
	}()

	if panicked != http.ErrAbortHandler {
		t.Fatalf("expected panic(http.ErrAbortHandler), got %v", panicked)
	}

	// Code unset (default 200 on ResponseRecorder), empty body, no headers flushed
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body, got %q", w.Body.String())
	}
	if w.Header().Get("GuardFil-Request-Id") != "" {
		t.Fatalf("expected no GuardFil-Request-Id header, got %q", w.Header().Get("GuardFil-Request-Id"))
	}
	if w.Code != 200 {
		t.Fatalf("expected default code 200, got %d", w.Code)
	}

	// Assert bounded transport rejection counter incremented
	prom := counters.Prometheus()
	if !strings.Contains(prom, "guardfil_rejections_total 1") {
		t.Fatalf("expected reject counter incremented, got:\n%s", prom)
	}
}

func TestLegacyErrorStringsRemoved(t *testing.T) {
	legacyStrings := []string{
		"DECISION_UNAVAILABLE",
		"NOT_READY",
		"METRICS_UNAUTHORIZED",
		"RANDOM_UNAVAILABLE",
		"QUERY_CREDENTIAL_FORBIDDEN",
	}

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	rootDir := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))

	filesChecked := 0
	for _, dirName := range []string{"internal", "cmd"} {
		dir := filepath.Join(rootDir, dirName)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			filesChecked++
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content := string(b)
			for _, s := range legacyStrings {
				if strings.Contains(content, s) {
					t.Errorf("file %s contains legacy error string %q", path, s)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if filesChecked == 0 {
		t.Fatal("expected to scan non-test Go files in internal/ and cmd/")
	}
}

func TestStartRejectsConfigurationSubstitutionBeforeBind(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(d, "credentials")
	if err := os.Mkdir(creds, 0700); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(creds, "metrics")
	if err := os.WriteFile(tok, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ready := false
	c := config.Config{ConfigRoot: d, CredentialsRoot: creds, Data: config.Listener{Address: "127.0.0.1:0"}, Management: config.Listener{Address: "127.0.0.1:1", MetricsTokenFile: tok}, StateDir: d}
	s, err := New(c, &ready, &telemetry.Counters{})
	if err != nil {
		t.Fatal(err)
	}
	replacement := c
	replacement.Data.TLSCertFile = tok
	if err := s.Start(replacement); err == nil || !strings.Contains(err.Error(), "differs from admitted") {
		t.Fatalf("substituted startup config result: %v", err)
	}
	if len(s.listeners) != 0 {
		t.Fatal("substituted config opened a listener")
	}
}
