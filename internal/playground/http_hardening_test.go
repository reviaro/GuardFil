package playground

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestCheckListenAddrTable(t *testing.T) {
	tests := []struct {
		name             string
		addr             string
		allowNonLoopback bool
		wantErr          bool
	}{
		{"127.0.0.1:0 loopback ok", "127.0.0.1:0", false, false},
		{"localhost:8787 ok", "localhost:8787", false, false},
		{"[::1]:1 ipv6 loopback ok", "[::1]:1", false, false},
		{"0.0.0.0:8787 refused without flag", "0.0.0.0:8787", false, true},
		{"0.0.0.0:8787 accepted with flag", "0.0.0.0:8787", true, false},
		{":8787 refused without flag", ":8787", false, true},
		{":8787 accepted with flag", ":8787", true, false},
		{"192.168.1.2:1 refused without flag", "192.168.1.2:1", false, true},
		{"192.168.1.2:1 accepted with flag", "192.168.1.2:1", true, false},
		{"garbage not-an-addr refused without flag", "not-an-addr", false, true},
		{"garbage not-an-addr refused with flag", "not-an-addr", true, true},
		{"garbage localhost:notaport refused without flag", "localhost:notaport", false, true},
		{"garbage localhost:notaport refused with flag", "localhost:notaport", true, true},
		{"garbage invalid:::port refused without flag", "invalid:::port", false, true},
		{"garbage invalid:::port refused with flag", "invalid:::port", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckListenAddr(tc.addr, tc.allowNonLoopback)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckListenAddr(%q, %t): got err=%v, wantErr=%t", tc.addr, tc.allowNonLoopback, err, tc.wantErr)
			}
		})
	}
}

func TestHTTPHardeningStatusCodes(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	handler := p.Handler()

	// 1. 403 Forbidden: bad Host header
	badHosts := []string{"evil.example", "evil.example:8787", "127.0.0.1.evil.example", "127.0.0.1.evil.example:8787", "localhost.evil.example"}
	for _, h := range badHosts {
		req := httptest.NewRequest(http.MethodGet, "http://"+h+"/", nil)
		req.Host = h
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("bad host %q: got status %d, want 403", h, w.Code)
		}
		var errResp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil || errResp["error"] == "" {
			t.Fatalf("expected json error response for 403, got %s", w.Body.String())
		}
	}

	// 2. 403 Forbidden: bad Origin header on POST
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://evil.example")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("bad origin: got status %d, want 403", w.Code)
		}
	}

	// 3. 403 Forbidden: mismatched port in Origin on POST
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://127.0.0.1:9999")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("mismatched origin port: got status %d, want 403", w.Code)
		}
	}

	// 4. 403 Forbidden: no Origin and Sec-Fetch-Site cross-site on POST
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-site fetch without origin: got status %d, want 403", w.Code)
		}
	}

	// 5. 405 Method Not Allowed
	postOnlyEndpoints := []string{"/api/evaluate", "/api/policy", "/api/policy/reset", "/api/fixtures"}
	for _, ep := range postOnlyEndpoints {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787"+ep, nil)
		req.Host = "127.0.0.1:8787"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET to %s: got status %d, want 405", ep, w.Code)
		}
	}
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/state", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST to /api/state: got status %d, want 405", w.Code)
		}
	}

	// 6. 404 Not Found JSON
	unknownPaths := []string{"/unknown", "/api/unknown", "/something/else", "/index.html"}
	for _, pth := range unknownPaths {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787"+pth, nil)
		req.Host = "127.0.0.1:8787"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("GET %s: got status %d, want 404", pth, w.Code)
		}
		var errResp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil || errResp["error"] == "" {
			t.Fatalf("expected JSON error for 404 on %s, got %s", pth, w.Body.String())
		}
	}

	// 7. 415 Unsupported Media Type on POST
	badMediaTypes := []string{"text/plain", "application/xml", "", "multipart/form-data"}
	for _, mt := range badMediaTypes {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8787"
		if mt != "" {
			req.Header.Set("Content-Type", mt)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q: got status %d, want 415", mt, w.Code)
		}
	}

	// 8. 413 Payload Too Large (> 4 MiB)
	{
		largeBody := `{"tool":"fake.read_note","payload":"` + strings.Repeat("a", 4*1024*1024+1024) + `"}`
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(largeBody))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: got status %d, want 413: %s", w.Code, w.Body.String())
		}
	}
}

func TestOriginMatchingAndExactSecurityHeaders(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	handler := p.Handler()

	const expectedCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

	// 1. Origin matching Host -> 200
	validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))
	validPayload := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000,"cancelled":false,"expired_envelope":false}`, validB64)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8787/api/evaluate", strings.NewReader(validPayload))
	req.Host = "localhost:8787"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:8787")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("matching Origin got status %d, want 200: %s", w.Code, w.Body.String())
	}

	// 2. Exact security headers on response
	headers := w.Header()
	if headers.Get("Content-Security-Policy") != expectedCSP {
		t.Fatalf("CSP mismatch: got %q, want %q", headers.Get("Content-Security-Policy"), expectedCSP)
	}
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options mismatch: got %q", headers.Get("X-Content-Type-Options"))
	}
	if headers.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("Referrer-Policy mismatch: got %q", headers.Get("Referrer-Policy"))
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control mismatch: got %q", headers.Get("Cache-Control"))
	}
	if headers.Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Fatalf("Cross-Origin-Opener-Policy mismatch: got %q", headers.Get("Cross-Origin-Opener-Policy"))
	}
}

func TestOversizedPayloadReachesKernelThroughHTTP(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()

	// 1 MiB+1 oversize payload fixture
	oversize := strings.Repeat(" ", 1<<20+1)
	reqObj := map[string]any{
		"tool":             "fake.read_note",
		"payload_b64":      base64.StdEncoding.EncodeToString([]byte(oversize)),
		"credential":       "valid",
		"ttl_ms":           30000,
		"cancelled":        false,
		"expired_envelope": false,
	}
	bodyBytes, err := json.Marshal(reqObj)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/evaluate", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 carrying LIMIT_EXCEEDED, got status %d: %s", resp.StatusCode, string(b))
	}

	var res Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if res.Effect != "BLOCK" || res.Code != "LIMIT_EXCEEDED" || res.Stage != "parse" {
		t.Fatalf("oversize fixture did not return LIMIT_EXCEEDED in parse stage: %+v", res)
	}
}

func TestResultDispatchEligibleAlwaysFalseInJSON(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()

	// Evaluate ALLOW case
	validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))
	allowBody := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000,"cancelled":false,"expired_envelope":false}`, validB64)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/evaluate", strings.NewReader(allowBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	defer resp.Body.Close()
	rawJSON, _ := io.ReadAll(resp.Body)

	var res Result
	if err := json.Unmarshal(rawJSON, &res); err != nil {
		t.Fatalf("unmarshal Result failed: %v", err)
	}
	if res.DispatchEligible {
		t.Fatal("res.DispatchEligible is true on ALLOW")
	}
	if strings.Contains(string(rawJSON), `"dispatch_eligible":true`) {
		t.Fatal("raw JSON has dispatch_eligible:true")
	}
	if !strings.Contains(string(rawJSON), `"dispatch_eligible":false`) {
		t.Fatal("raw JSON missing dispatch_eligible:false")
	}

	// Check /api/state
	respState, err := server.Client().Get(server.URL + "/api/state")
	if err != nil {
		t.Fatalf("Get /api/state failed: %v", err)
	}
	defer respState.Body.Close()
	rawStateJSON, _ := io.ReadAll(respState.Body)
	if strings.Contains(string(rawStateJSON), `"dispatch_eligible":true`) {
		t.Fatal("raw state JSON has dispatch_eligible:true")
	}
}

func TestWebAssetsCompliance(t *testing.T) {
	// 1. GET / contains no "<script>" without src, no inline "style=" / "<style", and has id="error-banner"
	htmlStr := string(indexHTML)
	if !regexp.MustCompile(`\bid=["']error-banner["']`).MatchString(htmlStr) {
		t.Fatal("expected index.html to contain element with id=\"error-banner\"")
	}
	scriptTagRE := regexp.MustCompile(`(?i)<script\b[^>]*>`)
	scriptTags := scriptTagRE.FindAllString(htmlStr, -1)
	if len(scriptTags) == 0 {
		t.Fatal("expected at least one script tag in index.html")
	}
	for _, tag := range scriptTags {
		if !strings.Contains(tag, "src=") {
			t.Fatalf("index.html contains script tag without src: %q", tag)
		}
	}
	if strings.Contains(strings.ToLower(htmlStr), "<style") {
		t.Fatalf("index.html contains <style tag")
	}
	inlineStyleRE := regexp.MustCompile(`(?i)\bstyle\s*=`)
	if match := inlineStyleRE.FindString(htmlStr); match != "" {
		t.Fatalf("index.html contains inline style attribute: %q", match)
	}

	// 2. app.js contains none of innerHTML, outerHTML, insertAdjacentHTML, document.write, eval(, new Function, .trim(), alert(, confirm(, prompt(, "all fail-closed except"
	jsStr := string(appJS)
	forbiddenTokens := []string{
		"innerHTML",
		"outerHTML",
		"insertAdjacentHTML",
		"document.write",
		"eval(",
		"new Function",
		".trim()",
		"alert(",
		"confirm(",
		"prompt(",
		"all fail-closed except",
	}
	for _, tok := range forbiddenTokens {
		if strings.Contains(jsStr, tok) {
			t.Fatalf("app.js contains forbidden token %q", tok)
		}
	}

	// 3. Embedded assets contain no "http://" or "https://" URLs or URL schemes,
	// protocol-relative "//host" in src/href/url(), or "javascript:"
	assets := map[string][]byte{
		"index.html": indexHTML,
		"app.js":     appJS,
		"app.css":    appCSS,
	}
	schemeRE := regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?):`)
	jsSchemeRE := regexp.MustCompile(`(?i)\bjavascript:`)
	protoRelativeRE := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']?\s*//|url\(\s*["']?\s*//`)
	for name, content := range assets {
		s := string(content)
		if strings.Contains(s, "http://") || strings.Contains(s, "https://") {
			t.Fatalf("%s contains http:// or https:// URL", name)
		}
		if match := schemeRE.FindString(s); match != "" {
			t.Fatalf("%s references URL scheme: %q", name, match)
		}
		if match := jsSchemeRE.FindString(s); match != "" {
			t.Fatalf("%s references javascript: scheme: %q", name, match)
		}
		if match := protoRelativeRE.FindString(s); match != "" {
			t.Fatalf("%s references protocol-relative URL: %q", name, match)
		}
	}

	// 4. index.html contains rel="icon" with href="data:,"; app.js references "policy-error"
	if !strings.Contains(htmlStr, `rel="icon"`) || !strings.Contains(htmlStr, `href="data:,"`) {
		t.Fatal("expected index.html to contain rel=\"icon\" with href=\"data:,\"")
	}
	if !strings.Contains(jsStr, "policy-error") {
		t.Fatal("expected app.js to reference \"policy-error\"")
	}
}

func TestStrictJSONDecoding(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	handler := p.Handler()

	tests := []struct {
		name     string
		endpoint string
		body     string
	}{
		{
			name:     "evaluate unknown field",
			endpoint: "/api/evaluate",
			body:     `{"tool":"fake.read_note","extra":1}`,
		},
		{
			name:     "evaluate trailing data",
			endpoint: "/api/evaluate",
			body:     `{"tool":"fake.read_note","payload_b64":"e30=","credential":"valid","ttl_ms":30000} {"extra":1}`,
		},
		{
			name:     "policy unknown field",
			endpoint: "/api/policy",
			body:     `{"source":"default: deny","extra":1}`,
		},
		{
			name:     "policy trailing data",
			endpoint: "/api/policy",
			body:     `{"source":"default: deny"} trailing`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787"+tc.endpoint, strings.NewReader(tc.body))
			req.Host = "127.0.0.1:8787"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: got status %d, want 400: %s", tc.name, w.Code, w.Body.String())
			}
		})
	}

	// Fully valid evaluate body without "extra" -> 200, with "extra":1 -> 400
	{
		validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))
		validBody := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000}`, validB64)
		reqValid := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(validBody))
		reqValid.Host = "127.0.0.1:8787"
		reqValid.Header.Set("Content-Type", "application/json")
		wValid := httptest.NewRecorder()
		handler.ServeHTTP(wValid, reqValid)
		if wValid.Code != http.StatusOK {
			t.Fatalf("valid evaluate body: got status %d, want 200: %s", wValid.Code, wValid.Body.String())
		}

		extraBody := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000,"extra":1}`, validB64)
		reqExtra := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(extraBody))
		reqExtra.Host = "127.0.0.1:8787"
		reqExtra.Header.Set("Content-Type", "application/json")
		wExtra := httptest.NewRecorder()
		handler.ServeHTTP(wExtra, reqExtra)
		if wExtra.Code != http.StatusBadRequest {
			t.Fatalf("valid evaluate body with extra field: got status %d, want 400: %s", wExtra.Code, wExtra.Body.String())
		}
	}
}

func TestContentTypeAndOriginPortCheck(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	handler := p.Handler()

	validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))
	validBody := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000,"cancelled":false,"expired_envelope":false}`, validB64)

	// 1. Valid body with Content-Type text/plain -> 415
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(validBody))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("text/plain with valid body: got status %d, want 415", w.Code)
		}
	}

	// 2. Valid body with Content-Type "application/json; charset=utf-8" -> 200
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(validBody))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("application/json; charset=utf-8 with valid body: got status %d, want 200: %s", w.Code, w.Body.String())
		}
	}

	// 3. Origin http://127.0.0.1:9999 when Host is 127.0.0.1:8787 -> 403 (port mismatch)
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(validBody))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://127.0.0.1:9999")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("mismatched origin port with valid body: got status %d, want 403", w.Code)
		}
	}

	// 4. Host 127.0.0.1:8787 with Origin http://evil.example:8787 (same port) -> 403
	{
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/evaluate", strings.NewReader(validBody))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://evil.example:8787")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("disallowed origin hostname on same port: got status %d, want 403", w.Code)
		}
	}
}

func TestHTTPByteExactPayloadTransport(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	client := server.Client()

	postEvaluate := func(payloadJSON string) (*http.Response, Result) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/api/evaluate", strings.NewReader(payloadJSON))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		var res Result
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&res)
		}
		return resp, res
	}

	// 1. payload_b64 of bytes {"note_id":"a\xffb"} -> BLOCK PARSE_INVALID/parse
	rawInvalidUTF8 := []byte("{\"note_id\":\"a\xffb\"}")
	b64InvalidUTF8 := base64.StdEncoding.EncodeToString(rawInvalidUTF8)
	body1 := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000}`, b64InvalidUTF8)
	resp1, res1 := postEvaluate(body1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for payload_b64 invalid UTF-8, got %d", resp1.StatusCode)
	}
	if res1.Effect != "BLOCK" || res1.Code != "PARSE_INVALID" || res1.Stage != "parse" {
		t.Fatalf("invalid UTF-8 payload got effect=%s code=%s stage=%s, want BLOCK PARSE_INVALID parse", res1.Effect, res1.Code, res1.Stage)
	}
	direct1 := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    rawInvalidUTF8,
		Credential: "valid",
		TTLMillis:  30000,
	})
	if res1.Effect != direct1.Effect || res1.Code != direct1.Code || res1.Stage != direct1.Stage {
		t.Fatalf("HTTP result (%s %s %s) != direct Evaluate (%s %s %s)", res1.Effect, res1.Code, res1.Stage, direct1.Effect, direct1.Code, direct1.Stage)
	}

	// 2. payload_b64 of {"note_id":"\ud800"} (lone surrogate escape as raw text)
	rawLoneSurrogate := []byte("{\"note_id\":\"\\ud800\"}")
	b64LoneSurrogate := base64.StdEncoding.EncodeToString(rawLoneSurrogate)
	body2 := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000}`, b64LoneSurrogate)
	resp2, res2 := postEvaluate(body2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for payload_b64 lone surrogate, got %d", resp2.StatusCode)
	}
	direct2 := p.Evaluate(context.Background(), Input{
		Tool:       "fake.read_note",
		Payload:    rawLoneSurrogate,
		Credential: "valid",
		TTLMillis:  30000,
	})
	if res2.Effect != direct2.Effect || res2.Code != direct2.Code || res2.Stage != direct2.Stage {
		t.Fatalf("HTTP result (%s %s %s) != direct Evaluate (%s %s %s) for lone surrogate", res2.Effect, res2.Code, res2.Stage, direct2.Effect, direct2.Code, direct2.Stage)
	}
	if res2.Code != "PARSE_INVALID" {
		t.Fatalf("expected PARSE_INVALID for lone surrogate, got %s", res2.Code)
	}

	// 3. Old payload field -> 400
	bodyOld := `{"tool":"fake.read_note","payload":"{}","credential":"valid","ttl_ms":30000}`
	respOld, _ := postEvaluate(bodyOld)
	if respOld.StatusCode != http.StatusBadRequest {
		t.Fatalf("old payload field got status %d, want 400", respOld.StatusCode)
	}

	// 4. Invalid base64 -> 400
	bodyBadB64 := `{"tool":"fake.read_note","payload_b64":"%%%invalid-b64%%%","credential":"valid","ttl_ms":30000}`
	respBadB64, _ := postEvaluate(bodyBadB64)
	if respBadB64.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid base64 got status %d, want 400", respBadB64.StatusCode)
	}
}

func TestHTTPBoundaries(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	client := server.Client()

	validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))

	// 1. ttl_ms 1 -> 200
	bodyTTL1 := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":1}`, validB64)
	resp1, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(bodyTTL1))
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("ttl_ms 1: got status %v, err %v", resp1.StatusCode, err)
	}
	resp1.Body.Close()

	// 2. ttl_ms 60000 -> 200
	bodyTTL60000 := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":60000}`, validB64)
	resp60000, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(bodyTTL60000))
	if err != nil || resp60000.StatusCode != http.StatusOK {
		t.Fatalf("ttl_ms 60000: got status %v, err %v", resp60000.StatusCode, err)
	}
	resp60000.Body.Close()

	// 3. Request body of 4 MiB - 64 bytes -> not 413 (any 200 result)
	prefix := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000`, validB64)
	suffix := `}`
	targetLen200 := 4*1024*1024 - 64
	padLen := targetLen200 - len(prefix) - len(suffix)
	if padLen < 0 {
		t.Fatalf("prefix+suffix too long for 4 MiB - 64")
	}
	body4MMinus64 := prefix + strings.Repeat(" ", padLen) + suffix
	if len(body4MMinus64) != targetLen200 {
		t.Fatalf("expected len %d, got %d", targetLen200, len(body4MMinus64))
	}
	respNear, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(body4MMinus64))
	if err != nil {
		t.Fatalf("Post 4 MiB - 64: %v", err)
	}
	defer respNear.Body.Close()
	if respNear.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatalf("4 MiB - 64 bytes unexpectedly returned 413")
	}
	if respNear.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for 4 MiB - 64 bytes, got %d", respNear.StatusCode)
	}

	// 4. Request body of 4 MiB + 1 bytes -> 413
	body4MPlus1 := strings.Repeat(" ", 4*1024*1024+1)
	respOver, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(body4MPlus1))
	if err != nil {
		t.Fatalf("Post 4 MiB + 1: %v", err)
	}
	defer respOver.Body.Close()
	if respOver.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("4 MiB + 1 got status %d, want 413", respOver.StatusCode)
	}

	// 5. Valid evaluate object followed by > 4 MiB of whitespace -> 413
	validBody := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000}`, validB64)
	bodyValidWith4MWhitespace := validBody + strings.Repeat(" ", 4*1024*1024+1024)
	respWsOver, err := client.Post(server.URL+"/api/evaluate", "application/json", strings.NewReader(bodyValidWith4MWhitespace))
	if err != nil {
		t.Fatalf("Post valid object with >4MiB whitespace: %v", err)
	}
	defer respWsOver.Body.Close()
	if respWsOver.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("valid evaluate object followed by > 4 MiB whitespace got status %d, want 413", respWsOver.StatusCode)
	}
}

func TestEmptyBodyEndpoints(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	client := server.Client()

	postEmpty := func(endpoint string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, server.URL+endpoint, bytes.NewReader(nil))
		if err != nil {
			t.Fatalf("NewRequest %s: %v", endpoint, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", "0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s empty body: %v", endpoint, err)
		}
		return resp
	}

	// 1. /api/policy/reset with empty body -> 200
	respReset := postEmpty("/api/policy/reset")
	defer respReset.Body.Close()
	if respReset.StatusCode != http.StatusOK {
		t.Fatalf("empty body to /api/policy/reset: got status %d, want 200", respReset.StatusCode)
	}

	// 2. /api/fixtures with empty body -> 200
	respFixtures := postEmpty("/api/fixtures")
	defer respFixtures.Body.Close()
	if respFixtures.StatusCode != http.StatusOK {
		t.Fatalf("empty body to /api/fixtures: got status %d, want 200", respFixtures.StatusCode)
	}

	// 3. /api/evaluate with empty body -> 400
	respEval := postEmpty("/api/evaluate")
	defer respEval.Body.Close()
	if respEval.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body to /api/evaluate: got status %d, want 400", respEval.StatusCode)
	}

	// 4. /api/policy with empty body -> 400
	respPolicy := postEmpty("/api/policy")
	defer respPolicy.Body.Close()
	if respPolicy.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body to /api/policy: got status %d, want 400", respPolicy.StatusCode)
	}
}

func TestEvaluateSyntheticFlagInHTTPJSON(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	client := server.Client()

	postEval := func(body string) (int, string, Result) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/api/evaluate", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		var res Result
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(raw, &res); err != nil {
				t.Fatalf("Unmarshal Result: %v", err)
			}
		}
		return resp.StatusCode, string(raw), res
	}

	validB64 := base64.StdEncoding.EncodeToString([]byte(`{"note_id":"synthetic-note-001"}`))

	// 1. ALLOW result
	allowBody := fmt.Sprintf(`{"tool":"fake.read_note","payload_b64":%q,"credential":"valid","ttl_ms":30000}`, validB64)
	statusAllow, rawAllow, resAllow := postEval(allowBody)
	if statusAllow != http.StatusOK {
		t.Fatalf("expected 200 on ALLOW, got %d", statusAllow)
	}
	if resAllow.Effect != "ALLOW" {
		t.Fatalf("expected effect ALLOW, got %s", resAllow.Effect)
	}
	if !resAllow.Synthetic {
		t.Fatalf("expected res.Synthetic == true on ALLOW, got false")
	}
	if !strings.Contains(rawAllow, `"synthetic":true`) {
		t.Fatalf(`expected raw HTTP JSON to contain "synthetic":true, got: %s`, rawAllow)
	}

	// 2. BLOCK result (policy deny)
	deleteB64 := base64.StdEncoding.EncodeToString([]byte(`{"record_id":"synthetic-rec-001"}`))
	blockBody := fmt.Sprintf(`{"tool":"fake.delete_record","payload_b64":%q,"credential":"valid","ttl_ms":30000}`, deleteB64)
	statusBlock, rawBlock, resBlock := postEval(blockBody)
	if statusBlock != http.StatusOK {
		t.Fatalf("expected 200 on BLOCK, got %d", statusBlock)
	}
	if resBlock.Effect != "BLOCK" {
		t.Fatalf("expected effect BLOCK, got %s", resBlock.Effect)
	}
	if !resBlock.Synthetic {
		t.Fatalf("expected res.Synthetic == true on BLOCK, got false")
	}
	if !strings.Contains(rawBlock, `"synthetic":true`) {
		t.Fatalf(`expected raw HTTP JSON to contain "synthetic":true, got: %s`, rawBlock)
	}
}
