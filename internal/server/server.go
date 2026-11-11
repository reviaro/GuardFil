package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/reviaro/guardfil/internal/config"
	"github.com/reviaro/guardfil/internal/failure"
	"github.com/reviaro/guardfil/internal/telemetry"
)

// Servers retains the exact configuration admitted by New. Start accepts a
// config only for the current bootstrap API, and rejects any replacement
// before opening a listener; transport credentials must never be selected by
// an unadmitted startup-time input.
type Servers struct {
	data, management *http.Server
	admitted         config.Config
	listeners        []net.Listener
	wg               sync.WaitGroup
}

var randReader io.Reader = rand.Reader

func New(c config.Config, ready *bool, counters *telemetry.Counters) (*Servers, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	dataMux := http.NewServeMux()
	mgmtMux := http.NewServeMux()
	health := func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, http.StatusOK, map[string]string{"status": "ok", "request_id": requestID(r)})
	}
	readiness := func(w http.ResponseWriter, r *http.Request) {
		if !*ready {
			jsonReply(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "request_id": requestID(r)})
			return
		}
		jsonReply(w, http.StatusOK, map[string]string{"status": "ready", "request_id": requestID(r)})
	}
	dataMux.HandleFunc("GET /healthz", health)
	dataMux.HandleFunc("GET /readyz", readiness)
	dataMux.HandleFunc("POST /guardfil/v1/decide", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusServiceUnavailable, failure.POLICY_UNAVAILABLE, failure.StagePolicy, false)
	})
	mgmtMux.HandleFunc("GET /healthz", health)
	mgmtMux.HandleFunc("GET /readyz", readiness)
	token, err := readToken(c.Management.MetricsTokenFile)
	if err != nil {
		return nil, err
	}
	mgmtMux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		code, ok := parseMetricsAuth(r.Header.Get("Authorization"), token)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, code, failure.StageAuth, false)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, counters.Prometheus())
	})
	ds := newHTTP(c.Data.Address, dataMux, counters)
	ms := newHTTP(c.Management.Address, mgmtMux, counters)
	for _, pair := range []struct {
		l config.Listener
		s *http.Server
	}{{c.Data, ds}, {c.Management, ms}} {
		if pair.l.TLSCertFile != "" {
			pair.s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
		}
	}
	return &Servers{data: ds, management: ms, admitted: c}, nil
}

func newHTTP(addr string, h http.Handler, c *telemetry.Counters) *http.Server {
	rh, wh, idle, _ := config.ServerTimeouts()
	return &http.Server{Addr: addr, Handler: middleware(h, c), ReadHeaderTimeout: rh, ReadTimeout: wh, WriteTimeout: wh, IdleTimeout: idle, MaxHeaderBytes: config.MaxHeaderBytes}
}

func (s *Servers) Start(c config.Config) error {
	if !reflect.DeepEqual(c, s.admitted) {
		return errors.New("server start configuration differs from admitted configuration")
	}
	for _, pair := range []struct {
		l config.Listener
		s *http.Server
	}{{s.admitted.Data, s.data}, {s.admitted.Management, s.management}} {
		ln, err := net.Listen("tcp", pair.s.Addr)
		if err != nil {
			return err
		}
		s.listeners = append(s.listeners, ln)
		s.wg.Add(1)
		go func(p struct {
			l config.Listener
			s *http.Server
		}, l net.Listener) {
			defer s.wg.Done()
			if p.l.TLSCertFile != "" {
				_ = p.s.ServeTLS(l, p.l.TLSCertFile, p.l.TLSKeyFile)
			} else {
				_ = p.s.Serve(l)
			}
		}(pair, ln)
	}
	return nil
}

func (s *Servers) Shutdown(ctx context.Context) error {
	var out error
	for _, h := range []*http.Server{s.data, s.management} {
		if err := h.Shutdown(ctx); err != nil {
			out = errors.Join(out, err)
		}
	}
	s.wg.Wait()
	return out
}

func middleware(next http.Handler, c *telemetry.Counters) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := make([]byte, 16)
		if _, err := io.ReadFull(randReader, id); err != nil {
			c.Reject()
			panic(http.ErrAbortHandler)
		}
		trusted := hex.EncodeToString(id)
		r.Header.Set("GuardFil-Request-Id", trusted)
		w.Header().Set("GuardFil-Request-Id", trusted)
		c.Request()
		if !validClientCorrelation(r) {
			c.Reject()
			writeError(w, r, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)
			return
		}
		if len(r.Header.Values("Authorization")) > 1 {
			c.Reject()
			writeError(w, r, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)
			return
		}
		if r.URL.RawQuery != "" && strings.Contains(strings.ToLower(r.URL.RawQuery), "token=") {
			c.Reject()
			writeError(w, r, http.StatusBadRequest, failure.PARSE_INVALID, failure.StageParse, true)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, config.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func requestID(r *http.Request) string { return r.Header.Get("GuardFil-Request-Id") }

func validClientCorrelation(r *http.Request) bool {
	values := r.Header.Values("GuardFil-Client-Request-Id")
	if len(values) > 1 {
		return false
	}
	if len(values) == 0 {
		return true
	}
	v := values[0]
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code failure.Code, stage failure.Stage, closeConn bool) {
	env, err := failure.PreDispatch(code, stage, requestID(r))
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	body, err := json.Marshal(env)
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Type", "application/json")
	if closeConn {
		w.Header().Set("Connection", "close")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func parseMetricsAuth(auth, expectedToken string) (failure.Code, bool) {
	if auth == "" || auth == "Bearer" {
		return failure.AUTH_REQUIRED, false
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return failure.AUTH_INVALID, false
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	if strings.Trim(tok, " \t") == "" {
		return failure.AUTH_REQUIRED, false
	}
	if len(tok) != len(expectedToken) || subtle.ConstantTimeCompare([]byte(tok), []byte(expectedToken)) != 1 {
		return failure.AUTH_INVALID, false
	}
	return "", true
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readToken(path string) (string, error) {
	i, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return "", errors.New("metrics token file must be regular and mode 0600")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" || len(v) > 4096 {
		return "", errors.New("invalid metrics token file")
	}
	return v, nil
}
