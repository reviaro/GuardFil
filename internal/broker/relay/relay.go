package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultHost            = "127.0.0.1"
	DefaultPort            = 8899
	DefaultSocketPath      = "/run/guardfil-broker/broker.sock"
	MaxRequestBytes        = 4 * 1024 * 1024  // 4 MiB
	MaxResponseBytes       = 16 * 1024 * 1024 // 16 MiB
	RequestReadTimeoutSec  = 30 * time.Second
	BrokerSocketTimeoutSec = 130 * time.Second
	AllowedPathResponses   = "/v1/responses"
	AllowedPathMessages    = "/v1/messages"
)

// ForwardFrame sends one request frame (4B big-endian length + body) and reads reply frame (4B status + 4B length + body).
func ForwardFrame(socketPath string, body []byte, timeout time.Duration) (int, []byte, error) {
	if len(body) > MaxRequestBytes {
		return 0, nil, errors.New("request body exceeds 4 MiB limit")
	}
	if timeout <= 0 {
		timeout = BrokerSocketTimeoutSec
	}

	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return 0, nil, fmt.Errorf("broker connect error: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return 0, nil, err
	}

	// Send 4-byte big-endian length + body
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("broker write header error: %w", err)
	}
	if _, err := conn.Write(body); err != nil {
		return 0, nil, fmt.Errorf("broker write body error: %w", err)
	}

	// Read 8-byte reply header (4B status, 4B length)
	var replyHdr [8]byte
	if _, err := io.ReadFull(conn, replyHdr[:]); err != nil {
		return 0, nil, fmt.Errorf("broker read header error: %w", err)
	}

	status := int(binary.BigEndian.Uint32(replyHdr[0:4]))
	replyLen := int(binary.BigEndian.Uint32(replyHdr[4:8]))

	if replyLen > MaxResponseBytes {
		return 0, nil, fmt.Errorf("reply frame length %d exceeds 16 MiB limit", replyLen)
	}
	if status < 100 || status > 599 {
		return 0, nil, fmt.Errorf("invalid reply status %d", status)
	}

	replyBody := make([]byte, replyLen)
	if _, err := io.ReadFull(conn, replyBody); err != nil {
		return 0, nil, fmt.Errorf("broker read body error: %w", err)
	}

	return status, replyBody, nil
}

type Config struct {
	Host             string
	Port             int
	SocketPath       string
	AllowedPath      string
	SocketTimeoutSec time.Duration
}

type Server struct {
	cfg        Config
	httpServer *http.Server
	listener   net.Listener
}

func NewServer(cfg Config) *Server {
	if cfg.Host == "" {
		cfg.Host = DefaultHost
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if cfg.AllowedPath == "" {
		cfg.AllowedPath = AllowedPathResponses
	}
	if cfg.SocketTimeoutSec <= 0 {
		cfg.SocketTimeoutSec = BrokerSocketTimeoutSec
	}

	s := &Server{cfg: cfg}
	// No ServeMux: it would clean paths and redirect (307) before the check.
	s.httpServer = &http.Server{
		Handler:      http.HandlerFunc(s.handleHTTP),
		ReadTimeout:  RequestReadTimeoutSec + 5*time.Second,
		WriteTimeout: cfg.SocketTimeoutSec + 10*time.Second,
	}
	return s
}

func (s *Server) Listen() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = l
	s.cfg.Port = l.Addr().(*net.TCPAddr).Port
	return nil
}

func (s *Server) Port() int {
	if s.listener != nil {
		return s.listener.Addr().(*net.TCPAddr).Port
	}
	return s.cfg.Port
}

func (s *Server) Serve() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	return s.httpServer.Serve(s.listener)
}

func (s *Server) Close() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	sendJSONError := func(status int, errCode string) {
		payload, _ := json.Marshal(map[string]string{"error": errCode})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("Connection", "close")
		w.WriteHeader(status)
		_, _ = w.Write(payload)
	}

	if r.Method != http.MethodPost {
		sendJSONError(http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	// Match the raw request target, as sent: an absolute-form target
	// ("http://host/v1/responses") or an unclean path is refused, not
	// reduced to its path.
	reqURI := r.RequestURI

	allowed := s.cfg.AllowedPath
	if reqURI != allowed && reqURI != allowed+"?beta=true" {
		sendJSONError(http.StatusNotFound, "not_found")
		return
	}

	// Refuse chunked or any Transfer-Encoding before reading or forwarding.
	if len(r.TransferEncoding) > 0 || len(r.Header.Values("Transfer-Encoding")) > 0 {
		sendJSONError(http.StatusBadRequest, "transfer_encoding_not_supported")
		return
	}

	clValues := r.Header.Values("Content-Length")
	if len(clValues) != 1 {
		if len(clValues) == 0 {
			sendJSONError(http.StatusLengthRequired, "content_length_required")
		} else {
			sendJSONError(http.StatusBadRequest, "content_length_required")
		}
		return
	}

	rawCL := strings.TrimSpace(clValues[0])
	if len(rawCL) == 0 || len(rawCL) > 9 {
		sendJSONError(http.StatusBadRequest, "invalid_content_length")
		return
	}
	for i := 0; i < len(rawCL); i++ {
		if rawCL[i] < '0' || rawCL[i] > '9' {
			sendJSONError(http.StatusBadRequest, "invalid_content_length")
			return
		}
	}

	contentLen, err := strconv.Atoi(rawCL)
	if err != nil || contentLen < 0 {
		sendJSONError(http.StatusBadRequest, "invalid_content_length")
		return
	}
	if contentLen > MaxRequestBytes {
		sendJSONError(http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}

	body := make([]byte, contentLen)
	if contentLen > 0 {
		_, err := io.ReadFull(r.Body, body)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
				sendJSONError(http.StatusRequestTimeout, "request_timeout")
			} else {
				sendJSONError(http.StatusBadRequest, "bad_request_body")
			}
			return
		}
	}

	status, replyBody, err := ForwardFrame(s.cfg.SocketPath, body, s.cfg.SocketTimeoutSec)
	if err != nil {
		sendJSONError(http.StatusBadGateway, "broker_relay_failed")
		return
	}

	contentType := "application/json"
	if status == http.StatusOK && !bytes.HasPrefix(bytes.TrimLeft(replyBody, " \t\r\n"), []byte("{")) {
		contentType = "text/event-stream"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(replyBody)))
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	if len(replyBody) > 0 {
		_, _ = w.Write(replyBody)
	}
}

// RunRelay runs the relay server and stops on SIGINT/SIGTERM.
func RunRelay(cfg Config) error {
	srv := NewServer(cfg)
	if err := srv.Listen(); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve()
	}()

	select {
	case <-sigCh:
		return srv.Close()
	case err := <-errCh:
		return err
	}
}
