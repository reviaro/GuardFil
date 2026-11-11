package neutral

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reviaro/guardfil/internal/broker/adapters"
	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/egress"
)

const (
	ProviderCeilingMicros = budget.GlobalCeilingMicros
	MaxRequestBytes       = 1 << 20 // 1 MiB
	MaxReplyBytes         = 4 << 20 // 4 MiB
	MaxSessionRequests    = 64
	DefaultMaxRequests    = 16
	InputMarginTokens     = 512
	ProviderTimeoutSec    = 150 * time.Second
)

var (
	DefaultLiveProviders = map[string]bool{
		"openai": true, "gemini": true, "anthropic": true,
	}
	DefaultProviderModels = map[string]map[string]bool{
		"openai":    {"gpt-6-luna": true},
		"gemini":    {"gemini-3.8-flash": true, "gemini-3.6-flash": true, "gemini-3.5-flash-lite": true},
		"anthropic": {"claude-sonnet-5-5": true},
	}
	// RetiredLedgerSpend is the counted spend, in micro-USD, on halted ledgers
	// a provider used before its current one. It still counts toward that
	// provider's $2. Empty by default: a new installation has none.
	RetiredLedgerSpend = map[string]int{}
	RetryStatuses      = map[int]bool{
		429: true, 500: true, 502: true, 503: true, 504: true,
	}
	RetryDelays = []time.Duration{
		5 * time.Second, 15 * time.Second, 30 * time.Second, 65 * time.Second,
	}
	KeyFiles = map[string]string{
		"openai":    "openai-api-key",
		"anthropic": "anthropic-api-key",
		"gemini":    "gemini-api-key",
	}
	LedgerRoots = map[string]struct {
		RootPath string
		ExpID    string
	}{
		"openai":    {RootPath: filepath.Join(os.Getenv("HOME"), ".local/state/guardfil/t2a-experiment"), ExpID: "guardfil-t2a-m1-openai-luna"},
		"gemini":    {RootPath: filepath.Join(os.Getenv("HOME"), ".local/state/guardfil/gemini-experiment-6"), ExpID: "guardfil-m4-gemini-6"},
		"anthropic": {RootPath: filepath.Join(os.Getenv("HOME"), ".local/state/guardfil/anthropic-experiment"), ExpID: "guardfil-m4-anthropic"},
	}
)

type TransportFunc func(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error)

func DefaultHTTPSTransport() TransportFunc {
	client := &http.Client{Timeout: ProviderTimeoutSec}
	return func(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
		httpReq, err := http.NewRequest(http.MethodPost, "https://"+req.Host+req.Path, bytes.NewReader(req.Body))
		if err != nil {
			return 0, nil, err
		}
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}
		for k, v := range auth {
			httpReq.Header.Set(k, v)
		}
		httpReq.Header.Set("Accept", "application/json")

		resp, err := client.Do(httpReq)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxReplyBytes+1))
		if err != nil {
			return resp.StatusCode, nil, err
		}
		if len(body) > MaxReplyBytes {
			return resp.StatusCode, nil, errors.New("provider reply too large")
		}
		return resp.StatusCode, body, nil
	}
}

type NeutralBrokerServer struct {
	CloudGuard     egress.Guard // configured by the host before serving
	ledgers        map[string]*budget.BudgetLedger
	label          string
	maxRequests    int
	keys           map[string]string
	transport      TransportFunc
	evidencePath   string
	liveProviders  map[string]bool
	providerModels map[string]map[string]bool // nil means any priced model
	priorSpend     map[string]int
	adapters       map[string]adapters.Adapter

	count         int
	stopped       bool
	busy          bool
	stopRequested bool
	mu            sync.Mutex
	sleepFn       func(time.Duration)
}

func NewNeutralBrokerServer(
	ledgers map[string]*budget.BudgetLedger,
	label string,
	maxRequests int,
	keys map[string]string,
	transport TransportFunc,
	evidencePath string,
	liveProviders map[string]bool,
	providerModels map[string]map[string]bool,
	priorSpend map[string]int,
) (*NeutralBrokerServer, error) {
	if maxRequests < 1 || maxRequests > MaxSessionRequests {
		return nil, errors.New("max_requests out of range")
	}
	if liveProviders == nil {
		liveProviders = DefaultLiveProviders
	}
	if priorSpend == nil {
		priorSpend = make(map[string]int)
	}
	if transport == nil {
		transport = DefaultHTTPSTransport()
	}

	s := &NeutralBrokerServer{
		ledgers:        ledgers,
		label:          label,
		maxRequests:    maxRequests,
		keys:           keys,
		transport:      transport,
		evidencePath:   evidencePath,
		liveProviders:  liveProviders,
		providerModels: providerModels,
		priorSpend:     priorSpend,
		adapters:       adapters.NewAdapters(),
		sleepFn:        time.Sleep,
	}
	s.transport = func(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
		if err := s.CloudGuard.Check(); err != nil {
			return http.StatusForbidden, egress.ErrorBody(err), nil
		}
		return transport(req, auth)
	}
	return s, nil
}

func reservationMicros(model string, bodyLen int, maxOutputTokens int) int {
	rate := budget.ModelRates[model]
	rin := rate.InputRateMicros
	rout := rate.OutputRateMicros
	amount := (bodyLen+InputMarginTokens)*rin + maxOutputTokens*rout
	if amount < budget.MinReservationMicros {
		return budget.MinReservationMicros
	}
	return amount
}

func providerMessage(body []byte) string {
	var errObj struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &errObj); err == nil && errObj.Error.Message != "" {
		msg := errObj.Error.Message
		if len(msg) > 300 {
			return msg[:300]
		}
		return msg
	}
	s := string(body)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (s *NeutralBrokerServer) sendWithRetries(req *adapters.HTTPRequest, auth map[string]string) (int, []byte, error) {
	status, body, err := s.transport(req, auth)
	if err != nil {
		return status, body, err
	}
	for _, delay := range RetryDelays {
		if !RetryStatuses[status] {
			break
		}
		s.sleepFn(delay)
		status, body, err = s.transport(req, auth)
		if err != nil {
			return status, body, err
		}
	}
	return status, body, nil
}

// Handle processes one neutral request line and returns map[string]any.
func (s *NeutralBrokerServer) Handle(raw []byte) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return map[string]any{"ok": false, "error": "broker stopped after a ledger or provider failure"}
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var req map[string]any
	if err := d.Decode(&req); err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("bad request: %v", err)}
	}

	provider, model, err := adapters.Validate(req)
	if err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("bad request: %v", err)}
	}

	if !s.liveProviders[provider] {
		return map[string]any{"ok": false, "error": fmt.Sprintf("provider %s is not enabled for live calls", provider)}
	}

	if _, priced := budget.ModelRates[model]; !priced {
		return map[string]any{"ok": false, "error": budget.NotAllowedMessage(provider, model)}
	}
	if s.providerModels != nil {
		allowedModels := s.providerModels[provider]
		if allowedModels != nil && !allowedModels[model] {
			return map[string]any{"ok": false, "error": budget.NotAllowedMessage(provider, model)}
		}
	}

	ledger := s.ledgers[provider]
	if ledger == nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("no ledger for %s", provider)}
	}

	apiKey, hasKey := s.keys[provider]
	if !hasKey || apiKey == "" {
		return map[string]any{"ok": false, "error": fmt.Sprintf("no key for %s", provider)}
	}

	if s.count >= s.maxRequests {
		return map[string]any{"ok": false, "error": "this session's request limit is reached"}
	}

	adapter := s.adapters[provider]
	if adapter == nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("no adapter for %s", provider)}
	}

	out, err := adapter.Build(model, req)
	if err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("build request error: %v", err)}
	}

	h := sha256.Sum256(out.Body)
	if err := s.CloudGuard.Check(); err != nil {
		return map[string]any{"ok": false, "error": err.Error(), "code": "CLOUD_REQUEST_BLOCKED"}
	}
	digest := "sha256:" + hex.EncodeToString(h[:])

	preflightReq, err := adapter.Preflight(model, out)
	if err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("preflight error: %v", err)}
	}
	if preflightReq != nil {
		status, pbody, err := s.sendWithRetries(preflightReq, adapter.Auth(apiKey))
		if err != nil {
			return map[string]any{"ok": false, "error": "provider unreachable (preflight; nothing was spent)"}
		}
		if status != 200 {
			detail := providerMessage(pbody)
			return map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("provider refused the request before any spend (HTTP %d): %s", status, detail),
			}
		}
	}

	mot := adapters.MaxOutputTokens
	if motVal, ok := req["max_output_tokens"]; ok && motVal != nil {
		mot = toInt(motVal)
	}

	amount := reservationMicros(model, len(out.Body), mot)
	if amount > budget.ReservationAmountMicros {
		return map[string]any{"ok": false, "error": "request too large for one reservation"}
	}

	if s.priorSpend[provider] > 0 {
		st, err := ledger.GetStatus()
		over := false
		if err != nil || s.priorSpend[provider]+st.TotalEncumberedMicros+amount > ProviderCeilingMicros {
			over = true
		}
		if over {
			return map[string]any{"ok": false, "error": fmt.Sprintf("%s's $2 across all its ledgers would be exceeded", provider)}
		}
	}

	s.count++
	requestID := fmt.Sprintf("neutral-%s-%d", s.label, s.count)

	permit, err := ledger.Reserve(requestID, digest, amount)
	if err != nil {
		s.stopped = true
		return map[string]any{"ok": false, "error": "the $2 ledger refused the request (budget or ledger state)"}
	}

	status, rbody, err := s.sendWithRetries(out, adapter.Auth(apiKey))
	if err != nil {
		_, _ = ledger.RecordFailure(permit, "REQUEST_TRANSPORT_FAILURE")
		s.stopped = true
		return map[string]any{"ok": false, "error": "provider unreachable"}
	}

	// Retry statuses (still failing after retries) and request-refused 4xx
	// statuses are not billed: settle at zero instead of halting the ledger.
	refused := status == 400 || status == 401 || status == 403 || status == 404 || status == 413 || status == 422
	if RetryStatuses[status] || refused {
		unbilled := &budget.Receipt{
			Status:        budget.TerminalStatusCompleted,
			ResponseID:    fmt.Sprintf("unbilled-%d-%s", status, requestID),
			RequestID:     requestID,
			RequestDigest: digest,
			Model:         model,
			ServiceTier:   budget.ModelRates[model].ServiceTier,
			InputTokens:   0,
			OutputTokens:  0,
			TotalTokens:   0,
		}
		if _, err := ledger.Settle(permit, unbilled); err != nil {
			s.stopped = true
			return map[string]any{"ok": false, "error": "the ledger could not settle the request"}
		}
		if refused {
			return map[string]any{"ok": false, "error": fmt.Sprintf("the provider refused the request (HTTP %d); nothing was billed", status)}
		}
		return map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("provider busy (HTTP %d) after retries; nothing was billed, try again later", status),
		}
	}

	reply, err := adapter.Parse(status, rbody)
	if err != nil {
		_, _ = ledger.RecordFailure(permit, "RECEIPT_SCHEMA_VIOLATION")
		s.stopped = true
		return map[string]any{"ok": false, "error": fmt.Sprintf("provider reply unusable (%v)", err)}
	}

	canonicalModel, ok := budget.CanonicalReplyModel(provider, model, reply.Model)
	if !ok {
		_, _ = ledger.RecordFailure(permit, "RECEIPT_MODEL_MISMATCH")
		s.stopped = true
		return map[string]any{"ok": false, "error": fmt.Sprintf("provider reply model mismatch: got %q, expected %q", reply.Model, model)}
	}

	tier := reply.ServiceTier
	if tier == "" {
		tier = budget.ModelRates[canonicalModel].ServiceTier
	}

	receipt := &budget.Receipt{
		Status:        budget.TerminalStatusCompleted,
		ResponseID:    reply.ResponseID,
		RequestID:     requestID,
		RequestDigest: digest,
		Model:         canonicalModel,
		ServiceTier:   tier,
		InputTokens:   reply.Usage.InputTokens,
		OutputTokens:  reply.Usage.OutputTokens,
		TotalTokens:   reply.Usage.InputTokens + reply.Usage.OutputTokens,
	}

	if _, err := ledger.Settle(permit, receipt); err != nil {
		s.stopped = true
		return map[string]any{"ok": false, "error": "the ledger could not settle the request"}
	}

	reply.ServiceTier = ""
	return map[string]any{"ok": true, "reply": reply}
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

func (s *NeutralBrokerServer) Serve(sockPath string) error {
	_ = os.Remove(sockPath)
	oldMask := syscall.Umask(0077)
	l, err := net.Listen("unix", sockPath)
	syscall.Umask(oldMask)
	if err != nil {
		return err
	}
	defer func() {
		_ = l.Close()
		_ = os.Remove(sockPath)
	}()

	fmt.Println("NEUTRAL_BROKER_READY")
	_ = os.Stdout.Sync()

	for {
		conn, err := l.Accept()
		if err != nil {
			if s.stopRequested {
				break
			}
			return err
		}

		s.busy = true
		s.handleConn(conn)
		s.busy = false

		if s.stopRequested {
			break
		}
	}
	return nil
}

func (s *NeutralBrokerServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	var data []byte
	buf := make([]byte, 65536)
	for {
		if bytes.Contains(data, []byte("\n")) || len(data) > MaxRequestBytes {
			break
		}
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		data = append(data, buf[:n]...)
	}

	var res map[string]any
	if len(data) > MaxRequestBytes {
		res = map[string]any{"ok": false, "error": "request too large"}
	} else {
		line := bytes.SplitN(data, []byte("\n"), 2)[0]
		res = s.Handle(line)
	}

	_ = conn.SetDeadline(time.Now().Add(ProviderTimeoutSec))
	resEnc, _ := json.Marshal(res)
	_, _ = conn.Write(append(resEnc, '\n'))
}

func (s *NeutralBrokerServer) RequestStop() {
	s.stopRequested = true
}

func CheckModels(keys map[string]string) int {
	checkPaths := map[string]struct {
		Host string
		Path string
	}{
		"openai":    {Host: "api.openai.com", Path: "/v1/models/%s"},
		"gemini":    {Host: "generativelanguage.googleapis.com", Path: "/v1beta/models/%s"},
		"anthropic": {Host: "api.anthropic.com", Path: "/v1/models/%s"},
	}

	bad := 0
	client := &http.Client{Timeout: 30 * time.Second}

	var providers []string
	for p := range keys {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	adaptersMap := adapters.NewAdapters()

	for _, p := range providers {
		modelsMap := budget.ProviderModels[p]
		var models []string
		for m := range modelsMap {
			models = append(models, m)
		}
		sort.Strings(models)

		for _, m := range models {
			cp := checkPaths[p]
			url := fmt.Sprintf("https://%s%s", cp.Host, fmt.Sprintf(cp.Path, m))
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				bad++
				continue
			}
			auth := adaptersMap[p].Auth(keys[p])
			for k, v := range auth {
				req.Header.Set(k, v)
			}
			req.Header.Set("Accept", "application/json")
			if p == "anthropic" {
				req.Header.Set("anthropic-version", "2023-06-01")
			}

			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("CHECK %s:%s HTTP 0 %v\n", p, m, err)
				bad++
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()

			info := make(map[string]any)
			if resp.StatusCode == 200 {
				var d map[string]any
				if err := json.Unmarshal(body, &d); err == nil {
					for _, k := range []string{"name", "id", "displayName", "version", "outputTokenLimit", "thinking"} {
						if v, ok := d[k]; ok {
							info[k] = v
						}
					}
				}
				infoEnc, _ := json.Marshal(info)
				fmt.Printf("CHECK %s:%s HTTP %d %s\n", p, m, resp.StatusCode, string(infoEnc))
			} else {
				fmt.Printf("CHECK %s:%s HTTP %d %s\n", p, m, resp.StatusCode, providerMessage(body))
				bad++
			}
		}
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func LoadKeys(keyDir string) map[string]string {
	keys := make(map[string]string)
	for p, f := range KeyFiles {
		pPath := filepath.Join(keyDir, f)
		data, err := os.ReadFile(pPath)
		if err == nil {
			keys[p] = strings.TrimSpace(string(data))
		}
	}
	return keys
}

func RunNeutralBroker(sockdir string, label string, maxRequests int, checkFlag bool) error {
	guard, err := egress.FromEnv()
	if err != nil {
		return err
	}
	keyDir := filepath.Join(os.Getenv("HOME"), ".config/guardfil/credentials.d")
	keys := LoadKeys(keyDir)

	if checkFlag {
		code := CheckModels(keys)
		if code != 0 {
			return errors.New("check failed")
		}
		return nil
	}

	if sockdir == "" || label == "" {
		return errors.New("--sockdir and --label are required")
	}

	if err := os.MkdirAll(sockdir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(sockdir, 0700); err != nil {
		return err
	}

	ledgers := make(map[string]*budget.BudgetLedger)
	for p := range keys {
		lr := LedgerRoots[p]
		if lr.RootPath == "" {
			continue
		}
		l, err := budget.OpenOrInitLedger(lr.RootPath, true, lr.ExpID)
		if err == nil {
			st, err2 := l.GetStatus()
			if err2 == nil && st.CanReserve() {
				ledgers[p] = l
			} else {
				fmt.Fprintf(os.Stderr, "%s ledger cannot reserve; %s disabled\n", p, p)
				_ = l.Close()
			}
		}
	}

	prior := make(map[string]int)
	for p := range ledgers {
		if sp, ok := RetiredLedgerSpend[p]; ok {
			prior[p] = sp
		}
	}
	if len(prior) > 0 {
		pEnc, _ := json.Marshal(prior)
		fmt.Fprintf(os.Stderr, "NEUTRAL_BROKER_PRIOR_SPEND %s\n", string(pEnc))
	}
	if len(ledgers) == 0 {
		fmt.Fprintf(os.Stderr, "no provider has a key and a usable ledger\n")
		return errors.New("no usable provider")
	}

	var pNames []string
	for p := range ledgers {
		pNames = append(pNames, p)
	}
	sort.Strings(pNames)
	fmt.Fprintf(os.Stderr, "NEUTRAL_BROKER_PROVIDERS %s\n", strings.Join(pNames, ","))

	evidencePath := filepath.Join(LedgerRoots["openai"].RootPath, fmt.Sprintf("neutral-broker-%s.jsonl", label))
	srv, err := NewNeutralBrokerServer(ledgers, label, maxRequests, keys, nil, evidencePath, DefaultLiveProviders, budget.ProviderModels, prior)
	if err != nil {
		return err
	}
	srv.CloudGuard = guard

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		srv.RequestStop()
	}()

	sockPath := filepath.Join(sockdir, "broker.sock")
	defer func() {
		for _, l := range ledgers {
			_ = l.Close()
		}
		fmt.Printf("NEUTRAL_BROKER_DONE requests=%d\n", srv.count)
	}()

	return srv.Serve(sockPath)
}
