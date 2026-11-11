package bootstrap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPAddr: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func setupFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "gf-boot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	cfgRoot := filepath.Join(dir, "config")
	credRoot := filepath.Join(dir, "credentials.d")
	stateDir := filepath.Join(dir, "state")
	runDir := filepath.Join(dir, "run")
	ownerDir := filepath.Join(dir, "owner")

	for _, d := range []string{cfgRoot, credRoot, stateDir, runDir, ownerDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	policyPath := filepath.Join(cfgRoot, "policy.yaml")
	policyContent := `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: allow-test
    effect: allow
    match:
      operations: [tool.invoke]
      principals: [synthetic]
      resources: [{kind: tool, value: test.tool}]
`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	metricsTok := filepath.Join(credRoot, "metrics-token")
	uiTok := filepath.Join(credRoot, "ui-token")
	if err := os.WriteFile(metricsTok, []byte(strings.Repeat("a", 32)), 0600); err != nil {
		t.Fatalf("write metrics token: %v", err)
	}
	if err := os.WriteFile(uiTok, []byte(strings.Repeat("b", 32)), 0600); err != nil {
		t.Fatalf("write ui token: %v", err)
	}

	approvalSock := filepath.Join(runDir, "approval.sock")
	approverSock := filepath.Join(ownerDir, "owner.sock")

	return dir, policyPath, approvalSock, approverSock
}

// TestPartialStartupFailureClosesApproverListener tests that when startup fails
// after approver is started (e.g. UI port conflict), approver and its listener
// are cleanly closed and not leaked.
func TestPartialStartupFailureClosesApproverListener(t *testing.T) {
	dir, policyPath, approvalSock, approverSock := setupFixture(t)

	// Pre-bind a TCP listener to collide with UI
	conflictListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer conflictListener.Close()
	uiAddr := conflictListener.Addr().String()

	dataAddr := freeTCPAddr(t)
	mgmtAddr := freeTCPAddr(t)

	cfgPath := filepath.Join(dir, "config", "guardfil.yaml")
	cfgContent := fmt.Sprintf(`config_root: %s
credentials_root: %s
state_dir: %s
data:
  address: "%s"
management:
  address: "%s"
  metrics_token_file: %s
approval:
  socket: %s
  policy_file: %s
  decision_log: %s
  approver_socket: %s
ui:
  active: true
  address: "%s"
  token_file: %s
`,
		filepath.Join(dir, "config"),
		filepath.Join(dir, "credentials.d"),
		filepath.Join(dir, "state"),
		dataAddr,
		mgmtAddr,
		filepath.Join(dir, "credentials.d", "metrics-token"),
		approvalSock,
		policyPath,
		filepath.Join(dir, "state", "decisions.jsonl"),
		approverSock,
		uiAddr,
		filepath.Join(dir, "credentials.d", "ui-token"),
	)

	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := ValidateConfig(cfgPath); err != nil {
		t.Fatalf("fixture invalid before startup: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	runErr := Run(ctx, cfgPath, logger)
	if runErr == nil || !strings.Contains(runErr.Error(), uiAddr) || !strings.Contains(runErr.Error(), "address already in use") {
		t.Fatalf("expected UI address collision, got %v", runErr)
	}

	// Verify that approver socket was closed and unlinked or connection is refused
	c, err := net.DialTimeout("unix", approverSock, 200*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatalf("approver socket %s is still accepting connections; listener was leaked", approverSock)
	}

	// Verify we can immediately bind a new unix listener on approverSock without conflict
	newListener, err := net.Listen("unix", approverSock)
	if err != nil {
		t.Fatalf("failed to bind new listener on approverSock after shutdown: %v", err)
	}
	newListener.Close()
}

// TestFilterSocketFailureClosesApproverListener tests that when FilterSocket fails,
// the approver server and listener are closed.
func TestFilterSocketFailureClosesApproverListener(t *testing.T) {
	dir, policyPath, approvalSock, approverSock := setupFixture(t)

	dataAddr := freeTCPAddr(t)
	mgmtAddr := freeTCPAddr(t)

	// The config accepts the directory, but ListenUnix must reject a regular file.
	badFilterSock := filepath.Join(dir, "run", "filter.sock")
	if err := os.WriteFile(badFilterSock, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config", "guardfil.yaml")
	cfgContent := fmt.Sprintf(`config_root: %s
credentials_root: %s
state_dir: %s
data:
  address: "%s"
management:
  address: "%s"
  metrics_token_file: %s
approval:
  socket: %s
  policy_file: %s
  decision_log: %s
  approver_socket: %s
  filter_socket: %s
ui:
  active: false
  address: "%s"
  token_file: %s
`,
		filepath.Join(dir, "config"),
		filepath.Join(dir, "credentials.d"),
		filepath.Join(dir, "state"),
		dataAddr,
		mgmtAddr,
		filepath.Join(dir, "credentials.d", "metrics-token"),
		approvalSock,
		policyPath,
		filepath.Join(dir, "state", "decisions.jsonl"),
		approverSock,
		badFilterSock,
		freeTCPAddr(t),
		filepath.Join(dir, "credentials.d", "ui-token"),
	)

	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := ValidateConfig(cfgPath); err != nil {
		t.Fatalf("fixture invalid before startup: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	runErr := Run(ctx, cfgPath, logger)
	if runErr == nil || !strings.Contains(runErr.Error(), badFilterSock) {
		t.Fatalf("expected filter socket failure, got %v", runErr)
	}

	// Verify approver listener is closed
	c, err := net.DialTimeout("unix", approverSock, 200*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatalf("approver socket %s is still accepting connections; listener was leaked", approverSock)
	}
}

func TestValidateConfigAndCatalog(t *testing.T) {
	dir, policyPath, approvalSock, approverSock := setupFixture(t)
	dataAddr := freeTCPAddr(t)
	mgmtAddr := freeTCPAddr(t)

	catPath := filepath.Join(dir, "config", "tool-catalog.yaml")
	catContent := `catalog_version: 1
tools:
  - id: test.tool
`
	if err := os.WriteFile(catPath, []byte(catContent), 0600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	cfgPath := filepath.Join(dir, "config", "guardfil.yaml")
	cfgContent := fmt.Sprintf(`config_root: %s
credentials_root: %s
state_dir: %s
data:
  address: "%s"
management:
  address: "%s"
  metrics_token_file: %s
approval:
  socket: %s
  policy_file: %s
  decision_log: %s
  approver_socket: %s
  tool_catalog: %s
`,
		filepath.Join(dir, "config"),
		filepath.Join(dir, "credentials.d"),
		filepath.Join(dir, "state"),
		dataAddr,
		mgmtAddr,
		filepath.Join(dir, "credentials.d", "metrics-token"),
		approvalSock,
		policyPath,
		filepath.Join(dir, "state", "decisions.jsonl"),
		approverSock,
		catPath,
	)

	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := ValidateConfig(cfgPath); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	// Validation must understand normal YAML quoting and flow syntax, and
	// reject a route absent from the catalog before installing configuration.
	for _, name := range []string{"agent-token", "upstream-key"} {
		if err := os.WriteFile(filepath.Join(dir, "credentials.d", name), []byte(strings.Repeat(name, 4)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, quote := range []string{"'", "\""} {
		gateway := fmt.Sprintf("gateway:\n  socket: %s\n  agent_token_file: %s\n  upstreams: [{name: app, base_url: 'https://example.invalid', credential_file: %s%s%s, credential_header: Authorization, routes: [{method: GET, path: /test, tool: test.tool}]}]\n", filepath.Join(dir, "run/gateway.sock"), filepath.Join(dir, "credentials.d/agent-token"), quote, filepath.Join(dir, "credentials.d/upstream-key"), quote)
		if err := os.WriteFile(cfgPath, []byte(cfgContent+gateway), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateConfig(cfgPath); err != nil {
			t.Fatalf("quoted flow YAML rejected: %v", err)
		}
		if err := os.WriteFile(cfgPath, []byte(cfgContent+strings.ReplaceAll(gateway, "tool: test.tool", "tool: missing.tool")), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateConfig(cfgPath); err == nil || !strings.Contains(err.Error(), "not in the tool catalog") {
			t.Fatalf("missing route tool accepted: %v", err)
		}
	}
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	// The validator checks the same policy/catalog numeric-field contract as Run.
	pol, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	pol = []byte(strings.Replace(string(pol), "      operations:", "      decimal: [{field: amount, operator: '>', value: '100'}]\n      operations:", 1))
	if err := os.WriteFile(policyPath, pol, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(cfgPath); err == nil {
		t.Fatal("numeric condition without catalog backing accepted")
	}
	if _, err := os.Stat(approvalSock); !os.IsNotExist(err) {
		t.Fatalf("validator opened approval socket: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state/decisions.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("validator wrote decision log: %v", err)
	}

	// Test ValidateCatalog
	cat, err := ValidateCatalog([]byte(catContent))
	if err != nil || cat == nil {
		t.Fatalf("ValidateCatalog failed: %v", err)
	}
	if !cat.Has("test.tool") {
		t.Errorf("expected catalog to have test.tool")
	}

	// Invalid catalog (bad version)
	if _, err := ValidateCatalog([]byte("catalog_version: 2\ntools: [{id: a.b}]\n")); err == nil {
		t.Errorf("expected ValidateCatalog to fail for catalog_version 2")
	}
}
