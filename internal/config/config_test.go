package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (Config, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "config")
	creds := filepath.Join(base, "credentials")
	state := filepath.Join(base, "state")
	for _, p := range []string{root, creds, state} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(creds, "metrics-token")
	if err := os.WriteFile(token, []byte("token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{ConfigRoot: root, CredentialsRoot: creds, Data: Listener{Address: "127.0.0.1:8080"}, Management: Listener{Address: "127.0.0.1:9090", MetricsTokenFile: token}, StateDir: state}, base
}

func TestValidateRemoteBindNeedsAcknowledgementAndTLS(t *testing.T) {
	c, _ := fixture(t)
	c.Data.Address = "0.0.0.0:8080"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "remote_bind_ack") {
		t.Fatalf("got %v", err)
	}
	c.Data.RemoteBindAck = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("got %v", err)
	}
}
func TestLoadRejectsUnknown(t *testing.T) {
	c, _ := fixture(t)
	p := filepath.Join(c.ConfigRoot, "config.yaml")
	body := `{"config_root":"` + c.ConfigRoot + `","credentials_root":"` + c.CredentialsRoot + `","data":{"address":"127.0.0.1:8080"},"management":{"address":"127.0.0.1:9090","metrics_token_file":"` + c.Management.MetricsTokenFile + `"},"state_dir":"` + c.StateDir + `","unknown":true}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "field unknown") {
		t.Fatalf("got %v", err)
	}
}
func TestManagementRejectsHostnamesAndWildcards(t *testing.T) {
	for _, addr := range []string{"localhost:9090", "0.0.0.0:9090", "[::]:9090"} {
		c, _ := fixture(t)
		c.Management.Address = addr
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "literal loopback") {
			t.Errorf("%s got %v", addr, err)
		}
	}
}
func TestCredentialAdmissionRejectsEscapesSymlinksAndModes(t *testing.T) {
	t.Run("escape", func(t *testing.T) {
		c, base := fixture(t)
		outside := filepath.Join(base, "outside")
		if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		c.Management.MetricsTokenFile = outside
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("symlink escape", func(t *testing.T) {
		c, base := fixture(t)
		outside := filepath.Join(base, "outside")
		_ = os.WriteFile(outside, []byte("x"), 0600)
		link := filepath.Join(c.CredentialsRoot, "link")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		c.Management.MetricsTokenFile = link
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("mode", func(t *testing.T) {
		c, _ := fixture(t)
		if err := os.Chmod(c.Management.MetricsTokenFile, 0640); err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "owner-only") {
			t.Fatalf("got %v", err)
		}
	})
}
func TestStateRequiresOwnerOnlyWritableDirectory(t *testing.T) {
	c, _ := fixture(t)
	if err := os.Chmod(c.StateDir, 0500); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("got %v", err)
	}
}
func TestCredentialInputsCannotOverlapAfterResolution(t *testing.T) {
	c, _ := fixture(t)
	c.Data.TLSCertFile = c.Management.MetricsTokenFile
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("got %v", err)
	}
}
func TestCredentialInputsCannotOverlapThroughHardLinks(t *testing.T) {
	c, _ := fixture(t)
	cert := filepath.Join(c.CredentialsRoot, "data-cert")
	if err := os.Link(c.Management.MetricsTokenFile, cert); err != nil {
		t.Fatal(err)
	}
	c.Data.TLSCertFile = cert
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("got %v", err)
	}
}
func TestCredentialOwnerIsChecked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires permission to create a non-owner file")
	}
	c, _ := fixture(t)
	if err := os.Chown(c.Management.MetricsTokenFile, 1, -1); err != nil {
		t.Skipf("filesystem cannot create a non-owner fixture: %v", err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "owned by the running uid") {
		t.Fatalf("got %v", err)
	}
}

func approvalFixture(t *testing.T) Config {
	t.Helper()
	c, base := fixture(t)
	run := filepath.Join(base, "run")
	if err := os.Mkdir(run, 0700); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(c.ConfigRoot, "policy.yaml")
	if err := os.WriteFile(pol, []byte("schema_version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.Approval = Approval{Socket: filepath.Join(run, "a.sock"), PolicyFile: pol, DecisionLog: filepath.Join(c.StateDir, "decisions.jsonl")}
	return c
}

func TestApprovalIsOptionalAndValidated(t *testing.T) {
	c, _ := fixture(t)
	if c.Approval.Enabled() {
		t.Fatal("approval enabled by default")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("config without approval: %v", err)
	}
	ok := approvalFixture(t)
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid approval: %v", err)
	}
	cases := map[string]func(c *Config){
		"partial":        func(c *Config) { c.Approval.DecisionLog = "" },
		"relative sock":  func(c *Config) { c.Approval.Socket = "a.sock" },
		"unclean sock":   func(c *Config) { c.Approval.Socket = filepath.Dir(c.Approval.Socket) + "/./a.sock" },
		"long sock":      func(c *Config) { c.Approval.Socket = "/" + strings.Repeat("s", 120) },
		"policy outside": func(c *Config) { c.Approval.PolicyFile = c.Management.MetricsTokenFile },
		"log outside":    func(c *Config) { c.Approval.DecisionLog = filepath.Join(filepath.Dir(c.StateDir), "d.jsonl") },
	}
	for name, mut := range cases {
		c := approvalFixture(t)
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	loose := approvalFixture(t)
	if err := os.Chmod(filepath.Dir(loose.Approval.Socket), 0755); err != nil {
		t.Fatal(err)
	}
	if err := loose.Validate(); err == nil {
		t.Error("world-readable socket directory admitted")
	}
	looseLog := approvalFixture(t)
	if err := os.WriteFile(looseLog.Approval.DecisionLog, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(looseLog.Approval.DecisionLog, 0644); err != nil {
		t.Fatal(err)
	}
	if err := looseLog.Validate(); err == nil {
		t.Error("group-readable decision log admitted")
	}
}

func TestApproverSocketValidation(t *testing.T) {
	ok := approvalFixture(t)
	ok.Approval.ApproverSocket = filepath.Join(filepath.Dir(ok.Approval.Socket), "approver.sock")
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid approver socket: %v", err)
	}
	if ok.Approval.AskTimeout().Seconds() != DefaultAskTimeoutSeconds {
		t.Fatalf("default timeout %v", ok.Approval.AskTimeout())
	}
	ok.Approval.AskTimeoutSeconds = 30
	if err := ok.Validate(); err != nil || ok.Approval.AskTimeout().Seconds() != 30 {
		t.Fatalf("timeout 30: %v", err)
	}
	cases := map[string]func(c *Config){
		"same as socket":    func(c *Config) { c.Approval.ApproverSocket = c.Approval.Socket },
		"relative":          func(c *Config) { c.Approval.ApproverSocket = "approver.sock" },
		"timeout too large": func(c *Config) { c.Approval.AskTimeoutSeconds = 601 },
		"timeout negative":  func(c *Config) { c.Approval.AskTimeoutSeconds = -1 },
		"timeout headless": func(c *Config) {
			c.Approval.ApproverSocket = ""
			c.Approval.AskTimeoutSeconds = 30
		},
	}
	for name, mut := range cases {
		c := approvalFixture(t)
		c.Approval.ApproverSocket = filepath.Join(filepath.Dir(c.Approval.Socket), "approver.sock")
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

func TestLoadAcceptsIntegerAskTimeoutButNotFloats(t *testing.T) {
	c := approvalFixture(t)
	c.Approval.ApproverSocket = filepath.Join(filepath.Dir(c.Approval.Socket), "approver.sock")
	doc := func(timeout string) string {
		return "config_root: " + c.ConfigRoot + "\ncredentials_root: " + c.CredentialsRoot +
			"\ndata: {address: \"127.0.0.1:8080\"}\nmanagement: {address: \"127.0.0.1:9090\", metrics_token_file: " +
			c.Management.MetricsTokenFile + "}\nstate_dir: " + c.StateDir + "\napproval:\n  socket: " + c.Approval.Socket +
			"\n  policy_file: " + c.Approval.PolicyFile + "\n  decision_log: " + c.Approval.DecisionLog +
			"\n  approver_socket: " + c.Approval.ApproverSocket + "\n  ask_timeout_seconds: " + timeout + "\n"
	}
	path := filepath.Join(c.ConfigRoot, "guardfil.yaml")
	if err := os.WriteFile(path, []byte(doc("30")), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Approval.AskTimeoutSeconds != 30 {
		t.Fatalf("integer timeout: %v %+v", err, got.Approval)
	}
	for _, bad := range []string{"30.5", "!!float 30"} {
		if err := os.WriteFile(path, []byte(doc(bad)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("timeout %q admitted", bad)
		}
	}
}

func uiFixture(t *testing.T) Config {
	t.Helper()
	c := approvalFixture(t)
	tok := filepath.Join(c.CredentialsRoot, "ui-token")
	if err := os.WriteFile(tok, []byte("ui-secret-token-0123456789abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.UI = UI{Active: true, Address: "127.0.0.1:8088", TokenFile: tok}
	return c
}

func TestUIValidation(t *testing.T) {
	c, _ := fixture(t)
	if c.UI.Installed() || c.UI.Serving() {
		t.Fatal("ui on by default")
	}
	ok := uiFixture(t)
	if err := ok.Validate(); err != nil || !ok.UI.Serving() {
		t.Fatalf("valid ui: %v", err)
	}
	inactive := uiFixture(t)
	inactive.UI.Active = false
	if err := inactive.Validate(); err != nil || !inactive.UI.Installed() || inactive.UI.Serving() {
		t.Fatalf("inactive ui: %v", err)
	}
	withTimeout := uiFixture(t)
	withTimeout.Approval.AskTimeoutSeconds = 30 // the active UI answers held calls
	if err := withTimeout.Validate(); err != nil {
		t.Fatalf("ui ask timeout: %v", err)
	}
	cases := map[string]func(c *Config){
		"no approval":      func(c *Config) { c.Approval = Approval{} },
		"remote":           func(c *Config) { c.UI.Address = "0.0.0.0:8088" },
		"hostname":         func(c *Config) { c.UI.Address = "localhost:8088" },
		"same as data":     func(c *Config) { c.UI.Address = c.Data.Address },
		"no token":         func(c *Config) { c.UI.TokenFile = "" },
		"token outside":    func(c *Config) { c.UI.TokenFile = c.Approval.PolicyFile },
		"token is metrics": func(c *Config) { c.UI.TokenFile = c.Management.MetricsTokenFile },
		"inactive timeout": func(c *Config) { c.UI.Active = false; c.Approval.AskTimeoutSeconds = 30 },
	}
	for name, mut := range cases {
		c := uiFixture(t)
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

func TestToolCatalogValidation(t *testing.T) {
	ok := approvalFixture(t)
	ok.Approval.ToolCatalog = filepath.Join(filepath.Dir(ok.Approval.PolicyFile), "tool-catalog.yaml")
	if err := os.WriteFile(ok.Approval.ToolCatalog, []byte("catalog_version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid catalog path: %v", err)
	}
	outside := approvalFixture(t)
	outside.Approval.ToolCatalog = outside.Management.MetricsTokenFile
	if err := outside.Validate(); err == nil {
		t.Error("catalog outside config_root admitted")
	}
	missing := approvalFixture(t)
	missing.Approval.ToolCatalog = filepath.Join(filepath.Dir(missing.Approval.PolicyFile), "nope.yaml")
	if err := missing.Validate(); err == nil {
		t.Error("missing catalog admitted")
	}
}

func TestGatewayValidation(t *testing.T) {
	fixture := func(t *testing.T) Config {
		c := approvalFixture(t)
		c.Approval.ToolCatalog = filepath.Join(filepath.Dir(c.Approval.PolicyFile), "tool-catalog.yaml")
		if err := os.WriteFile(c.Approval.ToolCatalog, []byte("catalog_version: 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		tok := filepath.Join(c.CredentialsRoot, "gateway-agent-token")
		key := filepath.Join(c.CredentialsRoot, "app-key")
		for _, p := range []string{tok, key} {
			if err := os.WriteFile(p, []byte(p+"-secret-value"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		c.Gateway = Gateway{Address: "127.0.0.1:18090", AgentTokenFile: tok, Upstreams: []Upstream{{
			Name: "stockapp", BaseURL: "http://stockapp:8000", CredentialFile: key, CredentialHeader: "Authorization",
			CredentialPrefix: "Bearer ", Routes: []Route{{Method: "POST", Path: "/api/orders", Tool: "stockapp.place_order"},
				{Method: "DELETE", Path: "/api/orders/{order_id}", Tool: "stockapp.cancel_order"}}}}}
		return c
	}
	if err := fixture(t).Validate(); err != nil {
		t.Fatalf("valid gateway: %v", err)
	}
	bad := map[string]func(*Config){
		"no catalog":        func(c *Config) { c.Approval.ToolCatalog = "" },
		"public no ack":     func(c *Config) { c.Gateway.Address = "0.0.0.0:18090" },
		"hostname":          func(c *Config) { c.Gateway.Address = "localhost:18090" },
		"same as data":      func(c *Config) { c.Gateway.Address = c.Data.Address },
		"no token":          func(c *Config) { c.Gateway.AgentTokenFile = "" },
		"token is key":      func(c *Config) { c.Gateway.AgentTokenFile = c.Gateway.Upstreams[0].CredentialFile },
		"token is ui token": func(c *Config) { c.Gateway.AgentTokenFile = c.Management.MetricsTokenFile },
		"base path":         func(c *Config) { c.Gateway.Upstreams[0].BaseURL = "http://stockapp:8000/api" },
		"base userinfo":     func(c *Config) { c.Gateway.Upstreams[0].BaseURL = "http://u:p@stockapp:8000" },
		"base scheme":       func(c *Config) { c.Gateway.Upstreams[0].BaseURL = "file:///etc" },
		"name":              func(c *Config) { c.Gateway.Upstreams[0].Name = "Stock App" },
		"header":            func(c *Config) { c.Gateway.Upstreams[0].CredentialHeader = "X Key" },
		"prefix newline":    func(c *Config) { c.Gateway.Upstreams[0].CredentialPrefix = "Bearer\r\nX: y" },
		"method":            func(c *Config) { c.Gateway.Upstreams[0].Routes[0].Method = "CONNECT" },
		"path dotdot":       func(c *Config) { c.Gateway.Upstreams[0].Routes[0].Path = "/api/../admin" },
		"path wildcard":     func(c *Config) { c.Gateway.Upstreams[0].Routes[0].Path = "/api/*" },
		"tool":              func(c *Config) { c.Gateway.Upstreams[0].Routes[0].Tool = "place_order" },
		"no routes":         func(c *Config) { c.Gateway.Upstreams[0].Routes = nil },
		"key outside root":  func(c *Config) { c.Gateway.Upstreams[0].CredentialFile = c.Approval.PolicyFile },
		// Audit finding 6: a {param} route could shadow a literal route, in either order.
		"param shadows literal": func(c *Config) {
			c.Gateway.Upstreams[0].Routes = append(c.Gateway.Upstreams[0].Routes,
				Route{Method: "DELETE", Path: "/api/orders/all", Tool: "stockapp.cancel_all"})
		},
		"literal before param": func(c *Config) {
			c.Gateway.Upstreams[0].Routes = append([]Route{{Method: "DELETE", Path: "/api/orders/all", Tool: "stockapp.cancel_all"}},
				c.Gateway.Upstreams[0].Routes...)
		},
		"two params same shape": func(c *Config) {
			c.Gateway.Upstreams[0].Routes = append(c.Gateway.Upstreams[0].Routes,
				Route{Method: "DELETE", Path: "/api/{kind}/{id}", Tool: "stockapp.delete_any"})
		},
		"no listener":        func(c *Config) { c.Gateway.Address = "" },
		"socket relative":    func(c *Config) { c.Gateway.Socket = "run/gateway.sock" },
		"socket unclean":     func(c *Config) { c.Gateway.Socket = filepath.Dir(c.Approval.Socket) + "/../x/gateway.sock" },
		"socket is approval": func(c *Config) { c.Gateway.Socket = c.Approval.Socket },
		"ack without address": func(c *Config) {
			c.Gateway.Address, c.Gateway.Socket, c.Gateway.RemoteBindAck = "", filepath.Join(filepath.Dir(c.Approval.Socket), "gateway.sock"), true
		},
	}
	for name, mutate := range bad {
		c := fixture(t)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	sock := fixture(t)
	sock.Gateway.Address, sock.Gateway.Socket = "", filepath.Join(filepath.Dir(sock.Approval.Socket), "gateway.sock")
	if err := sock.Validate(); err != nil {
		t.Errorf("socket-only gateway: %v", err)
	}
	ack := fixture(t)
	ack.Gateway.Address, ack.Gateway.RemoteBindAck = "0.0.0.0:18090", true
	if err := ack.Validate(); err != nil {
		t.Errorf("acknowledged non-loopback: %v", err)
	}
}

// Routes that cannot match the same request stay allowed.
func TestRoutesOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b Route
		want bool
	}{
		{Route{Method: "GET", Path: "/x/{id}"}, Route{Method: "GET", Path: "/x/admin"}, true},
		{Route{Method: "GET", Path: "/x/admin"}, Route{Method: "GET", Path: "/x/{id}"}, true},
		{Route{Method: "GET", Path: "/x/{id}"}, Route{Method: "POST", Path: "/x/admin"}, false},
		{Route{Method: "GET", Path: "/x/{id}"}, Route{Method: "GET", Path: "/x/{id}/items"}, false},
		{Route{Method: "GET", Path: "/a/{id}"}, Route{Method: "GET", Path: "/b/{id}"}, false},
		{Route{Method: "GET", Path: "/x/y"}, Route{Method: "GET", Path: "/x/y"}, true},
	} {
		if got := routesOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("%v %v: got %v", tc.a, tc.b, got)
		}
	}
}
