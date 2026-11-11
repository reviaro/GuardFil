// Package config loads the intentionally small P1.1 configuration surface.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	MaxHeaderBytes = 32 << 10
	MaxBodyBytes   = 1 << 20
)

type Config struct {
	ConfigRoot      string   `yaml:"config_root" json:"config_root"`
	CredentialsRoot string   `yaml:"credentials_root" json:"credentials_root"`
	Data            Listener `yaml:"data" json:"data"`
	Management      Listener `yaml:"management" json:"management"`
	StateDir        string   `yaml:"state_dir" json:"state_dir"`
	Approval        Approval `yaml:"approval" json:"approval"`
	UI              UI       `yaml:"ui" json:"ui"`
	Gateway         Gateway  `yaml:"gateway" json:"gateway"`
}

// Gateway is the optional HTTP API gateway: an outside agent calls an app's
// API through GuardFil.  Each request is mapped to a catalog tool, decided like
// any other call, and only allowed ones are forwarded, with the app's real
// credential added by GuardFil.  The agent holds only AgentTokenFile's token.
type Gateway struct {
	Address string `yaml:"address" json:"address"`
	// Socket is an optional Unix socket the gateway also (or only) listens
	// on, for agents in a networkless executor (mounted in like approval.sock).
	Socket         string     `yaml:"socket" json:"socket"`
	RemoteBindAck  bool       `yaml:"remote_bind_ack" json:"remote_bind_ack"`
	AgentTokenFile string     `yaml:"agent_token_file" json:"agent_token_file"`
	Upstreams      []Upstream `yaml:"upstreams" json:"upstreams"`
}

// Upstream is one app behind the gateway, reached as /<name>/... by the agent.
type Upstream struct {
	Name             string  `yaml:"name" json:"name"`
	BaseURL          string  `yaml:"base_url" json:"base_url"`
	CredentialFile   string  `yaml:"credential_file" json:"credential_file"`
	CredentialHeader string  `yaml:"credential_header" json:"credential_header"`
	CredentialPrefix string  `yaml:"credential_prefix" json:"credential_prefix"`
	Routes           []Route `yaml:"routes" json:"routes"`
}

// Route maps a method and path template (segments like {order_id} become
// arguments) to a catalog tool.
type Route struct {
	Method string `yaml:"method" json:"method"`
	Path   string `yaml:"path" json:"path"`
	Tool   string `yaml:"tool" json:"tool"`
}

// Enabled reports whether the gateway block is present.
func (g Gateway) Enabled() bool {
	return g.Address != "" || g.Socket != "" || g.AgentTokenFile != "" || len(g.Upstreams) > 0
}

// UI is the optional owner web UI.  Leaving the block out means GuardFil is
// deployed without it.  With the block, Active chooses whether it serves:
// inactive opens no listener at all.  It needs the approval service, listens
// on a literal loopback address only, and logs in with the token in TokenFile.
type UI struct {
	Active    bool   `yaml:"active" json:"active"`
	Address   string `yaml:"address" json:"address"`
	TokenFile string `yaml:"token_file" json:"token_file"`
}

// Installed reports whether the UI block is present.
func (u UI) Installed() bool { return u != UI{} }

// Serving reports whether the UI listener opens.
func (u UI) Serving() bool { return u.Installed() && u.Active }

// Approval enables the native-agent approval service on a Unix socket.  Socket,
// PolicyFile and DecisionLog are required together; leaving the block out
// disables it.  ApproverSocket (optional) enables "ask me": calls that need
// approval are held until the owner answers on that socket, for at most
// AskTimeoutSeconds (default 60).  Without it, such calls are blocked.
// ToolCatalog (optional) lists an application's tools and their arguments.
type Approval struct {
	Socket            string `yaml:"socket" json:"socket"`
	PolicyFile        string `yaml:"policy_file" json:"policy_file"`
	DecisionLog       string `yaml:"decision_log" json:"decision_log"`
	ApproverSocket    string `yaml:"approver_socket" json:"approver_socket"`
	AskTimeoutSeconds int    `yaml:"ask_timeout_seconds" json:"ask_timeout_seconds"`
	ToolCatalog       string `yaml:"tool_catalog" json:"tool_catalog"`
	ContentRulesFile  string `yaml:"content_rules_file" json:"content_rules_file"`
	// FilterSocket (optional) serves only filter requests (secret removal), so
	// it can be given to an agent's sandbox for its MCP result proxy.
	FilterSocket string `yaml:"filter_socket" json:"filter_socket"`
}

// DefaultAskTimeoutSeconds applies when approver_socket is set without a timeout.
const DefaultAskTimeoutSeconds = 60

// AskTimeout is the effective hold timeout ("ask me").
func (a Approval) AskTimeout() time.Duration {
	if a.AskTimeoutSeconds == 0 {
		return DefaultAskTimeoutSeconds * time.Second
	}
	return time.Duration(a.AskTimeoutSeconds) * time.Second
}

// Enabled reports whether any approval field was configured.
func (a Approval) Enabled() bool { return a != Approval{} }

// maxSocketPath keeps the socket path inside sun_path (108 bytes) with margin.
const maxSocketPath = 100

type Listener struct {
	Address          string `yaml:"address" json:"address"`
	RemoteBindAck    bool   `yaml:"remote_bind_ack" json:"remote_bind_ack"`
	TLSCertFile      string `yaml:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile       string `yaml:"tls_key_file" json:"tls_key_file"`
	MetricsTokenFile string `yaml:"metrics_token_file" json:"metrics_token_file"`
}

// Load admits the selected configuration only after the document has selected
// explicit roots. Root selection is non-secret; credential values are never
// accepted from the process environment or command line.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config read: %w", err)
	}
	var c Config
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	var node yaml.Node
	if err := d.Decode(&node); err != nil {
		return Config{}, fmt.Errorf("config syntax: %w", err)
	}
	if err := validateYAML(&node, 0); err != nil {
		return Config{}, err
	}
	var extra yaml.Node
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("config has trailing document")
	}
	known := yaml.NewDecoder(strings.NewReader(string(b)))
	known.KnownFields(true)
	if err := known.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config schema: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	if _, err := secureFile(path, c.ConfigRoot, "configuration"); err != nil {
		return Config{}, err
	}
	return c, nil
}

func validateYAML(n *yaml.Node, depth int) error {
	if depth > 16 {
		return errors.New("config exceeds YAML depth limit")
	}
	if n.Alias != nil || n.Anchor != "" || n.Tag == "!!merge" || n.Kind == yaml.AliasNode {
		return errors.New("config aliases, anchors, and merge keys are forbidden")
	}
	if strings.HasPrefix(n.Tag, "!") && n.Tag != "!!map" && n.Tag != "!!seq" && n.Tag != "!!str" && n.Tag != "!!bool" && n.Tag != "!!null" && n.Tag != "!!int" {
		return errors.New("config YAML tag is forbidden")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Value == "<<" || seen[k.Value] {
				return errors.New("config duplicate or merge key")
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := validateYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) Validate() error {
	if err := validateSecureDir(c.ConfigRoot, "config_root", false); err != nil {
		return err
	}
	if err := validateSecureDir(c.CredentialsRoot, "credentials_root", false); err != nil {
		return err
	}
	// Do this before parsing TLS so no startup path can share data-plane and
	// management-plane authority and still become ready.
	if err := validateCredentialSeparation(c); err != nil {
		return err
	}
	if err := validateListener("data", c.Data, false, c.CredentialsRoot); err != nil {
		return err
	}
	if err := validateManagement(c.Management, c.CredentialsRoot); err != nil {
		return err
	}
	if c.Data.Address == c.Management.Address {
		return errors.New("data and management addresses must differ")
	}
	if err := validateStateDir(c.StateDir); err != nil {
		return err
	}
	if err := validateApproval(c); err != nil {
		return err
	}
	if err := validateUI(c); err != nil {
		return err
	}
	return validateGateway(c)
}

var (
	upstreamName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	headerName   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	routeSegment = regexp.MustCompile(`^([A-Za-z0-9._~-]{1,128}|\{[a-z][a-z0-9_]{0,63}\})$`)
	routeTool    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{1,64}$`)
)

func validateGateway(c Config) error {
	g := c.Gateway
	if !g.Enabled() {
		return nil
	}
	if !c.Approval.Enabled() || c.Approval.ToolCatalog == "" {
		return errors.New("gateway requires the approval block with a tool_catalog")
	}
	if (g.Address == "" && g.Socket == "") || g.AgentTokenFile == "" || len(g.Upstreams) == 0 || len(g.Upstreams) > 16 {
		return errors.New("gateway requires address or socket, agent_token_file and 1 to 16 upstreams")
	}
	if g.Address != "" {
		host, _, err := net.SplitHostPort(g.Address)
		if err != nil {
			return fmt.Errorf("gateway address: %w", err)
		}
		if ip := net.ParseIP(host); ip == nil || (!ip.IsLoopback() && !g.RemoteBindAck) {
			return errors.New("gateway must use a literal IP address; non-loopback requires remote_bind_ack")
		}
		for _, other := range []string{c.Data.Address, c.Management.Address, c.UI.Address} {
			if g.Address == other {
				return errors.New("gateway address must differ from data, management and ui addresses")
			}
		}
	} else if g.RemoteBindAck {
		return errors.New("gateway remote_bind_ack needs an address")
	}
	if g.Socket != "" {
		if !filepath.IsAbs(g.Socket) || filepath.Clean(g.Socket) != g.Socket || len(g.Socket) > maxSocketPath {
			return errors.New("gateway socket must be a clean absolute path of at most 100 bytes")
		}
		a := c.Approval
		if g.Socket == a.Socket || g.Socket == a.ApproverSocket || g.Socket == a.FilterSocket {
			return errors.New("gateway socket must differ from the approval sockets")
		}
		if err := validateSecureDir(filepath.Dir(g.Socket), "gateway socket directory", true); err != nil {
			return err
		}
	}
	names := map[string]bool{}
	for _, u := range g.Upstreams {
		if !upstreamName.MatchString(u.Name) || names[u.Name] {
			return fmt.Errorf("gateway upstream name %q must be unique lower-case letters, digits, _ or -", u.Name)
		}
		names[u.Name] = true
		b, err := url.Parse(u.BaseURL)
		if err != nil || (b.Scheme != "http" && b.Scheme != "https") || b.Host == "" || b.User != nil ||
			b.RawQuery != "" || b.Fragment != "" || (b.Path != "" && b.Path != "/") {
			return fmt.Errorf("gateway upstream %s: base_url must be http(s)://host[:port] with no path", u.Name)
		}
		if u.CredentialFile != "" {
			if _, err := secureFile(u.CredentialFile, c.CredentialsRoot, "gateway "+u.Name+" credential"); err != nil {
				return err
			}
			if !headerName.MatchString(u.CredentialHeader) || len(u.CredentialPrefix) > 64 ||
				strings.ContainsAny(u.CredentialPrefix, "\r\n") {
				return fmt.Errorf("gateway upstream %s: credential_header must be a header name", u.Name)
			}
		} else if u.CredentialHeader != "" || u.CredentialPrefix != "" {
			return fmt.Errorf("gateway upstream %s: credential_header needs credential_file", u.Name)
		}
		if len(u.Routes) == 0 || len(u.Routes) > 256 {
			return fmt.Errorf("gateway upstream %s: 1 to 256 routes", u.Name)
		}
		for i, r := range u.Routes {
			if err := validateRoute(r); err != nil {
				return fmt.Errorf("gateway upstream %s route %s %s: %w", u.Name, r.Method, r.Path, err)
			}
			for _, prev := range u.Routes[:i] {
				if routesOverlap(prev, r) {
					return fmt.Errorf("gateway upstream %s: routes %s %s and %s %s can match the same request; "+
						"each request must map to exactly one tool", u.Name, prev.Method, prev.Path, r.Method, r.Path)
				}
			}
		}
	}
	return nil
}

// routesOverlap reports whether two routes can match the same request: same
// method and segment count, and at every position equal literals or a {param}
// on either side. The gateway decides a request as the tool of the route it
// matches, so an overlap would let one tool's decision run another endpoint.
func routesOverlap(a, b Route) bool {
	if a.Method != b.Method {
		return false
	}
	as := strings.Split(strings.Trim(a.Path, "/"), "/")
	bs := strings.Split(strings.Trim(b.Path, "/"), "/")
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if strings.HasPrefix(as[i], "{") || strings.HasPrefix(bs[i], "{") {
			continue
		}
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func validateRoute(r Route) error {
	switch r.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return errors.New("method must be GET, POST, PUT, PATCH or DELETE")
	}
	if !routeTool.MatchString(r.Tool) {
		return errors.New("tool must be app.tool")
	}
	if !strings.HasPrefix(r.Path, "/") || len(r.Path) > 1024 {
		return errors.New("path must start with /")
	}
	params := map[string]bool{}
	for _, seg := range strings.Split(r.Path[1:], "/") {
		if !routeSegment.MatchString(seg) || seg == "." || seg == ".." {
			return errors.New("path segments are plain names or {argument}")
		}
		if strings.HasPrefix(seg, "{") {
			if params[seg] {
				return errors.New("duplicate path argument")
			}
			params[seg] = true
		}
	}
	return nil
}

func validateUI(c Config) error {
	u := c.UI
	if !u.Installed() {
		return nil
	}
	if !c.Approval.Enabled() {
		return errors.New("ui requires the approval block")
	}
	if u.Address == "" || u.TokenFile == "" {
		return errors.New("ui requires address and token_file")
	}
	host, _, err := net.SplitHostPort(u.Address)
	if err != nil {
		return fmt.Errorf("ui address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("ui must use a literal loopback address")
	}
	if u.Address == c.Data.Address || u.Address == c.Management.Address {
		return errors.New("ui address must differ from data and management addresses")
	}
	if _, err := secureFile(u.TokenFile, c.CredentialsRoot, "ui token"); err != nil {
		return err
	}
	return nil
}

func validateApproval(c Config) error {
	a := c.Approval
	if !a.Enabled() {
		return nil
	}
	if a.Socket == "" || a.PolicyFile == "" || a.DecisionLog == "" {
		return errors.New("approval requires socket, policy_file and decision_log")
	}
	for _, f := range []struct{ name, path string }{{"approval socket", a.Socket}, {"approval decision_log", a.DecisionLog}} {
		if !filepath.IsAbs(f.path) || filepath.Clean(f.path) != f.path {
			return fmt.Errorf("%s must be a clean absolute path", f.name)
		}
	}
	if len(a.Socket) > maxSocketPath {
		return errors.New("approval socket path too long")
	}
	if err := validateSecureDir(filepath.Dir(a.Socket), "approval socket directory", true); err != nil {
		return err
	}
	if a.ApproverSocket != "" {
		if !filepath.IsAbs(a.ApproverSocket) || filepath.Clean(a.ApproverSocket) != a.ApproverSocket {
			return errors.New("approval approver_socket must be a clean absolute path")
		}
		if len(a.ApproverSocket) > maxSocketPath {
			return errors.New("approval approver_socket path too long")
		}
		if a.ApproverSocket == a.Socket {
			return errors.New("approval approver_socket must differ from socket")
		}
		if err := validateSecureDir(filepath.Dir(a.ApproverSocket), "approval approver_socket directory", true); err != nil {
			return err
		}
	} else if a.AskTimeoutSeconds != 0 && !c.UI.Serving() {
		return errors.New("approval ask_timeout_seconds requires approver_socket or an active ui")
	}
	if a.FilterSocket != "" {
		if !filepath.IsAbs(a.FilterSocket) || filepath.Clean(a.FilterSocket) != a.FilterSocket || len(a.FilterSocket) > maxSocketPath {
			return errors.New("approval filter_socket must be a clean absolute path of at most 100 bytes")
		}
		if a.FilterSocket == a.Socket || a.FilterSocket == a.ApproverSocket {
			return errors.New("approval filter_socket must differ from the other sockets")
		}
		if err := validateSecureDir(filepath.Dir(a.FilterSocket), "approval filter_socket directory", true); err != nil {
			return err
		}
	}
	if a.AskTimeoutSeconds < 0 || a.AskTimeoutSeconds > 600 {
		return errors.New("approval ask_timeout_seconds must be between 1 and 600")
	}
	if _, err := secureFile(a.PolicyFile, c.ConfigRoot, "approval policy_file"); err != nil {
		return err
	}
	if a.ToolCatalog != "" {
		if _, err := secureFile(a.ToolCatalog, c.ConfigRoot, "approval tool_catalog"); err != nil {
			return err
		}
	}
	if a.ContentRulesFile != "" {
		if _, err := secureFile(a.ContentRulesFile, c.ConfigRoot, "approval content_rules_file"); err != nil {
			return err
		}
	}
	if filepath.Dir(a.DecisionLog) != filepath.Clean(c.StateDir) {
		return errors.New("approval decision_log must be directly inside state_dir")
	}
	if i, err := os.Lstat(a.DecisionLog); err == nil {
		if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
			return errors.New("approval decision_log must be an owner-only regular file")
		}
		if err := requireOwner(i, "approval decision_log"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("approval decision_log: %w", err)
	}
	return nil
}

func validateManagement(l Listener, root string) error {
	if l.Address == "" {
		return errors.New("management address required")
	}
	host, _, err := net.SplitHostPort(l.Address)
	if err != nil {
		return fmt.Errorf("management address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("management must use a literal loopback address")
	}
	return validateListener("management", l, true, root)
}

func validateListener(name string, l Listener, metrics bool, root string) error {
	if l.Address == "" {
		return fmt.Errorf("%s address required", name)
	}
	host, _, err := net.SplitHostPort(l.Address)
	if err != nil {
		return fmt.Errorf("%s address: %w", name, err)
	}
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if !loopback && !l.RemoteBindAck {
		return fmt.Errorf("%s non-loopback bind requires remote_bind_ack", name)
	}
	if !loopback && (l.TLSCertFile == "" || l.TLSKeyFile == "") {
		return fmt.Errorf("%s non-loopback bind requires TLS files", name)
	}
	if (l.TLSCertFile == "") != (l.TLSKeyFile == "") {
		return fmt.Errorf("%s TLS certificate and key must be paired", name)
	}
	if l.TLSCertFile != "" {
		if _, err := secureFile(l.TLSCertFile, root, name+" TLS certificate"); err != nil {
			return err
		}
		if _, err := secureFile(l.TLSKeyFile, root, name+" TLS key"); err != nil {
			return err
		}
		if _, err := tls.LoadX509KeyPair(l.TLSCertFile, l.TLSKeyFile); err != nil {
			return fmt.Errorf("%s TLS: %w", name, err)
		}
	}
	if metrics {
		if l.MetricsTokenFile == "" {
			return errors.New("management metrics_token_file required")
		}
		if _, err := secureFile(l.MetricsTokenFile, root, "management metrics token"); err != nil {
			return err
		}
	}
	return nil
}

func validateCredentialSeparation(c Config) error {
	inputs := []struct{ plane, kind, path string }{
		{"data", "TLS certificate", c.Data.TLSCertFile}, {"data", "TLS key", c.Data.TLSKeyFile},
		{"management", "TLS certificate", c.Management.TLSCertFile}, {"management", "TLS key", c.Management.TLSKeyFile},
		{"management", "metrics token", c.Management.MetricsTokenFile},
		{"ui", "login token", c.UI.TokenFile},
		{"gateway", "agent token", c.Gateway.AgentTokenFile},
	}
	for _, u := range c.Gateway.Upstreams {
		inputs = append(inputs, struct{ plane, kind, path string }{"gateway", u.Name + " credential", u.CredentialFile})
	}
	type credentialInput struct {
		plane, kind string
		info        os.FileInfo
	}
	var seen []credentialInput
	for _, input := range inputs {
		if input.path == "" {
			continue
		}
		// Admission precedes identity comparison so every compared file has passed
		// containment, mode, and ownership checks. os.SameFile detects both
		// symlink-resolved aliases and distinct hard-link names for one inode.
		resolved, err := secureFile(input.path, c.CredentialsRoot, input.plane+" "+input.kind)
		if err != nil {
			return err
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("%s %s: %w", input.plane, input.kind, err)
		}
		for _, prior := range seen {
			if os.SameFile(prior.info, info) {
				return fmt.Errorf("credential input overlap: %s %s and %s %s", prior.plane, prior.kind, input.plane, input.kind)
			}
		}
		seen = append(seen, credentialInput{plane: input.plane, kind: input.kind, info: info})
	}
	return nil
}

func validateSecureDir(path, name string, writable bool) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", name)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	i, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !i.IsDir() || i.Mode().Perm()&0077 != 0 || (writable && i.Mode().Perm()&0200 == 0) {
		return fmt.Errorf("%s must be an owner-only directory", name)
	}
	return requireOwner(i, name)
}
func validateStateDir(path string) error { return validateSecureDir(path, "state_dir", true) }

// secureFile resolves both root and target before containment checking. This
// permits projected-volume symlinks within a declared root but rejects escapes.
func secureFile(path, root, name string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path", name)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("credential root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%s escapes declared root", name)
	}
	i, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("%s must be an owner-only regular file", name)
	}
	if err := requireOwner(i, name); err != nil {
		return "", err
	}
	return resolved, nil
}
func requireOwner(i os.FileInfo, name string) error {
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s must be owned by the running uid", name)
	}
	return nil
}

func ServerTimeouts() (time.Duration, time.Duration, time.Duration, time.Duration) {
	return 5 * time.Second, 15 * time.Second, 15 * time.Second, 30 * time.Second
}
