package approval

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"

	"github.com/reviaro/guardfil/internal/decision"
	"github.com/reviaro/guardfil/internal/policy"
	"go.yaml.in/yaml/v3"
)

// readPathTools are catalog tools that read the file system, with the argument
// that names what they read. Read names one file; Grep, Glob and LS search a
// directory and can return what lies under it.
var readPathTools = map[string]struct {
	arg  string
	file bool
}{
	"claude.read": {"file_path", true},
	"claude.grep": {"path", false},
	"claude.glob": {"path", false},
	"claude.ls":   {"path", false},
}

func mediatedReadRequest(raw []byte) bool {
	in, err := parseStdinRequest(raw)
	if err != nil {
		return false
	}
	spec, ok := readPathTools[in.Server+"."+in.Tool]
	if !ok {
		return false
	}
	var args map[string]any
	if json.Unmarshal(in.Arguments, &args) != nil {
		return false
	}
	p, _ := args[spec.arg].(string)
	if path.Clean(p) != p || (p != "/workspace" && !strings.HasPrefix(p, "/workspace/")) {
		return false
	}
	pattern, _ := args["pattern"].(string)
	return in.Tool != "glob" || (!path.IsAbs(pattern) && !strings.Contains(pattern, ".."))
}

// checkReadPath applies the policy's file-read rules (filesystem.read on a
// path) to a tool call that the tool rules already allowed:
//   - Read: the file path is decided as filesystem.read; a matching deny or
//     ask-me rule blocks it.
//   - Grep, Glob, LS: the directory is decided the same way, and the search is
//     also blocked if any read deny or ask-me rule names a path inside that
//     directory (or the directory is inside one), because the search could
//     return it whatever rule matches the directory itself.
//
// If the policy has no deny or ask-me read rule for the principal, the tool
// decision stands. Otherwise the path must be absolute and clean (the hook
// resolves it against the working directory) and a Glob pattern must stay
// inside it; anything else is blocked. Symbolic links are not resolved here:
// the executor's file system decides what a link reaches.
func checkReadPath(policyBytes []byte, cat *Catalog, stdinBytes []byte, out Output, targetPrincipal ...string) Output {
	req, err := parseStdinRequest(stdinBytes)
	if err != nil || req.Shell || req.WritePaths != nil || req.ReadPaths != nil {
		return out
	}
	spec, ok := readPathTools[req.Server+"."+req.Tool]
	if !ok {
		return out
	}
	princ := syntheticPrinc
	if len(targetPrincipal) > 0 && targetPrincipal[0] != "" {
		princ = targetPrincipal[0]
	}
	restricted := readRestrictions(policyBytes, princ)
	if len(restricted) == 0 {
		return out // no read rule can block this call
	}
	var args map[string]any
	_ = json.Unmarshal(req.Arguments, &args)
	p, _ := args[spec.arg].(string)
	if p == "" || !path.IsAbs(p) || path.Clean(p) != p {
		return BlockedOutput("READ_PATH_REQUIRED", out.PolicyDigest, "-", nil)
	}
	// A Glob pattern can name files outside its directory.
	if pat, _ := args["pattern"].(string); req.Tool == "glob" && (path.IsAbs(pat) || strings.Contains(pat, "..")) {
		return BlockedOutput("READ_PATTERN_LEAVES_PATH", out.PolicyDigest, "-", nil)
	}
	snapshot, err := policy.Compile(policyBytes)
	if err != nil {
		return BlockedOutput(err.Error(), "-", "-", nil)
	}
	r := evaluatePaths(snapshot, out.PolicyDigest, cat, princ, fsReadOperation, fsReadRouteID, []string{p},
		func(int) map[string]string { return map[string]string{"tool": req.Tool} })
	noRule := len(r.RuleIDs) == 0 && len(r.Reasons) == 1 && r.Reasons[0] == "POLICY_DENIED"
	if r.Effect != string(decision.ALLOW) && !noRule {
		return r // a read rule denied or held it, or the path was refused
	}
	if !spec.file {
		for _, prefix := range restricted {
			if pathsOverlap(p, prefix) {
				return BlockedOutput("READ_SEARCH_COVERS_RESTRICTED_PATH", out.PolicyDigest, "-", nil)
			}
		}
	}
	if r.Effect == string(decision.ALLOW) {
		out.RuleIDs = append(out.RuleIDs, r.RuleIDs...)
	}
	return out
}

// readRestrictions returns every path pattern that a deny or ask-me
// filesystem.read rule names for princ.
func readRestrictions(policyBytes []byte, princ string) []string {
	var d policy.Document
	dec := yaml.NewDecoder(bytes.NewReader(policyBytes))
	if dec.Decode(&d) != nil {
		return []string{"/**"} // unreadable: treat every search as covering a restriction
	}
	var out []string
	for _, rule := range d.Rules {
		if rule.Effect != "deny" && rule.Effect != "require_approval" {
			continue
		}
		if !contains(rule.Match.Operations, "filesystem.read") || !contains(rule.Match.Principals, princ) {
			continue
		}
		for _, res := range rule.Match.Resources {
			if res.Kind == "path" {
				out = append(out, res.Value)
			}
		}
	}
	return out
}

// pathsOverlap reports whether a search of directory dir can return a file
// that pattern names: the pattern lies inside or at dir, or dir lies inside a
// "/**" pattern. As in the policy kernel, a trailing "/**" is the only
// wildcard (it matches the directory and everything under it). A
// BASE/**/NAME pattern can name a file anywhere below BASE, so it is judged
// as BASE/**.
func pathsOverlap(dir, pattern string) bool {
	recursive := strings.HasSuffix(pattern, "/**")
	if i := strings.Index(pattern, "/**/"); i >= 0 {
		pattern = pattern[:i] + "/**"
		recursive = true
	}
	base := strings.TrimSuffix(pattern, "/**")
	if base == "" {
		return true
	}
	if base == "/" {
		return dir == "/"
	}
	d := strings.TrimSuffix(dir, "/") + "/"
	return base == dir || strings.HasPrefix(base, d) || (recursive && strings.HasPrefix(dir, base+"/"))
}
