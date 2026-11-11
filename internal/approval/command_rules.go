package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/shellparse"
	"go.yaml.in/yaml/v3"
)

// Command rules form a default-deny command boundary when configured for this
// principal. Explicit legacy whole-shell blocks and approvals still apply;
// an absent legacy grant does not prevent an explicit command grant.
func checkCommands(rawPolicy []byte, cat *Catalog, raw []byte, req approvalInput, outer Output, principal ...string) Output {
	princ := syntheticPrinc
	if len(principal) > 0 && principal[0] != "" {
		princ = principal[0]
	}
	var doc policy.Document
	if yaml.Unmarshal(rawPolicy, &doc) != nil {
		return outer
	}
	hasRules := false
	for _, r := range doc.Rules {
		if contains(r.Match.Principals, princ) && contains(r.Match.Operations, "shell.execute") {
			hasRules = true
			break
		}
	}
	if !hasRules {
		return outer
	}
	noOuterRule := outer.Effect == "BLOCK" && len(outer.RuleIDs) == 0 && len(outer.Reasons) == 1 && outer.Reasons[0] == "POLICY_DENIED"
	if outer.Effect != "ALLOW" && !askable(outer) && !noOuterRule {
		return outer
	}
	var payload struct {
		Command []string `json:"command"`
		Cwd     string   `json:"cwd"`
	}
	if json.Unmarshal(req.Arguments, &payload) != nil {
		return BlockedOutput("SCHEMA_INVALID", outer.PolicyDigest, outer.ActionDigest, nil)
	}
	commands, err := shellparse.Commands(payload.Command)
	if err != nil {
		return BlockedOutput("SHELL_COMMAND_UNRESOLVED", outer.PolicyDigest, outer.ActionDigest, nil)
	}
	selectors := make([]string, 0, len(commands))
	for _, cmd := range commands {
		encoded, _ := json.Marshal(cmd)
		selectors = append(selectors, string(encoded))
	}
	snapshot, err := policy.Compile(rawPolicy)
	if err != nil {
		return BlockedOutput("POLICY_UNAVAILABLE", outer.PolicyDigest, outer.ActionDigest, nil)
	}
	result := evaluatePaths(snapshot, outer.PolicyDigest, cat, princ, "shell.execute", commandRouteID, selectors,
		func(int) map[string]string { return map[string]string{"cwd": payload.Cwd} })
	// Preserve the exact submitted script and all admitted simple commands in
	// the action binding. The owner sees the original, untruncated script.
	sum := sha256.Sum256(append([]byte(outer.ActionDigest+"\n"+result.ActionDigest+"\n"), raw...))
	result.ActionDigest = "sha256:" + hex.EncodeToString(sum[:])
	if noOuterRule {
		return result
	}
	result.RuleIDs = append(result.RuleIDs, outer.RuleIDs...)
	if result.Effect != "ALLOW" && !askable(result) {
		return result
	}
	result.Reasons = append(result.Reasons, outer.Reasons...)
	if askable(outer) {
		result.Effect = "BLOCK"
	}
	return result
}
