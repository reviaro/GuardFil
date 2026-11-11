package approval

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/reviaro/guardfil/internal/policy"
	"github.com/reviaro/guardfil/internal/resource"
	"go.yaml.in/yaml/v3"
)

// Website rules are additional constraints on an admitted tool call, like
// file-read rules. A website allow never supplies a missing tool grant. Calls
// with no matching website rule keep their tool decision. Unknown URL forms
// fail closed whenever this principal has website rules.
func checkWebsite(rawPolicy []byte, target string, canFilter bool, out Output, principal ...string) Output {
	if out.Effect != "ALLOW" && !askable(out) {
		return out
	}
	princ := syntheticPrinc
	if len(principal) > 0 && principal[0] != "" {
		princ = principal[0]
	}
	var doc policy.Document
	if yaml.Unmarshal(rawPolicy, &doc) != nil {
		return BlockedOutput("POLICY_UNAVAILABLE", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	hasRules := false
	for _, r := range doc.Rules {
		if contains(r.Match.Principals, princ) && contains(r.Match.Operations, "http.request") {
			hasRules = true
			break
		}
	}
	if !hasRules {
		return out
	}
	selector, ok := websiteSelector(target)
	if !ok {
		return BlockedOutput("WEBSITE_URL_UNSUPPORTED", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	snapshot, err := policy.Compile(rawPolicy)
	if err != nil {
		return BlockedOutput("POLICY_UNAVAILABLE", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	r, err := snapshot.Evaluate(policy.Input{TenantID: syntheticTenant, PrincipalID: princ,
		Operation: "http.request", ResourceKind: "url", Resource: selector})
	if err != nil {
		return BlockedOutput("POLICY_EVALUATION_FAILED", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	out.RuleIDs = append(out.RuleIDs, r.Matched...)
	switch {
	case r.Denied:
		return BlockedOutput("POLICY_DENIED", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	case len(r.Checks) > 0:
		return BlockedOutput("CHECK_UNSUPPORTED", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	case r.RequiresSanitization && !canFilter:
		return BlockedOutput("TRANSFORM_UNAVAILABLE", out.PolicyDigest, out.ActionDigest, out.RuleIDs)
	}
	out.Filter = append(out.Filter, r.SanitizeRules...)
	if r.RequiresApproval {
		out.Effect = "BLOCK"
		out.Reasons = []string{ReasonApprovalNeeded}
	} else if r.Monitored {
		out.Reasons = append(out.Reasons, MonitoredReason)
	}
	return out
}

// Rules select an HTTPS origin and path, independent of query and fragment.
// Reject ambiguous spellings instead of normalizing a path differently from
// the eventual HTTP client. Explicit default ports and DNS trailing dots are
// refused too: otherwise they could evade a rule on the ordinary hostname.
func websiteSelector(target string) (string, bool) {
	if len(target) > MaxPayloadBytes {
		return "", false
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" ||
		strings.HasSuffix(u.Hostname(), ".") || strings.HasSuffix(u.Host, ":") {
		return "", false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return "", false
		}
	}
	u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = "", "", "", false
	if u.Path == "" {
		u.Path = "/"
	}
	selector := u.String()
	normalized, canonical, err := resource.NormalizeSelector(resource.URL, selector)
	return normalized, err == nil && canonical
}
