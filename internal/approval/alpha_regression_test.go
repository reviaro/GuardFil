package approval

import (
	"encoding/json"
	"errors"
	"github.com/reviaro/guardfil/internal/filter"
	"strings"
	"testing"
	"time"
)

func TestApprovalPreviewEscapesInvisibleCharacters(t *testing.T) {
	s, _ := askService(t, time.Second)
	defer s.Close()
	raw, _ := json.Marshal(map[string]any{"kind": "shell", "command": []string{"echo", "safe\u202ehidden\u202c\u200b"}, "cwd": "/workspace"})
	done := make(chan Output, 1)
	go func() { done <- s.Decide(raw) }()
	waitPendingCount(t, s, 1)
	p := s.Pending()[0]
	if strings.ContainsAny(p.Detail, "\u202e\u202c\u200b") || !strings.Contains(p.Detail, `\u202ehidden\u202c\u200b`) {
		t.Fatalf("unsafe preview: %q", p.Detail)
	}
	if visiblePreview(`\u202e`) == visiblePreview("\u202e") {
		t.Fatal("literal and actual controls have identical previews")
	}
	_ = s.Answer(p.ID, false)
	if (<-done).Effect != "BLOCK" {
		t.Fatal("denied preview released")
	}
}

func TestRuleEditsCancelHeldCallsAndResults(t *testing.T) {
	for _, edit := range []string{"policy", "content", "catalog"} {
		t.Run(edit, func(t *testing.T) {
			s, _ := askService(t, 5*time.Second)
			defer s.Close()
			s.SetContentRules(mustContentRules(t, `{"schema_version":1,"lists":[{"id":"ask","name":"Ask","action":"ask","direction":"response","tools":["*"],"words":["review"]}]}`))
			requestDone := make(chan Output, 1)
			resultDone := make(chan filter.Result, 1)
			go func() { requestDone <- s.Decide([]byte(shellReq)) }()
			go func() { resultDone <- s.Filter("notes.read", "review private result") }()
			waitPendingCount(t, s, 2)
			before := s.Pending()
			switch edit {
			case "policy":
				if _, err := s.SetPolicy([]byte(strings.ReplaceAll(askPolicy, "require_approval", "deny"))); err != nil {
					t.Fatal(err)
				}
			case "content":
				s.SetContentRules(nil)
			case "catalog":
				if err := s.SetCatalog(nil); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case out := <-requestDone:
				if out.Effect != "BLOCK" || !hasString(out.Reasons, "POLICY_CHANGED") {
					t.Fatalf("stale call: %+v", out)
				}
			case <-time.After(time.Second):
				t.Fatal("rule edit did not cancel held call")
			}
			select {
			case result := <-resultDone:
				if !result.Blocked || strings.Contains(result.Text, "private result") {
					t.Fatalf("stale result: %+v", result)
				}
			case <-time.After(time.Second):
				t.Fatal("rule edit did not cancel held result")
			}
			for _, p := range before {
				if s.Answer(p.ID, true) == nil {
					t.Fatal("stale approval remained answerable")
				}
			}
		})
	}
}

type alphaFailedLog struct{ short bool }

func (w alphaFailedLog) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("log unavailable")
}

func TestResultAndDecisionRequireCompleteLogWrite(t *testing.T) {
	for _, short := range []bool{false, true} {
		s, err := NewService([]byte(notesPolicy), alphaFailedLog{short: short})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		res := s.Filter("notes.read", "private result")
		if !res.Blocked || strings.Contains(res.Text, "private result") {
			t.Fatalf("unrecorded result released: %+v", res)
		}
		out := s.Decide([]byte(shellReq))
		if out.Effect != "BLOCK" || !hasString(out.Reasons, "DECISION_LOG_UNAVAILABLE") {
			t.Fatalf("unrecorded decision: %+v", out)
		}
	}
}

func TestResponseRulesRequireAFilteringCaller(t *testing.T) {
	for _, action := range []string{"block", "filter", "ask", "monitor"} {
		s, _ := newService(t)
		s.SetContentRules(mustContentRules(t, `{"schema_version":1,"lists":[{"id":"response","name":"Response","action":"`+action+`","direction":"response","tools":["*"],"words":["private"]}]}`))
		out := s.Decide([]byte(shellReq))
		if out.Effect != "BLOCK" || !hasString(out.Reasons, "TRANSFORM_UNAVAILABLE") {
			t.Fatalf("%s: unsupported response rule ignored: %+v", action, out)
		}
		s.Close()
	}
}
