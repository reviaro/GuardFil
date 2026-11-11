package broker_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reviaro/guardfil/internal/broker/boundary"
	"github.com/reviaro/guardfil/internal/broker/responses"
)

type ReplayTestCase struct {
	Name    string
	Payload string
}

func findRepoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() failed: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root with go.mod starting from %s", dir)
		}
		dir = parent
	}
}

func TestReplayParityWithPython(t *testing.T) {
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found, skipping replay parity test")
	}

	repoRoot := findRepoRoot(t)

	cases := []ReplayTestCase{
		{
			Name:    "valid_minimal",
			Payload: `{"model":"gpt-6-luna","stream":true}`,
		},
		{
			Name:    "valid_with_reasoning_none",
			Payload: `{"model":"gpt-6-luna","stream":true,"reasoning":{"effort":"none"}}`,
		},
		{
			Name:    "valid_with_tools",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"function","name":"test_fn"}]}`,
		},
		{
			Name:    "valid_inline_base64_image",
			Payload: `{"model":"gpt-6-luna","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}]}]}`,
		},
		{
			Name:    "refuse_wrong_model",
			Payload: `{"model":"gpt-5.6-terra","stream":true}`,
		},
		{
			Name:    "refuse_snapshot_model",
			Payload: `{"model":"gpt-6-luna-2026-01-01","stream":true}`,
		},
		{
			Name:    "refuse_effort_low",
			Payload: `{"model":"gpt-6-luna","reasoning":{"effort":"low"},"stream":true}`,
		},
		{
			Name:    "refuse_stream_false",
			Payload: `{"model":"gpt-6-luna","stream":false}`,
		},
		{
			Name:    "refuse_stream_missing",
			Payload: `{"model":"gpt-6-luna"}`,
		},
		{
			Name:    "refuse_background_true",
			Payload: `{"model":"gpt-6-luna","stream":true,"background":true}`,
		},
		{
			Name:    "refuse_tier_priority",
			Payload: `{"model":"gpt-6-luna","stream":true,"service_tier":"priority"}`,
		},
		{
			Name:    "refuse_mot_15",
			Payload: `{"model":"gpt-6-luna","stream":true,"max_output_tokens":15}`,
		},
		{
			Name:    "refuse_mot_1025",
			Payload: `{"model":"gpt-6-luna","stream":true,"max_output_tokens":1025}`,
		},
		{
			Name:    "refuse_mot_bool_true",
			Payload: `{"model":"gpt-6-luna","stream":true,"max_output_tokens":true}`,
		},
		{
			Name:    "refuse_hosted_web_search",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"web_search_preview"}]}`,
		},
		{
			Name:    "refuse_hosted_file_search",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"file_search"}]}`,
		},
		{
			Name:    "refuse_hosted_code_interpreter",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"code_interpreter"}]}`,
		},
		{
			Name:    "refuse_hosted_image_gen",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"image_generation"}]}`,
		},
		{
			Name:    "refuse_hosted_computer_use",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"computer_use_preview"}]}`,
		},
		{
			Name:    "refuse_hosted_remote_mcp",
			Payload: `{"model":"gpt-6-luna","stream":true,"tools":[{"type":"mcp"}]}`,
		},
		{
			Name:    "refuse_remote_image_url",
			Payload: `{"model":"gpt-6-luna","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_image","image_url":"https://example.com/test.png"}]}]}`,
		},
	}

	// Python script to evaluate each payload with both validate_and_prepare_request and remote_input_error
	pyScript := `
import json
import sys
from research.t2a.openai_broker.live_broker import validate_and_prepare_request
from broker.input_boundary import remote_input_error

payloads = json.loads(sys.stdin.read())
results = []
for p in payloads:
    raw = p.encode("utf-8")
    try:
        obj = json.loads(p)
        boundary_err = remote_input_error(obj)
    except Exception as e:
        boundary_err = str(e)
    
    outbound, digest, inserted, tool_types, mot, err = validate_and_prepare_request(raw)
    accepted = (err is None and boundary_err is None)
    results.append({
        "accepted": accepted,
        "error": err or boundary_err or "",
        "inserted_fields": inserted if accepted else [],
        "mot": mot if accepted else 0,
    })
print(json.dumps(results))
`

	var payloadStrings []string
	for _, tc := range cases {
		payloadStrings = append(payloadStrings, tc.Payload)
	}
	inputJSON, _ := json.Marshal(payloadStrings)

	cmd := exec.Command(pythonPath, "-B", "-c", pyScript)
	cmd.Dir = filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repoRoot, "internal", "broker", "testdata", "pyref"))
	cmd.Stdin = bytes.NewReader(inputJSON)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		t.Fatalf("python script execution failed: %v\nstderr: %s", err, errBuf.String())
	}

	type PyResult struct {
		Accepted       bool     `json:"accepted"`
		Error          string   `json:"error"`
		InsertedFields []string `json:"inserted_fields"`
		MOT            int      `json:"mot"`
	}
	var pyResults []PyResult
	if err := json.Unmarshal(outBuf.Bytes(), &pyResults); err != nil {
		t.Fatalf("failed to parse python results: %v, output: %s", err, outBuf.String())
	}

	if len(pyResults) != len(cases) {
		t.Fatalf("expected %d python results, got %d", len(cases), len(pyResults))
	}

	for i, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			py := pyResults[i]

			// Run Go checks
			var obj map[string]any
			_ = json.Unmarshal([]byte(tc.Payload), &obj)
			bErr := boundary.RemoteInputError(obj)

			val := responses.ValidateAndPrepareRequest([]byte(tc.Payload))
			goAccepted := (bErr == nil && val.ErrorReason == "")

			if goAccepted != py.Accepted {
				t.Fatalf("[%s] Accept parity mismatch! Go accepted=%v (err=%v/%s), Python accepted=%v (err=%s)",
					tc.Name, goAccepted, bErr, val.ErrorReason, py.Accepted, py.Error)
			}

			if goAccepted {
				if val.OutboundMaxOutputTokens != py.MOT {
					t.Errorf("[%s] MOT mismatch: Go=%d, Python=%d", tc.Name, val.OutboundMaxOutputTokens, py.MOT)
				}
				goInserted := strings.Join(val.InsertedFields, ",")
				pyInserted := strings.Join(py.InsertedFields, ",")
				if goInserted != pyInserted {
					t.Errorf("[%s] Inserted fields mismatch: Go=%s, Python=%s", tc.Name, goInserted, pyInserted)
				}
			}
		})
	}
}
