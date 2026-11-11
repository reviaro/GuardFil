// Command guardfil-approve evaluates one native Codex approval request (read as
// JSON from stdin) against GuardFil's policy engine and prints a single-line
// JSON verdict.  The decision logic lives in internal/approval.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/policy"
)

const (
	maxStdinBytes   = approval.MaxRequestBytes
	maxPayloadBytes = approval.MaxPayloadBytes
)

// Output is the verdict printed to stdout.
type Output = approval.Output

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("guardfil-approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "path to GuardFil policy YAML file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: guardfil-approve --policy <file>")
		return 2
	}

	stdinBytes, err := io.ReadAll(io.LimitReader(stdin, maxStdinBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "read stdin: %v\n", err)
		return 1
	}

	policyBytes, err := os.ReadFile(*policyPath)
	var out Output
	if err != nil {
		out = approval.BlockedOutput(policy.ErrInvalid.Error(), "-", "-", nil)
	} else {
		out = approval.Evaluate(policyBytes, stdinBytes)
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintf(stderr, "encode output: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
