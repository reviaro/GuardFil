// Command guardfil-mcp-proxy runs a stdio MCP server behind GuardFil's filter.
//
//	guardfil-mcp-proxy --socket /run/guardfil/filter.sock --server NAME -- COMMAND [ARGS...]
//
// It runs inside the agent's container, between the agent (its stdin/stdout)
// and the server it starts.  See internal/mcpproxy for what is filtered.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/reviaro/guardfil/internal/mcpproxy"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("guardfil-mcp-proxy", flag.ContinueOnError)
	sock := fs.String("socket", "", "GuardFil session approval socket (also filters results)")
	server := fs.String("server", "", "MCP server name (as in GuardFil tool IDs)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmdArgs := fs.Args()
	if *sock == "" || *server == "" || len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: guardfil-mcp-proxy --socket PATH --server NAME -- COMMAND [ARGS...]")
		return 2
	}
	child := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	child.Stderr = os.Stderr
	stdin, err := child.StdinPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardfil-mcp-proxy:", err)
		return 1
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guardfil-mcp-proxy:", err)
		return 1
	}
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "guardfil-mcp-proxy:", err)
		return 1
	}
	p := &mcpproxy.Proxy{Server: *server, Filter: mcpproxy.SocketFilter(*sock), Decide: mcpproxy.SocketDecider(*sock),
		Log: func(s string) { fmt.Fprintln(os.Stderr, "guardfil-mcp-proxy:", s) }}
	w := &lockedWriter{w: stdin}
	client := &lockedWriter{w: os.Stdout}
	go func() {
		if err := p.Upstream(os.Stdin, w, client); err != nil {
			fmt.Fprintln(os.Stderr, "guardfil-mcp-proxy:", err)
			_ = child.Process.Kill()
		}
		_ = stdin.Close()
	}()
	if err := p.Downstream(stdout, client, w); err != nil {
		fmt.Fprintln(os.Stderr, "guardfil-mcp-proxy:", err)
	}
	if err := child.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}
