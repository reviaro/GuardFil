// guardfil-workspace serves a single session's mediated filesystem on the host.
// The executor mounts this view, never its raw backing source.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/reviaro/guardfil/internal/workspacefs"
)

func main() {
	source := flag.String("source", "", "raw host workspace; never mounted into the agent")
	mount := flag.String("mount", "", "private empty directory for the mediated view")
	socket := flag.String("socket", "", "session approval socket")
	virtual := flag.String("virtual-root", "/workspace", "workspace path seen by the agent")
	other := flag.Bool("allow-other", true, "allow Docker's daemon to bind the mount (needs user_allow_other in /etc/fuse.conf)")
	flag.Parse()
	if *source == "" || *mount == "" || *socket == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	w, err := workspacefs.New(*source, *virtual, workspacefs.SocketAuthorizer(*socket))
	if err != nil {
		fmt.Fprintln(os.Stderr, "workspace:", err)
		os.Exit(1)
	}
	defer w.Close()
	s, err := w.Mount(*mount, *other)
	if err != nil {
		fmt.Fprintln(os.Stderr, "workspace mount:", err)
		fmt.Fprintln(os.Stderr, "Filesystem mediation is required; the raw workspace will not be used as a fallback.")
		os.Exit(1)
	}
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		if err := s.Unmount(); err != nil {
			fmt.Fprintln(os.Stderr, "workspace unmount:", err)
		}
	}()
	fmt.Println("GUARDFIL_WORKSPACE_READY")
	s.Wait()
}
