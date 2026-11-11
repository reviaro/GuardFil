package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reviaro/guardfil/internal/playground"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	allowNonLoopback := flag.Bool("allow-non-loopback", false, "permit binding to non-loopback interfaces")
	toolsFlag := flag.String("tools", "demo", "tool set: demo or claude-code")
	flag.Parse()

	toolSet, err := playground.ParseToolSet(*toolsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := playground.CheckListenAddr(*addr, *allowNonLoopback); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid listen address %q: %v\n", *addr, err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on %q: %v\n", *addr, err)
		os.Exit(1)
	}
	defer ln.Close()

	pg, err := playground.New(playground.WithToolSet(toolSet))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing playground: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Handler:           pg.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("SYNTHETIC / ADVISORY ONLY - nothing is executed, dispatch_eligible is always false")
	fmt.Printf("GuardFil Playground listening on %s\n", playground.DisplayURL(*addr))

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop()
	fmt.Println("\nShutting down playground...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Playground stopped.")
}
