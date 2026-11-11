package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/reviaro/guardfil/internal/bootstrap"
)

func main() {
	configPath := flag.String("config", "/etc/guardfil/guardfil.yaml", "non-secret configuration file path")
	validateConfig := flag.Bool("validate-config", false, "validate configuration file and exit")
	validateCatalog := flag.String("validate-catalog", "", "validate tool catalog file path and exit")
	flag.Parse()

	if *validateCatalog != "" {
		raw, err := os.ReadFile(*validateCatalog)
		if err != nil {
			fmt.Fprintf(os.Stderr, "catalog read: %v\n", err)
			os.Exit(1)
		}
		if _, err := bootstrap.ValidateCatalog(raw); err != nil {
			fmt.Fprintf(os.Stderr, "catalog invalid: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *validateConfig {
		if err := bootstrap.ValidateConfig(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := bootstrap.Run(context.Background(), *configPath, slog.New(slog.NewJSONHandler(os.Stderr, nil))); err != nil {
		slog.Error("guardfil stopped", "error", err)
		os.Exit(1)
	}
}
