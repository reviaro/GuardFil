package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reviaro/guardfil/internal/broker/budget"
	"github.com/reviaro/guardfil/internal/broker/messages"
	"github.com/reviaro/guardfil/internal/broker/neutral"
	"github.com/reviaro/guardfil/internal/broker/relay"
	"github.com/reviaro/guardfil/internal/broker/responses"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("subcommand required: responses, messages, neutral, relay, or migrate-ledger")
	}

	subcmd := args[0]
	subArgs := args[1:]

	// The brokers (and migrate-ledger validation) accept built-in models plus
	// the owner's model list.
	if subcmd == "responses" || subcmd == "messages" || subcmd == "neutral" || subcmd == "migrate-ledger" {
		if err := budget.LoadModels(budget.DefaultModelsPath()); err != nil {
			return err
		}
		if subcmd == "migrate-ledger" {
			return runMigrateLedger(subArgs)
		}
		err := runBroker(subcmd, subArgs)
		if errors.Is(err, budget.ErrLedgerCorrupt) && !errors.Is(err, budget.ErrMigrationState) {
			return fmt.Errorf("%w (if you removed a model from ~/.config/guardfil/models.yaml or changed its price after using it, restore that entry)", err)
		}
		return err
	}

	switch subcmd {
	case "relay":
		return runRelay(subArgs)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown subcommand %q", subcmd)
	}
}

func runBroker(subcmd string, subArgs []string) error {
	switch subcmd {
	case "responses":
		return runResponses(subArgs)
	case "messages":
		return runMessages(subArgs)
	default:
		return runNeutral(subArgs)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `guardfil-broker - unified GuardFil broker and relay

Subcommands:
  responses       OpenAI Responses API broker for native Codex
  messages        Anthropic Messages API broker for native Claude Code
  neutral         Model-neutral broker for Python agent (OpenAI, Anthropic, Gemini)
  relay           HTTP-to-Unix-socket local TCP relay
  migrate-ledger  Migrate legacy provider budget ledgers to schema v2 paths/IDs

The brokers accept the built-in models plus those listed, with prices, in
~/.config/guardfil/models.yaml.

Run 'guardfil-broker <subcommand> --help' for details on a subcommand.
`)
}

func runResponses(args []string) error {
	fs := flag.NewFlagSet("responses", flag.ContinueOnError)
	sockdir := fs.String("sockdir", "", "Directory where broker.sock will be created (required)")
	caseLabel := fs.String("case-label", "", "Case label for request_id and evidence (required)")
	maxRequests := fs.Int("max-requests", responses.DefaultMaxRequests, "Maximum requests allowed")
	expRoot := fs.String("experiment-root", "", "Path to experiment root directory")
	initLedger := fs.Bool("initialize-ledger", false, "Initialize ledger if missing")
	keyFile := fs.String("key-file", "", "Path to OpenAI API key file")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sockdir == "" {
		return errors.New("--sockdir is required")
	}
	if *caseLabel == "" {
		return errors.New("--case-label is required")
	}

	return responses.RunResponsesBroker(*sockdir, *caseLabel, *maxRequests, *expRoot, *initLedger, *keyFile)
}

func runMessages(args []string) error {
	fs := flag.NewFlagSet("messages", flag.ContinueOnError)
	sockdir := fs.String("sockdir", "", "Directory where broker.sock will be created (required)")
	label := fs.String("label", "", "Session label (required)")
	maxRequests := fs.Int("max-requests", 3, "Maximum requests allowed")
	evidence := fs.String("evidence", "", "Path to evidence JSONL file")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sockdir == "" {
		return errors.New("--sockdir is required")
	}
	if *label == "" {
		return errors.New("--label is required")
	}

	return messages.RunMessagesBroker(*sockdir, *label, *maxRequests, *evidence)
}

func runNeutral(args []string) error {
	fs := flag.NewFlagSet("neutral", flag.ContinueOnError)
	sockdir := fs.String("sockdir", "", "Directory where broker.sock will be created")
	label := fs.String("label", "interactive", "Session label")
	maxRequests := fs.Int("max-requests", 3, "Maximum requests allowed")
	check := fs.Bool("check", false, "Run free provider preflight checks and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *check {
		return neutral.RunNeutralBroker("", "", 0, true)
	}

	if *sockdir == "" {
		return errors.New("--sockdir is required")
	}

	return neutral.RunNeutralBroker(*sockdir, *label, *maxRequests, false)
}

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	port := fs.Int("port", relay.DefaultPort, "Local TCP port")
	path := fs.String("path", "", "Allowed path (/v1/responses or /v1/messages)")
	socketPath := fs.String("socket-path", relay.DefaultSocketPath, "Broker Unix domain socket path")
	host := fs.String("host", relay.DefaultHost, "Local bind host")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--path is required")
	}

	cfg := relay.Config{
		Host:             *host,
		Port:             *port,
		AllowedPath:      *path,
		SocketPath:       *socketPath,
		SocketTimeoutSec: 130 * time.Second,
	}
	return relay.RunRelay(cfg)
}

func runMigrateLedger(args []string) error {
	fs := flag.NewFlagSet("migrate-ledger", flag.ContinueOnError)
	provider := fs.String("provider", "all", "Provider ledger to migrate: openai, anthropic, gemini, or all")
	dryRun := fs.Bool("dry-run", false, "Validate and report migration actions without modifying disk state")
	defaultRoot := filepath.Join(os.Getenv("HOME"), ".local/state/guardfil")
	stateRoot := fs.String("state-root", defaultRoot, "Ledger state root directory")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	var targets []string
	if *provider == "all" {
		targets = budget.SupportedProviders
	} else if _, ok := budget.ProviderLedgerSpecs[*provider]; ok {
		targets = []string{*provider}
	} else {
		return fmt.Errorf("invalid --provider %q (want openai, anthropic, gemini, or all)", *provider)
	}

	var errs []error
	for _, p := range targets {
		res, err := budget.MigrateProviderLedger(*stateRoot, p, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "provider=%s error=%v\n", p, err)
			errs = append(errs, fmt.Errorf("migrate %s ledger: %w", p, err))
			continue
		}
		fmt.Printf("provider=%s status=%s committed_micros=%d retained_micros=%d reservations=%d halted=%t halt_reason=%s\n",
			res.Provider, res.Status, res.CommittedSpendMicros, res.RetainedFailedMicros, res.TotalReservationsCount, res.Halted, res.HaltReason)
	}
	return errors.Join(errs...)
}
