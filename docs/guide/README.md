# GuardFil Guide

Welcome to the GuardFil guide. GuardFil runs an AI coding agent inside a constrained container, checks supported tool requests, and enforces workspace read/write rules through a policy-controlled filesystem. Native integrations submit shell commands for approval; custom agents must use the Python client for tool and command checks. See [workspace and command rules](workspace-and-commands.md) for setup and limits.

## Index

- [Concepts](concepts.md): What GuardFil is, how the boundary works, how requests flow, and what it does not protect.
- [Installation and Setup](install.md): Requirements, `guardfil-local.sh` commands, and where configuration, state, and credentials live.
- [Running Agents](running-agents.md): Running native Codex, Claude Code, or Python agents with `run-agent`, agent identities, MCP servers, and gateway sockets.
- [Policy Language](policy.md): The policy engine, default deny, rules, effects, operations, resources, patterns, decimal amount conditions, and conflict resolution.
- [Web UI](web-ui.md): Managing rules, YAML configuration, held "ask me" calls, decision logs, content rules, and the Try It test bench.
- [Content Rules](content-rules.md): Filtering or blocking word lists, regex patterns, secret redactions, prompt-injection scanning, and the filter obligation.
- [Tool Catalog](tool-catalog.md): The catalog format, tool argument types and validation, and installing custom catalogs.
- [MCP and Gateway](mcp-and-gateway.md): Filtering Model Context Protocol (MCP) servers with `guardfil-mcp-proxy` and credential injection via the HTTP API gateway.
- [Models and Budget](models-and-budget.md): The `guardfil-broker`, supported providers, pinned models, the $2.00 ledgers, reservations, and credential isolation.
- [Command Reference](commands.md): Reference of all subcommands in `guardfil-local.sh` and binaries in `cmd/`.
- [Troubleshooting](troubleshooting.md): Common error messages, failure reasons, and how to fix them.

## Where to Start

If you are new to GuardFil, follow this path:

1. **Understand the security boundary**: Read [Concepts](concepts.md) to learn how GuardFil constrains agent execution.
2. **Set up GuardFil locally**: Read [Installation and Setup](install.md) to initialize `$GF_HOME` and launch the local service.
3. **Launch your first agent**: Read [Running Agents](running-agents.md) to run Codex or Claude Code on a local workspace.
4. **Manage what is permitted**: Read [Policy Language](policy.md) and [Web UI](web-ui.md) to configure allowed tools, file writes, and approval prompts.

## Other documents

- The repository [README](../../README.md) has the quickstart.
- [Developer integration](../developer-integration.md) and the [operator reference](../operator-reference.md) cover the Go build and the container service.
