# Command Reference

This document provides a comprehensive reference of all CLI commands, lifecycle tools, and binaries in GuardFil.

---

## 1. `deployments/local/guardfil-local.sh`

The primary control script for local development and execution.

```sh
deployments/local/guardfil-local.sh <subcommand> [options]
```

### Subcommands

| Subcommand | Arguments | Description |
| --- | --- | --- |
| `init` | `[--ui none\|inactive\|active]` | Initializes `$GF_HOME` (default `~/.guardfil-local`), sets up permissions, copies default configuration, starter policy, and tool catalog, and generates random security tokens. |
| `up` | *(None)* | Builds the image and starts the GuardFil container using Docker Compose, waits for `approval.sock`, extracts helper binaries to `$GF_HOME/bin/`, and reports status. |
| `check` | *(None)* | Verifies the host can serve a mediated workspace (FUSE 3 and `user_allow_other` in `/etc/fuse.conf`). Exits non-zero and prints the fix if not. |
| `status` | *(None)* | Checks whether `approval.sock` is active, displays the Web UI address and token location, and shows the decision log path. |
| `ui` | `<none\|inactive\|active>` | Changes the Web UI operating mode in configuration and restarts the container. |
| `catalog` | `<FILE>` | Installs an app's tool catalog. GuardFil loads the agents' tools plus this file (`$GF_HOME/config/tool-catalog.yaml`). Restarts GuardFil. |
| `credential` | `<NAME>` | Stores an app secret for the gateway from stdin in `$GF_HOME/credentials/NAME`. |
| `gateway` | `<FILE>` \| `--remove` | Installs or removes the API gateway's upstreams ([MCP and gateway](mcp-and-gateway.md)). Restarts GuardFil. |
| `down` | *(None)* | Stops and removes the GuardFil Compose stack. |
| `logs` | *(None)* | Displays the last 50 log lines from the GuardFil service container. |
| `run-codex` | `[options]` | Shortcut to run native Codex in the executor (`run-agent --runtime codex`). |
| `run-agent` | `[options]` | Runs an agent runtime (`codex`, `claude-code`, or `python`) in the hardened container executor. |

Catalog, gateway and UI changes are staged and checked with the Go configuration validator before installation. Build the current `guardfil-local:dev` image with `guardfil-local.sh up` first. Validation runs without network access; if a restart fails, the command restores the previous configuration and attempts to restart it. A failure to restart the restored configuration is reported explicitly. Removing a gateway also removes its stale socket.

---

## 2. `guardfil` (`cmd/guardfil`)

The main GuardFil daemon binary. Runs the policy kernel, approval service, filter socket, Web UI, and API gateway.

```sh
guardfil [-config <path>]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-config` | `/etc/guardfil/guardfil.yaml` | Path to the non-secret GuardFil configuration file. |
| `-validate-config` | `false` | Validate configuration, effective saved policy/content rules, catalog and route bindings, then exit without listeners or log writes. |
| `-validate-catalog` | *(None)* | Validate the specified catalog file and exit. |

---

## 3. `guardfil-approve` (`cmd/guardfil-approve`)

Evaluates a single approval request read from stdin against a policy YAML file and outputs a single-line JSON decision to stdout.

```sh
guardfil-approve --policy <file> < request.json
```

| Flag | Default | Description |
| --- | --- | --- |
| `--policy` | *(Required)* | Path to the GuardFil policy YAML file. |

---

## 4. `guardfil-broker` (`cmd/guardfil-broker`)

Host-side model brokers (the only process that reads an API key) and the in-executor relay. `run-agent` starts the right broker for you; you rarely run it by hand.

```sh
guardfil-broker <subcommand> [flags]
```

### Subcommand: `responses`
OpenAI Responses API broker for native Codex (`gpt-6-luna` by default, plus listed models).

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-sockdir` | Path | *(Required)* | Directory where `broker.sock` will be created. |
| `-case-label` | String | *(Required)* | Case label for request identifiers and evidence logging. |
| `-max-requests`| Integer | `3` | Maximum requests this broker session may make. The ledger's own cap and the $2 ceiling still apply. |
| `-experiment-root` | Path | None | Path to directory holding experiment state and ledgers. |
| `-initialize-ledger` | Boolean | `false` | Initialize a new ledger if missing. |
| `-key-file` | Path | None | Path to OpenAI API key file. |

### Subcommand: `messages`
Anthropic Messages API broker for Claude Code (`claude-sonnet-5-5` by default, plus listed models).

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-sockdir` | Path | *(Required)* | Directory where `broker.sock` will be created. |
| `-label` | String | *(Required)* | Session label. |
| `-max-requests`| Integer | `3` | Maximum requests permitted. |
| `-evidence` | Path | None | Path to evidence JSONL log file. |

### Subcommand: `neutral`
Model-neutral broker supporting OpenAI, Anthropic, and Gemini.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-sockdir` | Path | *(Required unless -check)* | Directory where `broker.sock` will be created. |
| `-label` | String | `"interactive"` | Session label. |
| `-max-requests`| Integer | `3` | Maximum requests allowed. |
| `-check` | Boolean | `false` | Runs free pre-flight checks against providers and exits. |

### Subcommand: `relay`
Local HTTP-to-Unix socket relay running in the container anchor.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-port` | Integer | `8899` | Local TCP port to bind. |
| `-path` | String | *(Required)* | Permitted HTTP path (`/v1/responses` or `/v1/messages`). |
| `-socket-path` | Path | `/run/guardfil-broker/broker.sock` | Path to host broker Unix socket. |
| `-host` | String | `127.0.0.1` | Local bind host address. |

---

## 5. `guardfil-mcp-proxy` (`cmd/guardfil-mcp-proxy`)

Runs an MCP stdio server behind GuardFil's filter socket.

```sh
guardfil-mcp-proxy --socket <PATH> --server <NAME> -- <COMMAND> [ARGS...]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--socket` | Path | *(Required)* | Path to GuardFil filter Unix domain socket. |
| `--server` | String | *(Required)* | MCP server name matching tool catalog prefixes (e.g. `notes`). |

---

## 6. `guardfil-playground` (`cmd/guardfil-playground`)

Synthetic advisory playground web server for experimenting with policy evaluation rules.

```sh
guardfil-playground [-addr <addr>] [-tools <tools>] [-allow-non-loopback]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-addr` | String | `127.0.0.1:8787` | TCP address to listen on. |
| `-tools` | String | `"demo"` | Tool set schema: `demo` or `claude-code`. |
| `-allow-non-loopback` | Boolean | `false` | Permit binding to non-loopback network interfaces. |

---

## 7. `guardfil-advisory-demo` (`cmd/guardfil-advisory-demo`)

Evaluates synthetic mock-tool action fixtures against the policy kernel without dispatching network calls or modifying disk state. Outputs results directly to stdout. Takes no command-line flags.
