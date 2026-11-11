# Installation and Setup

This document covers system requirements, environment variables, filesystem layout, and the `guardfil-local.sh` lifecycle commands.

## System Requirements

- **Operating System**: Linux (x86_64).
- **Container Engine**: Docker with Docker Compose plugin (Compose v2).
- **Python**: Python 3.11 or newer (standard library only; no pip dependencies required for core operations).
- **FUSE 3**: `/dev/fuse`, `fusermount3` and a kernel with `openat2` (Linux 5.6+). An administrator must add
  `user_allow_other` to `/etc/fuse.conf` once (`echo user_allow_other | sudo tee -a /etc/fuse.conf`) so Docker can
  mount the mediated workspace view. Run `guardfil-local.sh check` to verify. See
  [host setup](workspace-and-commands.md#host-setup-and-existing-policies).
- **Agent Runtimes (Host)**:
  - Native Codex (`codex`) if running the Codex runtime.
  - Claude Code CLI (`claude`) if running the Claude Code runtime.

## Directory Layout and Environment

By default, GuardFil stores local configuration, sockets, and state under `~/.guardfil-local`. You can override this location by setting the `GF_HOME` environment variable.

| Path | Description | Permissions |
| --- | --- | --- |
| `$GF_HOME/config/` | Core configuration directory | `0700` |
| `$GF_HOME/config/guardfil.yaml` | Main GuardFil daemon configuration | `0600` |
| `$GF_HOME/config/policy.yaml` | Compiled policy rules | `0600` |
| `$GF_HOME/config/tool-catalog.yaml` | Application tool catalog definitions | `0600` |
| `$GF_HOME/credentials/` | Generated authentication tokens | `0700` |
| `$GF_HOME/credentials/ui-token` | Secret bearer token for the Web UI | `0600` |
| `$GF_HOME/credentials/metrics-token`| Token for Prometheus/metrics endpoint | `0600` |
| `$GF_HOME/credentials/gateway-agent-token` | Token agents use to call the API gateway | `0600` |
| `$GF_HOME/config/app-catalog.yaml`, `gateway.yaml` | The app catalog and gateway upstreams you installed | `0600` |
| `$GF_HOME/owner/` | Directory holding `owner.sock` (used for "ask me" approvals) | `0700` |
| `$GF_HOME/run/` | Unix domain sockets directory (`approval.sock`, `filter.sock`) | `0700` |
| `$GF_HOME/state/` | Runtime state storage (`decisions.jsonl`) | `0700` |
| `$GF_HOME/bin/` | Extracted helper binaries (`guardfil-broker`, `guardfil-mcp-proxy`, `guardfil-workspace`) | `0700` |

> [!IMPORTANT]
> The `$GF_HOME/owner` directory and your API credentials are never mounted into agent containers. Agent containers only receive `$GF_HOME/run/approval.sock` (or their per-agent socket), the gateway socket when a gateway is installed, the filter socket when MCP servers run, and `/workspace`.

### Model Provider API Keys

Provider API keys are read exclusively by the host-side broker (`guardfil-broker`) and must be stored in `~/.config/guardfil/credentials.d/`:

```sh
mkdir -p -m 700 ~/.config/guardfil/credentials.d
( umask 077; cat > ~/.config/guardfil/credentials.d/openai-api-key )     # for Codex
( umask 077; cat > ~/.config/guardfil/credentials.d/anthropic-api-key )  # for Claude Code
( umask 077; cat > ~/.config/guardfil/credentials.d/gemini-api-key )     # for Gemini
```

## Management with `guardfil-local.sh`

The primary management script is located at `deployments/local/guardfil-local.sh`.

```
deployments/local/guardfil-local.sh <command> [options]
```

### Subcommands

| Command | Usage | Description |
| --- | --- | --- |
| `init` | `guardfil-local.sh init [--ui none\|inactive\|active]` | Creates `$GF_HOME`, sets permissions (`0700`/`0600`), installs default policy and catalog files, and generates UI and metrics tokens. |
| `up` | `guardfil-local.sh up` | Builds and launches the GuardFil service container in the background, waits for `approval.sock` to become ready, extracts helper binaries into `$GF_HOME/bin/`, and displays service status. |
| `check` | `guardfil-local.sh check` | Verifies the host can serve a mediated workspace (FUSE 3 and `user_allow_other`); exits non-zero with the fix if not. `init` and `up` print the same finding as a warning. |
| `status` | `guardfil-local.sh status` | Checks socket connectivity, prints the Web UI URL and token file location, and shows the decision log path. |
| `ui` | `guardfil-local.sh ui <none\|inactive\|active>` | Toggles the Web UI mode and restarts the GuardFil service container. |
| `catalog` | `guardfil-local.sh catalog <FILE>` | Installs an app's tool catalog, kept together with the agents' tools, and restarts GuardFil. |
| `credential` | `guardfil-local.sh credential <NAME> < SECRET` | Stores an app secret for the API gateway. |
| `gateway` | `guardfil-local.sh gateway <FILE>` \| `--remove` | Installs or removes the API gateway's upstreams ([MCP and gateway](mcp-and-gateway.md)). |
| `down` | `guardfil-local.sh down` | Stops and removes the GuardFil container stack via Docker Compose. |
| `logs` | `guardfil-local.sh logs` | Tails the last 50 lines of logs from the GuardFil service container. |
| `run-codex`| `guardfil-local.sh run-codex [options]` | Convenience shortcut to run native Codex inside the executor. |
| `run-agent`| `guardfil-local.sh run-agent [options]` | Runs an agent (Codex, Claude Code, or Python) inside the executor. |

### Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `GF_HOME` | `~/.guardfil-local` | Base path for GuardFil configuration, state, and sockets. |
| `GF_PROJECT` | `guardfil-local` | Docker Compose project name. Give each `GF_HOME` on one machine its own. |
| `GF_DATA_ADDR` | `127.0.0.1:18080` | Internal data listener address. |
| `GF_MGMT_ADDR` | `127.0.0.1:19090` | Internal management listener address. |
| `GF_UI_ADDR` | `127.0.0.1:8088` | HTTP address for the GuardFil Web UI. |
| `CODEX_BIN_DIR` | Auto-detected | Path to standalone Codex release binaries. |
