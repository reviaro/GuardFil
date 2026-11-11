# Developer integration guide

For people who build on GuardFil or contribute to it. To install and use
GuardFil, start with the [README quickstart](../README.md#quickstart) and the
[guide](guide/README.md).

GuardFil is an alpha. It supports a local, single-user deployment on Linux.

## Build and test

Prerequisites: Go `1.27.1` exactly (`GOTOOLCHAIN=local`), Python 3 for the
launcher, runners and Python tests, and Docker for the executor checks.

```sh
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly
go mod verify
./scripts/check-format.sh
go vet ./...
go test ./...
go test -race ./...
./scripts/test-failclosed-verification.sh
```

Without a local Go toolchain, `devenv/ci-docker.sh` runs the same checks for
a committed ref inside the pinned `golang:1.27.1-bookworm` image.

Python unit tests (standard library only):

```sh
python3 -m unittest deployments.local.test_executor deployments.local.test_workspace \
  deployments.local.test_workspace_scope deployments.local.test_run_codex \
  deployments.local.test_claude_hook deployments.local.test_agent_identity
python3 -m unittest deployments.local.test_local_config
python3 -m unittest redteam.m5.test_redteam redteam.m5.test_run_redteam \
  redteam.m6.test_standin redteam.m6.test_scripted_scorer redteam.m6.test_lab_mcp
```

Hosted CI (`.github/workflows/ci.yml`) runs three jobs on every push and
pull request:

| Job | What it runs |
|---|---|
| `verify` | Format, vet, Go tests with and without the race detector, the fail-closed script suite, the API gateway and headless end-to-end checks, and a reproducible-build comparison (`scripts/reproducibility.sh`). |
| `escape-suite` | Python unit tests, filesystem tests on real FUSE mounts, the executor escape suite (`deployments/local/escape_suite.py`), the Python runtime in the real executor, and the scripted red-team against pinned Codex and Claude Code. |
| `quickstart` | The README quickstart on a clean runner (`deployments/local/quickstart-check.sh`), with a scripted stand-in for the model provider. |

The mounted-filesystem tests need Linux, FUSE 3 and `user_allow_other` in
`/etc/fuse.conf`; they are skipped unless `GUARDFIL_FUSE_TEST=1` is set.

## Binaries

All are built from `cmd/`. The local image (`deployments/Dockerfile`) ships
`guardfil`, `guardfil-broker`, `guardfil-mcp-proxy` and `guardfil-workspace`.

| Binary | Role |
|---|---|
| `guardfil` | The service: approval socket, owner approvals, filter socket, web UI, API gateway, health and metrics listeners. |
| `guardfil-broker` | Host-side model broker. Holds the provider key, counts spend against the budget ledger and relays model requests for an agent that has no network. Subcommands: `responses`, `messages`, `neutral`, `relay`. |
| `guardfil-mcp-proxy` | Runs a stdio MCP server behind GuardFil inside the agent's container: asks for a decision on each `tools/call` and filters results. |
| `guardfil-workspace` | Serves one session's policy-mediated view of the workspace (FUSE) on the host. The executor mounts this view, never the raw directory. |
| `guardfil-approve` | Evaluates one approval request from stdin against a policy file and prints the verdict. Useful in scripts and tests. |
| `guardfil-playground` | A local page for trying policies against sample actions. See its [README](../cmd/guardfil-playground/README.md). |
| `guardfil-advisory-demo` | Evaluates synthetic fixtures and prints decisions; dispatches nothing. |

Packages under `internal/` are not a public Go API and can change without
notice.

## Integration surfaces

| Surface | Use it to | Details |
|---|---|---|
| Agent runners | Run Codex, Claude Code or a Python agent inside the executor | [Running agents](guide/running-agents.md) |
| Approval socket | Ask GuardFil to decide a shell command, file change or tool call | [Operator reference](operator-reference.md#approval-service) |
| Python client | Guard an app's own tools (`clients/python/guardfil_client.py`) or call a model through the broker (`guardfil_model.py`) | [Client README](../clients/python/README.md) |
| MCP proxy | Put an MCP server behind decisions and result filtering | [MCP and gateway](guide/mcp-and-gateway.md) |
| API gateway | Make GuardFil the only route to an app's HTTP API | [MCP and gateway](guide/mcp-and-gateway.md), [operator reference](operator-reference.md#api-gateway) |
| Tool catalog | Declare an app's tools and typed arguments | [Tool catalog](guide/tool-catalog.md) |
| Policy and content rules | Decide what is allowed, blocked, monitored, filtered or asked | [Policy](guide/policy.md), [content rules](guide/content-rules.md) |

### Approval socket protocol

A client connects to the Unix socket, sends one JSON request line and reads
one JSON verdict line. Treat anything other than `"effect": "ALLOW"` as a
block.

Request forms:

- MCP or app tool: `{"server": "...", "tool": "...", "arguments": {...}}`
- Shell: `{"kind": "shell", "command": ["bash", "-c", "git status"], "cwd": "/workspace"}`
- File write: `{"kind": "file_write", "changes": [{"path": "...", "change": "..."}]}`

The verdict carries `effect`, `reasons`, `rule_ids`, `policy_digest` and
`action_digest`. A caller that can filter results says so with
`"can_filter": true`; without it a Filter rule blocks the call
(`TRANSFORM_UNAVAILABLE`).

A custom runtime that only asks the socket is cooperative: GuardFil decides
the calls it is shown. Enforcement comes from running the agent in the
executor, where workspace IO, the network and credentials are outside its
reach. See [concepts](guide/concepts.md).

## Limits

- Local, single-user deployment; the UI uses loopback HTTP. Remote hosting
  and SSO are out of scope for the alpha.
- The mediated workspace needs Linux, FUSE 3, `openat2` and
  `user_allow_other`.
- The legacy `POST /guardfil/v1/decide` HTTP route on the data listener is
  disabled and always returns HTTP 503 (`POLICY_UNAVAILABLE`). Decisions are
  served on the approval socket and through the gateway.
- Builds are checked for reproducibility on Linux `amd64` only. Releases are
  not signed and carry no provenance attestation.
- See the README's [limits](../README.md#limits) and the
  [release notes](releases/v0.1.0-alpha.2.md) for the rest.
