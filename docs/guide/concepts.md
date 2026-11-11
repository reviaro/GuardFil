# Concepts

GuardFil is an authorization boundary and secure execution environment for AI coding agents. It ensures that an autonomous agent cannot perform any action—shell execution, file modification, or tool call—without explicit evaluation and approval.

## The Security Boundary

When you run an agent with GuardFil, it does not run directly on your host operating system. Instead, it runs inside a locked-down container sandbox managed by the GuardFil executor.

The executor uses a two-container architecture:

1. **Anchor Container**: Started with `--network none`. It runs the local loopback relay that bridges agent model traffic to the host broker over a Unix domain socket.
2. **Agent Container**: Joins the anchor container's network namespace (`--network container:gf-exec-anchor-...`). Because the anchor has no external network interfaces, the agent container's only networking is the loopback interface (`127.0.0.1`).

```
 host                                     | executor (two containers, no network)
                                          |
 your API key -> guardfil-broker <--------+-- relay (loopback only) <-- agent
                 ($2 ledger per provider) |                              |
                                          |         approval socket <----+ every shell command,
 GuardFil (policy, content rules, UI) <---+---------------------------------  file write, tool call
```

- The **broker** runs on the host. It is the only process that reads an API key. It checks each model request, adds the key, and settles the cost in the provider's ledger. Session-bound brokers also check the owner socket before each provider call so local-only file access stops further cloud requests.
- The **relay** runs in the executor's anchor container on loopback. It passes exactly one request shape (`/v1/responses` or `/v1/messages`) to the broker's Unix socket.
- **GuardFil** (the `guardfil` container) owns the policy, the approval socket, the filter socket, the decision log, the web UI and the API gateway.

### Container Hardening

Every executor container enforces strict security parameters:
- **Read-only Root**: The root filesystem is mounted read-only (`--read-only`).
- **Dropped Capabilities**: All Linux capabilities are dropped (`--cap-drop=ALL`).
- **No Privilege Escalation**: New privileges are blocked (`--security-opt no-new-privileges`).
- **Restricted Storage**: The only writable directories are the mounted project workspace (`/workspace`) and an isolated, size-capped temporary filesystem (`/tmp:rw,nosuid,nodev,size=256m`).
- **Resource Limits**: Hard caps on process IDs (`--pids-limit 256`), memory (`--memory 2g`), swap (`--memory-swap 2g`), and CPU cores (`--cpus 2`).
- **Isolated IPC**: Uses private IPC namespaces (`--ipc private`).
- **No Credentials**: No host environment variables, tokens, cloud credentials, or GuardFil configuration directories are mounted inside the containers.

## How a Tool Call Flows

Every external action attempted by the agent must pass through GuardFil before execution:

1. **Agent Request**: The agent emits an action (for example, executing a shell command, writing a file, or invoking an MCP tool).
2. **Hook or Proxy Interception**:
   - Native Codex submits an approval request via its app-server JSON-RPC callback.
   - Claude Code invokes its managed `PreToolUse` hook (`claude_hook.py`).
   - MCP tools run behind `guardfil-mcp-proxy`.
   - Python agents call the GuardFil Python client (`guardfil_client.py`).
3. **Approval Service**: The hook sends a structured JSON request over `/run/guardfil/approval.sock` to the GuardFil approval service.
4. **Policy Kernel Evaluation**: The policy engine (`internal/policy`) evaluates the action against active policy rules. It checks the calling principal, operation, resource pattern, and decimal predicates.
5. **Outcome Handling**:
   - **ALLOW**: The action proceeds.
   - **BLOCK**: The action is aborted and an error reason is returned to the agent.
   - **REQUIRE_APPROVAL ("Ask Me")**: The call is held in the web UI. If the owner approves, the service returns `ALLOW`; if rejected or timed out, it returns `BLOCK`.
   - **SANITIZE ("Filter")**: The action is permitted on the condition that its output passes through GuardFil's secret redactor and content scanner before being seen by the agent.
   - **MONITOR**: The action is permitted and flagged in the audit record.
6. **Decision Log**: Every evaluation is permanently recorded to `$GF_HOME/state/decisions.jsonl` with the decision, the reasons, the matching rule IDs and a SHA-256 of the request. File paths are logged; command text and argument values are not.

## What GuardFil Does NOT Protect

GuardFil provides robust container lockdown and deterministic policy gates, but users should understand its boundaries:

- **Allowed programs can run their own code**: exact and prefix command rules constrain submitted commands, but do not analyze interpreters, build scripts or Git hooks. Unresolved shell syntax is blocked when command rules apply. See [command rules](workspace-and-commands.md#exact-commands-and-prefixes).
- **Data already read**: ordinary readable files can reach the model provider. Configure [local-only paths](workspace-and-commands.md#local-only-data) to stop a session's cloud and external tool calls after access and keep its workspace outputs private. Data already sent cannot be recalled.
- **Single Machine, Single User**: GuardFil is designed for local workstations. It does not provide multi-tenant isolation, enterprise Single Sign-On (SSO), or mutual TLS across networks.
- **Filesystem compatibility**: the Linux FUSE view supports concurrent sessions, contained hard links and storage mounts. Escaping links, kernel API mounts, device nodes and other FUSE sources remain blocked. File approvals can be retained for the session. See [filesystem behavior](workspace-and-commands.md#filesystem-behavior) for limits, including IPC revocation and unmeasured scan costs.
- **Host applications**: controls apply inside the executor. Review agent changes before running builds or scripts directly on the host. The starter policy blocks writes to common host-run settings through the mediated workspace, including from shell commands.
- **Crash durability**: the Go ledger's failed-write and failed-fsync cases are not yet tested.
