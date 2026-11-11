# Running Agents

GuardFil provides a unified runner, `deployments/local/guardfil-local.sh run-agent`, supporting three agent runtimes:
- **Codex**: Native OpenAI Codex (`codex app-server`).
- **Claude Code**: Anthropic's Claude Code CLI (`claude -p`).
- **Python**: A standalone Python agent executing custom tools.

All runtimes execute inside the same hardened container executor with a read-only root, dropped capabilities, no external network, and only `/workspace` and a bounded `/tmp` writable.

## Command Syntax

```sh
deployments/local/guardfil-local.sh run-agent --runtime <codex|claude-code|python> --workspace <DIR> [options]
```

> [!NOTE]
> `--runtime` must come first on the command line.

---

## 1. Native Codex (`--runtime codex`)

Runs native Codex with its external sandbox policy.

```sh
deployments/local/guardfil-local.sh run-agent --runtime codex \
  --workspace ~/my-project \
  --prompt "Fix the failing test in tests/test_app.py" \
  --once
```

### Options for Codex

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--workspace` | Path | *(Required)* | Host directory mounted at `/workspace`. |
| `--prompt` | String | None | Initial user task or instruction. |
| `--once` | Flag | `false` | Run `--prompt` and exit immediately upon completion. |
| `--max-requests` | Integer | `16` | Maximum model requests for this session (1–64). The provider's $2.00 ledger still applies. |
| `--model` | String | `gpt-6-luna` | OpenAI model; others must be in your model list ([models and budget](models-and-budget.md)). |
| `--agent` | String | None | Sets agent identity to `agent.<NAME>` for per-agent policy rules. |
| `--mcp` | String | None | Registers an MCP server behind GuardFil's filter (`NAME=COMMAND`). Repeatable. (`NAME=demo` uses built-in notes server). |
| `--gateway-socket` | Path | `$GF_HOME/run/gateway.sock` if present | API gateway Unix socket to mount at `/run/guardfil/gateway.sock` (installed with `guardfil-local.sh gateway`). |
| `--gf-home` | Path | `~/.guardfil-local` | Overrides `$GF_HOME`. |
| `--codex-bin-dir` | Path | Auto | Path to directory containing the `codex` binary. |
| `--broker-cmd` | String | Auto | Custom model broker command to run instead of default. |
| `--transcript` | Path | None | File to record raw JSON-RPC messages. |

### How Codex Is Wired

1. The runner boots `guardfil-broker responses` on the host with the OpenAI API key.
2. The anchor container starts with the TCP-to-Unix relay listening on `127.0.0.1:8899`.
3. Codex starts inside the container pointing to `http://127.0.0.1:8899/v1/responses` with approval policy `externalSandbox`.
4. When Codex requests approval for shell commands, file modifications, or MCP calls, the runner intercepts the JSON-RPC approval event, converts it to a GuardFil request, queries `$GF_HOME/run/approval.sock`, and feeds the verdict back to Codex.

---

## 2. Claude Code (`--runtime claude-code`)

Runs Anthropic's Claude Code CLI with a managed `PreToolUse` hook.

```sh
deployments/local/guardfil-local.sh run-agent --runtime claude-code \
  --workspace ~/my-project \
  --prompt "Refactor internal/storage to use interfaces"
```

### Options for Claude Code

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--workspace` | Path | *(Required)* | Host directory mounted at `/workspace`. |
| `--prompt` | String | *(Required)* | Initial task for Claude Code. |
| `--max-requests` | Integer | `16` | Maximum model requests for this session. |
| `--max-turns` | Integer | `12` | Maximum agent turns. |
| `--model` | String | `claude-sonnet-5-5` | Anthropic model; others must be in your model list ([models and budget](models-and-budget.md)). |
| `--agent` | String | None | Agent identity name (`agent.<NAME>`). |
| `--mcp` | String | None | MCP server command behind GuardFil filter (`NAME=COMMAND`). Repeatable. |
| `--gateway-socket` | Path | `$GF_HOME/run/gateway.sock` if present | API gateway Unix socket to mount. |
| `--gf-home` | Path | `~/.guardfil-local` | Overrides `$GF_HOME`. |
| `--claude-bin` | Path | Auto | Path to host `claude` executable. |
| `--broker-cmd` | String | Auto | Custom Messages broker command. |
| `--transcript` | Path | None | Path to record raw streaming JSON events. |

### How Claude Code Is Wired

1. The runner starts `guardfil-broker messages` on the host with `~/.config/guardfil/credentials.d/anthropic-api-key`.
2. Inside the container, Claude Code is started in headless streaming mode (`claude -p`).
3. Claude Code configuration is injected with a managed `PreToolUse` hook pointing to `deployments/local/claude_hook.py`:
   - Configured with `"onFailure": "block"`, guaranteeing fail-closed behavior on crashes or timeouts.
   - Translates Claude tools into GuardFil approval requests:
     - `Bash` &rarr; `{"kind": "shell", "command": ["bash", "-c", CMD], "cwd": CWD}`
     - `Write`, `Edit`, `MultiEdit`, `NotebookEdit` &rarr; `{"kind": "file_write", "changes": [{"path": ..., "change": "add"|"update"}]}`
     - `mcp__<SERVER>__<TOOL>` &rarr; `{"server": SERVER, "tool": TOOL, "arguments": ..., "can_filter": true}`
     - Built-in tools (`Read`, `Grep`, `Glob`, `LS`, `WebFetch`, etc.) &rarr; `{"server": "claude", "tool": <name>, "arguments": <projected>}`
   - Resolves file read paths against the agent's current working directory so the kernel can enforce file-read policies.

---

## 3. Python Agent (`--runtime python`)

Runs custom Python agents using the GuardFil Python client library.

```sh
deployments/local/guardfil-local.sh run-agent --runtime python \
  --workspace ~/my-project \
  --task "Summarize project notes" \
  --model gemini:gemini-3.5-flash-lite
```

### Options for Python

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--workspace` | Path | *(Required)* | Host directory mounted at `/workspace`. |
| `--task` | String | *(Required)* | Task prompt for the agent. |
| `--model` | String | `gemini:gemini-3.5-flash-lite` | Provider and model identifier (`openai:gpt-6-luna`, `anthropic:claude-sonnet-5-5`, `gemini:gemini-3.6-flash`, `gemini:gemini-3.5-flash-lite`). |
| `--agent` | String | None | Agent identity name (`agent.<NAME>`). |
| `--agent-file` | Path | `python_agent_example.py` | Python script implementing the agent. |
| `--max-requests` | Integer | `8` | Maximum allowed model requests. |
| `--gf-home` | Path | `~/.guardfil-local` | Overrides `$GF_HOME`. |

### How the Python Agent Is Wired

1. The runner launches `guardfil-broker neutral`, which can speak to OpenAI, Anthropic, or Gemini.
2. The agent script imports `guardfil_client.GuardFil` pointing to `/run/guardfil/approval.sock`.
3. Tools are decorated with `@gf.guard("tool_id")`:
   ```python
   gf = GuardFil("/run/guardfil/approval.sock")

   @gf.guard("notes.read_note")
   def read_note(name: str) -> str:
       with open(f"/workspace/notes/{name}.txt") as f:
           return f.read()
   ```
4. If the policy denies the call, `gf.guard` raises a `Blocked` exception without running the tool body.

---

## Agent Identities

By default, calls from Codex or Claude Code are evaluated under principal `codex-agent`.

When you supply `--agent <NAME>` (for example, `--agent notes-bot`), GuardFil assigns the session principal:
```
agent.<NAME>
```
This enables granular, per-agent rules in `policy.yaml` or the Web UI:
- One agent can be allowed to invoke shell commands while another is restricted to read-only tools.
- A finance bot can be restricted to low transaction amounts while an admin agent requires interactive approvals.
