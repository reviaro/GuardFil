# Models and Budget

GuardFil protects model access and manages token costs using a host-side broker (`guardfil-broker`) backed by a spending ledger per provider.

Every model request made by an agent must pass through the broker. The broker validates request shapes, strips unauthorized provider tools, manages spending limits, and settles actual costs.

The shipped launchers bind the broker to an owner-created session. After that
session accesses [local-only files](workspace-and-commands.md#local-only-data),
the broker refuses further provider calls, including token counting and retries.
An unavailable owner service also blocks them. A privacy rejection before
dispatch does not incur provider spend; any unused reservation is released.
Cloud-driven agent turns then stop; no automatic local-model fallback is provided.

---

## 1. Supported Providers and Pinned Models

Each broker accepts its built-in models plus any you list with a price (below). The built-in models:

| Provider | Used by | Broker subcommand | Built-in models |
| --- | --- | --- | --- |
| OpenAI | Codex (`--runtime codex`) | `responses` | `gpt-6-luna` |
| Anthropic | Claude Code (`--runtime claude-code`) | `messages` | `claude-sonnet-5-5` |
| OpenAI, Anthropic, Gemini | Python agents (`--runtime python`) | `neutral` | `gpt-6-luna`, `claude-sonnet-5-5`, `gemini-3.6-flash`, `gemini-3.5-flash-lite` |

### Using another model

Codex and Claude Code take `--model`, and Python agents `--model provider:model`. Any model is allowed once it is in your model list, `~/.config/guardfil/models.yaml` (owner-only, mode 0600, next to the API keys):

```yaml
models:
  - provider: openai
    model: gpt-6-sol
    input_usd_per_million_tokens: 3
    output_usd_per_million_tokens: 12
  - provider: anthropic
    model: claude-opus-5-5
    input_usd_per_million_tokens: 15
    output_usd_per_million_tokens: 75
```

```sh
deployments/local/guardfil-local.sh run-agent --runtime claude-code --model claude-opus-5-5 --workspace ~/my-project --prompt "..."
```

- **Why a price is needed:** each request reserves its worst-case cost in the provider's $2.00 ledger before it is sent, and is settled at its real cost. Without a price the broker could not cap spend, so an unlisted model is refused with a message saying how to add it.
- **Prices** are whole US dollars per million tokens, from 1 to 10,000 (the ledger counts integer micro-dollars per token). Round a cheaper price up to 1; that overestimates cost, which is the safe side.
- **Use the provider's exact model id.** The broker checks that the reply names the same model; a reply naming a different (for example dated) id stops the request.
- **Keep an entry once you have used it, at the same price.** The ledger re-derives every past settlement from the price list when a broker starts; a removed or repriced model makes the ledger fail validation (the error says so). Add a new entry for a new price instead.
- **Built-in models** can be listed only at their built-in prices.
- **Large requests:** a request whose worst-case cost exceeds one reservation ($1.10) is refused rather than reserved short. With an expensive model, keep inputs smaller.
- The provider must accept the request shape GuardFil sends (for example, Codex requests use `reasoning.effort: none`).

`run-agent` starts the right broker on the host. It listens on a Unix socket that the executor's relay reaches at `/run/guardfil-broker/broker.sock`. Inside the executor, the agent talks to the relay on `127.0.0.1:8899`.

### Prohibited Features
The broker strictly enforces boundary rules:
- **No Provider-Hosted Tools**: Provider-side tools (web search, computer use, code interpreter, file search, image generation, hosted MCP) are refused. All tools must execute locally within GuardFil's container boundary.
- **No Remote Media Ingestion**: Inspecting remote image or document URLs directly through provider APIs is blocked.
- **Stateless Execution**: Requests using provider-side stored state (`prompt`, `previous_response_id`, `conversation`, or `store: true`) are rejected. All conversation history is passed explicitly per turn.

---

## 2. API Key Isolation

API keys are read exclusively by `guardfil-broker` on the host machine.

- **Host Path**: `~/.config/guardfil/credentials.d/`
  - `openai-api-key`
  - `anthropic-api-key`
  - `gemini-api-key`
- **Security Guarantee**:
  - The API key directory is never mounted into Docker containers.
  - The broker never outputs, logs, or transmits credentials to child processes or tools.
  - Permissions are locked to the user (`0700` directory, `0600` files).

---

## 3. The $2.00 Budget Ledger

Each provider operates with its own independent, append-only budget ledger (`internal/broker/budget/`).

- **Global Ceiling**: $2.00 USD (2,000,000 microdollars) per provider ledger.
- **Request Cap**: Up to 256 forwarded requests per ledger over its lifetime. Each session also has its own `--max-requests` cap.
- **Concurrency**: At most one request in flight per ledger.
- **Storage Location**:
  - OpenAI: `~/.local/state/guardfil/t2a-experiment/`
  - Gemini: `~/.local/state/guardfil/gemini-experiment-6/`
  - Anthropic: `~/.local/state/guardfil/anthropic-experiment/`

---

## 4. Reservations and Settlement

Costs are managed via a two-phase reservation and settlement lifecycle:

```
[Agent Request]
       |
       v
1. Compute Token Estimate (input tokens + margin + max output tokens)
       |
       v
2. Reserve Budget in Ledger (typically ~$0.02; max $1.10 cap)
   * If spend so far + this reservation would pass $2.00, the request is refused and never sent
       |
       v
3. Forward to Provider API (streaming response)
       |
       v
4. Parse Terminal Usage (response.completed / response.incomplete)
       |
       v
5. Settle Exact Cost (actual tokens consumed * rate)
   * Unused reservation released back to budget
   * The settlement is recorded in the ledger (ledger.json)
```

### Built-in prices

Costs are computed in integer micro-dollars per token (1 micro-dollar per token = $1 per million tokens):

| Model | Input Rate ($\mu\$$ / token) | Output Rate ($\mu\$$ / token) |
| --- | --- | --- |
| `gpt-6-luna` | 1 | 1 |
| `claude-sonnet-5-5` | 2 | 10 |
| `gemini-3.6-flash` | 2 | 8 |
| `gemini-3.5-flash-lite` | 1 | 3 |

### Unbilled Error Handling

In the OpenAI (`responses`) and model-neutral brokers, a reply the provider does not bill settles at zero: a refusal (HTTP 400, 401, 403, 404, 413, 422), or a retryable status (429, 5xx) that still fails after the broker's retries. The agent gets an error saying nothing was billed, and the ledger keeps working. A malformed agent request therefore cannot halt the shared ledger.

### Output Truncation

The broker caps output at `max_output_tokens` = 1024. A reply cut off at that cap (`response.incomplete`) settles at the tokens it actually used, and the partial reply is delivered.

### Checking a ledger

The ledgers live outside the repository (paths above), each as a `ledger.json` with its lock and journal files. Don't edit them by hand: the brokers refuse a ledger that fails validation.
