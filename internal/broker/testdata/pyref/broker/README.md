# Model-neutral broker

Agents ask a model through GuardFil without holding a key or knowing the
provider's wire format. The same agent code runs on OpenAI, Anthropic or
Gemini; only the `model` field changes (`openai:gpt-6-luna`,
`anthropic:claude-sonnet-5-5`, `gemini:gemini-flash-latest`).

- `adapters.py`: the neutral "chat with tools" request and reply, and one
  adapter per provider: OpenAI Responses, Anthropic Messages, Gemini
  generateContent. Tool-call arguments keep exact decimals.
- `neutral_broker.py`: the host process. One request per connection on
  `<sockdir>/broker.sock` (owner-only). For each request it validates, sizes
  a reservation (every input byte counted as a token, plus the output cap, at
  the model's ledger rate), reserves on the single $2 ledger, calls the
  provider, settles with the reported usage and returns the neutral reply. Any
  ledger or provider failure stops the broker.
- `clients/python/guardfil_model.py`: `ask_model(sock, request)` for agents.

**Live calls:** `LIVE_PROVIDERS` lists OpenAI, Gemini and Anthropic. Each
provider has **its own $2 ledger**. OpenAI keeps the
original one; Gemini and Anthropic each get a ledger under
`~/.local/state/guardfil/<provider>-experiment*`. Only the models in
`PROVIDER_MODELS` can be called: `gpt-6-luna`, `gemini-3.6-flash`,
`gemini-3.5-flash-lite` and `claude-sonnet-5-5`. `gemini-3.8-flash` is not allowed: calls to it hung past the timeout. Each must also be priced in `MODEL_RATES`
(`../research/t2a/openai_budget/constants.py`), rounded up to whole micro-USD per
token. A provider is used only if its key file exists
(`~/.config/guardfil/credentials.d/<provider>-api-key`, mode 0600).

The checks around each call:
- **Free preflight.** Gemini (`countTokens`) and Anthropic (`count_tokens`)
  check each request before anything is reserved. A malformed request is
  refused there, without spending anything or stopping the broker.
- **Transient errors.** Statuses 429 and 5xx are retried inside the one
  reservation. If they persist, the reservation is closed at zero tokens
  (response id `unbilled-<status>-<request>`), because the provider bills
  nothing for them. Any other failure still halts that provider's ledger.
- **One $2 per provider, across ledgers.** A ledger halts for good on any
  uncertain failure, and a new one then takes its place. The halted ones'
  counted spend can be recorded in `RETIRED_LEDGER_SPEND` (empty by default)
  and then still counts: the
  broker refuses a reservation that would take the provider's total over $2.
- **Stopping.** SIGTERM waits for a request in flight to finish, so a stop
  never leaves an unsettled reservation, which would halt the ledger.

`python3 -m broker.neutral_broker --check` is a free check that each keyed
provider knows its model. It spends nothing and prints no key.

```sh
python3 -m broker.neutral_broker --sockdir /tmp/gfnb --label demo-1 --max-requests 20
python3 -m unittest broker.test_adapters broker.test_neutral_broker
```
