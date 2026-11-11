# GuardFil

GuardFil runs supported AI coding agents inside a constrained container and
checks their shell, file-write and tool requests against your policy. The
agent has no direct network or provider API keys; model traffic and configured
tool access pass through GuardFil. The [limits below](#limits) describe what
these controls cover.

- **Agents:** native Codex, Claude Code, or your own Python agent.
- **You decide** in a web UI, per agent, what is allowed, blocked, monitored
  or held for your answer ("ask me"). Content rules filter or block words and
  secrets, and scan tool results for prompt injection.
- **Your API keys stay on the host.** The agent's model traffic goes through
  GuardFil's broker, which holds the key and enforces a spending limit.
- **Documentation:** Full user and operator guide in [docs/guide/](docs/guide/README.md).

> **Alpha: [`v0.1.0-alpha.2`](https://github.com/reviaro/GuardFil/releases/tag/v0.1.0-alpha.2).**
> Linux with Docker, for one person on one machine. Install from source using
> the tagged quickstart below. See the [release notes](docs/releases/v0.1.0-alpha.2.md)
> and [limits](#limits) before relying on it. Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
> Licensed under the [GNU AGPL v3](LICENSE).

## Quickstart

You need Linux with FUSE 3, Docker with Compose, Python 3.11+, and the agent you want
to run (Codex or Claude Code) installed on the host.

**0. One-time host setup** (needs an administrator). The agent sees your
workspace through a FUSE view, and Docker can only mount that view if FUSE's
`user_allow_other` option is on:

```sh
sudo apt-get install -y fuse3                        # Debian/Ubuntu, if fusermount3 is missing
echo user_allow_other | sudo tee -a /etc/fuse.conf
```

This lets any local user create FUSE mounts that other users can access; it
grants GuardFil nothing else. After cloning, `deployments/local/guardfil-local.sh check`
confirms the host is ready; `init` and `up` warn if it is not. Without it
agents do not start: there is no fallback to the raw folder. See
[workspace setup and existing-policy migration](docs/guide/workspace-and-commands.md#host-setup-and-existing-policies).

**1. Get GuardFil and set it up** (once):

```sh
git clone --branch v0.1.0-alpha.2 --single-branch https://github.com/reviaro/GuardFil.git
cd GuardFil
deployments/local/guardfil-local.sh init --ui active
```

This creates `~/.guardfil-local` (set `GF_HOME` to use another folder, and
`GF_PROJECT` to run a second one beside it on the same machine). It
holds GuardFil's config, a starter policy, the tool catalog for the
supported agents and its state, all owner-only.

**2. Add your API key** (only the broker on the host reads it):

```sh
mkdir -p -m 700 ~/.config/guardfil/credentials.d
( umask 077; cat > ~/.config/guardfil/credentials.d/anthropic-api-key )   # paste the key, then Ctrl-D
```

The file is `anthropic-api-key` for Claude Code, `openai-api-key` for Codex
and `gemini-api-key` for Gemini. Each provider has its own spending ledger
with a $2.00 ceiling.

**3. Start GuardFil:**

```sh
deployments/local/guardfil-local.sh up
```

It prints the web UI's address (`http://127.0.0.1:8088/`) and where its login
token is (`~/.guardfil-local/credentials/ui-token`).

**4. Run an agent inside it:**

```sh
deployments/local/guardfil-local.sh run-agent --runtime claude-code \
  --workspace ~/my-project --prompt "Add a README section about testing"

deployments/local/guardfil-local.sh run-agent --runtime codex \
  --workspace ~/my-project --prompt "Run the tests" --once
```

The agent sees only `--workspace`. Each call it makes is printed with
GuardFil's decision, and recorded in `~/.guardfil-local/state/decisions.jsonl`
and the web UI.

**5. Change what is allowed** in the web UI's Policy tab, or edit
`~/.guardfil-local/config/policy.yaml`. The starter policy:

- asks you (in the web UI) before each shell command;
- allows reading inside the workspace; narrower read blocks can protect secrets;
- allows writing inside the workspace, and records each write;
- allows Claude Code's read tools;
- blocks writes naming files your machine runs later, outside the boundary, in the
  workspace or any folder below it: git hooks and config (`.git/`, `.githooks/`, `.husky/`, `.pre-commit-config.yaml`),
  direnv and mise (`.envrc`, `.mise.toml`, `mise.toml`) and editor or dev-container
  config (`.vscode/`, `.idea/`, `.zed/`, `.devcontainer/`). To allow one, delete its
  `block-host-run-*` rule in the Policy tab. To be asked first instead, delete it
  and add an "Ask me" rule for File writes on that path;
- blocks the agents' own settings folders and everything else.

Codex runs `gpt-6-luna` and Claude Code runs `claude-sonnet-5-5` by default.
Use another model with `--model`, after listing it with its price in
`~/.config/guardfil/models.yaml` (the ledgers need a price to cap spend; see
[models and budget](docs/guide/models-and-budget.md)).

**6. Optional: let the agent call an app's API without seeing its key.**
GuardFil's API gateway maps each request to a catalog tool, decides it by
policy, adds the app's credential and filters the reply:

```sh
deployments/local/guardfil-local.sh catalog my-app-catalog.yaml       # the app's tools (kept with the agents' tools)
deployments/local/guardfil-local.sh credential my-app-key < key.txt   # the app's secret, owner-only
deployments/local/guardfil-local.sh gateway my-app-gateway.yaml       # its routes; see below
```

`my-app-gateway.yaml` holds only an `upstreams:` list:

```yaml
upstreams:
  - name: myapp
    base_url: http://127.0.0.1:5000
    credential_file: /etc/guardfil/credentials.d/my-app-key
    credential_header: Authorization
    credential_prefix: "Bearer "
    routes:
      - {method: GET, path: "/api/items/{id}", tool: myapp.get_item}
```

GuardFil then serves the gateway on `~/.guardfil-local/run/gateway.sock`.
`run-agent` mounts it into the executor at `/run/guardfil/gateway.sock` and
gives the agent `GUARDFIL_GATEWAY_TOKEN`. The agent calls, for example,
`curl --unix-socket /run/guardfil/gateway.sock -H "Authorization: Bearer $GUARDFIL_GATEWAY_TOKEN" http://localhost/myapp/api/items/7`.
Add policy rules for the app's tools (everything else stays blocked).
`gateway --remove` takes it out again.

Give an agent its own identity with `--agent NAME`. Its calls are then
decided as `agent.NAME`, so a rule can apply to one agent only. Stop GuardFil
with `guardfil-local.sh down`.

## Without the web UI

Use `deployments/local/guardfil-local.sh init --ui none` at setup, or
`deployments/local/guardfil-local.sh ui none` for an existing installation.
Policy, content filtering, MCP admission and gateway enforcement remain active.
Edit the configuration files and restart the service to load changes. Use the
[CLI reference](docs/guide/commands.md) and [Python client](clients/python/README.md)
to make guarded calls.
Calls requiring approval stay blocked unless an owner client approves them;
they cannot proceed just because the UI is absent. See
[the approval service](docs/operator-reference.md#approval-service-optional)
for the owner protocol.

## How it works

```
 host                                     | executor (two containers, no network)
                                          |
 your API key -> guardfil-broker <--------+-- relay (loopback only) <-- agent
                 ($2 ledger per provider) |                              |
                                          |         approval socket <----+ supported tool requests
 GuardFil (policy, content rules, UI) <---+-- mediated workspace <----------+ file reads and writes
```

- **The executor** has a read-only root, every capability dropped,
  `no-new-privileges`, limits on processes, memory and CPU, and no network.
  Its only writable places are your workspace and a small `/tmp`.
- **The model's traffic** goes to a relay on the executor's own loopback,
  which passes exactly one request shape to the host broker. The broker
  checks the request, adds the key, refuses provider-side tools (web search,
  code execution) and remote media, and settles the cost in the ledger.
- **Shell, file-write and guarded client requests** reach GuardFil before execution:
  - Codex through its app-server approval callbacks;
  - Claude Code through a managed `PreToolUse` hook that cannot be turned
    off from the workspace and blocks if GuardFil does not answer;
  - your own agent through the Python client's guarded calls.

  The agent can ask, but it can never answer a held call.
- **Workspace access** goes through a policy-controlled filesystem, including
  reads and writes from shell commands or Python code that omits the client.
- **MCP servers** run behind `guardfil-mcp-proxy`, which decides the actual
  `tools/call` before forwarding it and applies content rules to results.
  Admission does not depend on an agent asking for MCP approval.
- **Website rules** check the gateway's actual HTTPS destination and the
  initial URL in Claude Code's managed `WebFetch` hook. Tool permission is
  also required. See [Website enforcement](docs/guide/policy.md#website-enforcement).

## Evidence

- Release verification covered
  **155 browser and restart checks**, **32 headless checks**, **23 filesystem
  tests** on real FUSE mounts and **11 Python-runtime checks** in the real
  executor, including saved rules surviving restart and working without the UI.
  These are bounded checks, not exhaustive browser or input coverage.
- An escape suite (27 attempts: network, relay, host, GuardFil's own state
  and secrets) runs in CI against a real executor, and every attempt must
  fail.
- A scripted red-team drives unmodified Claude Code and Codex to move
  money, leak a planted secret and reach the internet through GuardFil. It
  runs with no API key. CI installs pinned versions of both runtimes and runs both halves.
- A live, model-driven red-team run against Codex held before the alpha.
- Hosted CI runs three jobs on every commit: verification, executor and
  native-agent checks (including real nested mounts), and the clean-runner
  quickstart. All passed on the merged code
  before the release was prepared; the
  [release notes](docs/releases/v0.1.0-alpha.2.md#verification) say what the
  release adds to that code.
- These checks use scripted provider stand-ins. The last live-model runs
  predate the alpha releases.

## Limits

- [Command rules](docs/guide/workspace-and-commands.md#exact-commands-and-prefixes)
  support exact arguments and prefixes. Unresolved shell syntax is blocked
  when command rules apply. An allowed program can still run its own code.
- Readable data can reach the model provider unless you mark its paths
  **Local-only files** in Policy. After access, that session's cloud requests
  and external tool calls stop, and its workspace outputs must remain in
  local-only paths. This also stops cloud-driven agent turns; it does not
  switch to a local model. See [local-only data](docs/guide/workspace-and-commands.md#local-only-data).
- The mediated workspace needs Linux, FUSE 3, `openat2` and the
  administrator-enabled `user_allow_other` setting. It supports
  concurrent overlapping sessions, contained links and ordinary storage
  mounts. Links outside the workspace, device nodes, kernel API mounts and
  other FUSE sources remain blocked. See [filesystem behavior](docs/guide/workspace-and-commands.md#filesystem-behavior).
- File Ask me prompts offer **Allow for session** for each exact path and
  operation. New paths still need approval; clear grants in the UI to revoke
  them. Rule changes and session end also clear them.
- Native shell and file-tool results cannot be filtered. Response-content
  rules targeting those calls cause `TRANSFORM_UNAVAILABLE`; scope response
  rules to MCP tools, the gateway or the Python `guard` client.
- Website rules do not inspect arbitrary URL-shaped MCP arguments or allowed
  shell commands. The gateway does not follow redirects; native WebFetch checks
  only its initial URL. They are not a general network firewall.
- The host-run blocks don't cover build files you run yourself (`Makefile`,
  `package.json` scripts, `.npmrc`). Review agent changes before you build. Shell commands are decided by the shell
  rules, which ask you by default.
- The supported quickstart is local and single-user; the UI uses loopback
  HTTP. Remote hosting and SSO are outside this alpha's scope.
- The Go ledger's crash-durability cases (a failed write or fsync) are not
  yet tested.
- Ambiguous provider billing keeps the reservation and halts further spend;
  it does not assume a zero-cost response.
- Claude Code refused to act as an adversarial red-teamer, so its live
  red-team is scripted, not model-driven.
- The independent security audit is partial: two executor/host-file units
  remain unreviewed. Confirmed findings were fixed.

## For developers

- Build and test: [docs/developer-integration.md](docs/developer-integration.md)
  (Go 1.27.1; `go test ./...`).
- Operating the service: [docs/operator-reference.md](docs/operator-reference.md).
- Release notes: [docs/releases/](docs/releases/).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports:
  [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 reviaro.

GuardFil is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License, version 3, as published by the
Free Software Foundation. See [LICENSE](LICENSE). It comes with no warranty.

In short:
- You may use, study, change and share GuardFil.
- If you distribute it, changed or not, you must give recipients the source
  under the same license.
- If you change it and let others use it over a network (for example, as a
  hosted service), you must offer those users the source of your changed
  version.

Contributions are accepted under the same license; see
[CONTRIBUTING.md](CONTRIBUTING.md).

