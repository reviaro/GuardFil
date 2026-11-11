# Operator reference

How to run and configure a local GuardFil deployment. For a first run, follow
the [README quickstart](../README.md#quickstart); for day-to-day use, see the
[guide](guide/README.md). GuardFil is an alpha and supports a local,
single-user deployment on Linux.

## Local deployment

`deployments/local/guardfil-local.sh` runs GuardFil in a hardened
container: read-only root filesystem, no capabilities, no new
privileges. It runs as your own user, and its folders live in `GF_HOME`
(default `~/.guardfil-local`).

```sh
deployments/local/guardfil-local.sh init --ui active   # or --ui inactive, or --ui none (default)
deployments/local/guardfil-local.sh up                 # build, start, wait for the approval socket
deployments/local/guardfil-local.sh ui inactive        # change the UI switch later (restarts)
deployments/local/guardfil-local.sh status | logs | down
deployments/local/guardfil-local.sh check               # can this host serve a mediated workspace?
```

- `init` creates `config/` (config and a starter policy), `credentials/`
  (random metrics and UI tokens), `state/` (decision log, policy versions)
  and `run/` (the approval socket). Everything is owner-only.
- The starter policy (`deployments/local/starter-policy.yaml`) lets the
  agent read `/workspace`, asks you before shell commands, allows and records
  writes in `/workspace`, and blocks writes to the agent's own settings
  (`.codex`, `.claude`) and to files your machine runs later (git hooks and
  config, direnv, editor tasks and similar). Everything else is blocked. See
  [policy](guide/policy.md).
- The container uses host networking. GuardFil listens only on loopback, so
  the UI at `127.0.0.1:8088` is reachable from this machine only. The
  agent's harness asks GuardFil on `$GF_HOME/run/approval.sock`.
- Addresses can be changed with `GF_DATA_ADDR`, `GF_MGMT_ADDR` and
  `GF_UI_ADDR`.

### Run an agent inside GuardFil

With GuardFil up, `run-agent` starts Codex, Claude Code or a Python agent in
a locked-down container and has GuardFil decide what it does:

```sh
deployments/local/guardfil-local.sh run-agent --runtime codex --workspace ~/myproject --prompt "add a README"
deployments/local/guardfil-local.sh run-agent --runtime claude-code --workspace ~/myproject --prompt "..."
```

`run-codex` is a shorthand for `run-agent --runtime codex`. Options for each
runtime are in [running agents](guide/running-agents.md).

- The agent runs as your user with a read-only root filesystem, no
  capabilities and **no network**: only a relay on its own `127.0.0.1` that
  passes model requests to the host broker. The broker holds the provider key
  and charges that provider's $2 ledger; the container never sees the key.
  See [models and budget](guide/models-and-budget.md).
- `--workspace` is mounted at `/workspace` through a policy-controlled
  filesystem, so file rules apply to every read and write, including those
  made by shell commands or the agent's own code. Rule paths refer to
  `/workspace/...`. See
  [workspace access and command rules](guide/workspace-and-commands.md).
- Shell commands, file changes and tool calls are decided on
  `$GF_HOME/run/approval.sock`, so rule changes and "Ask me" in the web UI
  apply to the next call. Anything but a clean ALLOW is declined.
- `--agent NAME` gives the session the identity `agent.NAME` for per-agent
  rules. Without it the agent is `codex-agent`, the principal the starter
  policy uses.
- `--mcp NAME=COMMAND` (repeatable) gives the agent an MCP server, run inside
  its container behind `guardfil-mcp-proxy`. The proxy asks GuardFil to
  decide each `tools/call` before forwarding it and filters every result.
  The server's tools must be in the tool catalog, named `NAME.tool` in rules.
  See [MCP and gateway](guide/mcp-and-gateway.md).
- Limits: an allowed program can still run its own code, within what the
  filesystem and network boundary permit. Results of native shell and file
  tools cannot be filtered.

## Tool catalog and decision client

An app with a built-in AI agent can ask GuardFil before it runs a tool the
agent chose. List the app's tools and their arguments in a **tool catalog**,
then call GuardFil from the app with the Python client
(`clients/python/guardfil_client.py`, standard library only).

```sh
deployments/local/guardfil-local.sh catalog deployments/example/approval/stockapp-catalog.yaml
```

```python
from decimal import Decimal
from guardfil_client import GuardFil, Blocked
gf = GuardFil(os.path.expanduser("~/.guardfil-local/run/approval.sock"))

@gf.guard("stockapp.place_order")          # runs only if GuardFil allows the call
def place_order(symbol, side, quantity, limit_price=None): ...

d = gf.check("stockapp.get_quote", {"symbol": "ACME"})   # or ask directly
d.allowed, d.monitored, d.asked, d.rule_ids
```

- Catalog entries are `app.tool` with typed arguments: `string` (optional
  `enum`, `max_length`, default 1,024), `integer` and `decimal` (optional
  `min` and `max`, quoted numbers compared exactly), `boolean`, and
  `required`. Bound the arguments that amount rules use: without `min: "0.01"`
  a negative price would make any order's value look small. A call with an unknown or missing argument, a wrong type or a
  value outside the enum is blocked before the policy is consulted. A tool not
  in the catalog is blocked.
- Rules then name the tool (`Tool` in the web UI, which suggests catalog
  tools). Allow, Block, Monitor and Ask me all apply. A held call shows its
  arguments to the owner.
- Amounts: pass `decimal.Decimal` or `int`. The client refuses floats, and
  GuardFil keeps decimals as exact literals.
- **Amount rules:** a tool rule can have a condition on a numeric argument, or
  on the product of two (an order's value). In the web UI pick **Tool**, then
  fill "when" (for example `quantity * limit_price` `>` `1000`). In YAML:

  ```yaml
  - id: ask-big-orders
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources: [{kind: tool, value: stockapp.place_order}]
      decimal:
        - {field: quantity*limit_price, operator: ">", value: "1000"}
  ```

  Operators: `>`, `>=`, `<`, `<=`, `==`, `!=`. The amount is a quoted plain
  number (no commas or currency signs). Comparison is exact (`0.1` equals
  `0.10`; no floating point). Several conditions in one rule must all hold.
  The argument must be an `integer` or `decimal` in the catalog, or the policy
  is refused.
- **A missing amount fails closed.** If a call lacks an argument a condition
  needs (an order with no `limit_price`), a Block, Ask me or Filter rule with
  that condition still applies as a restriction. An Allow, Monitor or Filter
  rule with an unknown condition cannot grant the call on its own. So
  "ask me above 1,000" also holds orders whose value is unknown.
- The catalog is read at start (`approval.tool_catalog` in the config);
  `catalog FILE` installs one and restarts. Calls to an agent's MCP servers
  are decided against the same catalog.
- **This is cooperative.** It protects only the calls the app sends through
  it. For enforcement, keep the credentials that act (for example the
  brokerage key) behind GuardFil's [API gateway](#api-gateway), so nothing
  reaches them without a decision.

## Filter: remove secrets from tool results

A **Filter** rule (`effect: sanitize`, "Filter" in the web UI, tool targets
only) permits a tool call on the condition that its result has secrets
removed before the agent sees it:

- private keys, AWS / GitHub / OpenAI / Anthropic / Stripe / Slack / Google
  keys, JWTs, bearer tokens and URL passwords, plus the values of secret-named
  fields (`password`, `api_key`, `secret`, `token`, ...). Each becomes
  `[REDACTED:<kind>]`. It is pattern based: a guard against accidental
  disclosure, not against an app that encodes a secret on purpose.
- Who filters: the API gateway (responses), the Python client's `@guard`
  (return values; `gf.filter(tool, result)` by hand), and the MCP
  proxy (tool results). A caller says so with `"can_filter": true`. Without
  it a Filter rule **blocks** the call (`TRANSFORM_UNAVAILABLE`), so nothing
  unfiltered gets through by mistake.
- If filtering fails, the result is withheld: the gateway returns 403, the
  client raises `FilterError`, and the MCP proxy returns an error result.
  Binary responses under a Filter rule are withheld too.
- Filter combines with Ask me: the owner is asked, and the result is still
  filtered.
- The decision log records each filtering with the number of secrets removed,
  never the content. `approval.filter_socket` (set by `guardfil-local.sh`)
  serves filtering only. It can be given to an agent's container because it
  cannot decide or approve anything.

## API gateway

For an outside agent that uses an app's HTTP API, GuardFil can be the only way
in. The agent gets a GuardFil token. GuardFil holds the app's real key, decides
each request like any tool call, and forwards only the allowed ones.

```yaml
gateway:
  address: 127.0.0.1:8090            # non-loopback needs remote_bind_ack: true (plain HTTP for now)
  agent_token_file: /etc/guardfil/credentials.d/gateway-agent-token
  upstreams:
    - name: stockapp                 # the agent calls /stockapp/api/...
      base_url: http://stockapp:8000
      credential_file: /etc/guardfil/credentials.d/stockapp-key
      credential_header: Authorization
      credential_prefix: "Bearer "
      routes:
        - {method: GET,    path: /api/quote/{symbol},     tool: stockapp.get_quote}
        - {method: POST,   path: /api/orders,             tool: stockapp.place_order}
        - {method: DELETE, path: /api/orders/{order_id},  tool: stockapp.cancel_order}
```

- It needs the approval block with a `tool_catalog`, and every route's tool
  must be in the catalog. Path arguments (`{symbol}`), query parameters and the
  JSON body object are the tool's arguments. Path and query values become
  numbers when the catalog says `integer` or `decimal`. Policy, amount rules,
  monitor and ask me all apply. A held request waits for your answer.
- Allowed: GuardFil rebuilds the request from the decided arguments (the
  matched path, the parsed query, the re-encoded body), adds the credential
  header and forwards it. The app's response goes back with only its status,
  `Content-Type` and `Location`. The app's key is replaced by
  `[REDACTED-BY-GUARDFIL]` if it appears in a response.
- Refused, and the app never sees the request: no or wrong token (401); no
  matching route, a `..` or encoded `/` in the path, a repeated query parameter
  or body key, an argument given twice, a non-JSON or non-object body, or
  anything the policy does not allow (403, with the reasons and rule IDs).
- Redirects from the app are not followed. Bodies are limited to 64 KiB and
  responses to 1 MiB.
- **Enforcement depends on the network:** the agent must have no route to the
  app except through GuardFil (for example, the app on a Docker network the
  agent is not on).

## Approval service

The launcher writes this configuration for you. To configure it by hand,
add an `approval:` block to `guardfil.yaml`. Agent runners and clients then
ask GuardFil whether to run each tool call, shell command or file write:

```yaml
approval:
  socket: /run/guardfil/approval.sock      # parent directory owner-only; path at most 100 bytes
  policy_file: /etc/guardfil/policy.yaml    # inside config_root, owner-only, must compile
  decision_log: /var/lib/guardfil/decisions.jsonl   # directly inside state_dir
```

- All three fields are required together. Without the block no socket is
  opened.
- Startup fails if the policy does not compile or the log cannot be opened.
- The socket is mode 0600. A client sends one JSON request line and reads one
  JSON verdict line (`effect` ALLOW or BLOCK, `reasons`, `rule_ids`,
  `policy_digest`, `action_digest`). Anything other than ALLOW must be treated
  as a block.
- Request forms: MCP `{"server","tool","arguments"}`, shell
  `{"kind":"shell","command":[argv],"cwd"}`, file write
  `{"kind":"file_write","changes":[{"path","change"}]}`.
- The decision log gets one JSON line per decision. Commands and tool
  arguments appear only as a SHA-256 hash. If the log cannot be written, the
  verdict is BLOCK.
- A rule with `effect: monitor` allows matching calls and marks them as
  monitored: the verdict's reasons include `POLICY_MONITORED` and the log line
  has `"monitored": true`. A matching `deny` still blocks.
- **Ask me.** Add `approver_socket` (another owner-only socket path) and
  optionally `ask_timeout_seconds` (1–600, default 60). A call blocked only by
  a `require_approval` rule is then held until the owner answers on the
  approver socket: `GET /v1/approvals` lists held calls (kind, tool or paths,
  rule IDs, request hash; never the command text), and
  `POST /v1/approvals/<id>` with `{"decision":"allow"}` or `{"decision":"deny"}`
  answers one. Allow gives ALLOW (`APPROVAL_GRANTED`). Deny gives BLOCK
  (`APPROVAL_REJECTED`). No answer before the timeout gives BLOCK
  (`APPROVAL_EXPIRED`), and so does shutdown. Without `approver_socket`, such
  calls are BLOCKed at once (`APPROVAL_UNAVAILABLE`). A call that a `deny`
  rule also matches is never held. The log line records `"asked"` and the time
  held.
- The policy can be changed while GuardFil runs only through the web UI (below).
  Otherwise edit `policy_file` and restart.

## Web UI

The owner's control page. It is part of the `guardfil` binary and needs the
`approval:` block.

```yaml
ui:
  active: true                                        # false: installed but no listener at all
  address: 127.0.0.1:8088                             # literal loopback only
  token_file: /etc/guardfil/credentials.d/ui-token   # login secret, 16+ bytes, owner-only
```

- **Deployed without the UI:** leave the `ui:` block out.
- **Installed but inactive:** `active: false`. No port is opened. Switching it
  on is a config change and a restart.
- **Active:** log in with the token. The session cookie is HttpOnly and
  SameSite=Strict, and lasts 12 hours. Ten failed logins in a minute lock
  logins for that minute.
- The page shows:
  - calls waiting for you, with **Allow** and **Deny** buttons (an active UI
    turns "ask me" on);
  - the rules in plain terms (action: Allow, Block, Monitor, Ask me, Filter; what:
    shell commands, tool, file writes or reads in a folder, website; for a
    tool, an optional amount condition), with Add and Delete;
  - recent decisions from the decision log;
  - the policy history, with Restore;
  - an advanced YAML editor.
- Every change is checked by GuardFil's policy compiler before it applies; an
  invalid policy is refused and nothing changes. It applies to the next call.
- Each change is saved as a numbered version in
  `<state_dir>/policy-versions/` with a note ("added rule …", "restored
  version 3"). `policy_file` is never overwritten. Restore puts an earlier
  version (or the original file, v0) back as a new version.
- At startup GuardFil uses the latest saved version, unless `policy_file`
  changed since it was saved. Then the file wins, because you edited it by
  hand. This also applies with the UI inactive or removed.
- Hardening: strict CSP (no inline script or eval), loopback-only Host header,
  JSON-only POSTs with a same-origin check, no caching, and no framing.
- A held call shows its complete shell command or tool arguments. Requests or
  results whose preview exceeds 1,000 runes are blocked rather than offered
  for approval. The preview exists only in memory while the call is held;
  decision logs store its hash. Up to 32 calls can wait, with at most eight
  per principal. Disconnecting or deleting a session cancels its held calls.

## Running the service container yourself

The launcher prepares everything in this section. Read it only if you run
the `guardfil` container without the launcher.

The image is a static Linux binary running as numeric UID/GID `65532:65532`, with a read-only root filesystem, no new privileges, all Linux capabilities dropped, and `/var/lib/guardfil` as the sole declared writable volume. The example is [deployments/example/compose.yaml](../deployments/example/compose.yaml); it does not publish either listener.

Before startup, provide:

1. `/etc/guardfil/guardfil.yaml` as a read-only, owner-only regular file.
2. `/etc/guardfil/credentials.d/metrics-token` as a read-only regular file, owned by UID 65532 and mode `0600`.
3. `/var/lib/guardfil` as a writable, owner-only directory owned by UID 65532 and mode `0700`.

The config, credentials, and state roots must resolve within their declared locations. Do not use environment variables or command-line arguments for secret values. A projected-volume symlink is acceptable only when its resolved target remains inside the declared root and passes the same ownership and mode checks. Hard-linked or symlinked credential inputs may not overlap.

The named state volume must be provisioned so `/var/lib/guardfil` is owned by UID 65532 and mode `0700`; a default Docker-created root-owned volume will fail the startup ownership check. Use a pre-provisioned volume or an operator-controlled provisioning step rather than weakening the runtime check.

### Startup with the example compose file

```sh
mkdir -p deployments/example/credentials.d
umask 077
printf '%s\n' 'replace-with-a-local-metrics-token' > deployments/example/credentials.d/metrics-token
chmod 600 deployments/example/credentials.d/metrics-token
export GO_BUILDER_IMAGE='golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195'
docker compose -f deployments/example/compose.yaml up --build
```

Replace the placeholder token before use. The example is local-only: do not publish port 8080 or 9090 as a remote security boundary.

### TLS and binding

Loopback data and management listeners may use plaintext for local development. A non-loopback data listener requires `remote_bind_ack: true`, a readable certificate and key under `credentials_root`, owner-only regular files owned by the running UID, and a valid key pair. The server requires TLS 1.3 or newer and HTTP/1.1.

Remote plaintext data, remote management, host networking, a management Service/Ingress, generic wildcard acknowledgement, h2c, HTTP/2 negotiation, and HTTP/3 are unsupported. Management exposure must not be inferred from a container loopback bind: the supported default is an unpublished namespace-local management listener.

### Probes and metrics

```sh
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
curl -i -H "Authorization: Bearer $(cat deployments/example/credentials.d/metrics-token)" \
  http://127.0.0.1:9090/metrics
```

Health is intentionally coarse. It does not reveal paths, policy,
configuration, credentials, exception text, or workload data. Readiness
reflects process startup and configuration admission. Metrics are limited to
`guardfil_requests_total`, `guardfil_rejections_total`,
`guardfil_decision_allows_total`, `guardfil_decision_authority_blocks_total`,
`guardfil_decision_policy_blocks_total`, and
`guardfil_decision_obligation_blocks_total`. These counters are
fixed-cardinality; a diagnostic decision allow is never a dispatch capability,
and absence of a metric is not proof that a request executed or that an upstream
side effect occurred.

## Failure handling and limits

- Invalid configuration, unsafe file ownership or modes, invalid TLS files, a
  policy that does not compile, or a decision log that cannot be opened stop
  the service from starting.
- If the decision log cannot be written, the verdict is BLOCK.
- `POST /guardfil/v1/decide` on the data listener is a disabled legacy route.
  It always returns HTTP 503 with code `POLICY_UNAVAILABLE` and never
  forwards traffic. Do not read it as a decision.
- The decision log is an append-only file in the state directory. It is not
  a tamper-proof or crash-certified audit journal.
- The deployment is local and single-user. Remote hosting, SSO and
  multi-tenant operation are out of scope for the alpha.
- Further limits are in the README's [limits](../README.md#limits) and the
  [release notes](releases/v0.1.0-alpha.2.md).
