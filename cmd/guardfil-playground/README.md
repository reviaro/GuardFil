# GuardFil playground

`guardfil-playground` is a local web UI for trying the GuardFil policy kernel by hand. Each request runs through the same packages the product uses: action normalization, identity, policy, decision, the `guardfil.error/1` envelope, and telemetry. You see the decision, its fields and the error envelope.

It is **advisory only**:

- Nothing is executed or dispatched. `dispatch_eligible` comes from the kernel's verdict, and it is always `false`.
- Tools, credentials and fixtures are all synthetic. The browser picks a credential by name (`valid`, `expired`, `unknown`, `none`) and never sends or receives a secret. Secrets and the identity key are generated at random when the process starts.
- The listener is loopback only by default.
  - Requests whose `Host` is not `localhost`, `127.0.0.1` or `[::1]` are refused (`403`). This defends against DNS rebinding.
  - POSTs need `Content-Type: application/json`. A cross-site `Origin` header, or `Sec-Fetch-Site: cross-site` with no Origin, is refused. Origin counts as cross-site unless it names a loopback host on the same port.
  - Request bodies are capped at 4 MiB.
- The payload travels as base64 (`payload_b64`), so the kernel sees exactly the bytes you typed. Invalid UTF-8 can't be silently repaired on the way in. The browser always sends what you type as valid UTF-8. To test invalid byte sequences, call `POST /api/evaluate` directly with your own `payload_b64`.
- The product's `/guardfil/v1/decide` endpoint is unchanged and still returns `503`. The playground's action registry carries a synthetic route and executor ID so that normalization can run, but nothing ever invokes them.

## Run it

You don't need Go installed. Run the pinned CI image from the repository root.

Linux or macOS shell:

```sh
docker run --rm -it -p 127.0.0.1:8787:8787 -v "$PWD:/src:ro" -w /src   -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -buildvcs=false"   golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195   go run ./cmd/guardfil-playground -addr 0.0.0.0:8787 -allow-non-loopback
```

Git Bash on Windows: `MSYS_NO_PATHCONV=1` stops MSYS from rewriting `/src` into a Windows path.

```sh
MSYS_NO_PATHCONV=1 docker run --rm -it -p 127.0.0.1:8787:8787 -v "$(pwd -W):/src:ro" -w /src   -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -buildvcs=false"   golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195   go run ./cmd/guardfil-playground -addr 0.0.0.0:8787 -allow-non-loopback
```

PowerShell, as one line:

```powershell
docker run --rm -it -p 127.0.0.1:8787:8787 -v "${PWD}:/src:ro" -w /src -e GOTOOLCHAIN=local -e GOFLAGS="-mod=readonly -buildvcs=false" golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 go run ./cmd/guardfil-playground -addr 0.0.0.0:8787 -allow-non-loopback
```

Then open <http://127.0.0.1:8787>. The first start downloads the image and one module, so it takes a minute. Stop it with Ctrl+C.

How the Docker setup stays local:

- The container listens on `0.0.0.0` because Docker needs that to forward the port.
- `-allow-non-loopback` is the explicit opt-in for that bind address.
- `-p 127.0.0.1:8787:8787` publishes the port on your machine's loopback only. **Keep the `127.0.0.1:` prefix.** The Host check only stops browsers. Any machine that can reach the port can send `Host: 127.0.0.1` itself, change the policy and load the process. The playground has no secrets to steal, but it is not meant to be reachable from a network.

With Go 1.27 installed you can skip Docker:

```sh
go run ./cmd/guardfil-playground          # listens on 127.0.0.1:8787
```

The command refuses a non-loopback `-addr` unless you pass `-allow-non-loopback`.

## Click-through test

The **Evaluate** tab has preset buttons that fill the form. Each row below should give the stated result, unless you have changed the policy.

| Input | Expected |
| --- | --- |
| Preset **Allowed read** (`fake.read_note`, credential `valid`) | `ALLOW`, code `POLICY_ALLOWED`. `decision_id`, `action_id` and `action_digest` are set, `expires_at` ≤ `deadline_at` and `dispatch_eligible: false`. |
| Preset **Denied delete** (`fake.delete_record`) | `BLOCK POLICY_DENIED (policy)`. The `guardfil.error/1` envelope shows `execution: not_dispatched`, delivery `withheld` and `retry: never`. |
| `fake.send_message` with credential `valid` | `BLOCK POLICY_DENIED (policy)`. No rule matches and the policy default is deny. |
| Preset **No credential** | `BLOCK AUTH_REQUIRED (auth)` |
| Credential `unknown` or `expired` | `BLOCK AUTH_INVALID (auth)` |
| Preset **Malformed JSON** | `BLOCK PARSE_INVALID (parse)` |
| Payload `{"note_id":"a\nb"}` (a JSON `\n` escape) | `BLOCK`. Control characters in strings stay rejected. |
| Preset **Unknown tool** | `BLOCK TOOL_REVISION_UNKNOWN (normalize)` |
| Tool name `fake.Read_note` or a Cyrillic look-alike | `BLOCK SCHEMA_INVALID (normalize)` |
| Tick **cancelled** | `BLOCK CANCELLED (policy)` |
| Preset **Expired envelope** | `BLOCK DEADLINE_EXCEEDED (policy)` |
| `ttl_ms` 60000 on an allowed read | `ALLOW`. `deadline_at` is 30 s after `received_at`, because the kernel clamps the lifetime. |

**Policy** tab:

1. Change `effect: allow` to `effect: deny` on `allow-read` and press **Apply**.
2. Check that the digest changes.
3. Run **Allowed read** again. It now returns `BLOCK POLICY_DENIED`.
4. Enter invalid YAML and press **Apply**. You get an error, and the previous policy and digest stay active.
5. Press **Reset** to restore the default.

The pipeline trace shows each kernel step: admit (parse and schema), authenticate, project, context, envelope, normalize and authorize. The step that failed is marked.

**Red-team fixtures** tab: **Run** evaluates the advisory demo's synthetic fixture set. Only `allow-read` is `ALLOW`, and every row has `dispatch_eligible: false`.

**History** tab: shows the last 50 results, newest first. Click a row to reopen its result card. The kernel counters keep running when you change the policy.

## Shadow mode: watch a Claude Code session

`-tools claude-code` adds 14 Claude Code tools to the catalog, next to the demo tools:

| Claude Code name | Kernel tool ID |
| --- | --- |
| `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `MultiEdit` | `cc.bash`, `cc.powershell`, `cc.read`, `cc.write`, `cc.edit`, `cc.multi_edit` |
| `Glob`, `Grep`, `WebFetch`, `WebSearch` | `cc.glob`, `cc.grep`, `cc.web_fetch`, `cc.web_search` |
| `Task`, `Agent`, `TodoWrite`, `NotebookEdit` | `cc.task`, `cc.agent`, `cc.todo_write`, `cc.notebook_edit` |

Each `cc.*` tool accepts only the empty payload `{}`, so decisions depend on the tool alone, not
its arguments. The starter policy keeps the demo rules and adds two:

- `allow-cc-low-risk` allows `cc.read`, `cc.glob`, `cc.grep` and `cc.todo_write`;
- `deny-cc-mutating` denies `cc.bash`, `cc.powershell`, `cc.write`, `cc.edit` and `cc.multi_edit`.

Everything else falls to `default: deny`. **Reset** restores this policy, not the demo one.
`GET /api/state` reports `tool_set` and `tool_map` (the table above; `[]` in demo mode).

A Claude Code `PreToolUse` hook can then ask the playground about every tool call the agent
makes and show the verdicts in **History**. The hook is a development tool in
[`devenv/guardfil-shadow-hook`](../../devenv/guardfil-shadow-hook/README.md); it sends only the tool ID and `{}`, never the arguments, always exits 0 and never
blocks a call. Install it in a scratch project's `.claude/settings.local.json`, not in global
settings.

Add `-tools claude-code` to any of the commands above, for example:

```sh
go run ./cmd/guardfil-playground -tools claude-code
```

This is advisory observation only. History holds the last 50
results in memory and is lost when the process stops.

## Automated tests

`go test ./internal/playground/` covers the following:

- every row above;
- an equivalence check against every advisory demo fixture;
- the HTTP hardening (Host, Origin, Content-Type, body limit, security headers, listen-address check);
- policy swaps under concurrent evaluation, which also runs with `-race`;
- static guards. The playground may not import the product server, bootstrap or config, use an HTTP client, run processes or touch files. Its web assets must have no inline script and no external URL, and nothing may be rendered through `innerHTML`.
