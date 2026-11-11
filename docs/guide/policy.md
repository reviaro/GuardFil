# Policy Language

GuardFil uses a declarative, deterministic YAML policy language to control agent capabilities. The policy kernel (`internal/policy`) evaluates every action against these rules.

## Document Structure

A policy document contains five top-level fields:

```yaml
schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: rule-identifier
    effect: allow | deny | require_approval | sanitize | monitor
    match:
      principals: [codex-agent]
      operations: [tool.invoke]
      resources:
        - kind: tool
          value: codex.exec_command
```

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | Integer | Must be `1`. |
| `tenant_id` | String | Identifier for the tenant (alphanumeric, dot, underscore, hyphen; 1–64 characters, e.g., `synthetic`). |
| `revision` | Integer | Monotonically increasing revision counter (`uint64 > 0`). |
| `default` | String | Must be `deny`. GuardFil strictly enforces default-deny semantics. |
| `rules` | List | Ordered list of policy rules (up to 1,000 rules). |

---

## Rule Definition

Each rule in the `rules` array contains:

- `id`: A unique alphanumeric string (1–64 characters). Duplicate IDs are rejected at compilation.
- `effect`: The decision produced when this rule matches:
  - `deny`: Blocks the action unconditionally.
  - `allow`: Permits the action if no blocking rule matches.
  - `require_approval`: Holds the call for human intervention ("Ask Me" in the Web UI). If the owner approves, it proceeds; otherwise it blocks (`APPROVAL_UNAVAILABLE`, `APPROVAL_REJECTED`, or `APPROVAL_EXPIRED`).
  - `sanitize`: Permitted on the condition that the call result is passed through GuardFil's secret redactor and content rules filter. If the caller cannot filter (`can_filter: false`), the call is blocked.
  - `monitor`: Permits the action like `allow`, but records a monitored flag in the decision log and Web UI.
- `match`: Criteria that must all match for the rule to trigger:
  - `principals`: List of agent identities (`codex-agent`, `agent.<NAME>`).
  - `operations`: Security operations (`tool.invoke`, `filesystem.write`, `filesystem.read`, `http.request`).
  - `resources`: List of resource selectors (`kind` and `value`).
  - `decimal`: Optional list of amount conditions for tool calls.
- `checks`: Optional list of named checks. A matching rule with checks never allows a call (no checks are wired in the local deployment, so leave it out).

---

## Operations and Resource Selectors

Each operation in GuardFil maps strictly to one trusted resource kind:

| Operation | Resource Kind | Value Syntax | Example |
| --- | --- | --- | --- |
| `tool.invoke` | `tool` | `server.tool` (exact match; no wildcards) | `codex.exec_command`, `claude.read` |
| `shell.execute` | `command` | Canonical JSON argument array, optionally followed by `/**` | `["git","status"]`, `["git","status"]/**` |
| `filesystem.write` | `path` | Canonical absolute path or path with `/**` | `/workspace/**`, `/workspace/app.py` |
| `filesystem.read` | `path` | Canonical absolute path or path with `/**` | `/workspace/docs/**`, `/workspace/key.pem` |
| `http.request` | `url` | Canonical `https://` URL or URL with `/**` | `https://api.github.com/**` |

### Pattern Syntax

Defined in `internal/resource/resource.go`:
- **Paths**: Must start with `/`, contain no `\` or `%`, and be lexically clean (`path.Clean`). A trailing `/**` matches the directory and any subdirectories or files beneath it.
- **URLs**: Must use `https://`, lowercase hostname, clean path, and no userinfo, query, or fragment. A trailing `/**` acts as a wildcard across subpaths.

- **Tools**: Format is `<server>.<tool>`. Wildcards are never permitted on tool IDs.

- **Paths in any folder**: `BASE/**/NAME` matches a file or folder named `NAME` directly in `BASE` or in any folder below it. `BASE/**/NAME/**` also matches everything inside such a folder. `NAME` is one literal path segment (no `*`, `/`, `.` or `..`), and a pattern holds at most one `/**/`. Names match exactly: `/workspace/**/.envrc` matches `/workspace/app/.envrc` but not `.envrc.bak`, and `/workspace/**/.git/**` does not match `.github/`. Write `/**/NAME` for any folder on the machine. URLs and tools do not have this form.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `/workspace/notes.md` | that file | anything else |
| `/workspace/docs/**` | `/workspace/docs` and everything under it | `/workspace/docs-old/a` |
| `/workspace/**/.env` | `/workspace/.env`, `/workspace/a/b/.env` | `/workspace/a/.env.example` |
| `/workspace/**/.git/**` | `/workspace/.git/config`, `/workspace/sub/repo/.git/hooks/x` | `/workspace/.gitignore` |

No other wildcard exists: a `*` anywhere else is a literal character.

### Website enforcement

Website rules are additional checks on tool calls. The HTTP gateway checks its
actual upstream URL before dispatch; a caller cannot replace that URL with an
argument or header. Claude Code's managed hook checks the `url` argument of
`claude.webfetch`. Both work with the UI absent. Tool permission is still
required, a website Allow cannot override a tool block, and a website Block
cannot be approved away by a tool-level Ask me. Unmatched websites retain the
tool decision. Monitor is recorded; Ask me uses the ordinary approval queue.

Selectors compare the HTTPS origin and path, ignoring the request's query and
fragment. With any Website rule for the caller, unsupported URL forms fail
closed as `WEBSITE_URL_UNSUPPORTED`: HTTP, encoded or unclean paths, userinfo,
uppercase hostnames, DNS trailing dots and explicit default port `:443`. Use
canonical HTTPS destinations; a local HTTP gateway continues working when
that principal has no Website rules. Paths are case sensitive. DNS aliases
and different hostnames are distinct selectors.

The gateway does not follow redirects. Native WebFetch checks only its initial
URL; it is not a redirect or network firewall. The constrained executor still
has no direct network. Arbitrary MCP tools with URL-shaped arguments, provider
web search and allowed shell commands are not interpreted as WebFetch. Route
HTTP access through the gateway when it must be mediated.

---

## How Actions Map to Operations

The approval bridge (`internal/approval/approval.go`) maps incoming requests from hooks and runtimes to operations:

1. **Shell Commands**:
   - Request: `{"kind": "shell", "command": ["bash", "-c", "ls"], "cwd": "/workspace"}`
   - Evaluated as: `tool.invoke` on tool `codex.exec_command`, plus `shell.execute` on every resolved command when command rules exist for this principal. See [exact commands and prefixes](workspace-and-commands.md#exact-commands-and-prefixes).
2. **File Writes**:
   - Request: `{"kind": "file_write", "changes": [{"path": "/workspace/main.go", "change": "add"}]}`
   - Evaluated as: `filesystem.write` on each path in `changes`.
3. **File Reads**:
   - Filesystem request: `{"kind":"file_read","paths":["/workspace/note"]}`; requires an explicit `filesystem.read` grant for every path.
   - Request from Claude Code `Read`, `Grep`, `Glob`, `LS`.
   - Tool rules evaluate `tool.invoke` (e.g. `claude.read`).
   - Read path checks (`internal/approval/read_rules.go`) evaluate `filesystem.read` against the normalized target path. For directory search tools (`Grep`, `Glob`, `LS`), searches covering any restricted path are blocked.
4. **Tool Calls**:
   - Request: `{"server": "notes", "tool": "read_note", "arguments": {"name": "todo"}}`
   - Evaluated as: `tool.invoke` on tool `notes.read_note`.

---

## Decimal Predicates (Amount Conditions)

For `tool.invoke` operations, rules can include decimal conditions on numeric tool arguments:

```yaml
decimal:
  - field: quantity * limit_price
    operator: "<="
    value: "10000.00"
```

- `field`: An argument name or the product of two argument names (`arg1 * arg2`).
- `operator`: `==`, `!=`, `<`, `<=`, `>`, `>=`.
- `value`: Quoted decimal string literal (evaluated exactly via arbitrary-precision rational arithmetic; no floating-point rounding errors).
- **Fail-Closed Evaluation**: If an argument named in a decimal predicate is missing or not a valid number, the predicate is *unknown*. An unknown predicate still matches `deny`, `require_approval`, and `sanitize` restrictions, but never matches `allow` or `monitor` grants. A `sanitize` rule with an unknown predicate cannot grant a call by itself; its filtering obligation remains if a separate rule authorizes the call.

---

## Conflict Resolution: Deny Always Wins

GuardFil evaluates all matching rules simultaneously. Rule ordering in the YAML file does not change the result:

1. **Deny Wins**: If any matching rule has `effect: deny`, the action is `BLOCK` (`POLICY_DENIED`).
2. **Approval Preempts Allow**: If any matching rule has `effect: require_approval` and no rule denies, the action is held for human confirmation.
3. **Sanitization Enforced**: If any matching rule has `effect: sanitize`, the action requires filtering.
4. **Allow / Monitor**: If no restrictive rule matches, the action is `ALLOW` if at least one `allow` or `monitor` rule matched.
5. **Default Deny**: If no rule matches, the action is `BLOCK`.

---

## Walkthrough: The Starter Policy

`guardfil-local.sh init` copies `deployments/local/starter-policy.yaml` to `$GF_HOME/config/policy.yaml`. All of its rules are for `codex-agent`, the principal every agent gets unless it runs with `--agent NAME`.

| Rule | Effect | What it covers |
| --- | --- | --- |
| `ask-shell` | Ask me | every shell command (`codex.exec_command`) |
| `monitor-workspace-writes` | Monitor | file writes under `/workspace/**`: allowed and recorded |
| `allow-workspace-reads` | Allow | filesystem reads under `/workspace/**`; narrower blocks still win |
| `block-workspace-dotfiles` | Block | writes to `/workspace/.codex/**` (Codex's own config) |
| `block-workspace-claude-settings` | Block | writes to `/workspace/.claude/**` (Claude Code's project settings) |
| `block-host-run-*` (11 rules) | Block | writes to files your machine runs later, in the workspace or any folder below it: `.git/`, `.githooks/`, `.husky/`, `.pre-commit-config.yaml`, `.envrc`, `.mise.toml`, `mise.toml`, `.vscode/`, `.idea/`, `.zed/`, `.devcontainer/` |
| `allow-claude-read`, `-glob`, `-grep`, `-ls` | Allow | Claude Code's read-only tools |

Everything else is blocked by `default: deny`.

**Allowing one of the blocked paths.** A block always wins, so adding an allow rule does not help. Delete the `block-host-run-*` rule for that path (Policy tab, or the YAML). Writes there are then allowed and recorded by `monitor-workspace-writes`. To be asked each time instead, delete it and add an Ask me rule for File writes on the same path.

**Read rules and searches.** A deny or ask-me `filesystem.read` rule is checked against the named path for a `Read`. A `Grep`, `Glob` or `LS` is blocked when its named folder could contain a restricted path. A `BASE/**/NAME` read rule counts as covering all of `BASE`, so one rule like "deny reads of `/workspace/**/.env`" intentionally blocks every recursive directory search under `/workspace`. Exact file patterns (such as `/workspace/key.pem`) block searches of parent folders containing the file, but do not block searches of sibling paths or subdirectories outside the exact file. The executor also checks the actual opened filesystem object through its mediated workspace. See [workspace access](workspace-and-commands.md#filesystem-behavior) for alias handling, migration and supported operations.

---

## Worked Examples

### Example 1: Block a Folder From Writes and Reads

Block access to production configurations or secrets in `/workspace/secrets/**`:

```yaml
- id: block-secrets-write
  effect: deny
  match:
    principals: [codex-agent]
    operations: [filesystem.write]
    resources: [{kind: path, value: /workspace/secrets/**}]

- id: block-secrets-read
  effect: deny
  match:
    principals: [codex-agent]
    operations: [filesystem.read]
    resources: [{kind: path, value: /workspace/secrets/**}]
```

### Example 2: Ask Before Invoking a Dangerous Tool

Require human confirmation before a database migration tool runs:

```yaml
- id: ask-db-migrate
  effect: require_approval
  match:
    principals: [codex-agent]
    operations: [tool.invoke]
    resources: [{kind: tool, value: db.migrate}]
```

### Example 3: Cap an Order Amount with Decimal Predicates

Allow placing orders only when total cost (`quantity * limit_price`) is at or below $5,000.00; ask confirmation for larger amounts:

```yaml
- id: allow-small-orders
  effect: allow
  match:
    principals: [codex-agent]
    operations: [tool.invoke]
    resources: [{kind: tool, value: stockapp.place_order}]
    decimal:
      - field: quantity * limit_price
        operator: "<="
        value: "5000.00"

- id: ask-large-orders
  effect: require_approval
  match:
    principals: [codex-agent]
    operations: [tool.invoke]
    resources: [{kind: tool, value: stockapp.place_order}]
    decimal:
      - field: quantity * limit_price
        operator: ">"
        value: "5000.00"
```

### Example 4: Rule for One Agent Only

Allow shell commands exclusively for an administrative agent (`agent.admin-bot`), leaving standard agents subject to default deny:

```yaml
- id: allow-admin-shell
  effect: allow
  match:
    principals: [agent.admin-bot]
    operations: [tool.invoke]
    resources: [{kind: tool, value: codex.exec_command}]
```

### Example 5: Enforce Output Sanitization (Filter)

Require that notes returned from the demo note server have secrets redacted:

```yaml
- id: filter-notes-read
  effect: sanitize
  match:
    principals: [codex-agent]
    operations: [tool.invoke]
    resources: [{kind: tool, value: notes.read_note}]
```
