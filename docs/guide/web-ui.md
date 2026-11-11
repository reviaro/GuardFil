# Web UI

GuardFil includes a lightweight, secure web interface for workstation owners. It allows you to monitor decisions in real time, review held calls, manage policy rules, configure content filtering, and edit raw configurations with full revision rollback.

The Web UI binds strictly to loopback (`127.0.0.1:8088` by default) and serves single-origin static assets protected by strict Content Security Policy (CSP) headers.

## Authentication and Login

1. When GuardFil initializes (`guardfil-local.sh init --ui active`), it generates a 32-byte cryptographically random token in:
   ```
   $GF_HOME/credentials/ui-token
   ```
2. Navigate to `http://127.0.0.1:8088/` in your browser.
3. Paste the token from `ui-token` into the login form and click **Log in**.
4. The server validates the token in constant time and sets an HTTP-only session cookie (`gf_session`) valid for 12 hours. It also gives the page an independent session token, kept in that tab's origin-scoped `sessionStorage` and sent in the `X-GuardFil-Session` header on every API request. Reloading preserves the login; a new tab may require login again. A cookie captured by another loopback port cannot authenticate by itself.

API clients that automate the UI must retain both the cookie and the `session_token` returned by `/api/login`. The owner Unix-socket approval API is unchanged.

> [!NOTE]
> The login endpoint enforces rate limiting: 10 failed login attempts within 1 minute will temporarily throttle subsequent requests.

---

## Screen Overview

Held previews show invisible Unicode and control characters as explicit escapes. If the complete displayed detail and paths exceed 1,000 runes, the call is blocked. Editing policy, catalog or content rules cancels waiting calls; retry them under the new rules.

### 1. Header and Navigation
- **Brand & Status**: Shows active policy version, total active rules, and whether the "Ask Me" approval listener is active (`on` or `off`).
- **Tab Switcher**: Toggle between the **Policy** tab and the **Content** tab.
- **Log out**: Clears the active session and returns to the login screen.

Use the arrow keys, Home or End while a tab is focused to switch sections. A
"Skip to controls" link is available to keyboard users. Tables scroll within
their own region on narrow screens, keeping every column available. Light and
dark themes follow your system preference.

The header reports connection interruptions and resumes updates automatically.
Unchanged approval buttons keep keyboard focus during polling. Save buttons
show progress and prevent repeated submission while a request is pending;
errors remain visible until dismissed or replaced by another message. A failed
content-rule save preserves the form so you can correct it and try again.

### 2. Waiting for You (Pending Approvals)
Located at the top of the interface and visible from both tabs:
- Appears whenever a matching rule has `effect: require_approval`.
- Displays the pending action (e.g., `shell command`, `write /workspace/src/app.py`, or `tool stockapp.place_order`).
- Shows the calling principal (`codex-agent` or `agent.<NAME>`), triggering rule IDs, elapsed waiting time, and expiry timestamp.
- Requests or results with previews longer than 1,000 runes are blocked (`APPROVAL_DETAIL_TOO_LARGE` for requests); an incomplete preview cannot be approved.
- At most eight calls per principal and 32 overall may wait. Disconnecting or deleting a session cancels its pending calls.
- **Allow**: Approves the action and sends `ALLOW` back to the agent.
- **Deny**: Rejects the action and returns `BLOCK` (`APPROVAL_REJECTED`) to the agent.
- If GuardFil is running without an approver socket, a warning displays: `"Ask me" is off: calls needing approval are blocked`.

---

## The Policy Tab

### 1. Rules Management
The Rules table summarizes the current policy in plain language:
- **Columns**: Action (`Allow`, `Block`, `Monitor`, `Ask me`, `Filter`), Principal, What (Target), Which (Value / Condition), and Delete.
- **Add Rule Form**:
  - **Action**: Select `Allow`, `Block`, `Monitor`, `Ask me`, or `Filter (tool results)`.
  - **Principal**: Choose `codex-agent`, an existing agent, or select `+ New agent...` to define a custom identity (e.g., `notes-bot`).
  - **What**:
    - `Shell commands (all)`: Controls `tool.invoke` on `codex.exec_command`.
    - `Tool`: Controls a specific tool (auto-completes from the installed tool catalog).
    - `File writes in folder`: Controls `filesystem.write` under a path (e.g., `/workspace/**`).
    - `File reads in folder`: Controls `filesystem.read` under a path (applies to Claude Code `Read`, `Grep`, `Glob`, `LS`).
    - `Website`: Applies `http.request` rules to the gateway's actual HTTPS destination and Claude Code's `WebFetch` URL. Tool permission is also required. Block and Ask me add restrictions; Allow cannot override a tool block. Unmatched websites retain the tool decision. Host and path are matched; query strings and fragments are ignored. See [URL enforcement](policy.md#website-enforcement) for supported URL forms and boundaries.
  - **When (Amount Conditions)**: For `Tool` targets, optionally specify an argument or product (e.g., `quantity * limit_price`), a comparison operator (`>`, `>=`, `<`, `<=`, `==`, `!=`), and an exact decimal threshold.

### 2. Recent Decisions
Displays a live feed of the last 100 evaluated actions parsed from `$GF_HOME/state/decisions.jsonl`:
- **Time**: Timestamp of the decision.
- **Principal**: The acting agent principal.
- **Result**: Visual indicator (`Allowed`, `Result filtered · N secrets removed`, `Blocked`, `monitored`, `asked`).
- **Call**: Action summary (tool name, shell command, or file path).
- **Rule / Reason**: Triggered rule IDs and kernel reason codes (e.g., `POLICY_ALLOWED`, `POLICY_DENIED`, `CONTENT_BLOCKED`).

### 3. Policy History & YAML Editor
- **Version List**: Shows every revision saved since initialization. Displays revision number (`v1`, `v2`...), author change notes, and timestamps.
- **Restore**: Click **Restore** next to any version (or `v0` for the original file) to roll back immediately.
- **Advanced YAML Editor**: Expand the collapsible panel to view and edit the raw YAML policy. Save with an optional changelog note; invalid YAML is rejected before publication.

---

## The Content Tab

The Content tab controls data loss prevention and prompt injection defenses.

### 1. Prompt-Injection Scanning
Configures heuristic scanning of tool outputs and API responses:
- **Action**: Choose `Filter`, `Block`, `Monitor`, `Ask me`, or `None (off)`.
- **Tools**: Comma-separated list of tool patterns (or `*` for all tools).

### 2. Content Rules (Word & Pattern Lists)
Create and manage company word lists or regular expression patterns:
- **Fields**:
  - **List Name** & **ID**: Human-readable name and alphanumeric identifier (e.g., `codenames`).
  - **Action**: `filter` (replaces matches with `[FILTERED:<id>]`), `block`, `monitor`, or `ask`.
  - **Direction**: `Both (in & out)`, `Request (outbound)`, or `Response (inbound)`.
  - **Tools**: Tool selector pattern (e.g., `*` or `stockapp.*`).
  - **Words**: Comma-separated list of literal phrases.
  - **Regex Patterns**: Comma-separated list of regular expressions.
  - **Case sensitive**: Checkbox to enforce exact casing.

### 3. Try It (Test Bench)
An interactive simulator to verify how content rules and injection scans evaluate text:
- Enter a tool name, select direction (`Response` or `Request`), and paste sample text.
- Click **Test** to view the resulting Action tag, triggered match lists and categories, and the rewritten sanitized output.

### 4. Content History & JSON Editor
- Review earlier revisions of the content rules document and restore previous snapshots.
- Direct JSON editing for advanced configurations.

---

## API Endpoints Reference

The Web UI server exposes the following HTTP endpoints on the local listener:

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/` | None | Serves `index.html`. |
| `GET` | `/app.js` | None | Serves JavaScript bundle. |
| `GET` | `/app.css` | None | Serves stylesheet. |
| `POST` | `/api/login` | None | Authenticates with `{"token": "..."}`; sets session cookie. |
| `POST` | `/api/logout` | Session | Invalidates session cookie. |
| `GET` | `/api/state` | Session | Returns current policy, pending approvals, rules, tools, and decisions. |
| `POST` | `/api/approvals/{id}` | Session | Answers held call: `{"decision": "allow"\|"deny"}`. |
| `POST` | `/api/rules` | Session | Adds or deletes a policy rule. |
| `POST` | `/api/policy` | Session | Saves raw policy YAML with optional note. |
| `POST` | `/api/policy/restore` | Session | Reverts policy to specified version number: `{"version": N}`. |
| `GET` | `/api/content` | Session | Returns active content rules, current version, and history. |
| `PUT` | `/api/content` | Session | Updates content rules document and saves snapshot. |
| `POST` | `/api/content/try` | Session | Tests text against content rules without side effects. |
| `POST` | `/api/content/restore`| Session | Reverts content rules to specified version: `{"version": N}`. |
