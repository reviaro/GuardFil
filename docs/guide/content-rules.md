# Content Rules and Sanitization

GuardFil inspects data crossing the agent boundary in both directions: outbound tool inputs from the agent and inbound tool results or API responses returning to the agent.

Result inspection is available through the MCP proxy, the HTTP gateway and the Python `guard` client. Native shell and built-in file-tool outputs do not have a result-filter path. If a response list or injection rule targets one of those calls, GuardFil refuses it with `TRANSFORM_UNAVAILABLE`; it does not silently skip the rule. Scope response rules to the tools whose results GuardFil can inspect. Request-only lists can still inspect shell commands.

This inspection performs three critical security tasks:
1. **Secret Redaction**: Automatically detects and redacts credentials, keys, and tokens.
2. **Company Word and Pattern Lists**: Enforces company-defined terminology or data classification rules.
3. **Prompt-Injection Defense**: Detects and neutralizes prompt injection payloads in tool outputs.

---

## 1. Secret Redaction

Whenever an output is filtered, GuardFil's regex-based secret scanner (`internal/filter/filter.go`) executes automatically.

Matched secrets are replaced with a standardized redaction token:
```
[REDACTED:<kind>]
```

### Recognized Secret Types

| Detector Kind | Description and Signature |
| --- | --- |
| `private_key` | RSA, EC, or OpenSSH private key blocks (`-----BEGIN ... PRIVATE KEY-----`). |
| `aws_access_key` | AWS IAM access keys (`AKIA[0-9A-Z]{16}` or `ASIA[0-9A-Z]{16}`). |
| `github_token` | GitHub personal access tokens (`ghp_...`, `github_pat_...`). |
| `anthropic_key` | Anthropic API keys (`sk-ant-...`). |
| `openai_key` | OpenAI API keys (`sk-...`, `sk-proj-...`). |
| `stripe_key` | Stripe live/test API keys (`sk_live_...`, `rk_live_...`). |
| `slack_token` | Slack bot or user tokens (`xoxb-...`, `xoxp-...`). |
| `google_api_key` | Google Cloud API keys (`AIza...`). |
| `jwt` | JSON Web Tokens (`eyJ...`). |
| `url_password` | Credentials embedded in URLs (`https://user:pass@host/`). |
| `bearer_token` | HTTP Bearer authorization headers (`Bearer <token>`). |
| `secret_field` | JSON fields or query strings named `password`, `token`, `secret`, `api_key`, etc. |
| `credential` | Exact matches for configured upstream gateway credentials. |

---

## 2. Word and Regex Lists

You define content rules in the web UI's Content tab (or its JSON editor). The document has the shape `{"schema_version": 1, "lists": [...], "injection": {"action": ..., "tools": [...]}}`. Each save is kept as a new version under `$GF_HOME/state/content-versions/` and you can restore any of them. An operator can also set a starting file with `content_rules_file` in `guardfil.yaml`; that file is version 0.

### One list

```json
{
  "id": "internal-codenames",
  "name": "Internal Project Codenames",
  "action": "filter",
  "direction": "both",
  "tools": ["*"],
  "words": ["Project Falcon", "Bluebird"],
  "patterns": ["EXT-[0-9]{4}"],
  "case_sensitive": false
}
```

- **ID & Name**: identifier of 1–48 lowercase letters, digits or hyphens, and a descriptive name.
- **Action**:
  - `filter`: Replaces matching text with `[FILTERED:<list-id>]`.
  - `block`: a matching request is blocked (`CONTENT_BLOCKED`); a matching result is replaced by `GuardFil withheld this result: <list ids>`.
  - `ask`: Holds the call for owner confirmation in the Web UI.
  - `monitor`: Allows the call and records a `CONTENT_MONITORED` tag in the decision log.
- **Direction**: Where the rule applies:
  - `request`: Outbound tool arguments sent by the agent.
  - `response`: Inbound tool outputs returning to the agent.
  - `both`: Evaluated in both directions.
- **Tools**: List of tools or wildcards (e.g., `["*"]`, `["stockapp.*"]`).
- **Words**: Array of literal phrases (up to 1,000 words per list).
- **Patterns**: Array of regular expressions (up to 1,000 patterns per list).

---

## 3. Prompt-Injection Scanning

Third-party websites, issue trackers, and file contents may contain adversarial prompt injections aimed at subverting the agent's LLM. GuardFil provides a heuristic scanner (`internal/content/injection.go`) focused on inbound responses.

### Detection Categories

- **Override Phrases (`override`)**:
  - `ignore all previous instructions`
  - `disregard the above prompts`
  - `system override`
  - `new instructions:`
  - `you are now`
- **Role Markup (`role_markup`)**:
  - Chat template tokens: `<|im_start|>`, `<|im_end|>`, `[INST]`, `[/INST]`
  - Markdown role headers: `### system`, `<system>`, `assistant:` at line starts
- **Malicious Directives (`command`)**:
  - `do not tell the user`, `never tell the user`
  - Financial extraction: `transfer ... to account ...`, `send ... to <URL>`
- **Hidden Unicode (`hidden_text`)**:
  - Unicode tag characters (`U+E0000` through `U+E007F`).
  - Zero-width spaces and formatters (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`, `U+2060`).
  - Bidirectional text controls (`U+202A`–`U+202E`, `U+2066`–`U+2069`).

### Injection Actions

When prompt injection is detected, GuardFil executes the configured action:
- `filter`: Hidden characters are stripped, and suspected override spans are replaced with:
  ```
  [GuardFil removed suspected instructions]
  ```
- `block`: The result is replaced by `GuardFil withheld this result: ...`.
- `ask`: The response is held in the Web UI for your inspection.
- `monitor`: The response passes through, and an alert is recorded in the log.
- `none`: Scanning disabled.

---

## 4. Conflict Resolution for Content Rules

When text triggers multiple rules across lists or injection scanners, GuardFil determines the final action using strict severity ranking:

$$\text{block} > \text{ask} > \text{filter} > \text{monitor} > \text{none}$$

The strongest action wins across all matched patterns.

---

## 5. The Filter Obligation (`effect: sanitize`)

When a policy rule has `effect: sanitize`, it creates a binding obligation:
1. **Pre-flight Check**: The approval service verifies that the calling client supports filtering (`"can_filter": true` in the approval request). If the client cannot filter, the call is blocked (`APPROVAL_UNAVAILABLE`).
2. **Filtering Execution**: The client runs the output through GuardFil. The MCP proxy uses the same session approval socket for both admission and filtering, preserving the agent's identity. The legacy filter-only socket remains available to clients.
3. **Audit Recording**: The decision log records the call as filtered, with the number of secrets removed and the content rule matches.

---

## 6. String-by-String JSON Filtering

Tool results and API responses frequently return JSON documents. Evaluating regexes across raw JSON strings creates vulnerabilities: JSON Unicode escapes (`\u0050`) can mask words, and embedded newlines (`\n`) break regex word boundaries.

GuardFil therefore decodes a result that is one valid JSON document and filters each string (object keys and values) exactly as the reader will see it, then re-encodes the document. Numbers keep their exact value. A secondary pass checks credential fields that need the key and value together (for example `"password": "..."`). A result that is not valid JSON is filtered as plain text.

The MCP proxy withholds a tool result it cannot get filtered and returns `GuardFil could not filter this tool result, so it was withheld.` instead.

Escaped content in NDJSON, prefixed JSON, nested JSON strings and repr output is also scanned. If a decoded view contains a secret or an actionable content match that cannot be safely rewritten in the original representation, GuardFil withholds the entire result. Excessively nested encodings are withheld when the bounded decoding limit is reached. Plain text and supported JSON retain their usual redaction behavior.
