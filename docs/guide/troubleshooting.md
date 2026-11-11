# Troubleshooting and Reason Codes

When GuardFil blocks an action or fails to complete an operation, it returns a structured reason code. This guide lists all reason codes and explains what they mean and how to resolve them.

---

## 1. Policy & Kernel Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `POLICY_DENIED` | No rule allowed the action, or an explicit deny rule matched. | Add an `allow` rule in the Web UI or check if a deny rule overlaps the target. |
| `POLICY_ALLOWED` | The action matched an allow rule and was permitted. | Normal successful operation. |
| `POLICY_FILTERED` | The action was allowed under the condition that its output is filtered. | Normal operation when `effect: sanitize` is applied. |
| `POLICY_MONITORED` | The action was allowed and flagged as monitored for auditing. | Normal operation when `effect: monitor` is applied. |
| `POLICY_UNAVAILABLE` | Policy YAML file is missing, unreadable, or syntactically invalid. | Check `$GF_HOME/config/policy.yaml` for syntax errors or invalid fields. |
| `POLICY_EVALUATION_FAILED` | Internal kernel evaluation error during rule processing. | Check daemon logs (`guardfil-local.sh logs`) for underlying cause. |

---

## 2. Approval & "Ask Me" Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `APPROVAL_DETAIL_TOO_LARGE` | The complete approval preview exceeds 1,000 runes. No approval is offered. | Shorten or split the request so the owner can review all of it. |
| `POLICY_CHANGED` | Policy, catalog or content rules changed while the call was being decided or held. | Retry under the current rules; an old approval cannot release it. |
| `TRANSFORM_UNAVAILABLE` | A sanitize rule or response-content rule requires filtering, but this caller cannot filter its results. | Use the MCP proxy, gateway or Python `guard` client. For native shell/file tools, scope content rules to requests; their results have no filter path. |
| `APPROVAL_UNAVAILABLE` | An ask-me rule matched but nobody can answer (the web UI is off), or a filter rule matched and the caller can't filter results. Also the reason for a held Read of a file under an ask-me read rule. | Turn the web UI on (`guardfil-local.sh ui active`), or call the tool through a client that filters (`can_filter: true`, e.g. the MCP proxy). |
| `APPROVAL_GRANTED` | The call was approved by the owner in the Web UI. | Normal operation when approved interactively. |
| `APPROVAL_REJECTED` | The call was explicitly rejected by the owner in the Web UI. | Expected when the owner clicks "Deny". |
| `APPROVAL_EXPIRED` | Nobody answered the held call in time. | Answer sooner, or raise `ask_timeout_seconds` in the `approval` block of `guardfil.yaml` (default 60 s, at most 600 s; `guardfil-local.sh ui` and `catalog` rewrite that file). |
| `APPROVAL_CONSUMED` | The one-time approval decision token has already been used. | Re-evaluate the action if another attempt is required. |
| `APPROVAL_STALE` | The approval authorization window expired. | Retry the action to obtain a fresh approval token. |

---

## 3. Request Parsing & Payload Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `PARSE_INVALID` | JSON payload is malformed, truncated, or contains duplicate object keys. | Ensure client emits valid JSON without duplicate dictionary keys. |
| `CONTROL_CHARACTER` | Request string contains unescaped ASCII control characters (< 0x20 or 0x7f). | Escape or strip raw control characters from inputs. |
| `DECIMAL_LITERAL_INVALID` | Numeric parameter is not a valid exact decimal representation. | Pass numbers as standard decimal strings (e.g. `"100.50"` without currency symbols). |
| `SCHEMA_INVALID` | Request payload structure does not match the required schema. | Verify required argument types against the tool catalog definition. |
| `LIMIT_EXCEEDED` | Request payload, argument count, or string length exceeded size limits. | Keep arguments within bounds (`max_length`, max 32 arguments per tool). |
| `REQUEST_TOO_LARGE` | Total request size exceeded `MaxRequestBytes` (64 KiB). | Reduce payload size sent across the approval socket. |
| `INTERNAL_ERROR` | An unexpected error occurred; GuardFil failed closed for safety. | Check `$GF_HOME/state/decisions.jsonl` and container logs. |

---

## 4. Tool Catalog Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `TOOL_REVISION_UNKNOWN` | The tool invoked by the agent is not registered in the tool catalog. | Add the tool specification to `$GF_HOME/config/tool-catalog.yaml`. |
| `PROTOCOL_UNSUPPORTED` | The action adapter requested is not supported by the kernel. | Use supported `decision_api` or stdio MCP adapters. |

---

## 5. File Read Enforcement Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `READ_PATH_REQUIRED` | A file read tool (`Read`, `Grep`, `Glob`, `LS`) omitted a path or used a non-canonical path. | Ensure the client supplies an absolute, normalized target path. |
| `READ_PATTERN_LEAVES_PATH` | A Glob pattern contained an absolute path or `..` directory traversal escaping the base directory. | Restrict glob search patterns to relative paths inside the directory. |
| `READ_SEARCH_COVERS_RESTRICTED_PATH` | A directory search (`Grep`, `Glob`, `LS`) covers a folder protected by a read deny rule. | Point searches to subfolders that do not overlap restricted directories. |

---

## 6. Content Rules & Sanitization Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `CONTENT_BLOCKED` | Request text matched a content list or the injection scanner with action `block`. (A blocked *result* is replaced by `GuardFil withheld this result: ...`.) | Review the lists in the web UI's Content tab. |
| `CONTENT_MONITORED` | Request or response text triggered an active monitor rule. | Informational; audit entry recorded in decision log. |
| `FILTER_UNSUPPORTED_CONTENT`| Gateway response could not be filtered due to unknown or unparseable content format. | Ensure upstream responses return valid UTF-8 JSON or text. |

---

## 7. API Gateway Reason Codes

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `GATEWAY_NO_ROUTE` | Method and path match no route (the path starts with the upstream's name: `/myapp/...`). | Check the routes in the file you installed with `guardfil-local.sh gateway`. |
| `GATEWAY_BAD_REQUEST` | HTTP request body was malformed or could not be decoded. | Ensure request bodies sent to gateway are valid JSON. |
| HTTP 401 `a GuardFil gateway token is required` | The request had no `Authorization: Bearer` header, or the token is not the gateway's agent token or a live session token. | Inside the executor, use `$GUARDFIL_GATEWAY_TOKEN` (`run-agent` sets it when a gateway is installed). |

---

## 8. Broker & Budget Ledger Reason Codes

When the $2.00 ceiling or the ledger's 256-request cap is reached, the broker refuses the request before sending it, and the agent sees an error from its model endpoint.

| Reason Code | Explanation | Resolution |
| --- | --- | --- |
| `COST_EXCEEDS_RESERVATION` | A reply cost more than the amount reserved for it. The ledger halts (a halt reason, not a per-call block) and refuses further requests. | Should not happen with the pinned models. Report it; don't edit the ledger by hand. |
| `MAX_REQUESTS_EXCEEDED` | The session reached its `--max-requests` cap. | Start a new session or raise `--max-requests` (Codex: 1–64). |
| `RESERVE_FAILED` | Broker could not reserve budget in the ledger (lease busy or lock failure). | Check for dangling broker processes on the host. |
| `DECISION_LOG_UNAVAILABLE`| GuardFil failed to append to `$GF_HOME/state/decisions.jsonl`. | Check disk space (`df -h`) and file permissions on `$GF_HOME/state`. |

---

## 9. Workspace Startup Errors

These are launcher messages, not reason codes. The agent does not start; GuardFil never falls back to mounting the raw folder.

| Message | Explanation | Resolution |
| --- | --- | --- |
| `workspace mediation needs /dev/fuse and fusermount3` | FUSE 3 is not installed or `/dev/fuse` is not accessible. | Install FUSE 3 (Debian/Ubuntu: `sudo apt-get install fuse3`). |
| `workspace mediation needs user_allow_other in /etc/fuse.conf` | Docker cannot bind a user's FUSE mount without this host-wide option. | An administrator runs `echo user_allow_other \| sudo tee -a /etc/fuse.conf` once. Verify with `guardfil-local.sh check`. |
| `guardfil-workspace is missing` | The helper binary was not extracted, usually after updating GuardFil. | Run `guardfil-local.sh up`. |
