# MCP Proxy and API Gateway

GuardFil provides two dedicated proxies for external tools and services:
1. **MCP Filter Proxy (`guardfil-mcp-proxy`)**: Intercepts Model Context Protocol stdio communication inside the container to sanitize outputs from local tools.
2. **API Gateway**: An HTTP reverse proxy that maps agent HTTP calls to catalog tools, enforces policy decisions, and injects secrets without exposing them to the agent.

---

## 1. The MCP Filter Proxy (`guardfil-mcp-proxy`)

The MCP proxy runs inside the agent container, between the agent and an MCP server process it starts. You normally don't run it by hand: `run-agent --mcp NAME=COMMAND` starts it for you (`--mcp notes=demo` runs the bundled notes demo server).

```sh
guardfil-mcp-proxy --socket /run/guardfil/filter.sock --server <NAME> -- <COMMAND> [ARGS...]
```

```
+---------------+         stdio          +--------------------+         stdio          +---------------+
| Agent Runtime | <--------------------> | guardfil-mcp-proxy | <--------------------> |  MCP Server   |
| (Claude/Codex)|                        +---------+----------+                        |  (Child Proc) |
+---------------+                                  |                                   +---------------+
                                                   | /run/guardfil/filter.sock
                                                   v
                                         +--------------------+
                                         |  GuardFil Filter   |
                                         +--------------------+
```

### Filtering Semantics

- **Tool Execution (`tools/call`)**: each text item and any `structuredContent` goes through GuardFil's filter socket. Items that cannot be read as text (images, audio, resources) are replaced by a notice, and other result fields (`_meta` and the like) are dropped. Before forwarding a call, the proxy asks GuardFil to decide it and forwards only the approved tool name and arguments; a call that is not allowed gets a JSON-RPC error and never reaches the server.
- **Protocol Handshake & Discovery**:
  - `initialize`: The server's instructions and capabilities are scanned as JSON text to eliminate prompt injections or leaked tokens.
  - `ping`: The response is forwarded as `{}`; any unexpected payload is discarded.
  - `tools/list`, `resources/read`, `prompts/get`: Output is scanned and sanitized before returning to the agent.
- **Server Notifications**:
  - `notifications/tools/list_changed`, `notifications/resources/list_changed`, `notifications/prompts/list_changed`: Forwarded with all parameters stripped.
  - `notifications/progress`, `notifications/cancelled`, `notifications/message`: Free text fields (`message`, `reason`, `data`) are sanitized.
  - Unknown notifications or server-initiated requests (such as sampling or user elicitation) are withheld, returning a JSON-RPC error.
- **Fail-Closed Behavior**: If GuardFil cannot filter something, the agent gets an error result (`isError: true`) in its place, never the unfiltered text. A server-initiated request gets JSON-RPC error `-32601` back.

---

## 2. The HTTP API Gateway

The API gateway lets an agent interact with third-party web services and internal APIs without giving the agent access to real API tokens.

### How It Works

```
Agent Container                     GuardFil API Gateway                  Upstream Service
+---------------+                  +--------------------+                +----------------+
| Agent         | -- HTTP + Token -> Decides tool call  |                |                |
|               |                  | Checks policy      |                |                |
|               |                  | Injects secret     | -- Real Auth ->| API Endpoint   |
|               |                  | Redacts responses  |<-- Response ---|                |
|               | <-- Sanitized ---| Logs decision      |                |                |
+---------------+                  +--------------------+                +----------------+
```

### Setting it up locally

```sh
deployments/local/guardfil-local.sh catalog my-app-catalog.yaml       # the app's tools (see tool-catalog.md)
deployments/local/guardfil-local.sh credential my-app-key < key.txt   # the app's secret
deployments/local/guardfil-local.sh gateway my-app-gateway.yaml       # the upstreams (format below)
```

- `catalog` stores the app's catalog and merges it with the agents' tools. Every tool a route names must be in it.
- `credential NAME` reads the secret from stdin (or prompts) into `$GF_HOME/credentials/NAME`, owner-only. Refer to it as `credential_file: /etc/guardfil/credentials.d/NAME`. The names `ui-token`, `metrics-token` and `gateway-agent-token` are reserved.
- `gateway FILE` installs the file as `$GF_HOME/config/gateway.yaml`. The file may hold only an `upstreams:` list, and every `credential_file` it names must already be stored. The script adds the socket (`/run/guardfil/gateway.sock`, which is `$GF_HOME/run/gateway.sock` on the host) and the agent token (`$GF_HOME/credentials/gateway-agent-token`).
- If GuardFil refuses the config (for example, a route names a tool that isn't in the catalog), it stops and the script prints its log. Fix the file and run the command again.
- `gateway --remove` takes the gateway out. `guardfil-local.sh status` shows whether its socket is up.

`run-agent` mounts the socket into the executor at `/run/guardfil/gateway.sock` and sets `GUARDFIL_GATEWAY_SOCKET` and `GUARDFIL_GATEWAY_TOKEN`. The token is the per-agent session token with `--agent NAME`, otherwise the shared agent token. That token only lets the agent ask the gateway; the app credential never enters the executor. A call from inside the executor:

```sh
curl --unix-socket /run/guardfil/gateway.sock \
  -H "Authorization: Bearer $GUARDFIL_GATEWAY_TOKEN" http://localhost/myapp/api/items/7
```

Add policy rules for the app's tools (`tool.invoke` on `myapp.get_item`, ...). Without one, every call is blocked.

### Request flow

1. **Agent Request**: The agent sends an HTTP request to the gateway with the gateway's agent bearer token (`agent_token_file`), or its per-agent session token when it runs with `--agent`.
2. **Tool Mapping**: The gateway matches the request method and path against configured upstream routes. Path parameters (e.g., `{order_id}`) and JSON body properties become tool arguments.
3. **Policy Evaluation**: The request is evaluated against the policy kernel using the mapped tool ID. Amount rules (decimal predicates) can inspect URL parameters or body fields.
4. **Credential Injection**: If permitted, the gateway strips the agent token, loads the real upstream credential from a secure host file, injects the configured header (e.g., `Authorization: Bearer <secret>`), and forwards the request to `base_url`.
5. **Response Sanitization**:
   - The gateway automatically strips and redacts all forms of the injected credential from the response body (raw string, JSON-escaped, and URL-encoded).
   - If the response contains the credential in headers (such as `Location`), the response is blocked.
   - If the tool requires filtering (`effect: sanitize`), the response body passes through content rules before returning to the agent.

---

## Gateway Configuration Format

Outside the local deployment, the block goes in `guardfil.yaml` directly. Give `socket` (a Unix socket path), `address`, or both. `address` must be a literal loopback IP and port, different from the data, management and UI addresses; non-loopback needs `remote_bind_ack: true`. There can be 1–16 upstreams:

```yaml
gateway:
  socket: /run/guardfil/gateway.sock
  agent_token_file: /etc/guardfil/credentials.d/gateway-agent-token
  upstreams:
    - name: stockapp
      base_url: https://api.brokerage.example.com
      credential_file: /etc/guardfil/credentials.d/broker-api-key
      credential_header: Authorization
      credential_prefix: "Bearer "
      routes:
        - method: POST
          path: /api/orders
          tool: stockapp.place_order
        - method: DELETE
          path: /api/orders/{order_id}
          tool: stockapp.cancel_order
        - method: GET
          path: /api/orders/{order_id}
          tool: stockapp.get_order
```

### Upstream Fields

| Field | Type | Description |
| --- | --- | --- |
| `name` | String | Reached by the agent as `http://gateway-address/<name>/...`. |
| `base_url` | URL | `http(s)://host[:port]` with no path. |
| `credential_file` | Path | File containing the upstream API secret (must reside in `credentials_root`). |
| `credential_header`| String | Header name for injected credential (e.g., `Authorization`, `X-API-Key`). |
| `credential_prefix`| String | Optional prefix added to the header value (e.g., `"Bearer "`). |
| `routes` | Array | List of routes mapped to catalog tools. |

### Route Fields

| Field | Type | Description |
| --- | --- | --- |
| `method` | String | HTTP verb (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`). |
| `path` | String | Path pattern. Segments like `{order_id}` are extracted as tool arguments. |
| `tool` | String | Catalog tool ID (must exist in the active tool catalog). |

### Overlap Detection

To prevent ambiguity, GuardFil strictly rejects overlapping routes at startup:
- Two routes cannot share the same HTTP method, segment count, and pattern shape if one route's wildcard (`{param}`) could shadow another's literal segment.
- Every incoming request maps deterministically to exactly one catalog tool.
