# Tool Catalog

A tool catalog defines the schema and argument contracts for application and agent tools. GuardFil uses the catalog (`internal/approval/catalog.go`) to validate tool calls before the policy engine evaluates them.

Calls that pass invalid arguments, omit required parameters, or exceed defined bounds are rejected immediately with fail-closed errors before reaching the tool.

---

## Catalog Document Format

A tool catalog is written in YAML and stored at `$GF_HOME/config/tool-catalog.yaml`:

```yaml
catalog_version: 1
tools:
  - id: stockapp.place_order
    description: Place an equity buy or sell order
    arguments:
      symbol:
        type: string
        required: true
        max_length: 12
      side:
        type: string
        required: true
        enum: [buy, sell]
      quantity:
        type: integer
        required: true
        min: "1"
        max: "100000"
      limit_price:
        type: decimal
        min: "0.01"
        max: "50000.00"
```

### Top-Level Fields

| Field | Type | Constraint | Description |
| --- | --- | --- | --- |
| `catalog_version` | Integer | Must be `1` | Format specification version. |
| `tools` | Array | 1 to 256 tools | List of tool specifications. Maximum file size is 256 KiB. |

---

## Tool Specification

Each entry in `tools` defines:
- `id`: Unique identifier formatted as `<server>.<tool>` (`codex.exec_command` and the internal canary tool are reserved) (e.g., `claude.read`, `notes.write_note`, `stockapp.place_order`).
  - Matches regex `^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{1,64}$`.
- `description`: Optional text describing the tool's function.
- `arguments`: Map of argument names (lower_snake_case: a lowercase letter, then lowercase letters, digits or `_`; 1–64 characters) to argument specifications. Up to 32 arguments per tool. A call with an argument the catalog does not list is refused (`SCHEMA_INVALID`).

---

## Argument Specifications (`ArgSpec`)

| Field | Type | Applicable To | Description |
| --- | --- | --- | --- |
| `type` | String | All | Data type: `string`, `integer`, `decimal`, or `boolean`. |
| `required` | Boolean | All | If `true`, calls lacking this argument are rejected (`SCHEMA_INVALID`). |
| `enum` | Array | `string` | Allowed list of string values (up to 64 items). Unmatched values trigger `SCHEMA_INVALID`. |
| `max_length` | Integer | `string` | Maximum length in characters (default 1024, at most 4096). Longer values are refused with `LIMIT_EXCEEDED`. |
| `min` | String | `integer`, `decimal` | Minimum allowed value as a quoted decimal literal (e.g., `"0.00"`). |
| `max` | String | `integer`, `decimal` | Maximum allowed value as a quoted decimal literal. A value outside `min`/`max` is refused with `LIMIT_EXCEEDED`. |

> [!IMPORTANT]
> Always bound numeric inputs with `min` and `max` when using amount rules (decimal predicates). Without a minimum bound, a negative price argument could cause a multiplication predicate (e.g. `quantity * limit_price`) to compute a negative total, bypassing upper spending limits.

---

## Installing Catalogs

When you run `guardfil-local.sh init`, GuardFil installs the default catalog from `deployments/local/executor-catalog.yaml`.

To install or update a custom application catalog:

```sh
deployments/local/guardfil-local.sh catalog /path/to/my-catalog.yaml
```

This copies the file to `$GF_HOME/config/tool-catalog.yaml` and reloads the GuardFil service container.

---

## The Default Executor Catalog

GuardFil includes default definitions for Claude Code and the Python example agent in `deployments/local/executor-catalog.yaml`:

### Claude Code Built-in Tools
Claude Code's tools are projected into GuardFil as `claude.<name>`:
- `claude.read`: Takes `file_path` (string, max 1024).
- `claude.glob`: Takes `pattern` (string) and `path` (string).
- `claude.grep`: Takes `pattern` (string) and `path` (string).
- `claude.ls`: Takes `path` (string).
- `claude.webfetch`: Takes `url` (string, max 2048).
- `claude.websearch`: Takes `query` (string, max 1024).
- `claude.task` / `claude.agent`: Takes `description` and `subagent_type`.
- `claude.todowrite`: Empty arguments.
- `claude.toolsearch`: Empty arguments.

> [!NOTE]
> `Bash` and file-modification tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) bypass the catalog because they are converted directly into kernel `shell` and `file_write` operations.

### Example Notes Tools
Used by the Python demo agent (`python_agent_example.py`):
- `notes.list_notes`: Lists saved notes (no arguments).
- `notes.read_note`: Reads note by `name` (required, max 64).
- `notes.write_note`: Saves note with `name` (required, max 64) and `text` (required, max 4000).
