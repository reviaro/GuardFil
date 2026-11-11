# GuardFil shadow hook (Claude Code, advisory)

Asks the local GuardFil playground what it would decide for each Claude Code tool call,
without ever blocking or changing the call. The verdicts show up in the playground's
History tab.

- Sends only the tool ID (e.g. `Bash` -> `cc.bash`) and payload `{}`. Arguments, commands,
  paths and file contents never leave Claude Code.
- Always exits 0 and prints nothing to stdout, so Claude Code ignores it for decisions.
- At most about 1 s per tool call (plus Node start-up); if the playground is down it silently does nothing.
- Verdicts are **per tool, not per argument**. `ALLOW` for `cc.read` means "Read is allowed",
  not "this read was safe": reading `~/.ssh` gets the same verdict.
- Tool inputs over 1 MiB (a very large Write) are truncated; the hook then recovers just the
  tool name, so the call still shows up in History.
- It sends to whatever listens on 127.0.0.1:8787 (or `GUARDFIL_SHADOW_PORT`), and only tool
  names, never arguments. Run it only while the playground holds that port. It connects
  directly and never uses a proxy.
- Names not in the table (MCP tools, new tools) are sent unchanged and show up as BLOCK,
  meaning "GuardFil doesn't know this tool":
  - `SCHEMA_INVALID` when the name isn't a valid kernel tool ID (capital letters, over 64
    characters), e.g. `LS`, `ExitPlanMode`, `Skill`;
  - `TOOL_REVISION_UNKNOWN` when it is a valid ID that isn't registered, e.g. most lowercase MCP names.
- If **every** call shows `TOOL_REVISION_UNKNOWN`, the playground is running in demo mode;
  restart it with the `claude-code` tool set.
- The name -> ID table must match the playground's `claude-code` tool set
  (`GET /api/state` -> `tool_map`).

## Use

1. Start the playground with the Claude Code tool set:
   `bash devenv/playground.sh <checkout> 8787 claude-code`
2. In a **scratch project** (not your global settings), create `.claude/settings.local.json`:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         { "matcher": "*", "hooks": [
           { "type": "command", "command": "node <repo>/devenv/guardfil-shadow-hook/hook.js", "timeout": 5 }
         ] }
       ]
     }
   }
   ```
3. Start `claude` in that folder and use it normally. Open http://127.0.0.1:8787, History tab.

Check that the hook's table matches the running playground (no output = identical):

```sh
diff <(node -e 'const s=require("fs").readFileSync(process.argv[1],"utf8");const m=s.match(/TOOL_MAP = \{([^}]*)\}/)[1];for(const [,k,v] of m.matchAll(/(\w+): '"'"'([^'"'"']+)'"'"'/g))console.log(k,v)' hook.js) \
     <(curl -s http://127.0.0.1:8787/api/state | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>JSON.parse(s).tool_map.forEach(e=>console.log(e.name,e.id)))')
```

Debug: `GUARDFIL_SHADOW_DEBUG=1` prints `cc.read -> ALLOW POLICY_ALLOWED` to stderr.
Remove the hook by deleting the `hooks` block (or the file).
