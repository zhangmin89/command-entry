# Pure-beta deployment guide (stage 3)

All server, policy, binding, log and record roots live **outside the model
workspace**. The cage keys never enter the cage.

## 1. Install layout (outside workspace)

```text
<install-root>            e.g. C:\Users\<user>\.codex\command-entry
├── server.py, common.py, entry_v2.py, worker_v2.py, windows_state.py,
│   wait_state.py, adapter.py, output_store.py, v1_support.py,
│   invoke.ps1, check_python.py, check_powershell.ps1
├── hook_v2.py            deny-all sentinel (referenced by hooks.json below)
├── policy.json           deployed policy (working_roots narrowed per stage 4)
├── binding.json          integrity anchor (built by scripts/build_binding.py)
├── serve-input\          serve_root: <execution_id>\{request.json, policy.json}
├── hook-records\        sentinel decision envelopes (no command content)
└── logs\                 server startup job-environment probe
```

## 2. Codex user configuration

### MCP server registration (`~/.codex/config.toml`)

```toml
[mcp_servers.command_entry_exec_server]
command = 'C:\Users\<user>\AppData\Local\Python\pythoncore-3.14-64\python.exe'
args = ['-X', 'utf8', '<install-root>\server.py',
        '--policy', '<install-root>\policy.json',
        '--binding', '<install-root>\binding.json']
```

Both flags exist: `--policy` (required) loads the policy, `--binding`
(optional) enables the startup self-check against the integrity anchor.
Writing `--policy` twice makes argparse take the LAST value (binding.json)
and the server exits with `policy_version_required` — this exact typo was
observed in the field.

Verify against the Codex version's config documentation before deploying;
the exact table name and fields follow the official user configuration page.

### Hook registration (`~/.codex/hooks.json`)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|shell|exec_command)$",
        "hooks": [
          {
            "type": "command",
            "command": "C:\\Users\\<user>\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe -X utf8 <install-root>\\hook_v2.py --records <install-root>\\hook-records"
          }
        ]
      }
    ]
  }
}
```

The matcher and `SHELL_TOOLS` in hook_v2.py must cover the actual tool
names the host emits (observed: Bash, shell, exec_command). An
uncovered name leaves the shell channel silently open: verify on day one by
triggering one raw shell call and confirming a new sentinel record with
`decision: "deny"` appears in hook-records. If the host introduces a new
shell tool name, add it in BOTH places.

**Never add `exec` to the deny set**: on Codex 0.154.0-alpha.x it is the
code-mode JS cell AND the only channel for MCP tool calls — denying it
self-locks the exec server. (Field evidence: 961 historical records, all
tool_name=Bash; no `exec` event ever reached the hook.)

**Diagnostic when zero records appear** (hook loaded? real tool names?):
temporarily set the matcher to `".*"`, restart, and let the agent do any
work. The sentinel records EVERY PreToolUse event it receives, including
passthrough, with the true `tool_name` in the record. Records appearing →
the hook is loaded; read the real tool names from the records and finalize
the matcher from them. Still zero records → the hook is not loaded at all:
check `/hooks` trust state and restart. Revert to the final matcher
afterwards.

A new hook definition must be reviewed and trusted in Codex CLI `/hooks`;
already-open desktop/IDE sessions must be restarted before verification.
The sentinel denies every shell/exec_command call and points to the exec
server tools. It reads no binding and never stores command content.

### Approval differentiation

- MCP server `command_entry_exec_server`: pre-trust once per session startup.
- Shell channel: set to untrusted (every call asks).

The concrete config keys depend on the Codex version's approval model;
apply them from the official config documentation at deploy time. The
effect we require: server tool calls flow without per-call prompts, raw
shell always prompts on top of the hook deny.

## 3. Same-day activation order (plan 0.5)

read_roots was already implemented with the server (stage 2). On switch day:

1. Deploy policy with explicit `read_roots` (default = working_roots set).
2. Register the server + hook, trust the hook in `/hooks`.
3. Enable pre-trust for the server; set shell to untrusted.
4. Restart Codex; verify: raw shell -> deny + pointer; read outside
   read_roots -> structured rejection.

## 4. Rollback

Replace the hook block in `~/.codex/hooks.json` with the retained V2
checker (keep a copy of the previous block before switching), remove the
MCP server entry, restore the previous AGENTS.md section, restart Codex.
Execution records are plain directories; nothing else to undo.

**Housekeeping rule**: any cleanup of the install root must FIRST archive
`hooks.json` (e.g. `hooks.json.backup-v2-<date>` next to it). A field
cleanup once deleted the only copy of the previous hook block; rollback
then means hand-rewriting the block from the archived copy.

## 5. Legacy routes after stage 3

- `prepare_mcp.py` and the V2 launch grammar: retired; the checker route is
  gone from the hook (deny-all sentinel).
- `entry_v2.py` CLI (`run`/`location`/`serve`): kept as an operations debug
  entry; it is not a model channel.
- `v1_support.py` stays as the Job/syntax library used by entry_v2; its
  V1 hook/canonical helpers have no callers and are inert.
