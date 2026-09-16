<!-- BEGIN COMMAND ENTRY PURE BETA -->
<!-- Install: replace this whole marked section in the user-level AGENTS.md. -->

# Command execution policy (pure beta)

The shell channel is closed. All command execution, file reads and progress
waiting go through the `command_entry_exec_server` MCP tools:

- `start_operation` — one business operation. Required: `operation`
  (native/script/python_unittest), `program`, `workdir`. `program` is the
  exact policy KEY listed in this tool's `inputSchema.properties.program.enum`.
  Use an advertised value unchanged: do not guess names, change case, add or
  remove `.exe`, or substitute an executable path. If no matching key is
  listed, report the missing configuration and follow Exceptions below.
  Optional integer
  `run_seconds` (1..1800) and `output_quota_bytes` (1024..16777216 per stream)
  override installed policy defaults (deployment template: 300 seconds and
  1048576 bytes). Omit to use defaults; invalid values are rejected, not
  clamped. There is no record-directory input: keep workspace records.
  `stdin_file` takes an absolute path; never
  inline stdin. `previous_execution` starts a retry only when the bound
  inputs actually changed. Batch files (.cmd/.bat) are never whitelisted —
  run package scripts through the script operation instead, e.g. an npm
  build is `{"operation": "script", "program": "node",
  "language": "javascript",
  "script": "C:\\nvm4w\\nodejs\\node_modules\\npm\\bin\\npm-cli.js",
  "args": ["run", "build"], "workdir": "<project>"}`.
- `status` / `output` — read the execution envelope; page through retained
  redacted output with `offset`/`count` (Unicode characters per stream).
- `cancel` — layered: graceful state machine first, hard kill after the
  grace window.
- `wait` — blocking observation with a policy budget. Rule of thumb: poll
  again after the number of seconds the previous response suggested; a run
  of no-progress observations stops automatic waiting once the policy
  threshold `wait_stop_after_no_progress` (default 12, ≈ 60 s at the 5 s
  poll interval) is reached — stopping is not confirmation of termination.
- `read_text` — stateless range read (`file`, `start_line`, `max_lines`,
  optional `encoding`). Complete coverage metadata is returned; continue
  with `next_start_line`; strict decoding, no silent truncation.
  `total_lines` is null unless the scan reached end of file — check
  `total_lines_known` instead of estimating.

## Identity and retries

Same content while still RUNNING dedups to the same execution id. After a
terminal state the same content is a new intent. An instance whose state is
`unknown` is NOT terminal: a duplicate start is refused (`dedup_blocked`,
the existing id is returned) until `cancel` confirms every known process is
dead (a `cancel-outcome.json` sidecar; the record itself stays `unknown`).
Changing only `run_seconds` or `output_quota_bytes` cannot start another
copy of running/unconfirmed business or alter its existing limits. Query
the returned execution ID; do not resubmit to retrieve output.
`claim_pending_unconfirmed_retry_later` means another server instance holds
an unfinished claim — retry the call later, never improvise a workaround.
A retry requires
`previous_execution` with **identical business content**: the form
(operation, program, args, bound paths) must match the previous attempt's
content fingerprint exactly, otherwise the server rejects with
`previous_execution_content_mismatch` — a retry with edited arguments is a
new intent, not a lineage retry. On top of that, genuinely changed bound
inputs (file contents) are required; merely adding a new input file never
satisfies the retry condition.

## Exceptions

Out-of-policy needs (missing program, unlisted path, larger budget) are
operations events, not raw shell:

1. Identify the missing program from the advertised enum, or the missing
   rule from the server's structured rejection.
2. Ask the user to evaluate it.
3. If approved, the user runs the installed executable's `update-policy`
   command to update and re-pin the binding, then restarts the server.
   Do not attempt to modify policy files yourself.

<!-- END COMMAND ENTRY PURE BETA -->
