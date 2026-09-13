<!-- BEGIN COMMAND ENTRY PURE BETA -->
<!-- Install: replace this whole marked section in the user-level AGENTS.md. -->

# Command execution policy (pure beta)

The shell channel is closed. All command execution, file reads and progress
waiting go through the `command_entry_exec_server` MCP tools:

- `start_operation` — one business operation. Required: `operation`
  (native/script/python_unittest), `program`, `workdir`. No timeout field:
  budgets come from policy. `stdin_file` takes an absolute path; never
  inline stdin. `previous_execution` starts a retry only when the bound
  inputs actually changed.
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

## Identity and retries

Same content while still RUNNING dedups to the same execution id. After a
terminal state the same content is a new intent. A retry requires
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

1. The server returns a structured rejection naming the missing rule.
2. Ask the user to evaluate it.
3. If approved, the user runs `update-policy.ps1`, re-pins the binding and
   restarts the server. Do not attempt to modify policy files yourself.

<!-- END COMMAND ENTRY PURE BETA -->
