# command-entry · pure beta

Windows command execution entry for Codex. Zero third-party dependencies:
Python 3.14 + PowerShell 7 only. Development plan: `pure-beta-dev-plan.md`
(v4, 2026-09-13). Baseline: V2 candidate `2.0.0-candidate.3-closeout.2`.

## Layout

- `entry_v2.py` — execution owner; owns the Windows Job Object and the full
  V2 `run()` lifecycle. CLI for operations debugging, plus `serve` mode for
  being spawned by the exec server (`--record-dir`, no console output).
- `worker_v2.py` — business process host; starts only after the owner's
  Job handshake. Calling convention only, not a security boundary.
- `common.py` — request shaping, content-derived identities, atomic writes.
- `windows_state.py` — process-instance observation, deny-write handles,
  Job-environment probes and spawn flag selection.
- `output_store.py` — bounded, redacted output retention.
- `wait_state.py` / `adapter.py` — observation layer and wait decisions.
- `server.py` — pure-beta exec server (stdio MCP, stateless): schema
  forms, policy validation, envelope building, detached entry spawning and
  read-only queries (start_operation/status/output/cancel/wait/read_text).
- `hook_v2.py` — **deny-all sentinel** (stage 3): every shell/exec_command
  call is denied with a pointer to the exec server. No shape validation,
  no binding reads, no command content in records.
- `v1_support.py` / `runtime.json` — retained as the Job/syntax library for
  entry_v2; the V1 hook/canonical routes are retired and inert.
- `policy.json` — deployment policy template.
- `tests/` — unittest suites; `scripts/` — stage smoke tests.

## stdin_file (restored, plan stage 1)

`stdin_file` is an absolute path to a file wired into the business child's
stdin. It is content-bound like every declared input:

- Merely adding a previously unbound input file never satisfies retry
  conditions (`verified_changed` requires modified content of already-bound
  files).
- Modifying the content of any bound file — including `stdin_file` — counts
  as a verified change and is a legitimate retry condition.

## read_text semantics (plan stage 2, A1 full read)

Stateless range read; the file itself is the storage, no record directory is
created. Encoding: BOM sniff, explicit `encoding` parameter (highest
priority), then utf-8 **strict**; decode failure returns a structured error,
never silent `\ufffd`. Offset semantics: 1-based line range with O(offset)
scan. "Complete" means a single consistent `open()` snapshot per call; reads
spanning concurrent in-place modifications are not globally consistent.
Single lines exceeding the quota return an explicit error, not truncation.

## Execution host decision (plan 0.1)

The exec server spawns `entry_v2.py serve` detached. The entry child owns
the Job and survives server crashes; `windows_state.spawn_creation_flags()`
probes the server's Job environment and reports `orphan_guaranteed` so the
policy key `require_orphan_guarantee` can fail closed when breakaway is not
available.

## Stage 3: channel convergence

The shell channel is closed: the sentinel hook denies every
exec_command/shell call and points to the exec server tools. Approval is
differentiated (MCP server pre-trusted once; shell untrusted).
`binding.json` is re-pinned as the integrity anchor for the server file set
+ policy only (built by `scripts/build_binding.py`); the hook no longer
consumes it. Legacy routes retired: prepare_mcp and the V2 launch grammar
are gone; the entry CLI remains an operations debug entry. Deployment:
`docs/deployment.md`; agent-facing policy text: `docs/AGENTS-template.md`.
