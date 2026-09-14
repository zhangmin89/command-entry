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
- `v1_support.py` — the Job/syntax/Capture/redact primitives used by
  entry_v2. Everything else from V1 (request validation, canonical command,
  hook, worker, CLI, and the runtime.json they read) was removed as dead
  code in the pure-beta cleanup; no callers existed outside V1 routes.
- `adapter.py` — observation comparison (`progress`) and the V2 wait
  decision descriptor. The V2 host-envelope decoder was removed (dead).
- `policy.json` — deployment policy template.
- `tests/` — unittest suites; `scripts/` — stage smoke tests.

## Per-call execution limits

`start_operation` accepts two optional integer fields for native programs,
scripts and Python unittest operations:

| Field | Deployment template default | Inclusive per-call range |
| --- | --- | --- |
| `run_seconds` | 300 seconds (5 minutes) | 1..1800 seconds (30 minutes) |
| `output_quota_bytes` | 1048576 bytes (1 MiB), each stream | 1024..16777216 bytes (16 MiB), each stream |

Omitting a field uses the installed policy's value. Explicit null, booleans,
strings, fractional values and out-of-range values are rejected before the
server claims or starts an execution. Values are never silently clamped.
The server saves the effective values in the request; the entry validates
them again and reports `run_budget_seconds` and `output_quota_bytes` in
status. This does not change approval, sandbox, program or path rules.

Example additions to a normal start form:
`"run_seconds": 900, "output_quota_bytes": 4194304`.

These options do not participate in the business dedup fingerprint. While
the same business is running or unconfirmed, changing resource values does
not launch it again or resize it: the existing execution ID is returned.
Read its status/output. After confirmed termination, a new explicit intent
can use different values. Lineage retry still requires changed bound inputs;
changing a budget alone does not satisfy that rule.

There is no per-call record-directory field. The template continues to use
`<workdir>/.codex-command-records`; no additional location is installed.
Wait/poll and cleanup limits are separate and unchanged. Output paging reads
retained data only; it does not enlarge a quota or re-execute business.
Existing redaction, decoding-loss reporting and the 16384-character
single-line capture guard remain: a larger quota does not promise lossless
output for every possible line.

This source change does not update an installed policy or binding. For the
new defaults, the user must update each execution operation's `run_seconds`
to 300 and `output_quota_bytes` to 1048576 in the deployed policy, preserving
all unrelated fields, then deploy the reviewed code and re-pin the binding.
Do not replace a deployed policy with the repository template (which has
placeholder working roots). Reload the server to expose the new MCP schema.

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

Deployed reality (2026-09-13): Codex launches MCP servers inside a Job that
does not permit breakaway, so `orphan_guaranteed` reports `false` — a server
or session crash can take in-flight business processes down with it. This is
an availability risk, not a security gap, and is accepted:
`require_orphan_guarantee` stays `false` (setting it `true` would reject
every start, since the host's Job is not user-configurable). The startup
probe logs the value on every server start.

## Stage 3: channel convergence

The shell channel is closed: the sentinel hook denies every
exec_command/shell call and points to the exec server tools. Approval is
differentiated (MCP server pre-trusted once; shell untrusted).
`binding.json` is re-pinned as the integrity anchor for the server file set
+ policy only (built by `scripts/build_binding.py`); the hook no longer
consumes it. Legacy routes retired: prepare_mcp and the V2 launch grammar
are gone; the entry CLI remains an operations debug entry. Deployment:
`docs/deployment.md`; agent-facing policy text: `docs/AGENTS-template.md`.
