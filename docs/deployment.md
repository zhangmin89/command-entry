# C# deployment guide

Deployment is separate from source migration. The user installs the reviewed
release, updates client registration and re-pins the policy. Keep the installed
runtime and its policy outside the agent's writable working roots.

## Release layout

~~~text
<install-root>/
  CommandEntry.exe
  CommandEntry.pdb
  policy.json
  binding.json
  serve-input/
  hook-records/
  logs/
~~~

The executable contains the MCP server, owner/worker, sentinel and maintenance
commands. It needs no Python interpreter or installed .NET runtime for those
roles. A configured interpreter is required when executing work in that
language. Fixed PowerShell adapters are embedded in the executable and covered
by its binding. The runtime launches interpreters through `Process.Start`;
it has no PowerShell SDK dependency.

## Prepare and switch

1. Build and test a fresh native release using
   [the verification instructions](csharp-migration.md).
2. Copy it to a separate reviewed release directory. Retain the old release.
3. Preserve the installed policy's program mappings, roots, budgets and record
   locations. The repository policy is a template with placeholder roots.
4. Generate a binding in a new file with absolute paths:

~~~text
CommandEntry.exe build-binding --runtime-root <install-root> --policy <policy-path> --output <new-binding-path>
~~~

5. Register the MCP executable as `<install-root>/CommandEntry.exe` with
   argument entries `--policy`, the reviewed policy path, `--binding`, and
   the new binding path.
6. Register the hook using the same executable's `sentinel` command:

~~~text
CommandEntry.exe sentinel --records <hook-records-path>
~~~

   The command-based hook must quote absolute executable and record paths when
   needed. Keep the existing `^(Bash|shell|exec_command)$` matcher.
   `exec` remains outside that matcher because it is the MCP code-mode cell.
7. Stop creating new work through the old server, restart/re-trust the changed
   client registration, then verify tools/list, a harmless execution, and its
   status/output. Verify a shell hook event produces a deny decision and an
   envelope-only sentinel record.
8. Keep `serve_root` and `record_root` aligned with the previous installation
   when existing execution IDs must remain queryable. Preserve a consistent
   backup of claims, published requests, `serve_root/publication-index.jsonl`
   and execution records, including their sidecars. Retain the policy mappings needed to resolve each original cwd to
   its record root; copying one root alone does not preserve the execution view.

The sentinel reads no policy or binding and never records command content.
Its executable now shares the server binary covered by the runtime binding;
the install location and hook-registration trust still protect the hook entry.

The first valid start in each server loads the publication index and scans old
requests once. Later starts read only appended index entries. Stop all old
server writers before switching: versions without this index must not publish
into the same `serve_root` concurrently with this version. Reservations are
flushed before publication or owner launch; an interrupted reservation can
leave a counter gap and block the affected intent pending manual recovery.
Do not delete or rebuild the index to clear that block. Preserve it with the
claims and original request/record evidence. A rollback to an older writer
requires reconciling these reservations first; merely restoring the old binary
does not make unpublished reservations safe to ignore.

## Policy maintenance

Use the native commands:

~~~text
CommandEntry.exe update-policy --repo-root <install-root> --policy <reviewed-candidate>
CommandEntry.exe update-policy --repo-root <install-root> --add-program NAME --program-path PATH --kind native
~~~

The updater validates the candidate before changes, archives the old policy
and binding under `policy-backups`, commits the candidate, and re-pins it.
A mid-flight failure restores the old pair. Passing the live policy as the
candidate performs validation and re-pinning without changing its bytes.

Create bindings with `CommandEntry.exe build-binding --runtime-root PATH
--policy PATH --output NEW-PATH`. The former PowerShell maintenance wrappers
have been removed; update automation to call the native subcommands. Python
and PowerShell interpreters are not needed for maintenance.

Program execution uses the `programs` mappings. The top-level `python` and
`powershell` fields remain for legacy template/test compatibility;
`claim_timeout_seconds` and `programs.*.wait_category` are also legacy fields.
They do not configure interpreter execution, claim expiry or active MCP wait
behavior. Current waiting uses `wait_budget_seconds`,
`wait_poll_interval_seconds` and `wait_stop_after_no_progress`.

The `metrics` command reports `complete`, `hook.unparsed_records` and
`server.unparsed_event_lines`. Malformed JSON or non-object records are
counted without changing their files. Decision totals and rates use only
parsed records; `complete: false` means the report has missing input data.
Filesystem access and text-decoding failures still surface as errors; the
partial-report behavior covers JSON parsing/shape failures after decoding.

The fixed publication-maintenance command defaults to preview and requires
stopped C# runtime processes before applying. It refuses changed claims,
occupied destinations, unexpected record contents and invalid bindings.
Its three reviewed records are moved intact with a manifest; it is not a
general record-cleanup command.

## Rollback and retained evidence

Retain the old runtime, policy/binding pair and client registration before
switching. A rollback restores that reviewed set and restarts the client.
Do not mix an old binding with new executable bytes.

Keep execution records. An unknown execution remains unconfirmed even if its
server disappeared; use its existing cancellation flow to confirm the known
process instances are dead. If original records are missing, preserve claims
and requests for manual recovery; cancellation cannot establish process death
from absent evidence. Do not infer claim expiry from directory age. Source
migration does not reset those records or deploy a recovery command.

If a claim remains but its published request is missing, startup reports
`claim_publication_missing`. If publication history and claims are lost but a
derived execution ID already has a record, it reports
`execution_identity_already_recorded`. If publication remains but the result
is missing without a valid startup-failure sidecar, duplicate work stays
blocked. Restoring file presence alone does not establish process death or
validate the association between the request, bound inputs and outcome.

Mutable snapshot replacement uses Windows `FileRenameInfoEx` with replace and
POSIX semantics. Validate the held-reader regression on the destination OS
and filesystem before deployment. Unsupported information classes, filesystem
restrictions and other replacement errors surface as failures; error 87 is
not silently treated as proof that a compatibility fallback is appropriate.

The accepted Job, network and write-fence limitations remain documented in
[residual risks](residual-risks.md).
