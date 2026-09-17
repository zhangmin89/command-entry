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
   backup of claims, published requests, `serve_root/_prepared/`, `serve_root/publication-index.jsonl`
   and execution records, including their sidecars. Retain the policy mappings needed to resolve each original cwd to
   its record root; copying one root alone does not preserve the execution view.

The sentinel reads no policy or binding and never records command content.
Its executable now shares the server binary covered by the runtime binding;
the install location and hook-registration trust still protect the hook entry.

The first valid start in each server loads the publication index and scans old
requests once. Later starts read appended index entries and check the latest
publications and standalone claims for equivalent business content. Stop all old
server writers before switching: older writers must not publish into the same
`serve_root` concurrently with this version. New journal entries use schema 2:
`prepared` reserves the identity and hashes an immutable request/policy plan
under `_prepared/`; `launch_committed` is flushed only after request, policy and
claim publication, and always before owner launch. Schema 1 remains readable
but cannot establish that launch was never authorized.

Admission compares resolved, case-insensitive declared paths (including artifact
values and expected-version keys), default UTF-8 encoding and empty optional
collections. Program keys, arguments, artifact names and acceptance values keep
their original meaning. Existing fingerprints, IDs and journal entries are not
rewritten. Equivalent running/unconfirmed work returns its original ID; prepared
work resumes from its original plan. A retry can reference an earlier terminal
instance and keeps that instance's lineage and changed-bound-input requirement.
If an old reservation/claim has no request or verifiable prepared plan, another
spelling cannot establish that it is different work: new admission may reject
with `publication_identity_unverifiable` until the original evidence is restored.

The server passes expected publication SHA-256 values from its approved in-memory
request and policy snapshots through the owner environment. The owner requires
both values on this launch route, checks each held file handle before parsing
its bytes, and clears the private environment variables before launching work.
Missing or mismatched proof records a startup failure before creating
business records. Explicit operator `run`/`serve` commands retain their existing
local-input contract; this check does not provide an OS sandbox against arbitrary
same-user process access.

Resubmitting the same business content resumes a schema-2 prepared publication
under the original identity and resource limits. Recovery checks the plan hash,
unchanged policy, claim identity, matching existing publication files and absence
of an execution record. It preserves the plan and does not replace conflicting
evidence. A recorded publication failure remains queryable and does not turn
into an automatic business launch when publication is completed.

Once launch is committed, missing records and unknown process state retain the
existing deduplication block; a crash between commitment and owner launch is
not automatically replayed. Schema-1 interrupted reservations also remain
blocked. Preserve the index, prepared plans, claims and original request/record
evidence; do not edit or rebuild the index to clear a block. Older versions
reject schema 2, so binary rollback alone is not a supported recovery procedure.

`serve_root/_prepared/` contains durable publication evidence. **Do not manually
delete, modify or apply age-based cleanup to these files**, even after commitment
or execution completion. Back them up consistently with the publication index,
claims, published requests and execution records. There is currently no supported
cleanup protocol for prepared plans.

New-business admission reads and verifies the SHA-256 of the snapshot referenced
by each fingerprint's current schema-2 index entry; it does not read every
historical prepared plan. If a referenced snapshot is missing or changed,
admission fails closed across the same `serve_root`, including unrelated new
business. This does not terminate already running processes. Preserve the
remaining evidence for recovery; do not remove or rewrite index entries to
bypass the failure.

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

Program execution and the test fixtures use only the `programs` mappings,
including `programs.python` and `programs.powershell`. The duplicate top-level
`python` and `powershell` fields are no longer used or required. Remove them
from the reviewed policy candidate when switching to this C# release, and
re-pin the changed policy through the maintenance flow above. Preserve older
policy snapshots with their original bytes and bindings.

The MCP `tools/list` response publishes all configured program keys in
`start_operation.inputSchema.properties.program.enum`, preserving their exact
case and suffixes. This list comes from the same loaded policy snapshot used
to validate starts; it does not re-read the policy file. After updating and
re-pinning the installed policy, restart the server and refresh the client's
tool definitions. The AGENTS template refers to this enum instead of maintaining
a second list of keys. Server-side program validation remains authoritative.

`claim_timeout_seconds` and `programs.*.wait_category` remain legacy fields.
They do not configure claim expiry or active MCP wait behavior.
Current waiting uses `wait_budget_seconds`,
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

## Rejected-call audit

Handled tool-call failures at the execution-server boundary are recorded in
`<log_root>/rejections/<audit_id>.json`. The default `log_root` is `logs` beside
the policy. This includes validation failures before an execution ID or request
directory exists. Each refusal gets a new audit ID; it is not an execution ID
and cannot be passed to `status`, `output` or `cancel`.

The MCP error retains its original `error` and `reason`, and adds
`rejection_audit` with `audit_id`, `recorded` and, on success, `record_file`.
The record is flushed and published before `recorded: true` is returned.
If writing fails, `recorded: false` and a classified `storage_error` explicitly
report the gap; the original refusal remains unchanged. The existing
`server-events.jsonl` also receives the audit ID, context and `audit_recorded`,
but that shared event log remains best effort.

Each record includes the time, tool, error category, reason and allowlisted
context. Starts retain `operation`, `program`, `workdir`, `language`, `script`
and `previous_execution` when supplied. Other tools retain `execution_id` and
`file` when supplied. Missing fields stay absent; null and non-string values
are represented by their JSON type, without their contents. String metadata
uses the existing credential redaction rules, suppresses private-key fields
and is limited to 1024 Unicode scalars per field. `redacted_fields` and
`truncated_fields` identify changes. Arguments, stdin, parameter-file contents,
script contents and unknown request fields are not copied into this audit.
It is diagnostic metadata, not a replayable copy of the request.

To investigate `program_not_configured`, find the returned audit ID or filter
the rejection records by `reason`, then inspect `context.program` and
`context.workdir`. Preserve these records with the event log. They have no
automatic retention or cleanup. Failures before dispatch, such as malformed
MCP protocol messages or server startup failures, are outside this audit;
rejections after execution publication continue to use the execution record.
The change does not reconstruct older refusals whose metadata was never saved.

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
