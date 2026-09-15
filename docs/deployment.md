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
   when existing execution IDs must remain queryable.

The sentinel reads no policy or binding and never records command content.
Its executable now shares the server binary covered by the runtime binding;
the install location and hook-registration trust still protect the hook entry.

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
process instances are dead. Source migration does not reset those records.

The accepted Job, network and write-fence limitations remain documented in
[residual risks](residual-risks.md).
