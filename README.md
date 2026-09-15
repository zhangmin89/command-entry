# command-entry · C#

Windows command execution entry for Codex, implemented in C# on .NET 10.
The stdio MCP transport uses the official ModelContextProtocol.Core SDK
(pinned to 2.2.0). Windows x64 Native AOT is the deployment target.

## Layout

- `src/CommandEntry/` — MCP server, detached owner/worker, policy checks,
  process identity, output retention, text reads, sentinel and maintenance.
- `tests/` — C# executable regression suite and fixed JSON reference data.
- `PowerShellAdapter.cs` — fixed PowerShell invocation adapter embedded in the executable.
- Maintenance runs directly through the executable's C# subcommands.
- `policy.json` — deployment template; review its paths before use.

Project implementation, test assertions, policy validation, binding generation
and metrics no longer depend on Python source files. User Python work remains
supported through the configured interpreter. C# tests generate small Python
inputs specifically to verify that user-facing capability.

## Interpreter processes

The native executable uses `Process.Start` to run the configured `pwsh.exe`,
`node.exe` and `python.exe`. It does not host language engines or reference the
PowerShell SDK. Process isolation, Job ownership, stdin forwarding, output
capture, cancellation and exit-code handling retain the existing worker flow.

PowerShell parameter binding uses a fixed embedded script string passed through
`-EncodedCommand`. File paths travel separately in
child-process environment variables; argument values remain in bound JSON
files. The adapter removes its private variable before executing user work.
The adapter still executes as PowerShell code. No adapter `.ps1` files are
created or needed in the published release.

PowerShell, Node and Python scripts execute without a separate syntax-check
process. Interpreter diagnostics and exit codes are captured during execution.
Bash retains its `-n` precheck before the business process starts. Request,
path, file-binding, parameter and retry validation remain in place.

## Build and test

Run through the approved command-entry MCP tools, using the native `dotnet`
policy key. Replace `<repo-root>` with the absolute repository directory.

~~~text
dotnet build tests/CommandEntry.Tests.csproj --configuration Release --verbosity minimal
dotnet tests/bin/Release/net10.0-windows/win-x64/CommandEntry.Tests.dll --root <repo-root> --server <repo-root>/src/CommandEntry/bin/Release/net10.0-windows/win-x64/CommandEntry.exe
~~~

The dependency-free executable runner reports every test group, continues to
the remaining groups after a failure, and returns a nonzero exit code if any
group failed. Building the project
does not execute its tests. Full script-contract tests also require the
PowerShell, Node and Python interpreters configured in the template.

Native publishing, artifact checks and the same suite against Native AOT:
[C# migration and verification](docs/csharp-migration.md).
Deployment remains a separate user operation: [deployment](docs/deployment.md).

## Execution contract

The six MCP tools remain `start_operation`, `status`, `output`, `cancel`,
`wait` and `read_text`. See [agent instructions](docs/AGENTS-template.md).

| Per-call option | Template default | Accepted range |
| --- | --- | --- |
| run_seconds | 300 | 1..1800 |
| output_quota_bytes | 1048576 per stream | 1024..16777216 |

Limits must be integers; null, booleans, fractions and out-of-range values
are rejected. Values are recorded in the execution envelope. Changing only
limits does not create another copy of running or unconfirmed work.

- Declare an absolute `stdin_file` to supply binary stdin. Its content is bound
  like other input files.
- Declare source inputs with `input_paths` when a later retry needs to prove
  they changed. A retry preserves business content and requires changes to
  previously bound files; newly added files alone do not qualify.
- Queries use the existing execution ID. Confirmed terminal work can be
  started as a new intent. Unknown work remains blocked until cancellation
  confirms all known process instances are dead. Queries reject `cwd`; their
  record location comes from the original request.
- Missing historical evidence never proves termination. Missing `result.json`
  requires manual recovery of the original evidence; `wait` returns
  `unconfirmed` without creating evidence, even if its directory exists. A
  validated startup-failure sidecar with no result instead reports
  `start_failed`; cancellation reports `already_terminal` and a new intent
  is allowed. An existing result always takes precedence. Claims whose request
  is missing are preserved and rejected with `claim_publication_missing`.
  A derived ID that already has a record is rejected with
  `execution_identity_already_recorded`, preventing reuse after history loss.
- Output is drained after its retention quota is exhausted. Only bounded,
  redacted text is retained. Paging offsets count Unicode code points.
  Scheme-qualified URL userinfo, Bearer values and supported token formats
  are redacted in output and errors even after non-ASCII prefixes. ASCII
  identifier boundaries (letters, digits and underscore) remain respected.
- `read_text` uses strict decoding and explicit coverage metadata.
  `total_lines` is unknown until scanning reaches EOF. Oversized requested
  lines produce errors; continuation uses `next_start_line`.
- `wait` distinguishes completion, budget exhaustion and stopping automatic
  waiting without evidence of progress. Stopping does not imply termination.
- Process exit success and requested artifact acceptance are separate results.

The migration preserves the policy-level write fence, serial stdio behavior
and host-dependent Job limitations described in
[residual risks](docs/residual-risks.md).

Windows environment names are merged case-insensitively before owner startup.
For conflicting spellings, the ordinal-first spelling supplies the value,
independent of enumeration order; the internal owner-input variable is always
set by the launcher. Other inherited variables remain available to children.
