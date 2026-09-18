# command-entry · C#

Windows command execution entry for Codex, implemented in C# on .NET 10.
The stdio MCP transport uses the official ModelContextProtocol.Core SDK
(pinned to 2.2.0). Windows x64 Native AOT is the deployment target.

## Layout

- `src/CommandEntry/` — executable project containing only `Program.cs` for entry dispatch.
- `src/CommandEntry.Server/` — MCP server, queries, owner launch, text reads,
  sentinel, policy updates and metrics.
- `src/CommandEntry.Deployment/` — deployment orchestration, policy validation and binding generation.
- `src/CommandEntry.Owner/` — task validation, Job ownership, output capture,
  timeout, cleanup and result publication.
- `src/CommandEntry.Worker/` — Job handshake, business-process launch, stdin
  forwarding and exit-code propagation.
- `src/CommandEntry.Common/` — shared records, paths, file bindings, output
  handling, PowerShell adapter and Windows process primitives.
- `tests/` — xUnit unit, integration and regression tests, fixed reference data and an independent subprocess probe.
- Maintenance runs directly through the executable's C# subcommands.
- `policy.json` — deployment template; review its paths before use.

The executable includes five class libraries through its project references.
Server references Deployment and Common; Deployment, Owner and Worker reference
Common. Existing types retain the `CommandEntry` namespace and internal
visibility; friend assemblies permit the entry point, consuming modules and
regression tests to use them.

Server, Owner and Worker remain separate processes started from the same
`CommandEntry.exe`. Owner still assigns Worker to its Job before the handshake
allows Worker to start business work. Managed builds include five module DLLs;
Native AOT compiles their referenced code into the single executable. Managed
runtime bindings cover all five module DLLs as well as the entry assembly,
apphost, deps and runtimeconfig files.

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
policy key. The test project uses xUnit.net v3 and Microsoft Testing Platform.

~~~text
dotnet build tests/CommandEntry.Tests.csproj --configuration Release
dotnet tests/bin/Release/net10.0-windows/win-x64/CommandEntry.Tests.dll
~~~

Direct assembly execution emits live test progress without extra progress flags.
When using `dotnet test`, add `--output Detailed` for SDK-rendered test results.
[Test suites and automation](docs/testing.md) documents category filters,
TRX reports, interpreter prerequisites and `scripts/test.ps1`.
The automated Managed run covers unit and integration tests; the NativeAot
run publishes, inspects the PE artifact and reruns integration tests.
GitHub Actions runs both modes on Windows.

Implementation details: [C# migration](docs/csharp-migration.md).
Deployment remains a separate user operation: [deployment](docs/deployment.md).
Use `CommandEntry.exe deploy --runtime-root PATH --policy PATH --output NEW-PATH`
to validate the policy and create its runtime binding in one command.

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
