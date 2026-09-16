# C# migration and verification

## Implementation

The server, owner, worker, sentinel, policy maintenance and metrics are C#.
Old Python implementations and unittest modules have been replaced. Tests
execute the real MCP protocol and processes through xUnit and Microsoft Testing Platform.

`CommandEntry` contains only `Program.cs` and references the Server, Owner,
Worker and Common class libraries. Each role library references only Common;
maintenance commands belong to Server. The three process roles still launch
the same executable and retain their existing arguments, environment handoff,
Job handshake and execution records. The class-library split does not merge
their processes. Native AOT compiles the libraries into the executable.

The native executable continues to launch configured interpreters with
`Process.Start`; no PowerShell SDK is referenced by the runtime or tests.
The PowerShell invocation adapter is a fixed C# string constant, executed by that
interpreter via `-EncodedCommand`. User paths are separate environment data;
structured parameters stay in bound JSON files. Full parameter-name checks
and exit-code propagation are retained. Maintenance
commands are called directly in C#. The old five `.ps1` entry files and their
project Content entries have been removed.

The `python_unittest` operation and Python script execution remain public
capabilities. PowerShell, Node and Python use the configured interpreter for
execution without a separate syntax-check process. Syntax failures retain the
interpreter's stderr and nonzero exit code as an `exited` execution, rather
than a pre-execution `rejected` result. Their `syntax.status` is
`not_applicable`, indicating that no precheck applies; it does not mean syntax
validation passed. Bash retains `-n` and rejects failed prechecks before
starting the business process. Request, path, file-binding, parameter and retry
validation remain unchanged.

## Regression coverage

| Replaced Python area | C# coverage |
| --- | --- |
| V2 regression, stdin, execution options, no-window probes | ContractTests, ScriptTests |
| MCP server, publication, claims, cancellation, waiting | LifecycleTests |
| Policy validation, binding, updates, metrics, sentinel | MaintenanceTests |
| Publication maintenance preview, blockers, backup, quarantine | PublicationMaintenanceTests |
| Numeric and text parity | ContractTests + Fixtures/reference.json |
| C# conformance cleanup/write failures and short reads | CleanupTests |
| Environment collisions, Unicode-prefix redaction, JSON replacement/cleanup, missing history, invalid failure records, startup-failure queries, owner-exit snapshots, metrics completeness and query fields | AuditRegressionTests (17 independent facts) |
| Interpreter subprocess arguments, binary stdin, cwd, streams and exit codes | ScriptTests.ExternalInterpretersPreserveProcessContract |
| Embedded PowerShell diagnostics and special-character paths | ScriptTests.EmbeddedPowerShellErrorsRemainTextAndInvalidSourceDoesNotExecute |
| Syntax errors from actual interpreter execution | ScriptTests.RuntimeSyntaxErrorsAreRetainedAndBatchNeverRuns |
| Interpreter startup during planning applies only to Bash | ScriptTests.OnlyBashPlanningStartsAnInterpreter |
| Native artifact validation | RuntimeCommands.InspectAot + the integration suite |

The fixed reference JSON was exported from the original implementation before
its removal: 281 finite double values (seed 20260915), five prepared requests,
45 text-read cases and redaction examples. Tests use these independent expected
values directly; they do not execute a reference implementation.
The legacy query/read shapes in `RequestShape` remain for these frozen
compatibility fixtures. Active MCP tools validate their own fields; query
tools accept an execution ID without an ignored `cwd` field.

The suite retains execution evidence under
`.codex-command-records/csharp-test-*`. Synthetic records used for maintenance
tests are also confined to those test directories.

The former `.smoke` checks are covered by xUnit tests:

| Former smoke check | C# assertion coverage |
| --- | --- |
| Initialize, server identity, tool list, text read, PowerShell start/output/status/wait | SmokeTests.EndToEndSessionClosesCleanly |
| Repeat the same request after completion | SmokeTests.EndToEndSessionClosesCleanly: new execution ID and successful output |
| Deduplicate a request while still running | ContractTests.TimeoutAndDuplicateOptionsKeepOneExecution |
| Reject an unknown start field before creating execution records | SmokeTests.UnknownStartFieldIsRejectedBeforePublication |
| Query an absent execution ID, then continue using the session | SmokeTests.MissingExecutionStatusIsRejectedAndSessionRemainsUsable |
| Close stdin, exit normally, and retain server events | SmokeTests.EndToEndSessionClosesCleanly |

These tests assert outcomes that the old scripts only printed. The clean-exit
assertion runs before fixture disposal; forced teardown cannot make it pass.
The tests do not read or execute `.smoke` files. Historical inputs, request
records and logs in that directory remain preserved.

Two equivalence defects exposed during migration were repaired:

- Plain large-double output is converted to scientific notation by moving
  existing round-trip digits, avoiding rounding by a second numeric format.
- Missing file/path exceptions retain the `FileNotFoundError` classification.

Canonical fingerprints involving affected large doubles can consequently
differ from earlier faulty C# output. Existing execution records are not
rewritten by this source migration.

## Build and run the managed suite

Requirements: Windows x64, .NET SDK 10, and PowerShell, Node and Python on
PATH for interpreter tests. Use the approved command-entry MCP tools.

~~~text
dotnet test --project tests/CommandEntry.Tests.csproj --configuration Release
~~~

Tests use xUnit assertions and independently report facts and theory rows.
See [test suites and automation](testing.md) for filters, TRX reporting and
the checked PowerShell automation entry.

The audit checks hold a share-delete reader open throughout a real `Save`,
assert old/new snapshot contents, and separately verify that bound inputs and
exclusive locks still block replacement. They also hold an execution result
open while the selected server binary publishes its terminal state, and check
Unicode-prefix redaction through that binary's stdout/stderr MCP responses.
These process checks exercise the published executable during the AOT run.
A deterministic observation callback reproduces an owner publishing a terminal
record between the initial snapshot read and the process observation; the
query must return that published terminal record and keep unconfirmed work
unknown when no terminal record was published.

## Native AOT

Publishing additionally requires Windows C++ build tools and the Windows SDK.
Preserve the normal Windows `OS` and `PROCESSOR_ARCHITECTURE` environment
variables; do not suppress the native toolchain's checks.

Run `scripts/test.ps1` with `Mode=NativeAot` through a PowerShell script
operation and a JSON parameters file. It publishes into a unique artifact
directory, checks the PE architecture, PE32+ header, absence of a managed CLR
header and managed application companions, then runs the integration suite
against the published executable. See [testing](testing.md).

The native executable can also inspect an artifact directly:

~~~text
CommandEntry.exe inspect-aot --executable <absolute-published-executable>
~~~

## Commands and published layout

| Command | Purpose |
| --- | --- |
| --policy PATH --binding PATH | stdio MCP server with startup integrity check |
| sentinel --records PATH | read one hook event from stdin and return its decision |
| validate-policy --policy PATH | validate the policy structure |
| build-binding --runtime-root PATH --policy PATH --output PATH | create a new binding; refuses overwrite |
| update-policy --repo-root PATH [--policy PATH] | validate, back up the old pair, commit and re-pin |
| update-policy --repo-root PATH --add-program NAME --program-path PATH --kind KIND | reviewed program addition |
| metrics --records PATH --events PATH --serve PATH | envelope-only metrics |
| publication-maintenance --install-root PATH --source-root PATH [--apply true] | preview/apply the fixed reviewed maintenance operation |
| location | actual cwd and root/home exclusions |

The native runtime consists of `CommandEntry.exe`; keep `CommandEntry.pdb`
for diagnosis. There are no published PowerShell adapter or maintenance files.
Bindings cover the executable, including its embedded adapter constants. Managed development
bindings additionally cover the application DLL, deps and runtimeconfig files,
plus `CommandEntry.Common.dll`, `CommandEntry.Server.dll`,
`CommandEntry.Owner.dll` and `CommandEntry.Worker.dll`. Binding checks require
every module and reject a changed hash for any member.
Binding generation holds read handles through hashing and writing; it checks
the written artifact and refuses to overwrite an existing output file.

Policy updates validate before changing the target pair, archive both old
files, and restore them after a commit/re-pin failure. Maintenance uses C#
without launching Python. Policy version 3 is required by Server, Owner and policy validation; unsupported
versions remain rejected. Binding schema version 2 is independently versioned.

Deployment and changes to installed configuration are user operations.
Follow [deployment](deployment.md); preserve existing policies and records.
