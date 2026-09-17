# Testing

The test project uses xUnit.net v3 (package `xunit.v3.mtp-v2` 4.0.0),
Microsoft Testing Platform and Microsoft's TRX report extension. Package
versions live in `Directory.Packages.props`; `global.json` selects the
.NET 10 native MTP command mode. There is no custom discovery loop or test Main.

## Requirements

Use Windows x64 and .NET SDK 10. PowerShell 7 (`pwsh.exe`), Node
(`node.exe`) and Python (`python.exe`) must be on PATH for integration tests.
The test fixture copies the repository policy and assigns those interpreter
paths only in its private policy. It never updates an installed policy.
Native AOT verification also requires the Windows C++ build tools and SDK.

Run commands through the approved command-entry MCP tools. Native commands use
the `dotnet` program key. For `scripts/test.ps1`, use a PowerShell script
operation; pass named parameters through a bound JSON `parameters_file`
(for example `{"Mode":"NativeAot"}`), as required by the command-entry contract.

## Suites

| Selection | Scope |
| --- | --- |
| `Category=Unit` | Numeric canonicalization, request identities, redaction, in-memory output decoding, sentinel parsing and cleanup callbacks |
| `Category=Integration` | Files, locks, Windows processes, MCP protocol, interpreters, lifecycle, policy and runtime bindings |
| `Suite=Regression` | Focused audit, output/index, cleanup and policy-version regressions; overlaps the two categories |
| `Suite=Smoke` | End-to-end session and rejection/recovery checks; part of Integration |

Every test has exactly one Category. Suite is an additional label, not a third
disjoint category. Run both categories to cover the complete suite.
Tests run sequentially because some change process environment and observe
related processes. Each fixture has a unique workspace; synthetic execution
evidence is retained under `.codex-command-records/`.

The independent subprocess helper is `CommandEntry.TestProbe`. It has no test
framework dependency. Process tests run that helper through the real
Server → Owner → Worker path. The three runtime roles remain separate processes.

Frozen reference data supplies 281 numeric examples, five request identities,
text-read cases and redaction expectations. Numeric, identity and redaction
rows are individually reported by xUnit theories. The 17 audit regressions are
independent facts, so one failing scenario does not hide later results.
Cleanup and interpreter matrices also use theories with separately named rows.

## Local commands

~~~text
dotnet test --project tests/CommandEntry.Tests.csproj --configuration Release
dotnet test --project tests/CommandEntry.Tests.csproj --configuration Release --filter-trait "Category=Unit"
dotnet test --project tests/CommandEntry.Tests.csproj --configuration Release --filter-trait "Category=Integration"
dotnet test --project tests/CommandEntry.Tests.csproj --configuration Release --filter-trait "Suite=Regression"
dotnet test --project tests/CommandEntry.Tests.csproj --configuration Release --filter-trait "Suite=Smoke"
~~~

MTP arguments are passed directly, without the VSTest bridge separator.
Add `--report-trx --results-directory artifacts/test-results/manual` for TRX.
Add `--no-build` only after building the same configuration.

`scripts/test.ps1` is the automated entry:
- `Mode=Managed` (default): build, run Unit, then Integration.
- `Mode=NativeAot`: build the tests/probe, publish into a fresh directory,
  inspect the actual PE artifact, then run Integration against that executable.

Each invocation uses a unique directory under `artifacts/test-results/`.
The script checks every command's exit code and requires nonempty TRX reports
with all selected tests passed; empty discovery or skipped tests cannot make
the automation pass. Native publication and tests execute sequentially.

The fixture normally uses the matching managed Release/Debug build.
`COMMAND_ENTRY_TEST_SERVER` selects an explicitly supplied server executable;
the automation sets and restores it for AOT testing. AOT artifact inspection
belongs to the NativeAot automation step, so pointing this variable at a file
alone does not prove that file is native.

## CI

`.github/workflows/tests.yml` runs the same script on Windows for pushes,
pull requests and manual dispatch. Managed and NativeAot jobs use separate
runners and upload TRX reports even after a failure.
No deployment is performed.

The policy template and both execution entry points require policy version 3.
Regression tests reject unsupported versions before a second business execution.
Binding schema version 2 and publication-index schema versions 1/2 are separate
formats; their versions do not follow the policy revision. New publications use
schema 2 with hash-bound prepared plans and a durable launch-commit transition.
`AuditV7Tests` exercises interrupted publication stages with/without an old
claim, warm/restarted servers, conflicting evidence, concurrent event writers,
wait-lock diagnostics and ASCII handshake values.

`AuditBoundaryTests` covers independently pinned owner publications (request,
policy and missing proof), cross-server path/default-encoding aliases, legacy
running/unknown identities, prepared aliases without published requests,
unidentifiable claims, rejection of changed committed snapshots, retry lineage including earlier legacy instances, artifact
path equivalence, occupied event mutexes, unconfirmed wait results, and validation
of the actual read handle against allowed roots before any bytes are consumed.
