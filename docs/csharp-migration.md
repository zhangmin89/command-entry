# C# MCP server and Native AOT

The six public MCP tools are implemented in `src/CommandEntry` using .NET 10
and the official `ModelContextProtocol.Core` SDK, pinned to 2.2.0. The stdio
transport and protocol handling use the SDK. The existing Python sources
remain available as a behavioral reference and for the existing operational
scripts and shell sentinel. This change does not switch the installed server.

## Build and verification

Use the approved command-entry MCP tools to execute these operations from the
repository root. `dotnet` is the native policy key; no shell command is needed.

```text
dotnet build src/CommandEntry/CommandEntry.csproj --configuration Release --verbosity minimal
dotnet publish src/CommandEntry/CommandEntry.csproj --configuration Release --runtime win-x64 --output artifacts/command-entry-win-x64 --verbosity minimal
```

Publishing requires the Windows C++ build tools and Windows SDK in addition
to the .NET SDK. The execution environment must preserve the Windows `OS`
and `PROCESSOR_ARCHITECTURE` variables. Missing `OS=Windows_NT` caused Native
AOT's cross-OS check to reject this Windows-to-Windows publish; the source
does not override these variables or suppress the check.

Run `scripts/test-native-aot.py` with the Python script operation. It checks
the PE architecture, absence of a managed CLR header and managed application
companions, and presence of the required script helpers. It then runs the
MCP contract suite against the published executable. The same suite runs
against the managed build through the Python unittest operation:

```text
python -m unittest tests.test_csharp_migration -v -f
```

The suite covers argument boundaries, binary stdin, no-console execution,
Python-compatible request identities, redaction and output quotas, Unicode
paging, strict UTF-8/GBK/UTF-16 range reads, syntax and batch rejection,
deduplication across server instances, claim recovery, retry bindings,
acceptance checks, cancellation, abandoned executions, wait accounting,
server exit survival, and policy/runtime integrity rejection.

Test records are retained under `.codex-command-records/csharp-test-*`.

For deterministic numeric parity and cleanup fault injection, build the
existing conditional harness into a separate output directory:

```text
dotnet build src/CommandEntry/CommandEntry.csproj --configuration Release -p:DefineConstants=CONFORMANCE --output artifacts/command-entry-conformance --verbosity minimal
dotnet artifacts/command-entry-conformance/CommandEntry.dll conformance
```

Run these from this repository root. The harness uses its configured Python
interpreter, a fixed random seed, and retained cleanup records. Publish without
`CONFORMANCE` for deployment. `scripts/check-read-text-parity.py` records both
implementations' CR/LF, decoding and block-boundary results for diagnosis.

## Runtime layout

| File | Purpose |
| --- | --- |
| `CommandEntry.exe` | Native MCP server, detached owner and worker modes |
| `invoke.ps1` | Existing PowerShell parameter binding implementation |
| `check_powershell.ps1` | Existing PowerShell syntax check |
| `check_python.py` | Existing Python syntax check for requested Python work |
| `CommandEntry.pdb` | Native symbols; keep with release artifacts for diagnosis |

The server, owner and worker need neither a Python interpreter nor an
installed .NET runtime. Executing Python work still requires the configured
Python interpreter; PowerShell and JavaScript work similarly use their
configured interpreters. Development contract tests use Python. The existing
Python sentinel and policy maintenance scripts remain separate components.

## Execution and integrity contracts

- Business and syntax-check processes use `ProcessStartInfo`,
  `UseShellExecute=false`, `ArgumentList`, `CreateNoWindow=true`, and an
  explicit working directory. No `Arguments` string is constructed.
- The detached owner requires native creation flags that `ProcessStartInfo`
  does not expose. A small `LibraryImport` boundary calls `CreateProcessW`
  for the fixed `CommandEntry.exe` only. Its input-directory reference is
  passed in a child-only environment block and removed before starting the
  worker. Business arguments never cross this native launcher boundary.
- The owner holds the kill-on-close Job. The worker receives permission to
  start its business process only after Job assignment. Process cancellation
  identifies instances by PID and creation time, and confirms their death.
- File bindings deny concurrent writes/deletes while an execution uses its
  inputs. Request identifiers and persisted envelopes retain the existing
  format. Atomic claims and publication preserve the duplicate-start rules.
- Output continues draining after retention is exhausted. Only bounded,
  redacted text is persisted. Output offsets count Unicode code points.
- `read_text` preserves the Python CR lookahead and loaded-block diagnostic
  behavior: a fault before the CR line is completed rejects the range; a fault
  later in an already-loaded block is reported as `decode_warning` after a
  complete range. It does not scan subsequent blocks just to find warnings.
- MCP error messages are redacted, so credential-shaped diagnostic text can
  be replaced. This is intentional. A corrupt `wait-state.json` remains a
  structured failure requiring operator investigation; it is never deleted
  or silently reset. Cleanup errors preserve the primary error in the record
  and do not turn an unconfirmed process exit into a successful exit.
- Existing path, program, syntax, retry and acceptance checks remain in the
  execution path. Policy checks are not replaced by the SDK or process API.
- Agent Governance Toolkit and SecureString are not introduced. The SDK and
  AOT are not treated as substitutes for policy, redaction or process control.

## Reviewed deployment

Deployment and changes to installed configuration remain user operations.
Use a separate release directory and stop creating work through the old
server before switching. Retain existing execution records and the sentinel.
The old `scripts/build_binding.py` targets Python runtime files and must not
be used to build a C# binding. Use the updated maintenance workflow below.

1. Copy the published runtime files into the intended release directory.
2. Keep the reviewed installed policy's program mappings, roots, limits and
   record locations. Do not replace it with the repository template.
3. Run `scripts/build-dotnet-binding.ps1` using the PowerShell script
   operation and a JSON parameters file with absolute string values for
   `RuntimeRoot`, `PolicyPath`, and a **new** `OutputPath`. It hashes the native
   executable and three script helpers while holding read-only handles, then
   creates and validates a schema-version-2 binding. It refuses overwrite.
   Startup requires the current process executable, the owner/worker executable
   and every helper to be present in the verified set. Paths are resolved and
   compared using Windows case-insensitive semantics; another directory's
   identical files cannot stand in for the running files. Managed development
   apphost bindings additionally cover `CommandEntry.dll`, `.deps.json` and
   `.runtimeconfig.json`; the builder includes these when the DLL is present.
4. Point the MCP client command at the release's `CommandEntry.exe`, with
   argument-list entries `--policy`, the reviewed policy path, `--binding`,
   and the new binding path. Restart the server and verify tools/list plus
   a harmless execution and its status/output before using normal workloads.

Keep `serve_root` and `record_root` aligned with the existing installation
when previous execution IDs must remain queryable. Never remove an unknown
execution merely to permit a restart; use cancellation to confirm all known
process instances are dead.

For later policy updates, install the updated `update-policy.ps1`,
`scripts/build-dotnet-binding.ps1` and the existing `scripts/validate_policy.py`
alongside the release. Policy maintenance still uses the configured Python
interpreter and the unchanged policy validation rules. Invoke the update script
through the approved PowerShell script operation with a JSON parameters file.
`RepoRoot` is the release root; `PolicyPath` is the reviewed candidate policy,
or use the existing `AddProgram` parameters for an approved program change.

When `CommandEntry.exe` exists, the updater uses the .NET binding builder even
if old Python files are also present. It validates the candidate first, backs
up the old policy/binding pair, commits the policy, creates a new candidate
binding with the final policy path, and replaces the binding only after the
builder succeeds. A failure restores the old pair; diagnostic candidate files
are retained. The two files are not an atomic multi-file transaction: stop
starting work during maintenance, and restart the server after a successful
update. Python-only installations retain their existing update path.

## Validation limits

The black-box checks exercise the C# MCP routes. They do not port every
Python unit test's internal monkey-patching surface. Legacy Python debug
queries and maintenance scripts are still available through their original
entry points; this release's `run` CLI is for prepared execution requests.

Job breakaway availability is still a property of the host environment. A
server-process crash can be survived while termination of a containing host
Job can still terminate the owner. `orphan_guaranteed` continues to report
that distinction, and `require_orphan_guarantee` continues to reject starts
when the configured guarantee is unavailable.
