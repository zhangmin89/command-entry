using System.Text;

namespace CommandEntry;

// Fixed invocation adapter embedded in the reviewed executable. User paths and
// parameters remain data; they are never interpolated into PowerShell code.
internal static class PowerShellAdapter
{
    internal const string RequestVariable = "COMMAND_ENTRY_POWERSHELL_REQUEST";

    internal static string[] InvocationArguments() => Arguments(Invocation);
    private static string[] Arguments(string code) =>
        ["-NoProfile", "-OutputFormat", "Text", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(code))];

    private const string Invocation = """
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $RequestPath = [Environment]::GetEnvironmentVariable('COMMAND_ENTRY_POWERSHELL_REQUEST')
        Remove-Item -LiteralPath 'Env:COMMAND_ENTRY_POWERSHELL_REQUEST'
        if (-not (Test-Path -LiteralPath $RequestPath -PathType Leaf)) { throw 'Request file missing.' }
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
        $request = Get-Content -LiteralPath $RequestPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
        $parameters = @{}
        if ($request.mode -eq 'cmdlet') {
            $target = Get-Command -Name $request.command -CommandType Cmdlet -ErrorAction Stop
            if ($request.ContainsKey('parameters')) { $parameters = $request.parameters }
        } else {
            $target = Get-Command -Name $request.script -CommandType ExternalScript -ErrorAction Stop
            if ($request.ContainsKey('parameters_file')) {
                $parameters = Get-Content -LiteralPath $request.parameters_file -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
            }
        }
        if ($parameters -isnot [System.Collections.IDictionary]) { throw 'Parameters must be a JSON object.' }
        foreach ($key in $parameters.Keys) {
            if (-not $target.Parameters.ContainsKey($key)) { throw 'Unknown or abbreviated parameter name.' }
        }
        $global:LASTEXITCODE = 0
        & $target @parameters
        $invocationSucceeded = $?
        $invocationExitCode = $LASTEXITCODE
        if ($invocationExitCode -ne 0) { exit $invocationExitCode }
        if (-not $invocationSucceeded) { exit 1 }
        """;

}
