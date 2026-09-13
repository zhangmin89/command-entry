[CmdletBinding()]
param([Parameter(Mandatory)][ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$RequestPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
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
# Explicit script exit propagates through PowerShell; no inference of subgoal success here.
